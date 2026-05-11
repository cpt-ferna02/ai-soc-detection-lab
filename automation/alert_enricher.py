#!/usr/bin/env python3
"""
alert_enricher.py — AI-Assisted SOC Detection Lab
Phase 6: AI Enrichment Pipeline

Reads Wazuh alerts from the alerts.json log, sends alert context to the
Claude API, and saves structured enrichment as JSON + Markdown reports.

Author: Fernagod
Project: AI-Assisted SOC Detection Lab
"""

import json
import os
import sys
import time
import argparse
import re
from datetime import datetime
from pathlib import Path

import anthropic  # pip install anthropic

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WAZUH_ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"   # on Ubuntu-SIEM
REPORTS_DIR = Path("reports")
SAMPLE_LOGS_DIR = Path("sample-logs")

CLAUDE_MODEL = "claude-opus-4-5"

# Only process alerts at or above this Wazuh severity level
MIN_ALERT_LEVEL = 8

# ---------------------------------------------------------------------------
# Wazuh alert loader
# ---------------------------------------------------------------------------

def load_alerts(path: str, min_level: int, max_alerts: int = 20) -> list[dict]:
    """
    Parse Wazuh alerts.json (newline-delimited JSON objects).
    Returns alerts at or above min_level, newest first, up to max_alerts.
    """
    alerts = []
    log_path = Path(path)

    if not log_path.exists():
        print(f"[!] Alert log not found at {path}")
        print(f"    If running offline, place sample alerts in {SAMPLE_LOGS_DIR}/sample_alerts.json")
        return alerts

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                level = int(alert.get("rule", {}).get("level", 0))
                if level >= min_level:
                    alerts.append(alert)
            except json.JSONDecodeError:
                continue  # skip malformed lines

    # Sort newest first, cap at max_alerts
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return alerts[:max_alerts]


def load_sample_alerts(path: str) -> list[dict]:
    """Load a JSON array of sample alerts for offline testing."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]

# ---------------------------------------------------------------------------
# Alert → prompt builder
# ---------------------------------------------------------------------------

def build_alert_summary(alert: dict) -> str:
    """Extract the most useful fields from a Wazuh alert for the prompt."""
    rule    = alert.get("rule", {})
    agent   = alert.get("agent", {})
    data    = alert.get("data", {})
    win     = data.get("win", {})
    evtdata = win.get("eventdata", {})
    system  = win.get("system", {})

    mitre_ids = rule.get("mitre", {}).get("id", [])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    lines = [
        f"Timestamp       : {alert.get('timestamp', 'N/A')}",
        f"Agent           : {agent.get('name', 'N/A')} ({agent.get('ip', 'N/A')})",
        f"Rule ID         : {rule.get('id', 'N/A')}",
        f"Rule Level      : {rule.get('level', 'N/A')}",
        f"Description     : {rule.get('description', 'N/A')}",
        f"MITRE ATT&CK    : {', '.join(mitre_ids) if mitre_ids else 'N/A'}",
        f"Rule Groups     : {', '.join(rule.get('groups', []))}",
    ]

    # Sysmon Event ID 1 — process creation fields
    if evtdata.get("image"):
        lines += [
            f"Process Image   : {evtdata.get('image', 'N/A')}",
            f"CommandLine     : {evtdata.get('commandLine', 'N/A')}",
            f"ParentImage     : {evtdata.get('parentImage', 'N/A')}",
            f"ParentCmdLine   : {evtdata.get('parentCommandLine', 'N/A')}",
            f"User            : {evtdata.get('user', 'N/A')}",
            f"Hashes          : {evtdata.get('hashes', 'N/A')}",
            f"CurrentDirectory: {evtdata.get('currentDirectory', 'N/A')}",
        ]

    # Sysmon Event ID 3 — network connection
    if evtdata.get("destinationIp"):
        lines += [
            f"DestinationIP   : {evtdata.get('destinationIp', 'N/A')}",
            f"DestinationPort : {evtdata.get('destinationPort', 'N/A')}",
            f"DestinationHost : {evtdata.get('destinationHostname', 'N/A')}",
            f"Protocol        : {evtdata.get('protocol', 'N/A')}",
        ]

    # Raw full_log as fallback context
    if alert.get("full_log"):
        lines.append(f"Full Log        : {alert.get('full_log', '')[:500]}")

    return "\n".join(lines)


SYSTEM_PROMPT = """You are an expert SOC analyst and threat intelligence specialist.
You will receive a Wazuh SIEM alert from a Windows endpoint monitored with Sysmon.
Analyze the alert and return a structured JSON object — NO markdown fences, NO preamble.

Required JSON schema:
{
  "severity": "Critical|High|Medium|Low",
  "confidence": "High|Medium|Low",
  "mitre_technique": "T-ID — Technique Name",
  "mitre_tactic": "Tactic name (e.g. Execution, Persistence, Discovery)",
  "summary": "2-3 sentence plain-English summary of what happened and why it matters.",
  "ioc_indicators": ["list", "of", "key", "observables"],
  "investigation_steps": ["numbered", "actionable", "investigation", "steps"],
  "containment_actions": ["immediate", "containment", "actions"],
  "false_positive_likelihood": "High|Medium|Low",
  "false_positive_reasoning": "One sentence explaining why this might be benign.",
  "verdict": "Malicious|Suspicious|Likely Benign"
}
Return only the JSON object. No other text."""


def enrich_alert(client: anthropic.Anthropic, alert: dict) -> dict:
    """Send one alert to Claude and return the parsed enrichment dict."""
    alert_text = build_alert_summary(alert)

    message = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze this Wazuh alert:\n\n{alert_text}"
            }
        ]
    )

    raw = message.content[0].text.strip()

    # Strip accidental markdown fences if Claude adds them
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    enrichment = json.loads(raw)
    return enrichment

# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def save_json_report(alert: dict, enrichment: dict, out_dir: Path) -> Path:
    """Save combined alert + enrichment as a JSON file."""
    rule_id = alert.get("rule", {}).get("id", "unknown")
    ts = alert.get("timestamp", datetime.utcnow().isoformat())
    # sanitise timestamp for filename
    ts_clean = re.sub(r"[:\.\+]", "-", ts)[:19]
    filename = out_dir / f"enriched_{rule_id}_{ts_clean}.json"

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "original_alert": alert,
        "ai_enrichment": enrichment,
    }
    filename.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return filename


def save_markdown_report(alert: dict, enrichment: dict, out_dir: Path) -> Path:
    """Save a human-readable Markdown incident report."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = rule.get("id", "unknown")
    ts = alert.get("timestamp", datetime.utcnow().isoformat())
    ts_clean = re.sub(r"[:\.\+]", "-", ts)[:19]
    filename = out_dir / f"report_{rule_id}_{ts_clean}.md"

    verdict = enrichment.get("verdict", "Unknown")
    severity = enrichment.get("severity", "Unknown")
    verdict_emoji = {"Malicious": "🔴", "Suspicious": "🟡", "Likely Benign": "🟢"}.get(verdict, "⚪")

    iocs = "\n".join(f"- `{i}`" for i in enrichment.get("ioc_indicators", []))
    inv  = "\n".join(f"{n+1}. {s}" for n, s in enumerate(enrichment.get("investigation_steps", [])))
    cont = "\n".join(f"- {a}" for a in enrichment.get("containment_actions", []))

    md = f"""# {verdict_emoji} AI SOC Incident Report

| Field | Value |
|---|---|
| **Generated** | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} |
| **Agent** | {agent.get('name', 'N/A')} `{agent.get('ip', 'N/A')}` |
| **Rule** | {rule_id} — {rule.get('description', 'N/A')} |
| **Alert Timestamp** | {ts} |
| **Wazuh Level** | {rule.get('level', 'N/A')} |

---

## Verdict: {verdict_emoji} {verdict}

| | |
|---|---|
| **Severity** | {severity} |
| **Confidence** | {enrichment.get('confidence', 'N/A')} |
| **MITRE Technique** | `{enrichment.get('mitre_technique', 'N/A')}` |
| **MITRE Tactic** | {enrichment.get('mitre_tactic', 'N/A')} |
| **False Positive Risk** | {enrichment.get('false_positive_likelihood', 'N/A')} |

---

## Summary

{enrichment.get('summary', 'No summary available.')}

---

## Key Indicators of Compromise

{iocs if iocs else '_No IOCs extracted._'}

---

## Investigation Steps

{inv if inv else '_No steps provided._'}

---

## Containment Actions

{cont if cont else '_No containment actions recommended._'}

---

## False Positive Assessment

{enrichment.get('false_positive_reasoning', 'N/A')}

---

## Raw Alert Context

```
{build_alert_summary(alert)}
```

---
*Generated by alert_enricher.py — AI-Assisted SOC Detection Lab*
"""
    filename.write_text(md, encoding="utf-8")
    return filename

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Phase 6: Enrich Wazuh alerts with Claude AI analysis"
    )
    parser.add_argument(
        "--alerts-log",
        default=WAZUH_ALERTS_LOG,
        help=f"Path to Wazuh alerts.json (default: {WAZUH_ALERTS_LOG})"
    )
    parser.add_argument(
        "--sample",
        metavar="FILE",
        help="Use a JSON sample file instead of live Wazuh log (for offline testing)"
    )
    parser.add_argument(
        "--min-level",
        type=int,
        default=MIN_ALERT_LEVEL,
        help=f"Minimum Wazuh alert level to process (default: {MIN_ALERT_LEVEL})"
    )
    parser.add_argument(
        "--max-alerts",
        type=int,
        default=20,
        help="Maximum number of alerts to process in one run (default: 20)"
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPORTS_DIR),
        help=f"Directory to write reports (default: {REPORTS_DIR})"
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("ANTHROPIC_API_KEY"),
        help="Anthropic API key (default: $ANTHROPIC_API_KEY env var)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # --- API key check ---
    if not args.api_key:
        print("[!] No Anthropic API key found.")
        print("    Set ANTHROPIC_API_KEY env var or pass --api-key")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=args.api_key)

    # --- Output dir ---
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Load alerts ---
    if args.sample:
        print(f"[*] Loading sample alerts from {args.sample}")
        alerts = load_sample_alerts(args.sample)
    else:
        print(f"[*] Loading alerts from {args.alerts_log} (level >= {args.min_level})")
        alerts = load_alerts(args.alerts_log, args.min_level, args.max_alerts)

    if not alerts:
        print("[!] No alerts found matching criteria. Exiting.")
        sys.exit(0)

    print(f"[*] Found {len(alerts)} alert(s) to process\n")

    # --- Process each alert ---
    results = []
    for i, alert in enumerate(alerts, 1):
        rule   = alert.get("rule", {})
        desc   = rule.get("description", "Unknown")
        level  = rule.get("level", "?")
        rule_id = rule.get("id", "?")

        print(f"[{i}/{len(alerts)}] Rule {rule_id} (L{level}): {desc}")
        print("          → Sending to Claude API...", end=" ", flush=True)

        try:
            enrichment = enrich_alert(client, alert)
            verdict    = enrichment.get("verdict", "Unknown")
            severity   = enrichment.get("severity", "Unknown")
            print(f"✓  [{severity}] {verdict}")

            json_path = save_json_report(alert, enrichment, out_dir)
            md_path   = save_markdown_report(alert, enrichment, out_dir)
            print(f"             → {md_path.name}")

            results.append({
                "rule_id":    rule_id,
                "description": desc,
                "verdict":    verdict,
                "severity":   severity,
                "json":       str(json_path),
                "markdown":   str(md_path),
            })

        except json.JSONDecodeError as e:
            print(f"✗  JSON parse error: {e}")
        except anthropic.APIError as e:
            print(f"✗  API error: {e}")

        # Respect rate limits between calls
        if i < len(alerts):
            time.sleep(1.0)

    # --- Summary ---
    print(f"\n{'─'*60}")
    print(f"  Run complete — {len(results)}/{len(alerts)} alerts enriched")
    print(f"  Reports written to: {out_dir.resolve()}")
    print(f"{'─'*60}")

    verdicts = [r["verdict"] for r in results]
    for v in ["Malicious", "Suspicious", "Likely Benign"]:
        count = verdicts.count(v)
        if count:
            emoji = {"Malicious": "🔴", "Suspicious": "🟡", "Likely Benign": "🟢"}[v]
            print(f"  {emoji} {v}: {count}")

    print()

    # Save run summary JSON
    summary_path = out_dir / f"run_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    summary_path.write_text(
        json.dumps({"run_at": datetime.utcnow().isoformat(), "results": results}, indent=2),
        encoding="utf-8"
    )
    print(f"  Run summary: {summary_path.name}\n")


if __name__ == "__main__":
    main()
