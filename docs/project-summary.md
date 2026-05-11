# AI-Assisted SOC Detection Lab — Project Summary

**Author:** Fernagod  
**Last Updated:** May 2026  
**Status:** Phase 5 Complete — Phase 6 In Progress

---

## What This Project Is

A fully functional home Security Operations Center (SOC) lab built from scratch. The lab simulates a real enterprise security environment where attacks are executed, telemetry is collected, alerts are generated, and an AI pipeline analyzes and enriches the detections. The goal is to demonstrate real SOC analyst, detection engineering, and security automation skills for a cybersecurity portfolio.

---

## Infrastructure Built

### Virtual Machines (VirtualBox)

| VM | OS | IP Address | Role |
|---|---|---|---|
| Kali Linux | Kali Rolling | 192.168.56.101 | Attacker |
| Win10-Victim | Windows 10 Education | 192.168.56.102 | Victim Endpoint |
| Ubuntu-SIEM | Ubuntu Server 24.04 LTS | 192.168.56.103 | SIEM + AI Pipeline |

**Network:** VirtualBox Host-Only network (192.168.56.0/24) for lab traffic + NAT for internet access.

All three VMs can communicate with each other. Connectivity was verified with ping tests across all nodes.

---

## Software Stack

| Component | Tool | Purpose |
|---|---|---|
| Hypervisor | Oracle VirtualBox 7.x | VM management |
| SIEM | Wazuh 4.7.5 | Log collection, alerting, dashboards |
| Endpoint Telemetry | Sysmon (Microsoft Sysinternals) | Deep Windows event logging |
| Attack Simulation | Atomic Red Team | Safe MITRE ATT&CK mapped simulations |
| AI Enrichment | Anthropic Claude API | Alert analysis and investigation reports |
| Detection Format | Sigma + Wazuh XML rules | Vendor-neutral and platform-specific detections |

---

## Phase-by-Phase Breakdown

### Phase 0 — Architecture Design ✅
- Created a three-node architecture diagram using diagrams.net
- Defined attacker, victim, and SIEM roles for each VM
- Documented the telemetry flow: Windows → Sysmon → Wazuh Agent → Wazuh Manager
- Saved architecture diagram to `docs/architecture.png`

---

### Phase 1 — Virtualization Setup ✅

**What was done:**
- Installed Oracle VirtualBox on the host machine
- Created a Host-Only network adapter (192.168.56.0/24)
- Kali Linux was already installed — kept as the attacker VM
- Created Windows 10 VM (Win10-Victim) from Microsoft evaluation ISO
  - 4GB RAM, 2 CPUs, 50GB disk
  - Local account: labuser
  - Set static IP 192.168.56.102 on host-only adapter
- Created Ubuntu Server VM (Ubuntu-SIEM) from Ubuntu 24.04 LTS ISO
  - 4GB RAM, 2 CPUs, 60GB disk
  - Local account: labuser / Password123!
  - Set static IP 192.168.56.103 via netplan
- Verified all three VMs can ping each other
- Windows Firewall ICMP rule added to allow ping

**Key commands used:**
```powershell
# Windows — set static IP
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.102 -PrefixLength 24

# Windows — allow ping
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow
```

```bash
# Ubuntu — set static IP via netplan
sudo nano /etc/netplan/00-installer-config.yaml
sudo netplan apply
sudo chmod 600 /etc/netplan/00-installer-config.yaml
```

---

### Phase 2 — SIEM Setup (Wazuh) ✅

**What was done:**
- Downloaded Wazuh 4.7.5 all-in-one installer on Ubuntu-SIEM
- Installed with `--ignore-check` flag to bypass Ubuntu 24.04 compatibility check
- Wazuh installs three components:
  - **Wazuh Manager** — processes alerts and rules
  - **Wazuh Indexer** — stores and indexes events (OpenSearch-based)
  - **Wazuh Dashboard** — web UI for viewing alerts
- Saved admin credentials at end of install
- Accessed dashboard at https://192.168.56.103
- Confirmed dashboard loads and login works

**Install command:**
```bash
curl https://packages.wazuh.com/4.7/wazuh-install.sh -o wazuh-install.sh
sudo bash wazuh-install.sh -a --ignore-check
```

**Credentials:**
- URL: https://192.168.56.103
- Username: admin
- Password: tBx43M8wa8zHRJN?JEX3.967GPmZVOVu

---

### Phase 3 — Endpoint Telemetry ✅

**What was done:**

**Sysmon Installation (Windows VM):**
- Downloaded Sysmon from Microsoft Sysinternals
- Created a custom Sysmon config file (basic config logging all process creation, network connections, file creation, registry changes)
- Installed Sysmon with config: `Sysmon64.exe -accepteula -i sysmonconfig.xml`
- Verified Sysmon service running

**Key Sysmon Event IDs being collected:**

| Event ID | What It Captures |
|---|---|
| 1 | Process creation (full command line) |
| 3 | Network connections |
| 7 | Image/DLL loaded |
| 11 | File created |
| 13 | Registry value set |
| 22 | DNS query |

**Wazuh Agent Installation (Windows VM):**
- Deployed agent from Wazuh dashboard (Deploy New Agent → Windows)
- Agent registered with manager at 192.168.56.103
- Added Sysmon event channel to ossec.conf:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
- Fixed config error where localfile block was outside ossec_config tags
- Confirmed agent shows Active in Wazuh dashboard
- Verified 430+ events flowing from Win10-Victim including MITRE-mapped alerts

**Result:** Real-time Windows telemetry visible in Wazuh dashboard within seconds of activity on the endpoint.

---

### Phase 4 — Attack Simulation ✅

**Tool:** Atomic Red Team (by Red Canary) — safe MITRE ATT&CK mapped simulations

**Setup:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Simulations Run:**

#### T1082 — System Information Discovery
- **Command:** `Invoke-AtomicTest T1082 -TestNumbers 1`
- **What it did:** Ran systeminfo.exe and queried registry keys to enumerate the OS, hardware, network configuration, and installed hotfixes
- **Logs created:** Sysmon Event ID 1 for systeminfo.exe and reg.exe process creation
- **Why attackers use it:** To understand the target environment before deciding on next attack steps
- **Detection difficulty:** Medium — systeminfo.exe is a legitimate tool

#### T1053.005 — Scheduled Task Persistence
- **Command:** `Invoke-AtomicTest T1053.005 -TestNumbers 1`
- **What it did:** Created two scheduled tasks (T1053_005_OnLogon and T1053_005_OnStartup) that would survive reboots
- **Logs created:** Sysmon Event ID 1 for schtasks.exe with /create argument
- **Why attackers use it:** Persistence — to maintain access after the system reboots
- **Detection difficulty:** Medium — schtasks.exe is used by legitimate software

#### T1012 — Query Registry
- **Command:** `Invoke-AtomicTest T1012 -TestNumbers 1`
- **What it did:** Queried dozens of registry keys including Run keys, installed software, and system configuration
- **Logs created:** Sysmon Event ID 1 for reg.exe with query arguments
- **Why attackers use it:** To find persistence locations, installed security tools, and system information
- **Detection difficulty:** High — reg.exe queries are extremely common in normal Windows operation

**All simulations generated visible alerts in Wazuh with MITRE ATT&CK mappings.**

---

### Phase 5 — Detection Engineering ✅

**What was done:**
- Wrote custom Wazuh detection rules in `/var/ossec/etc/rules/local_rules.xml`
- Overcame XML syntax errors through iterative debugging
- Successfully loaded rules and confirmed firing in Wazuh dashboard

**Custom Rules Written:**

```xml
<group name="local,">

  <rule id="100001" level="5">
    <match>test</match>
    <description>Test rule</description>
  </rule>

  <rule id="100002" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
    <description>PowerShell execution detected (T1059.001)</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>

  <rule id="100003" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)schtasks\.exe</field>
    <description>Scheduled task created (T1053.005)</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>

  <rule id="100004" level="8">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)reg\.exe</field>
    <description>Registry query detected (T1012)</description>
    <mitre><id>T1012</id></mitre>
  </rule>

  <rule id="100005" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)systeminfo\.exe</field>
    <description>System information discovery (T1082)</description>
    <mitre><id>T1082</id></mitre>
  </rule>

</group>
```

**Confirmed detections:**
- Rule 100002 fired on PowerShell execution — visible in Wazuh with correct MITRE mapping
- Rule group "local" visible in Top 5 rule groups dashboard

---

## Challenges Encountered and Solved

| Challenge | Solution |
|---|---|
| Wazuh 4.7 not supporting Ubuntu 24.04 | Used `--ignore-check` flag to bypass OS check |
| Ubuntu repo certificate errors | Fixed with `sudo timedatectl set-ntp true` |
| Windows VM clock sync issues | Set DNS to 8.8.8.8 and re-ran commands |
| GitHub raw content domain blocked | Created Sysmon config manually via PowerShell |
| Clipboard sharing not working in VMs | Installed VirtualBox Guest Additions |
| Wazuh agent showing Disconnected | Fixed ossec.conf — localfile block was outside ossec_config tags |
| Custom rules causing Wazuh to fail | Debugged XML syntax errors iteratively using journalctl logs |
| No backup of original rules file | Learned to always backup config files before editing |

---

## Current Detection Coverage

| MITRE Technique | Rule ID | Level | Status |
|---|---|---|---|
| T1059.001 — PowerShell Execution | 100002 | 10 | ✅ Firing |
| T1053.005 — Scheduled Task | 100003 | 10 | ✅ Active |
| T1012 — Query Registry | 100004 | 8 | ✅ Active |
| T1082 — System Info Discovery | 100005 | 12 | ✅ Active |

---

## Up Next

### Phase 6 — AI Enrichment Pipeline
Build a Python script that:
- Reads Wazuh alerts
- Sends alert context to Claude API
- Receives structured analysis: severity, MITRE mapping, investigation steps, remediation
- Saves enriched alerts as JSON and Markdown reports

### Phase 7 — Reporting
- Attack timelines for each simulation
- Incident reports generated by AI pipeline
- Screenshots organized

### Phase 8 — GitHub Polish
- Initialize git repository
- Write professional README with architecture diagram, detection examples, AI pipeline explanation
- Push all docs, detections, automation scripts, and reports

---

## Project Folder Structure

```
C:\Users\Fernagod\Documents\ai-soc-detection-lab\
├── docs/
│   ├── architecture.png
│   ├── architecture.md
│   └── attack-log.md
├── detections/
│   └── local_rules.xml
├── automation/
│   └── alert_enricher.py      ← (Phase 6)
├── reports/                    ← (Phase 7)
├── screenshots/
│   ├── phase2-wazuh-dashboard.png
│   ├── phase3-agent-active.png
│   ├── phase3-events-flowing.png
│   ├── phase3-security-alerts.png
│   ├── phase4-attack-dashboard.png
│   ├── phase4-security-alerts.png
│   └── phase5-custom-rule-firing.png
├── attack-scripts/
└── sample-logs/
```

---

## Key Takeaways So Far

1. **Real enterprise tools are complex** — Wazuh, Sysmon, and Atomic Red Team all required troubleshooting and deep understanding to deploy correctly.

2. **Configuration management matters** — Nearly every issue came from a misconfiguration, not a software bug. Always backup config files before editing.

3. **Detection engineering is harder than it looks** — Writing XML rules that load correctly, match the right events, and avoid false positives requires precision.

4. **Telemetry is everything** — Without Sysmon, most of these attacks would be invisible. The difference between basic Windows logging and Sysmon logging is dramatic.

5. **MITRE ATT&CK is the common language** — Every simulation, every rule, and every alert maps back to a MITRE technique. This is how real SOC teams communicate about threats.
