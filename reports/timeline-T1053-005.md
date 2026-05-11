# Attack Timeline — T1053.005 Scheduled Task Persistence
**Date:** 2026-05-10  
**Simulated by:** Atomic Red Team

| Time | Event | Source | Details |
|------|-------|--------|---------|
| 21:15:07 | Attacker creates scheduled tasks | Atomic Red Team | schtasks.exe /create |
| 21:15:07 | Two tasks created | Windows Task Scheduler | T1053_005_OnLogon, T1053_005_OnStartup |
| 21:15:07 | Sysmon captures process creation | Sysmon Event ID 1 | schtasks.exe with /create argument |
| 21:15:07 | Wazuh agent forwards event | Wazuh Agent | Shipped to manager |
| 21:15:07 | Rule 100003 fires | Wazuh Manager | Level 10 alert generated |
| 21:15:07 | AI enrichment triggered | alert_enricher.py | Claude API called |
| 21:15:09 | Incident report generated | Python script | report_100003.md saved |

**Severity:** High  
**MITRE Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task  
**Root Cause:** Attacker established persistence via scheduled tasks to survive reboots  
**Recommended Action:** Delete malicious scheduled tasks, review all scheduled tasks on endpoint, check for additional persistence mechanisms