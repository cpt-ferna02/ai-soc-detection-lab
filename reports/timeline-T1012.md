# Attack Timeline — T1012 Registry Query
**Date:** 2026-05-10  
**Simulated by:** Atomic Red Team

| Time | Event | Source | Details |
|------|-------|--------|---------|
| 21:16:30 | Attacker queries registry | Atomic Red Team | reg.exe query |
| 21:16:30 | Multiple registry hives queried | Windows Registry | HKLM\SOFTWARE, HKLM\SYSTEM, Run keys |
| 21:16:30 | Sysmon captures process creation | Sysmon Event ID 1 | reg.exe with query arguments |
| 21:16:30 | Wazuh agent forwards event | Wazuh Agent | Shipped to manager |
| 21:16:30 | Rule 100004 fires | Wazuh Manager | Level 8 alert generated |
| 21:16:30 | AI enrichment triggered | alert_enricher.py | Claude API called |
| 21:16:32 | Incident report generated | Python script | report_100004.md saved |

**Severity:** Medium  
**MITRE Technique:** T1012 — Query Registry  
**Root Cause:** Attacker enumerated registry to identify installed software, persistence locations, and system configuration  
**Blind Spots:** Registry queries via PowerShell Get-ItemProperty or WMI do not spawn reg.exe and bypass this detection  
**Recommended Action:** Review what data was accessed, correlate with other discovery activity on the same timeline