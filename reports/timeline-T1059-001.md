# Attack Timeline — T1059.001 PowerShell Execution
**Date:** 2026-05-10  
**Simulated by:** Atomic Red Team

| Time | Event | Source | Details |
|------|-------|--------|---------|
| 21:14:33 | Attacker executes encoded PowerShell | Atomic Red Team | powershell.exe -EncodedCommand |
| 21:14:33 | Sysmon captures process creation | Sysmon Event ID 1 | Full command line logged |
| 21:14:33 | Wazuh agent forwards event | Wazuh Agent | Shipped to manager at 192.168.56.103 |
| 21:14:33 | Rule 100002 fires | Wazuh Manager | Level 10 alert generated |
| 21:14:33 | AI enrichment triggered | alert_enricher.py | Claude API called |
| 21:14:35 | Incident report generated | Python script | report_100002.md saved |

**Severity:** Critical  
**MITRE Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Root Cause:** Encoded PowerShell with ExecutionPolicy Bypass — characteristic of offensive tooling  
**IOC:** SHA256=ABC3E2D7F1B94056E2C1A34D78F29B6E5D0C1A2B3E4F5A6B7C8D9E0F1A2B3C4D  
**Recommended Action:** Isolate endpoint, capture memory dump, review parent process chain