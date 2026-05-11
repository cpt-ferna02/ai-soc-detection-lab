## T1053.005 — Scheduled Task Persistence
**Date:** 2026-05-10
**Atomic Test:** #1

**What the technique does:**
Attacker creates scheduled tasks that run automatically on logon or startup,
allowing them to survive reboots without needing to re-compromise the system.

**Why attackers use it:**
Persistence is critical — if the victim reboots, the attacker loses access.
Scheduled tasks are built into Windows, trusted by the OS, and easy to hide
among hundreds of legitimate tasks.

**What logs it created:**
- Sysmon Event ID 1: process creation for schtasks.exe with /create argument
- Two tasks created: T1053_005_OnLogon and T1053_005_OnStartup

**How defenders detect it:**
Alert on schtasks.exe being spawned with /create by unusual parent processes
like PowerShell or cmd.exe outside of software installation windows.

**Detection difficulty:**
Medium — schtasks.exe is used legitimately by many applications and Windows
itself, so context of the parent process matters heavily.

**Blind spots:**
Attackers can use the Task Scheduler COM object directly through PowerShell
which creates tasks without spawning schtasks.exe at all.

---

## T1012 — Query Registry
**Date:** 2026-05-10
**Atomic Test:** #1

**What the technique does:**
Attacker queries registry keys to gather information about installed software,
startup programs, system configuration, and security settings.

**Why attackers use it:**
The registry stores a wealth of intelligence — what security tools are installed,
what runs at startup, what users exist, and what software is present. All useful
for planning the next attack phase.

**What logs it created:**
- Sysmon Event ID 1: process creation for reg.exe with query arguments
- Multiple registry hives queried including HKLM\SOFTWARE and HKLM\SYSTEM

**How defenders detect it:**
Alert on reg.exe being spawned rapidly querying multiple sensitive keys,
especially HKLM\Software\Microsoft\Windows\CurrentVersion\Run which reveals
persistence locations.

**Detection difficulty:**
High — reg.exe is used constantly by legitimate software and Windows itself.
Detecting malicious use requires behavioral context and volume analysis.

**Blind spots:**
Registry queries made through WMI or PowerShell's Get-ItemProperty cmdlet
do not spawn reg.exe and will bypass process-based detections entirely.