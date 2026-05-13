# Detection Rules

Custom Wazuh detection rules for the AI-Assisted SOC Detection Lab.
All rules are mapped to MITRE ATT&CK techniques.

---

## Rule 100002 — PowerShell Execution (T1059.001)
**Level:** 10 (High)  
**Log Source:** Sysmon Event ID 1 (Process Creation)

Detects execution of powershell.exe — commonly used by attackers for
code execution, download cradles, and living-off-the-land techniques.

**False Positives:**
- Legitimate admin scripts
- Software installers using PowerShell
- Windows Update processes

**Detection Gap:**
Does not detect PowerShell running under alternative hosts (pwsh.exe)
or renamed binaries.

---

## Rule 100003 — Scheduled Task Created (T1053.005)
**Level:** 10 (High)  
**Log Source:** Sysmon Event ID 1 (Process Creation)

Detects schtasks.exe spawned with /create argument — a common
persistence mechanism used by attackers to survive reboots.

**False Positives:**
- Software installers creating legitimate scheduled tasks
- Windows system maintenance tasks
- IT management tools

**Detection Gap:**
Attackers can create scheduled tasks via the Task Scheduler COM object
through PowerShell without spawning schtasks.exe — bypassing this rule.

---

## Rule 100004 — Registry Query (T1012)
**Level:** 8 (Medium)  
**Log Source:** Sysmon Event ID 1 (Process Creation)

Detects reg.exe spawned with query arguments — used by attackers
to enumerate system configuration, installed software, and persistence
locations like Run keys.

**False Positives:**
- High volume — reg.exe is used constantly by Windows and software
- Extremely common during software installation

**Detection Gap:**
Registry queries via PowerShell Get-ItemProperty or WMI do not spawn
reg.exe and will completely bypass this detection.

---

## Rule 100005 — System Information Discovery (T1082)
**Level:** 12 (Critical)  
**Log Source:** Sysmon Event ID 1 (Process Creation)

Detects systeminfo.exe execution — used by attackers to enumerate
OS version, hardware, hotfixes, and network configuration immediately
after initial access.

**False Positives:**
- IT inventory tools
- Help desk troubleshooting scripts
- Legitimate admin activity

**Detection Gap:**
WMI-based system enumeration (Win32_OperatingSystem) produces no
systeminfo.exe process and bypasses this detection entirely.