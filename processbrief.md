
# Phase 1 – Simulation & Log Collection (`tracexec`)

**Goal:** Simulate dropper-style malware behavior and collect endpoint telemetry using Sysmon for detection engineering.

---

## 1. Windows 10 VM Setup

- Installed Windows 10 (64-bit) on VirtualBox
- Specs:
  - 2 vCPUs
  - 4 GB RAM
  - 40 GB disk
- Shared folders configured for easy log/file transfer
- Installed:
  - Python 3.10 (Windows build)
  - Sysinternals Suite
  - Text editor (Notepad++) and terminal tools

---

## 2. Sysmon Setup

- Downloaded `Sysmon64.exe` from Microsoft Sysinternals
- Cloned SwiftOnSecurity’s Sysmon config:
  ```bash
  git clone https://github.com/SwiftOnSecurity/sysmon-config.git
  ```
- Installed Sysmon:
  ```bash
  sysmon64.exe -accepteula -i sysmonconfig-export.xml
  ```

Enabled monitoring of:
- Event ID 1: Process creation
- Event ID 11: File creation
- Event ID 13: Registry value set

---

## 3. Dropper Simulation

Built and ran a Python script (`dropper.py`) to simulate a dropper malware:

- Dropped a renamed binary (`notepad.exe`) to `%AppData%` as `WindowsUpdate.exe`
- Added registry key to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Executed the dropped binary

### Script

```python
import os, subprocess, winreg, shutil

# Step 1: Drop a renamed legitimate binary (notepad.exe) into AppData
malware_path = os.path.join(os.getenv("APPDATA"), "WindowsUpdate.exe")
shutil.copy("C:\\Windows\\System32\\notepad.exe", malware_path)

# Step 2: Add registry persistence
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                     r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(key, "FakeUpdater", 0, winreg.REG_SZ, malware_path)
winreg.CloseKey(key)

# Step 3: Execute the dropped binary
subprocess.Popen([malware_path])
```

This mimicked the behavior of a typical first-stage dropper (e.g., AgentTesla, Lokibot).

---

## 4. Sysmon Log Capture

- Used `wevtutil` to export logs after running the dropper:
  ```bash
  wevtutil epl Microsoft-Windows-Sysmon/Operational sysmon_log.evtx
  ```
- Moved the `.evtx` file to `logs/` directory

---

## Logged Event Summary

| Event ID | Description                                 |
|----------|---------------------------------------------|
| 11       | File creation in `%AppData%` (`WindowsUpdate.exe`) |
| 13       | Registry persistence key written (HKCU...\Run) |
| 1        | Execution of dropped binary from AppData     |

---

---

# Phase 2 – Detection Engineering (Sigma Rules)

**Objective:** Build real-world Sigma detection rules based on behavioral patterns from our dropper simulation logs.

---

## Behavioral Summary

During Phase 1, our dropper performed the following:

1. Dropped a renamed binary into `AppData`:
   ```
   C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe
   ```
2. Set a persistence key in:
   ```
   HKU\S-1-5-21-...\CurrentVersion\Run\FakeUpdater
   ```
3. Executed the dropped binary using:
   ```
   Parent: C:\Users\vboxuser\AppData\Local\Programs\Python\Python313\python.exe
   ```

This mimics the behavior of stage-1 commodity malware.

---

## Goal: Build Sigma Rules for the Chain

We crafted 3 Sigma rules based on:

| Event Type | Goal |
|------------|------|
| **Event ID 11** | File dropped to disk (AppData) |
| **Event ID 13** | Registry persistence set |
| **Event ID 1**  | Executed dropped payload |

---

## Rule 1 – Execution from AppData

### Sample Log:

```
UtcTime:        2025-06-18 03:30:17.838
Image:          C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe
ParentImage:    C:\Users\vboxuser\AppData\Local\Programs\Python\Python313\python.exe
CommandLine:    C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe
```

### Sigma Rule:

```yaml
title: Suspicious EXE Execution from AppData (Python Dropper)
id: efd829a4-cc39-11ec-9d64-0242ac120002
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    Image|contains: '\\AppData\\'
    ParentImage|endswith: 'python.exe'
  condition: selection
level: high
```

---

## Rule 2 – Registry Persistence Set
Sysmon Event ID 13 – Registry Value Set

Triggered when any value in the Windows Registry is added or modified.

It tells you:

 - Who modified the registry (Image, User)

 - What was modified (TargetObject)

 - What was written (Details)

Why Is This Dangerous?

 - Persistence is one of the most important stages of an attack chain.
 - The attacker wants the malware to stay active even after reboot or logout.

 Registry autorun is popular because:

 - It’s silent (no popups, no UAC)

 - Works at both user-level (HKCU) and system-level (HKLM)

 - Can point to any file path (e.g., %AppData%, %Temp%, .bat, .exe, .vbs)

 - Doesn’t require admin if using HKCU

### Sample Log:

```
UtcTime:        2025-06-18 03:30:17.805
Image:          C:\Users\vboxuser\AppData\Local\Programs\Python\Python313\python.exe
TargetObject:   HKU\...\CurrentVersion\Run\FakeUpdater
Details:        C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe
RuleName:	T1060,RunKey → 🔥 This is an ATT&CK-mapped detection!

```

### Sigma Rule:

```yaml
title: Registry Autorun Persistence via AppData Executable
id: 620ff2e8-cc3a-11ec-9d64-0242ac120002
logsource:
  product: windows
  service: sysmon
  category: registry_set
detection:
  selection:
    EventType: SetValue
    TargetObject|contains: '\\CurrentVersion\\Run'
    Details|contains: '\\AppData\\'
  condition: selection
level: high
```
Why This Is Strong:

 - It doesn’t depend on exact SID (HKU\S-1-5-...) or username

 - Works for HKCU, HKLM, or SID-based HKU

 - Catches malware that installs itself in user space and registers autorun
 - HKCU\Software\Microsoft\Windows\CurrentVersion\Run = User-level autorun

 - HKLM\... = Machine-level autorun

---

## 🛠 Rule 3 – File Dropped in AppData

### Sample Log:

```
UtcTime:         2025-06-18 03:30:17.767
Image:           C:\Users\vboxuser\AppData\Local\Programs\Python\Python313\python.exe
TargetFilename:  C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe
```

### Sigma Rule:

```yaml
title: Executable Dropped in AppData by Python or Script Engine
id: 78a218e0-cc3b-11ec-9d64-0242ac120002
logsource:
  product: windows
  service: sysmon
  category: file_create
detection:
  selection:
    TargetFilename|contains: '\\AppData\\'
    TargetFilename|endswith: '.exe'
    Image|endswith:
      - 'python.exe'
      - 'powershell.exe'
      - 'wscript.exe'
      - 'cscript.exe'
  condition: selection
level: high
```

---

## What We Learned

- **AppData writes** by scripting engines are rarely legitimate.
- **Registry autorun keys** pointing to `AppData` are high-confidence indicators.
- **Execution from AppData** chained to these behaviors forms a reliable malware pattern.

We now have a **complete detection chain** for a real dropper:
```
Drop → Persist → Execute
```

---
