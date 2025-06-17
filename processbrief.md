
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
