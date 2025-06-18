### Summary

 - Case Name: ShadowDrop – AppData Dropper Simulation
 - Objective: Detect and document a Python-based malware dropper using Sysmon logs
- System: Windows 10 VM
- User: WIN10DET\\vboxuser
- Dropper Script: dropper.py (written in Python 3.13)
- Payload: WindowsUpdate.exe (renamed Notepad)

### Timeline of Events
2025-06-18 03:30:17.767
 - Action: Executable dropped to %AppData%
 - Process: python.exe
 - Target Filename: C:\\Users\\vboxuser\\AppData\\Roaming\\WindowsUpdate.exe
 - Sysmon Event ID: 11
 - Detection Rule: Executable Dropped in AppData by Python

2025-06-18 03:30:17.805
 - Action: Registry key added for persistence
 - Process: python.exe
 - Registry Path: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\FakeUpdater
 - Payload Path: C:\\Users\\vboxuser\\AppData\\Roaming\\WindowsUpdate.exe
 - Sysmon Event ID: 13
 - Detection Rule: Registry Autorun via AppData EXE

2025-06-18 03:30:17.838
 - Action: Malware executed from drop location
 - Process: WindowsUpdate.exe
 - Parent Process: python.exe
 - Command Line: C:\\Users\\vboxuser\\AppData\\Roaming\\WindowsUpdate.exe
 - Sysmon Event ID: 1
 - Detection Rule: Execution from AppData (Python Dropper)

### Observed Indicators of Compromise (IOCs)
 - Dropped Binary: WindowsUpdate.exe
 - Drop Path: %AppData%\\Roaming\\WindowsUpdate.exe
 - Autorun Registry Key: HKCU\\...\\Run\\FakeUpdater
 - SHA256 Hash: DA5807BB0997CC6B5132950EC87EDA2B33B1AC4533CF1F7A22A6F3B576ED7C5B
 - MD5 Hash: 6F51BCABF1B2B34AD7E670AEE6DA451F

### Defensive Coverage
|  Detection  |  Rule Name  |  ATT&CK ID  |
|-------------|-------------|-------------|
|File Drop  |  `Executable Dropped in AppData by Python`  |  T1059 (Script)  |
|Persistence  |  `Registry Autorun Persistence via AppData Executable`  |  T1547.001 (Autorun Registry)  |
|Execution  |  `Suspicious EXE Execution from AppData` |  T1055 (Execution Flow)  |

### Outcome
 - All three stages of the dropper chain were detected via custom Sigma rules.
 - Logs were exported and Sigma rules validated.
 - Detection logic is now reusable across similar threats.