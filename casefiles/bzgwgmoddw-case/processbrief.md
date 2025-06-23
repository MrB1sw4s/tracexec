# Process Brief — bzgwgmoddw-case  
**Detonation, Detection & Analysis Steps**

---

##  Objective
Detonating a **dropper/payload execution chain**(AveMariaRAT) on a controlled Windows 10 VM, then **collect telemetry** with Sysmon, extract Indicators of Compromise (IOCs), and build **Sigma detection rules**.

---

##  Environment Setup
- **VM Specs**:
  - FlareVM on Windows 10 (x64), 2 vCPUs, 4 GB RAM
  - Installed Python 3.13, Sysinternals tools
  - Installed Sysmon (`sysmon64.exe`)
  - Applied `SwiftOnSecurity/sysmonconfig.xml`

- **Sysmon Monitored Events**:
  - **Event ID 1** — Process Creation
  - **Event ID 11** — File Creation
  - **Event ID 13** — Registry Value Set
  - (Event ID 3 — Network Connections, was empty due to VM isolation)

---

##  Simulation Steps

1. **Dropper Preparation**
   - Downloaded AveMariaRAT sample and extracted the executable.
   - Placed `RAT.exe` (AveMariaRAT) on Desktop.
   - Isolated the VM and turned on Procmon and Sysmon.
2. **Payload Execution**
   - Dropper spawned payload (`bzgwgmoddw.exe` from `%Temp%`).
   - Payload triggered `WerFault.exe` (error handling), created crash dump file under:
     ```
     C:\ProgramData\Microsoft\Windows\WER\Temp\WER996C.tmp.dmp
     ```
   - Payload also wrote compatibility store entries to:
     ```
     Registry Keys: \REGISTRY\A\{547415f1-6bd6-b094-b04e-f658d9b93e22}\Root\InventoryApplicationFile\bzgwgmoddw.exe|d2634becc9c668fa\LowerCaseLongPath
     Details: c:\users\vboxuser\desktop\extracted_payload\bzgwgmoddw.exe
     Registry Keys: \REGISTRY\A\{547415f1-6bd6-b094-b04e-f658d9b93e22}\Root\InventoryApplicationFile\bzgwgmoddw.exe|d2634becc9c668fa\Publisher
     Details: (Empty)
     ```

   - Persistence/Inventory Indicators — RAT is being registered under Windows Application Inventory (InventoryApplicationFile), often part of AppCompat or Application Experience telemetry.
   - svchost.exe is the one making these reg entries — suspicious behavior for a system process.
   - No observable network activity (sandbox isolated).

---

## Analysis & Findings

| Event | Observation |
|--------|------------|
| Event 1 | Dropper (`RAT.exe`) executed by `explorer.exe`. Payload extracted into `%Temp%` and spawned |
| Event 11 | `WerFault.exe` invoked by payload (`bzgwgmoddw.exe`). WER dump file created |
| Event 13 | Registry keys modified under `CurrentVersion\AppCompatFlags`. Payload binary path recorded |
| Hashes | Payload SHA256: `A5B365B1AC3044E9094719AF16126AB5C45C381AFAE5A954033E3DE31711D3B9` |

**Strings Extracted**  
- Payload showed typical NSIS installer strings (e.g. `NullsoftInst`), API calls indicating potential file operations and GUI components (`CreateDialogParamW`, `WritePrivateProfileStringA`, `MoveFileExA`).  
- Suggests packing behavior or staged installer. Suggests this is actually an NSIS self-extracting dropper — not a true RAT binary itself.
- Payload wrote bzgwgmoddw.exe into Temp and then invoked Windows Error Reporting (WerFault.exe)
- Suggests a crash handler or anti-sandbox routine — or using WerFault as a masquerading launcher
- Clever evasion — looks like a Windows error report, but actually part of its startup.

**What we Know**
- Standard NSIS Installer framework — these strings show mostly USER32, KERNEL32, WINMM, MSWSOCK APIs — classic Windows I/O and GUI.
- SetServiceW and DeleteMonitorA — potentially hints that payload might try service manipulation or printer removal? Unusual combo.
- No obvious C2 domains or hardcoded credentials — probably packed/encrypted inside.

---

##  Detection Engineering

**Key Detections Implemented**:
- **Sigma Rule 1**: Suspicious execution from `%AppData%` or `%Temp%` by scripting engines.
- **Sigma Rule 2**: Registry autorun changes under `HKCU\Run`.
- **Sigma Rule 3**: AppCompatFlags modification by unknown binaries.
- **YARA Rule**: Match unique strings (`NullsoftInst`, suspicious NSIS stub sizes) and API imports.

**Automation**:
- Developed `tracexec.py` to:
  - Parse `.evtx` or `.csv` log files.
  - Highlight suspicious process trees (`RAT.exe → bzgwgmoddw.exe → WerFault.exe`)
  - Export findings into `analysis/output.md`

---


**Outcome**:  
A successful end-to-end DFIR simulation that mimics **real-world threat behavior**, from dropper execution to detection engineering — fully documented with a repeatable methodology.
