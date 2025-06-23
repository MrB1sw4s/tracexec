# Incident Timeline — bzgwgmoddw-case

## Summary
- **Case Name**: `bzgwgmoddw-case — payload of AveMariaRAT`
- **Objective**: Detonating a dropper (RAT.exe), extract payload (bzgwgmoddw.exe), and document behavior.
- **Host**: Modified Windows 10 VM (`flarevm\vboxuser`)
- **Dropper**: `RAT.exe` (AveMariaRAT executable)
- **Payload**: `bzgwgmoddw.exe` (extracted NSIS installer payload)
- **SHA256 Payload**: `A5B365B1AC3044E9094719AF16126AB5C45C381AFAE5A954033E3DE31711D3B9`

---

## Timeline of Events

#### 2025-06-23 08:53:00.444 — Dropper execution
- **Action**: User executed dropper
- **Process**: `C:\Users\vboxuser\Desktop\RAT.exe`
- **Parent**: `C:\Windows\explorer.exe`
- **Command Line**: `C:\Users\vboxuser\Desktop\RAT.exe`
- **Sysmon Event ID**: `1`

#### 2025-06-23 08:53:00.445 — Registry modification
- **Action**: Application compatibility data written
- **Process**: `C:\Windows\system32\svchost.exe`
- **TargetObject**:  
  `HKU\S-1-5-21-1478595787-3034630928-447031921-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Users\vboxuser\Desktop\RAT.exe`
- **Details**: Binary Data
- **Sysmon Event ID**: `13`

#### 2025-06-23 08:53:00.845 — Payload extracted & spawned
- **Action**: Payload `bzgwgmoddw.exe` extracted and executed
- **Process**: `C:\Users\vboxuser\AppData\Local\Temp\bzgwgmoddw.exe`
- **Parent**: `C:\Users\vboxuser\Desktop\RAT.exe`
- **Sysmon Event ID**: `1`

#### 2025-06-23 08:53:01.022 — Error handler triggered
- **Action**: Error handling (`WerFault.exe`)
- **Process**: `C:\Windows\SysWOW64\WerFault.exe`
- **Parent**: `C:\Users\vboxuser\AppData\Local\Temp\bzgwgmoddw.exe`
- **Command Line**: `C:\Windows\SysWOW64\WerFault.exe -u -p 6888 -s 692`
- **Sysmon Event ID**: `11`

#### 2025-06-23 08:53:01.022 — Payload drop artifact
- **Action**: Crash dump file written
- **File**: `C:\ProgramData\Microsoft\Windows\WER\Temp\WER996C.tmp.dmp`
- **Sysmon Event ID**: `11`

#### 2025-06-23 08:53:00.445 — Application compatibility key updated
- **Action**: Registry value set by payload
- **Process**: `C:\Windows\system32\svchost.exe`
- **TargetObject**:  
  `HKU\S-1-5-21-1478595787-3034630928-447031921-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\bzgwgmoddw.exe|d2634becc9c668fa\LowerCaseLongPath`
- **Details**: `c:\users\vboxuser\desktop\extracted_payload\bzgwgmoddw.exe`
- **Sysmon Event ID**: `13`

---

## Analysis Conclusion
- The dropper (`RAT.exe`) successfully extracted payload (`bzgwgmoddw.exe`).
- Payload invoked error handler (`WerFault.exe`), wrote compatibility store data and dump file.
- Registry and file system changes confirmed dropper’s persistence and execution strategy.
