
# IOCs – ShadowDrop Operation

This file lists all Indicators of Compromise (IOCs) observed during the ShadowDrop simulation. 

What Are IOCs?

Indicators of Compromise = digital clues that suggest a system was attacked, exploited, or touched by malware.

Think:

 - Hashes of malicious files

 - Registry keys used for persistence

 - File paths where malware hides

 - IPs, domains, mutexes, named pipes, etc.

They are like fingerprints left behind at the scene of a cybercrime.

 
These can be used for threat hunting, enrichment, and retroactive detection.

---

## Dropped Executable

| Indicator Type | Value |
|----------------|-------|
| File Name      | WindowsUpdate.exe |
| Drop Path      | C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe |
| SHA256         | DA5807BB0997CC6B5132950EC87EDA2B33B1AC4533CF1F7A22A6F3B576ED7C5B |
| MD5            | 6F51BCABF1B2B34AD7E670AEE6DA451F |
| IMPHASH        | 09ED737A03DB7295BF734A9953F6EB5E |
| Signed?        | Yes (Notepad.exe, Microsoft) |
| Description    | Renamed native binary used as payload |

---

## Registry Keys

| Key Path | Details |
|----------|---------|
| HKCU\Software\Microsoft\Windows\CurrentVersion\Run\FakeUpdater | Launches `WindowsUpdate.exe` from AppData |

---

## Related Processes

| Executable | Role        | Path |
|------------|-------------|------|
| python.exe | Dropper     | C:\Users\vboxuser\AppData\Local\Programs\Python\Python313\python.exe |
| WindowsUpdate.exe | Payload    | C:\Users\vboxuser\AppData\Roaming\WindowsUpdate.exe |

---

## User Context

| Field | Value |
|-------|-------|
| Hostname | WIN10DET |
| Username | vboxuser |
| User SID | S-1-5-21-1782853840-3466286049-131357715-1000 |

---

## MITRE ATT&CK TTPs

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | Command and Scripting Interpreter (Python) | T1059.006 |
| Persistence | Registry Run Key | T1547.001 |
| Defense Evasion | Signed Binary Proxy Execution | T1218 |

---

> This IOC sheet belongs to **Project: tracexec_ShadowDrop**
