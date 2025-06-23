# Indicators of Compromise — bzgwgmoddw-case

| **Indicator** | **Value** |
|---------------|-----------|
| Dropper       | `RAT.exe` |
| Payload       | `bzgwgmoddw.exe` |
| Payload SHA256| `A5B365B1AC3044E9094719AF16126AB5C45C381AFAE5A954033E3DE31711D3B9` |
| Drop Path     | `C:\Users\vboxuser\AppData\Local\Temp\bzgwgmoddw.exe` |
| Dropper Path  | `C:\Users\vboxuser\Desktop\RAT.exe` |
| RegKey Modified| `HKU\S-1-5-21-1478595787-3034630928-447031921-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Users\vboxuser\Desktop\RAT.exe` |
| RegKey Modified| `HKU\S-1-5-21-1478595787-3034630928-447031921-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\bzgwgmoddw.exe|d2634becc9c668fa\LowerCaseLongPath` |
| Error Handler | `C:\Windows\SysWOW64\WerFault.exe` |
| Crash Dump    | `C:\ProgramData\Microsoft\Windows\WER\Temp\WER996C.tmp.dmp` |
| Sample Mutexes| None observed |
| Command Line  | `C:\Windows\SysWOW64\WerFault.exe -u -p 6888 -s 692` |
