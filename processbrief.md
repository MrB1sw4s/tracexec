# 🧱 Phase 1 – Simulation & Log Collection (`tracexec`)

**Goal:** Simulate dropper-style malware behavior and collect endpoint telemetry using Sysmon for detection engineering.

---

## ✅ 1. Windows 10 VM Setup

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

## ✅ 2. Sysmon Setup

- Downloaded `Sysmon64.exe` from Microsoft Sysinternals
- Cloned SwiftOnSecurity’s Sysmon config:
  ```bash
  git clone https://github.com/SwiftOnSecurity/sysmon-config.git
- Installed Sysmon:
  ```bash
  sysmon64.exe -accepteula -i sysmonconfig-export.xml
-Enabled monitoring of:
  - Event ID 1: Process creation
  - Event ID 11: File creation
  - Event ID 13: Registry value set
