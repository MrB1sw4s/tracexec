# tracexec

**tracexec** is a behavioral detection lab designed to simulate and detect malware that drops a file, registers for persistence, and executes. The environment uses **Sysmon logs** and **custom Sigma/YARA rules** to emulate real-world SOC-level detection.

---

## Objective

Detect malicious behavior patterns like:
- File written to hidden/appdata directories
- Registry-based autorun persistence
- Process spawned from suspicious locations

---

## Components

- `dropper.py`: Custom Python dropper that mimics malware behavior
- `sysmon_log.evtx`: Sysmon logs capturing file-write, registry, and execution
- Sigma/YARA rules: [Coming next]
- IOC & timeline mapping: [Coming next]

---

## Project Structure
tracexec/
├── logs/ # Raw Sysmon logs
├── scripts/ # Dropper simulation
├── rules/ # Detection rules (Sigma, YARA)
├── analysis/ # Timeline, IOC mapping
├── demo/ # Screencast or walkthroughs
└── README.md

---

## Status

✅ Phase 1: Simulate malware behavior → capture Sysmon logs COMPLETE  
🔄 Phase 2: Rule engineering in progress  
🚧 Phase 3: Packaging `tracexec()` into CLI/tool coming next

---
