# tracexec

**tracexec** is a behavioral detection lab designed to simulate and detect malware that drops a file, registers for persistence, and executes. The environment uses **Sysmon logs** and **custom Sigma/YARA rules** to emulate real-world SOC-level detection.

It's a detection R&D zone.

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

logs/

↳ Contains raw Sysmon logs (sysmon_log.evtx)

scripts/

↳ Dropper simulation script (dropper_sim.py)

rules/

↳ Detection rules — Sigma and YARA (sigma-shadowdrop.yml, yara-shadowfile.yar)

analysis/

↳ Timeline of events, IOC mapping, attack flow notes

demo/

↳ Optional screencast, walkthrough .gif or .mp4

processbrief.md

↳ Full setup documentation 

README.md

↳ Project overview, usage, goals



---

## Status

 - Phase 1: Simulate malware behavior → capture Sysmon logs COMPLETE  
 - Phase 2: Detection Engineering (Sigma Rules) COMPLETE  
 - Phase 3: Packaging `tracexec()` into CLI/tool coming next

---
