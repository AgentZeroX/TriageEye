# TriageEye 👁️

**TriageEye** is an automated dynamic malware analysis tool for Windows designed for the quick triage of suspicious samples. It tracks execution behavior in real-time and generates structured reports for rapid analysis.

<p align="center">
  <img src="screenshot.png" alt="TriageEye Interface" width="100%">
</p>

## 🛡️ Core Monitoring Capabilities
TriageEye utilizes a "best-effort" monitoring approach to capture volatile artifacts:

* **Process Tree:** Tracks descendants of the root PID via **ETW** (`Microsoft-Windows-Kernel-Process`) and live snapshots.
* **Command Lines:** Captures full execution arguments from process creation events.
* **Network Activity:** Monitors TCP/UDP connections using `psutil` (preferred) or `netstat` fallback.
* **Registry Activity:** Monitors persistence and configuration changes via **ETW** (`Microsoft-Windows-Kernel-Registry`).
* **File Operations:** Tracks dropped files and activity in "interesting paths" like `Temp`, `Downloads`, and `Startup`.

## 🚀 Analysis Modes
* **`exe`**: Launch and monitor a standalone executable.
* **`office`**: Open documents to monitor macro-based behavior.
* **`wait`**: Attach to an existing loader or wait for a specific process to appear.

## 📊 Reporting & Output
* **HTML Report:** A visual timeline and tables for easy sharing and human reading.
* **JSON Report:** Detailed structured data for integration with other SOC tools.
* **Live Console:** Real-time, color-coded output for immediate feedback during analysis.

## 🛠️ Requirements
* **OS:** Windows 10/11 or Windows Server.
* **Language:** Python 3.9+.
* **System Tools:** `logman` and `tracerpt` (default on Windows).
* **Library:** `psutil` (recommended for accurate snapshots).

> [!CAUTION]
> **Safety First:** Always run TriageEye inside a dedicated Virtual Machine (VM). Use snapshots before execution and never analyze samples on your primary host system.

---

## 👤 Author
**AgentZeroX** - Penetration Tester & Security Researcher

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
