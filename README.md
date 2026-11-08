# Windows Event Log Analysis & Threat Detection

## Overview
This repository contains production-ready Splunk Search Processing Language (SPL) queries and detailed incident triage walkthroughs for detecting adversary behavior within Windows enterprise environments. The focus is on auditing process executions, command-line obfuscation, and suspicious system activity mapped to the MITRE ATT&CK framework.

---

## Repository Structure

```text
├── README.md
├── suspicious-powershell-execution.spl
└── walkthrough-powershell-triage.md
```

- **`suspicious-powershell-execution.spl`**: Production-tested Splunk detection rule designed to catch obfuscated and unauthorized PowerShell activity (Event ID 4688).
- **`walkthrough-powershell-triage.md`**: Step-by-step SOC Level 1/2 analytical workflow, base64 decoding guidance, and incident remediation steps.

---

## Detection Scenarios

### 1. Suspicious PowerShell Execution (WIN-01)
- **Objective:** Detect execution of PowerShell processes leveraging suspicious parameters (`-enc`, `-EncodedCommand`, `downloadstring`, `iex`, `-bypass`, `-w hidden`).
- **Data Source:** Windows Security Logs (`WinEventLog:Security`)
- **Event ID:** 4688 (Process Creation with Command Line Auditing enabled)
- **MITRE ATT&CK:** [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

## Setup & Prerequisites
1. **Audit Policy:** Ensure Advanced Audit Policy for Process Creation is enabled (`Audit Process Creation` -> Success).
2. **Command Line Logging:** Enable "Include command line in process creation events" via Group Policy:
   `Computer Configuration -> Administrative Templates -> System -> Audit Process Creation`.
3. **Splunk Ingestion:** Ensure the Splunk Universal Forwarder is ingesting `WinEventLog:Security` into the target index.
