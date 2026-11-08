Triage Walkthrough: Suspicious PowerShell Execution (WIN-01)
1. Executive Summary
 * Alert: Suspicious PowerShell Execution (Encoded Command / Bypass Flags)
 * Severity: Medium/High
 * Triage Result: Identification of obfuscated or unauthorized PowerShell commands potentially used for staging or execution.
 * MITRE Mapping: T1059.001 (Command and Scripting Interpreter: PowerShell)
2. Technical Context & Telemetry
 * Index: windows
 * Sourcetype: WinEventLog:Security
 * Event Code: 4688 (Process Creation)
 * Monitored Processes: powershell.exe, pwsh.exe
3. Investigation Steps
 * Decode Command Line: Extract base64 encoded strings (-enc, -EncodedCommand) and decode to reveal underlying instructions.
 * Analyze Parent Process: Determine what spawned PowerShell (e.g., word.exe, wscript.exe, or cmd.exe).
 * Review Network Connections: Cross-reference timestamps with Zeek/Sysmon EventID 3 to identify callback IPs.
4. Remediation Actions
 * Isolate Host: Disconnect infected machine from the network if malicious payload execution is confirmed.
 * Terminate Process Tree: Kill anomalous PowerShell processes.
 * Credential Reset: Force password resets for user accounts involved in the session.
