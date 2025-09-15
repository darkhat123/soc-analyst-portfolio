# Scenario 
Within the CyberPredator Enterprise, you operate as a Detection & Hunting Engineer, translating adversary TTP research into operational detection capabilities. This workflow focuses on an in-depth analysis of Indicator Removal—specifically, Windows Event Log Clearing (T1070.001)—as observed in campaigns attributed to APT28, APT41, and Aquatic Panda, aimed at degrading investigative visibility.

Your assignment is to deconstruct the Windows Event Log Clearing tradecraft—mapping associated tools, impacted event channels, and residual forensic traces. Following this, you will identify high-fidelity telemetry sources, craft resilient Sigma detection rules, and validate their efficacy against historical datasets using chainsaw, iteratively tuning detection logic before staging and production deployment.

## Question 1: Process Creation Detection: Which built-in Windows command-line utility provides native support for managing—and in particular clearing—event logs?

This attack is mapped to T1070.001 Indicator Removal: Clear Windows Event Logs, we can see from the mitre website that event logs including Security, Application and System can be cleared using a few methods.
The most common method involves using wevtutil. wevtutil is used to manage windows event logs and is used by system administrators for querying and exporting logs. It can be abused to clear logs.

Command: `wevtutil cl system`

These can also be cleared using powershell
Command: `Remove-EventLog -LogName Security`

These logs may also be deleted by deleting them using their path in the filesystem.

Answer: wevtutil

## Question 2: Process Creation Detection: Which WMI class typically appears in logs when attackers use WMIC commands to clear critical Windows event logs via the command line?
- WMI (Windows Management Instrumentation) is Microsoft’s management framework for querying and controlling Windows systems.
- Attackers abuse WMIC (the command-line interface to WMI) to interact with WMI classes.
- To clear logs, they specifically target the `Win32_NTEventLogFile` class (alias NTEVENT) and call its `ClearEventLog()` method.

Answer: nteventlog

## Question 3: PowerShell Detection: Which PowerShell logging channel must be enabled to capture this technique’s execution, and which Event ID should be monitored as recommended in the MITRE ATT&CK technique page?
When commands are executed by an attacker in powershell to be able to see what commands are being run and their arguments in full we need to enable powershell script block logging Event ID 4104. This can be used to detect 
cmdlets such as `Clear-EventLog` or `Remove-EventLog -LogName Security`

Answer: PowerShell Script Block Logging , 4104

## Question 4: PowerShell detection: Which built-in PowerShell cmdlets are commonly leveraged by attackers to clear Windows Event Logs?

We answered this in the previous question

Answer: Clear-EventLog, Remove-EventLog

## Question 5: PowerShell detection: Which native .NET API methods in the System.Diagnostics.Eventing.Reader and System.Diagnostics namespaces can an attacker invoke from PowerShell to clear Windows Event Logs?

- System.Diagnostics.EventLog (classic) — part of the System.Diagnostics namespace. It exposes an EventLog.Clear() method that removes all entries from a classic event log. This is the older API used by many .NET apps and by some PowerShell usages. 
Microsoft Learn
- System.Diagnostics.Eventing.Reader.EventLogSession (modern) — part of System.Diagnostics.Eventing.Reader. It exposes ClearLog(string) / ClearLog(string, string) and is the .NET API typically used to clear modern Windows event channels (including admin/operational/channel-style logs).

Answer: EventLogSession.ClearLog,EventLog.Clear

## Question 6: File Deletion Detection:  Which Windows Event IDs should be monitored to detect the clearing of System or Security event logs as an indication of potential log removal?

Monitor for unexpected deletion of Windows event logs (via native binaries) and may also generate an alterable event (Event ID 1102: "The audit log was cleared"). When an eventlog is cleared, a new event is created that alerts that the eventlog was cleared. For Security logs, its event code 1100 and 1102. For System logs, it is event code 104.

Answer: 104,1102

## Question 7: 
