# Windows Authentication and RDP Session Analysis

**Project:** Windows Server Incident Response (TryHackMe lab)  
**Environment:** Windows Server 2019, `THM-WINFUN2`  
**Scope:** Security log authentication events and Remote Desktop Services session telemetry  
**Finding:** **Inconclusive** — RDP activity was observed, but unauthorized access or compromise was not established.

> **Portfolio integrity note:** This is an investigation of an authorized training environment. Details below summarize observations retained from separate lab sessions; they are **not** one continuous incident timeline. Example commands are reproducible investigation procedures, not claims that every command was executed exactly as shown. Lab IP addresses are retained as lab context only.

## 1. Investigation objective

Determine whether the observed Administrator logons over Remote Desktop Protocol (RDP) indicated suspicious access, and identify what corroborating evidence would be needed before reaching a conclusion.

Key questions:

- Which account authenticated, and what type of logon occurred?
- What source address, logon identifier, and time were recorded?
- Do RDP session events support an established interactive session?
- What process, PowerShell, or service activity occurred around the logon?
- Were audit logs complete enough to support the conclusion?

## 2. Relevant Windows event sources

| Source / Event ID | Typical meaning | Analytical limitation |
| --- | --- | --- |
| Security **4624** | Successful logon; **LogonType 10** commonly indicates RemoteInteractive/RDP | Successful authentication does not by itself prove malicious access |
| Security **4625** | Failed logon | Multiple failures alone do not prove compromise or credential theft |
| Security **4634** | Logon session ended | Useful for session context; not a guarantee all user activity stopped |
| Security **4672** | Special privileges assigned to a new logon | Privileges assigned are **not** proof those privileges were exercised |
| Security **4688** | New process created, when auditing is enabled | Process creation alone does not establish malicious intent; coverage depends on policy/retention |
| TerminalServices-RemoteConnectionManager/Operational **1149** | RDP user authentication succeeded | Does **not** alone prove a completed interactive desktop session |
| TerminalServices-LocalSessionManager/Operational **21** | Session logon succeeded | Correlate with host, user, source, and time |
| TerminalServices-LocalSessionManager/Operational **24** | Session disconnected | Disconnect is not equivalent to logoff |
| TerminalServices-LocalSessionManager/Operational **25** | Session reconnection succeeded | Reconnection may be legitimate; assess context |

## 3. Observations from the lab

### Earlier lab session (October 2026)

- Successful Administrator **4624 / LogonType 10** events were observed in the Security log.
- Event **1149** recorded successful RDP authentication from `10.130.86.114`.
- Event **21** recorded a successful RDP session logon (Session ID 2) associated with that source in the available session logs.
- Multiple **24** disconnect and **25** reconnection events were present. These were consistent with interrupted/re-established sessions; the precise cause was **not** proven.
- Additional addresses appeared in older entries; they should not be merged into one attack narrative without verifying their timestamps and sessions.

### Later capstone lab session (November 9, 2026)

- A freshly restarted Windows Server environment had a recorded boot time of **03:11:55**.
- Three Administrator RDP logons from `10.129.93.13` were identified in the available records.
- Searches found no matching **4688** process-creation events in the examined **10-minute** window and no **7045** service-installation events in the examined **one-hour** window.
- The absence of matching events **within those windows** did not establish absence of activity outside them or in unavailable telemetry.

**Important:** The October and November source IP addresses and session identifiers come from different lab instances/sessions. They must not be treated as one continuous RDP session or as evidence of lateral movement.

## 4. Reusable investigation commands

Run with appropriate permissions on an authorized Windows system. These commands are **read-only**.

### A. Inspect successful and failed logons

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4624,4625
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, RecordId, Message
```

**Why:** Establish when authentication succeeded or failed, then inspect the event XML or rendered message for account, source IP, LogonType, and Logon ID. `Message` is convenient for initial review but structured event fields are preferable for consistent correlation.

### B. Inspect RDP authentication and session activity

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    Id = 1149
} | Select-Object TimeCreated, Id, RecordId, Message

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    Id = 21,24,25
} | Select-Object TimeCreated, Id, RecordId, Message
```

**Why:** Correlate authentication with session logon, disconnection, and reconnection. A 1149 event alone is insufficient to claim the user reached an interactive desktop.

### C. Check process creation close to a logon

```powershell
$start = Get-Date '2026-11-09 03:00:00'  # Replace with actual incident window
$end   = $start.AddMinutes(30)

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $start
    EndTime   = $end
} | Select-Object TimeCreated, RecordId, Message
```

**Why:** Look for activity temporally close to the logon. Where available, correlate account, Logon ID, process identifiers, and parent process. Merely sharing a time window does not prove the logged-on user launched a process.

### D. Check Windows service installations

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7045
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, RecordId, Message
```

**Why:** Identify newly installed services. Event **7045** records installation, not proof the service started, that its binary executed, or that the service is malicious.

### E. Assess the retained evidence window

```powershell
Get-WinEvent -ListLog 'Security' |
    Select-Object LogName, RecordCount, MaximumSizeInBytes, LogMode, IsEnabled

Get-WinEvent -LogName Security -Oldest -MaxEvents 1 |
    Select-Object TimeCreated, RecordId, Id
```

**Why:** Check whether an expected event could have been overwritten due to a circular log, whether the log is enabled, and how far back retained records extend. A log restart or instance replacement also requires a fresh baseline.

## 5. Correlation method

1. Establish the host, boot time, log availability, time zone, and investigation window.
2. Identify **4624** with **LogonType 10** and record target account, source address, Logon ID, timestamp, and Record ID.
3. Locate related **1149**, **21**, **24**, and **25** records; verify the account, host, source address, and chronology rather than joining on time alone.
4. Examine relevant **4688**, PowerShell logs, and **7045** events around the session, accounting for different audit sources and possible missing records.
5. Seek authorization context (expected administrator access, change tickets, owner confirmation) and endpoint/network corroboration.
6. Record what is confirmed, what is only a hypothesis, and what is unknown because of logging gaps.

## 6. Assessment and evidence limitations

**Observed:** Successful Administrator RDP-related authentication/session activity was recorded in separate authorized lab sessions. Some sessions included disconnections and reconnections. Within specific capstone search windows, matching process-creation and service-installation events were not found.

**Not established:** Unauthorized access, attacker identity, malicious execution, persistence, lateral movement, or exfiltration.

**Limitations:** Circular event-log retention, short-lived lab instances, baseline changes after restart, incomplete visibility across event channels, and narrow query windows. These limitations prevent a strong conclusion from a lack of findings.

**Conclusion:** **Inconclusive.** RDP activity warranted systematic review, but the retained evidence did not establish a security compromise. A prudent analyst would preserve available evidence, check approved access context, extend corroborating telemetry when available, and escalate only according to the evidence and organizational thresholds.

## 7. Lessons learned

- **An event is an observation; compromise is a conclusion supported by evidence.**
- **1149 authentication success is not the same as Event 21 session logon.**
- **Disconnect and reconnect events should not be assumed malicious.**
- **Privilege assignment is not privilege use.**
- **No matching events in a queried window is not proof of no activity.**
- **Host restarts and lab replacements break assumptions about reused session IDs and process IDs.**

