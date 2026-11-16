# Windows Process Creation & PowerShell Investigation

**Project:** Windows Incident Response — Windows Server 2019 (TryHackMe lab)  
**Investigation area:** Process creation, parent/child relationships, PowerShell telemetry and evidence limitations  
**Environment:** Authorized training lab; observations came from more than one lab session  
**Outcome:** No malicious process chain established from the evidence available

> **Evidence integrity note:** This document describes observations made during training, not a confirmed security breach. Events from different lab sessions must not be joined as though they occurred on the same continuously running host. Commands below are examples of repeatable investigation techniques; they are not themselves evidence that a particular event existed.

## 1. Investigation objective

Determine whether observed Windows processes and PowerShell activity were associated with suspicious logons, malicious execution, or persistence. The focus was on:

- Windows Security **Event ID 4688** (new process creation)
- Windows PowerShell operational logging, especially **Event ID 4104** (script-block content, when enabled and available)
- Process names, command lines, parent-process relationships and account context
- Correlation to authentication evidence only when event times, host identity, session and relevant identifiers support it

## 2. Lab environment and telemetry checks

The investigation used a Windows Server 2019 Standard (build 17763) training instance identified in the sessions as **THM-WINFUN2**. The Security event log used circular retention, meaning older records could be overwritten. Lab expiration and restart created discontinuities in available evidence.

We checked whether process-creation auditing was configured under **Detailed Tracking → Audit Process Creation**, and inspected available PowerShell event channels. Having an event channel enabled is not the same as having complete script-block coverage: recording Event 4104 depends on logging configuration and the type of PowerShell activity.

## 3. Observations from training

| Observation | What it supports | What it does **not** prove |
|---|---|---|
| Event 4688 entries included `WmiPrvSE.exe` launched by `svchost.exe` in one session | Process-creation telemetry was present for these processes | Malicious WMI execution |
| Another Event 4688 example showed `WMIC.exe` associated with an Amazon SSM agent worker process, using a hostname query (`computersystem get DNSHostName /value`) | A host-information command ran in a management-agent context | That the command was malicious or attacker-controlled |
| Investigated PowerShell Operational events including Event 4104 in a separate practical exercise | Script-content inspection was part of the workflow | That every PowerShell command was captured or that suspicious script text necessarily executed successfully |
| An unfamiliar executable path `C:\badr\badr.exe` appeared in earlier training material | A lead for further verification | Malware, parent/child relationship, persistence, or confirmed execution chain without supporting records |
| During the later Phase 4 capstone, no matching Event 4688 was found within the selected post-logon window | No qualifying event was located **in that search and available dataset** | That no process executed, or that the RDP session was benign |

**Important:** The rows above do not represent one attack timeline. They describe separate checks/sessions. The unfamiliar executable remains an unresolved lead; do not claim it was launched by `wscript.exe` or caused a compromise without verifying the relationship.

## 4. Reusable read-only investigation commands

### Check whether process creation is audited

```powershell
auditpol /get /subcategory:"Process Creation"
```

**Purpose:** Reports current audit policy for process creation. **Limitation:** A current policy check does not establish what was enabled at the time of a historic event. Command-line inclusion also has separate policy requirements.

### Retrieve recent process creation events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = (Get-Date).AddHours(-4)
} -ErrorAction Stop |
    Select-Object TimeCreated, RecordId, ProviderName, Message |
    Format-List
```

**Purpose:** Lists recent event records for a bounded interval. **Interpretation:** Examine the message's new process name, creator process, subject identity, logon ID and command line **if recorded**. Event-message formats differ by Windows version and locale.

### Search process events by executable name

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'powershell\.exe|pwsh\.exe|wmic\.exe|wscript\.exe|sc\.exe' } |
    Select-Object TimeCreated, RecordId, Message |
    Format-List
```

**Purpose:** A first-pass keyword hunt. **Limitation:** Searching rendered messages may be slow, locale-sensitive and prone to false matches. In a mature environment, parse XML fields and prefer centrally normalized EDR/SIEM telemetry.

### Inspect PowerShell script-block logs (if present)

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = (Get-Date).AddHours(-4)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, RecordId, Message |
    Format-List
```

**Purpose:** Inspect recorded script-block text. **Limitation:** The presence of a command string in a log does not by itself prove its objective succeeded. Absence of Event 4104 does not exclude PowerShell usage; verify logging configuration, channel retention, collection gaps and other telemetry.

### Check configured script-block logging policy

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue |
    Select-Object EnableScriptBlockLogging, EnableScriptBlockInvocationLogging
```

**Purpose:** Read a common policy location. **Limitation:** Missing values may be policy-not-configured, not a comprehensive proof of historical logging status; verify effective Group Policy and collection configuration.

## 5. Correlation workflow

1. **Anchor the host and session.** Confirm host identity, boot/session boundaries, timezone and available retention window.
2. **Select an authenticating event.** For example, a relevant Event 4624, including account, Logon Type and Logon ID.
3. **Search the subsequent interval.** Look for Event 4688, PowerShell 4104 and other endpoint telemetry with compatible timestamps.
4. **Verify identity and process ancestry.** Prefer EDR process GUIDs and creation times; use Windows PIDs only in context because they can be reused. A matching Logon ID must be assessed on the same host/boot context.
5. **Compare evidence sources.** Script-block text may indicate what code was submitted; Event 4688 indicates process creation; service Event 7045 indicates installation. None alone establishes the full execution chain.
6. **Check for benign explanations.** Consider administrators, patch jobs, management agents, approved deployments and expected maintenance windows.
7. **Record both findings and gaps.** An empty search result is a finding about searched, available telemetry—not proof that activity never occurred.

## 6. How an analyst would test a suspicious process lead

A lead such as `C:\badr\badr.exe` would justify checking (when available):

- The executable's first and last observed execution time, exact host and account
- Parent-process identity, command line, process GUID and EDR telemetry
- File existence, SHA-256 hash, signature and file metadata
- Network connections and child processes related to the same process instance
- Approval or change records and the source of the executable
- Correlated service creation, scheduled tasks and other persistence artifacts

If the executable is no longer present or relevant logs were overwritten, document the limitation. **Do not assign a malicious verdict solely from an unusual path or filename.**

## 7. Investigation finding

**Final assessment: Inconclusive.** The available observations demonstrate process and PowerShell logging analysis skills but did not establish a verified malicious process chain tied to the investigated RDP sessions. Some evidence was unavailable due to session changes, time-window limitations and circular log retention.

**Recommended follow-up in a more persistent lab:** Enable and validate appropriate auditing before a controlled test, preserve an export of the Security and PowerShell logs, establish a clean baseline, and correlate test-generated process activity with its exact authentication context. Use only authorized simulations.

## 8. Skills demonstrated

- Event ID 4688 interpretation and process-creation audit verification
- PowerShell Event 4104 inspection and logging caveats
- Investigation of parent/child process relationships and Windows management activity
- Timeline and session-aware correlation
- Evidence-based reporting without unsupported compromise claims

---

**Portfolio disclosure:** This report is based on authorized hands-on training and contains illustrative read-only commands. It is not an employer incident report. Sensitive data from any real environment should be removed before public publication.
