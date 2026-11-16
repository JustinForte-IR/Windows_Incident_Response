# Windows Service Persistence Investigation

**Portfolio project:** Windows Incident Response — Windows Server 2019 (TryHackMe)  
**Investigation area:** Service installation, service start evidence, process execution, and persistence validation  
**Investigation outcome:** **Inconclusive — no service-based persistence established from the available capstone evidence**  
**Evidence type:** Actual lab observations are labeled separately from reusable investigation commands and simulated examples.

> **Evidence integrity:** This document reflects an authorized training lab. It does **not** claim a real organizational compromise. The October and November 2026 lab sessions were not one continuous incident. The hypothetical `WindowsHelper` / `helper.exe` malware scenario used in Phase 5 training is **not** evidence from this TryHackMe host.

## 1. Investigation objective

Determine whether a potentially suspicious Windows logon was followed by service creation, service execution, or other evidence of persistence. The investigation considered:

- What service-related events were present in the available event-log window?
- Could a particular service installation be linked to the observed RDP session?
- Did any service execute a suspicious binary, and under which account?
- Were logs and host telemetry sufficiently complete to confirm or exclude persistence?

## 2. Windows service evidence: what each source establishes

| Source | Typical interpretation | What it **does not** establish by itself |
|---|---|---|
| **System / Service Control Manager 7045** | A service was installed; includes service name, image path, type and start account when available | That the service started, that its executable ran, or that the service is malicious |
| **System / Service Control Manager 7036** | A service entered a reported state such as *Running* or *Stopped* | That the state persists now, or that the service is malicious |
| **Security 4697** | A service was installed, when this security audit event is available and configured | Complete coverage of all service operations across hosts |
| **Security 4688** | A process was created, subject to process-creation auditing and retention | That an installation succeeded or a process was malicious |
| **PowerShell Operational 4104** | Recorded PowerShell script-block content, when logging is available | That the recorded command succeeded or changed system state |
| **EDR process and service telemetry** | May connect a service-creation process, service binary execution, account and process ancestry | Authorization, intent and maliciousness without additional validation |

**Important distinction:** `7045` means *installation observed*; `7036` indicates a *state transition observed*; verified process telemetry supports *execution observed*. For strong attribution, connect these to the same host, boot period, relevant identifiers and timestamps.

## 3. Actual observations from the Windows lab

### November 9, 2026 — Phase 4 capstone session

- The Windows Server training instance had restarted; the fresh boot baseline was recorded as **03:11:55**.
- Three **Administrator RDP logons** were identified from lab source IP **`10.129.93.13`** in the available Security records.
- A targeted search found **no matching Event ID 7045** in the **one-hour window examined** following the selected authentication activity.
- A separate search found **no matching Security Event ID 4688** in the **10-minute post-logon window examined**.
- The lab had finite event-log retention and prior session discontinuities; absence of events in a bounded search was not proof that service installation or execution never occurred.

**Assessment:** The examined evidence did not establish service-based persistence, a malicious installer process, or confirmed compromise. Nor did it rule out activity outside the searched intervals or missing telemetry.

### Earlier sessions — supporting context, not the same incident

Earlier practical sessions included Windows service and process investigation concepts, but they must **not** be merged with the November capstone timeline. No validated service-to-malware execution chain from the actual host is claimed in this repository.

## 4. Read-only service investigation commands

These commands are for **authorized Windows systems**. Replace example time windows with a verified investigation interval. The commands are reusable techniques; not every command below was necessarily executed during the historical lab.

### 4.1 List installed-service events in a selected time window

```powershell
$start = Get-Date '2026-11-09 03:00:00'  # Example; set actual window
$end = $start.AddHours(2)

Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    ProviderName = 'Service Control Manager'
    Id        = 7045
    StartTime = $start
    EndTime   = $end
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, RecordId, Id, Message |
    Format-List
```

**Look for:** Service name, executable path/arguments, service type and account. **Limit:** No matches means none found in the queried retained dataset and time interval, **not** proof that no service was ever installed. Compare the query interval to the actual RDP timestamps.

### 4.2 Inspect reported service state transitions

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id      = 7036
    StartTime = $start
    EndTime   = $end
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

**Look for:** Transitions involving a service of interest. A historical *Running* event does not prove the service is still running.

### 4.3 Read the current configuration of a named service

```powershell
Get-CimInstance Win32_Service -Filter "Name='ExampleService'" |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId
```

**Look for:** Configured binary path, service account, start mode and current state. **Limit:** A current configuration snapshot is not proof of configuration at an earlier incident time.

### 4.4 Inspect a service binary safely (if present)

```powershell
$path = 'C:\Path\To\SuspectedService.exe'  # Replace with verified path
Get-Item -LiteralPath $path -ErrorAction Stop |
    Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
Get-FileHash -LiteralPath $path -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $path |
    Select-Object Status, SignerCertificate
```

**Look for:** Hash, signature status, metadata and consistency with approved software. **Limits:** A hash identifies bytes for comparison; a valid signature does not guarantee benign behavior; file times can be altered. Handle suspected malware according to organizational procedure—do not open or execute it merely to investigate.

### 4.5 Search for process creation around an installation

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $start
    EndTime   = $end
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'sc\.exe|powershell\.exe|pwsh\.exe|services\.exe' } |
    Select-Object TimeCreated, RecordId, Message |
    Format-List
```

**Look for:** Service-creation commands (for example, `sc.exe create`), a PowerShell parent process, corresponding account/logon context, and evidence that the service binary was later launched. **Limits:** Keyword searches are a first pass; field-normalized EDR/SIEM events are preferable, and Event 4688 command lines require the appropriate auditing settings.

### 4.6 Check service-installation auditing availability

```powershell
auditpol /get /subcategory:"Security System Extension"
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4697
    StartTime = $start
    EndTime   = $end
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, RecordId, Message
```

**Limit:** Current audit policy does not establish the historical setting. Event 4697 coverage depends on the system configuration and available records. Do not assume every endpoint collects it.

## 5. Evidence-correlation workflow

1. **Establish the context:** Confirm host identity, boot time, timezone, available retention, event channel availability, and exact search intervals.
2. **Anchor the access event:** Identify a relevant RDP `4624` (LogonType 10) and supporting session events (`1149`, `21`, `24`, `25`) from the **same lab session**.
3. **Look for installation:** Query SCM `7045` and, if enabled, Security `4697` close to the access event; record service name, path and account.
4. **Identify the installer:** Seek `4688`, PowerShell `4104`, or EDR evidence of the actual installer command and its account/process context.
5. **Establish execution separately:** Search for `7036` state transitions, service process creation, and EDR evidence that `services.exe` launched the configured binary.
6. **Validate security significance:** Inspect binary metadata/hash/signature, privilege context, deployment records, host role and administrator approval.
7. **Classify precisely:** Distinguish *observed*, *correlated*, *suspected*, *confirmed*, and *unknown* findings; document missing evidence and alternative explanations.

A suspicious service path (for example, one in a user-writable folder) is **a lead**, not automatic proof of malware. Services installed by authorized maintenance, endpoint agents or deployment software may resemble attacker behavior.

## 6. What would strengthen or change this lab conclusion?

Examples of additional evidence that could establish a meaningful persistence chain include:

- A relevant `7045` record with a verifiable service binary path and timestamp.
- `4688`/EDR evidence linking the service-creation command to the investigated user session.
- `7036` and process telemetry showing that the named service entered Running state and executed its binary.
- File hash or forensic analysis linking the **executed** executable to known malware.
- Owner/change-management confirmation that installation was unauthorized.
- Associated network or follow-on activity, carefully interpreted without prematurely labeling traffic as C2 or exfiltration.

None of these combined claims is asserted as proven in the actual November 9 lab session.

## 7. ATT&CK mapping — only when supported by behavior

- **T1543.003 — Create or Modify System Process: Windows Service:** Appropriate when evidence supports attacker-created or attacker-modified service persistence; **not** from the mere existence of a benign Windows service.
- **T1059.001 — Command and Scripting Interpreter: PowerShell:** Appropriate when relevant adversary PowerShell execution is established; script text alone needs careful interpretation.
- **T1078 — Valid Accounts:** Appropriate when valid-account misuse is supported, not just because Administrator logged in.
- **T1021.001 — Remote Services: Remote Desktop Protocol:** Depends on the established remote-access/lateral-movement behavior, not every legitimate RDP logon.

## 8. Findings and disposition

| Question | Conclusion for this actual lab |
|---|---|
| Did the selected November search return a matching `7045` event? | **No**, within the one-hour examined window |
| Was a malicious service identified? | **Not established** |
| Was service-binary execution linked to the RDP logon? | **Not established** |
| Can service persistence be excluded across all time? | **No**; retention, time-window, and session limitations apply |
| Can a compromise be confirmed? | **No**, not from the observed evidence |

**Final assessment: Inconclusive.** The investigated Windows Server training evidence did not establish malicious service persistence or compromise. This is a defensible analytic outcome based on the observable records and stated limitations.

## 9. Ready explanation

> "In a Windows Server incident-response lab I correlated RDP authentication with process-creation and Windows service-installation telemetry. I checked for service-installation Event 7045 in a bounded post-logon window, but there was no matching record in the retained logs. I did not interpret that absence as proof that persistence was impossible. I documented the time-window and retention limitations and identified the additional evidence—installer ancestry, service execution, file verification and authorization records—needed before concluding compromise."


