
# Windows Server Authentication & Persistence Investigation

**Project type:** Authorized training-lab investigation  
**Environment:** TryHackMe Windows Server 2019 (THM-WINFUN2)  
**Focus:** Authentication, RDP sessions, process creation, and Windows service persistence  
**Outcome:** Inconclusive; compromise was not established by the available evidence.

## Investigation objective

Determine whether the available host telemetry supports suspicious remote access, associated process execution, or service-based persistence. Distinguish observed events from unverified assumptions.

## Environment and telemetry

- Windows Server 2019 lab host.
- Windows Security event log, including Event ID 4624 and checks for 4688.
- Terminal Services / Remote Desktop-related event channels examined during training.
- Service installation checks using System Event ID 7045.
- PowerShell-based queries for selected event IDs and time windows.

The lab had session restarts and a circular Security log. Consequently, the evidence available in any one session was bounded by retention and collection timing. Events from distinct lab sessions must not be merged into a single continuous incident timeline without independent validation.

## Selected observations

During the Phase 4 capstone, a new lab baseline was established after a restart. On **9 November 2026**, the review found:

1. Three Administrator RDP logon observations associated with source address `10.129.93.13` in the available Security data.
2. No matching process-creation (4688) records identified in the examined 10-minute follow-up window.
3. No matching service-installation (7045) records identified in the examined one-hour window.
4. Process-creation auditing was verified as enabled at the time of checking; this did **not** retrospectively guarantee complete historical process telemetry.

These are **bounded search findings**, not claims that the host had no process execution or service activity outside the reviewed windows, and not proof that the remote logons were malicious.

## Analyst workflow

1. **Baseline the system:** Record hostname, OS build, boot time, collection time, log retention mode, and earliest accessible event records.
2. **Investigate remote access:** Review 4624 Logon Type 10 and RDP session events; identify account, source, session, Logon ID where recorded, and time sequence.
3. **Correlate process activity:** Review relevant 4688 records within an explicit follow-up interval; validate whether collection coverage exists before drawing conclusions from missing events.
4. **Check service persistence:** Search System 7045 events and available service state telemetry; distinguish service installation, start state, and present-day existence.
5. **Assess limitations:** Document circular logs, reboots, session expiration, missing fields, and telemetry gaps.
6. **Report outcome:** Separate confirmed observations, unresolved leads, and recommended additional evidence collection.

## Example read-only investigation commands

> These commands illustrate the investigative method. They are not original evidence exports. Run only in authorized environments. Replace dates, host-specific filters, and windows with actual incident values.

```powershell
# Confirm host and boot context
Get-CimInstance Win32_OperatingSystem |
  Select-Object CSName, Caption, Version, LastBootUpTime

# Inspect current Security log retention configuration
Get-WinEvent -ListLog Security |
  Select-Object LogName, RecordCount, MaximumSizeInBytes, LogMode

# Review successful logons in the available Security log
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated, Id, RecordId, Message

# Check process-creation records within a chosen time window
$start = Get-Date '2026-11-09 09:00:00'  # Example only, not an observed event time
$end   = $start.AddMinutes(10)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start; EndTime=$end} |
  Select-Object TimeCreated, Id, RecordId, Message

# Check for installed service records within the same investigation period
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$start; EndTime=$start.AddHours(1)} |
  Select-Object TimeCreated, Id, RecordId, Message
```

**Notes:** Event 4624 requires examination of its structured fields to determine Logon Type; the command above retrieves all 4624 records in the interval, not only RDP logons. Absence of results must be interpreted against log retention, source coverage, and the actual queried interval.

## Findings and conclusion

The available telemetry documented Administrator RDP activity. Within the selected follow-up windows, the investigation did not establish associated suspicious process creation or service-installation persistence. Therefore, **there was insufficient evidence to conclude that the observed access represented a compromise**.

The lack of matching events is not proof of benign activity. A stronger determination would require access authorization records, fuller process/EDR telemetry, network context, identity activity, and adequate retention across the relevant period.

## Skills demonstrated

- Windows Event Log triage and temporal correlation
- RDP investigation and Logon Type interpretation
- PowerShell-based event filtering
- Persistence checks using service-installation telemetry
- Evidence preservation mindset and documentation of telemetry limitations
- Conservative, evidence-supported incident reporting

## Evidence and integrity

This repository is a **training case-study summary**. Do not publish screenshots, raw logs, personal information, credentials, or organization-sensitive indicators without authorization. Include sanitized evidence exports only when their provenance and accuracy have been verified. No unverified sample output is represented as original evidence.

## Future improvements

- Add verified, sanitized event exports and annotated screenshots from an authorized persistent lab.
- Add a reproducible query notebook with structured EventData extraction.
- Re-run a controlled RDP-to-process correlation with reliable 4688 or EDR coverage.
- Document rule tests against benign and suspicious scenarios.

---

*This repository describes a training investigation. It does not claim employment experience, an actual breach, or validated malware execution.*
