# Incident Investigation Report — Windows Server Authentication & Persistence Review

**Repository:** `Windows_Incident_Response`  
**Case ID:** `WIN-IR-LAB-001` (portfolio identifier, not an enterprise ticket)  
**Environment:** Authorized TryHackMe Windows Server 2019 lab (`THM-WINFUN2`)  
**Primary review date:** 9 November 2026  
**Investigation type:** Training exercise / retrospective event-log review  
**Final disposition:** **Inconclusive — compromise not established**  
**Report basis:** Analyst notes and previously documented observations; original EVTX exports and verified evidence hashes are not included.

> **Reader's note:** This is a training investigation, not a real customer incident. The simulated `WindowsHelper` malware scenario used in separate Phase 5 exercises is **not** evidence from this host. Earlier October sessions are discussed only as background, not merged into the November capstone timeline.

## 1. Executive summary

A Windows Server 2019 training host was examined to assess whether observed Administrator Remote Desktop activity was associated with suspicious process execution or Windows service installation. In the available 9 November 2026 capstone records, three successful Administrator RDP logon observations were associated with source address `10.129.93.13`. Targeted searches did not identify matching process-creation Event ID **4688** records in the examined **10-minute follow-up window**, or matching service-installation Event ID **7045** records in the examined **one-hour window**.

The evidence supports the presence of recorded remote interactive logons; it **does not demonstrate** that those logons were unauthorized, malicious, or followed by persistence. The absence of matches in limited searches does **not** prove that no processes executed or that persistence was impossible. Circular event-log retention, lab restarts, bounded queries, and unavailable corroborating telemetry limit confidence.

**Final assessment: Inconclusive.** Further authorization checks, better-preserved telemetry, and corroboration from endpoint/network sources would be necessary to reach a stronger conclusion.

## 2. Scope and objectives

**In scope**

- Authentication and RDP activity associated with the selected November lab session.
- Windows Security Event **4624** for successful logons.
- Windows Security Event **4688** for process-creation searches.
- System / Service Control Manager Event **7045** for service-installation searches.
- Relevant logging and audit-coverage limitations.

**Out of scope / not established**

- A proven credential theft event, attacker identity, lateral movement, malicious payload, or successful persistence.
- Actual endpoint detection and response (EDR), network packet capture, or a validated organization change-management record.
- Combining distinct lab instances into one continuous incident timeline.

**Investigation question:** Did the retained evidence substantiate malicious follow-on activity connected to the Administrator RDP logons?

## 3. Environment and evidence provenance

| Item | Recorded context | Constraint |
|---|---|---|
| Host | `THM-WINFUN2`, Windows Server 2019 training system | Short-lived lab instance; environment may change across restarts |
| Relevant capstone session | 9 November 2026 | Individual event timestamps not republished without source exports |
| Event logs | Windows Security and System; Terminal Services context considered in training | Circular retention and incomplete continuity |
| Source address | `10.129.93.13` in November capstone observations | IP ownership, authorization, and intent not independently validated |
| Primary evidence material | Analyst notes and summarized event-query findings | Not equivalent to preserved raw forensic artifacts |

Earlier **October 2026** exercises examined successful RDP authentication and session telemetry (including **1149, 21, 24 and 25**) with a different source address, `10.130.86.114`. Those observations are **not** part of the November incident chain and cannot establish movement between the addresses.

## 4. Evidence register

| Ref | Source | Observation | Evidentiary interpretation |
|---|---|---|---|
| **E-01** | Security Event 4624 | Three Administrator RDP logon observations associated with `10.129.93.13` | Successful remote interactive logons recorded; authorization not determined |
| **E-02** | Security Event 4688 query | No matching records found in the selected **10-minute follow-up window** | No *observed matches* in the bounded search; not proof of no execution |
| **E-03** | System Event 7045 query | No matching records found in the selected **one-hour window** | No *observed service-installation matches* in this window; not proof of absence elsewhere |
| **E-04** | Audit policy review | Process Creation auditing appeared enabled **when inspected** | Does not prove equivalent audit coverage earlier in time |
| **E-05** | Host / log assessment | Restarted lab instance and circular Security log retention | Historical event availability may be incomplete |

**Evidence custody status:** No verified primary EVTX package, screenshot set, or cryptographic hashes are attached to this portfolio. The entries above are documented observations, **not** a claim that physical or electronic exhibits were formally acquired.

## 5. Investigation methodology

1. **Establish scope and baseline.** Identify the current host, boot period, clock/time zone and available log history; avoid reusing identifiers across rebooted instances.
2. **Review logons.** Identify successful remote interactive logons using Event 4624 / LogonType 10; collect account, source IP, Logon ID, timestamp and Record ID when available.
3. **Corroborate RDP context.** Use Terminal Services authentication and session events, distinguishing authentication success from session establishment and reconnect/disconnect transitions.
4. **Review process activity.** Search Event 4688 near the relevant session and correlate only when host, identifiers, timing and audit coverage support the connection.
5. **Review service persistence.** Search Event 7045 within a defined period; a 7045 record, if found, establishes installation, **not** service execution or malicious intent.
6. **Assess coverage and alternative explanations.** Consider legitimate administration, missing telemetry, record rollover and restarted lab sessions.
7. **Document the decision.** Report observations, uncertainty, relevant gaps and proportionate next steps without asserting unsupported compromise.

### Example read-only PowerShell searches

The commands below are **reproducible examples** for an authorized Windows host. They are **not purported original command transcripts** from the lab. Replace the timestamps with the actual investigated interval.

```powershell
# Search successful and failed Windows logons within an explicit window
$start = Get-Date '2026-11-09 03:00:00' # Example only
$end   = $start.AddHours(2)
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624,4625; StartTime=$start; EndTime=$end
} | Select-Object TimeCreated, Id, RecordId, Message
```

```powershell
# Search process-creation telemetry; a non-match is not proof of no execution
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4688; StartTime=$start; EndTime=$end
} | Select-Object TimeCreated, RecordId, Message
```

```powershell
# Search Windows service installations; 7045 is installation evidence
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=7045; StartTime=$start; EndTime=$end
} | Select-Object TimeCreated, RecordId, Message
```

**Operational caveat:** On a real case, logon and process details should be parsed from structured event XML fields, not inferred from text alone. Verify log configuration, field availability, local/UTC time alignment and retention prior to concluding a search is comprehensive.

## 6. Findings and interpretation

### Finding F-01 — Remote interactive access recorded

**Assessment:** Supported. Three Administrator RDP logon observations were identified in the retained November records with source `10.129.93.13`.

**Not supported:** That the source was an attacker, the credential was stolen, or the access was unauthorized. Such judgments require approved-user context and corroboration.

### Finding F-02 — No correlated process event identified in the selected search

**Assessment:** The targeted Event 4688 query did not return matching process-creation records during the examined **10-minute period**.

**Limit:** Audit-policy state at inspection time does not establish historical logging coverage. Narrow selection criteria, gaps or retention may account for missing matches.

### Finding F-03 — No service installation identified in the selected search

**Assessment:** The targeted Event 7045 query did not return matching service-installation records during the examined **one-hour period**.

**Limit:** This does not eliminate persistence via another time window or mechanism. Even if 7045 had appeared, additional evidence would be needed to establish the service launched and was malicious.

### Finding F-04 — Incomplete continuity and preserved evidence

**Assessment:** Lab restarts and circular retention limit comparisons between sessions; original raw artifacts are not available in this published portfolio package.

**Limit:** A continuous, precise minute-by-minute attack timeline cannot responsibly be asserted.

## 7. Incident classification and confidence

| Question | Decision |
|---|---|
| Was successful Administrator remote access observed? | **Yes**, within the available November records |
| Was it shown to be unauthorized? | **Not established** |
| Was malicious PowerShell or process execution established? | **No** |
| Was Windows service persistence established? | **No** |
| Can benign administration be confirmed? | **No**, insufficient independent authorization context |
| Is compromise confirmed? | **No — inconclusive** |

**Confidence statement:** High confidence in the **limited observations documented**, but low confidence in any stronger claim about the host's overall security state due to telemetry and provenance gaps.

## 8. Recommended follow-up (authorized environment)

1. Validate account owner and RDP authorization against approved administration records.
2. Verify earliest/latest retained event for each channel; export relevant EVTX logs and record collection metadata.
3. Cross-check Terminal Services events, process creation, PowerShell logging and available EDR telemetry for the **same** boot/session.
4. Examine service and scheduled-task configuration if authorized, including historical change context.
5. Correlate source-IP activity with host/firewall/network records where available; do not assume that an IP string identifies a person.
6. Preserve original exports securely, generate SHA-256 hashes **of files actually collected**, and maintain chain-of-custody notes.
7. Reassess disposition if new evidence establishes unauthorized access or harmful execution.

## 9. Lessons learned

- **Authentication is an observation; compromise is a conclusion requiring corroboration.**
- **No query result** is a statement about a defined search and available telemetry, not proof that an action never occurred.
- **7045 ≠ service execution**; investigation of service execution requires additional state/process evidence.
- Separate sessions, boot periods and clock contexts must not be stitched into one attack story.
- Clear disclosure of evidence gaps makes the report more credible and useful.

## 10. Portfolio disclosure and related documentation

This project demonstrates practical training in event-log triage, hypothesis-driven investigation, evidence correlation, scope limitation and professional reporting. It does **not** claim prior employment in a SOC, production access or an actual enterprise breach. IPs shown are training-lab observations; sanitize or remove any additional host/user identifiers before publishing.

Related repository documents:

- [`../README.md`](../README.md) *(when viewed from the `report/` folder)*
- [`../investigation/authentication-analysis.md`](../investigation/authentication-analysis.md)
- [`../investigation/process-investigation.md`](../investigation/process-investigation.md)
- [`../investigation/service-persistence.md`](../investigation/service-persistence.md)
- [`../evidence/evidence-summary.md`](../evidence/evidence-summary.md)

---

**Report prepared for training and portfolio demonstration.**
