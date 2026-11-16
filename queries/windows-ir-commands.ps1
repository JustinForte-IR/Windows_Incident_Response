# Windows Incident Response: Read-Only Investigation Commands
# Portfolio: https://github.com/JustinForte-IR/Windows_Incident_Response
# Purpose: Demonstrate repeatable, authorized Windows Server event-log triage.
# This script DOES NOT change audit policy, create services, remove files,
# block connections, or claim to establish compromise automatically.
# Tested conceptually for Windows PowerShell 5.1 syntax; run and validate
# in your own authorized lab before relying on outputs operationally.

[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$LookbackHours = 24,

    [ValidateRange(1, 5000)]
    [int]$MaxEventsPerQuery = 100,

    [string]$SuspectedSourceIp = ''
)

$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-$LookbackHours)
$end = Get-Date

function Read-LogEvents {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int[]]$Ids
    )

    try {
        $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        @(Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            Id        = $Ids
            StartTime = $start
            EndTime   = $end
        } -MaxEvents $MaxEventsPerQuery -ErrorAction Stop)
    }
    catch {
        Write-Warning "No accessible matching events for '$LogName' IDs $($Ids -join ', '). Possible causes: no matches, disabled channel, access restrictions, or retention gaps. Detail: $($_.Exception.Message)"
        @()
    }
}

function Get-EventFields {
    param([Parameter(Mandatory)]$EventRecord)

    # Event XML supplies named EventData fields (more reliable than
    # hard-coded .Properties[] indices across event versions).
    $fields = @{}
    try {
        [xml]$xml = $EventRecord.ToXml()
        foreach ($datum in @($xml.Event.EventData.Data)) {
            if ($null -ne $datum -and $datum.Name) {
                $fields[[string]$datum.Name] = [string]$datum.'#text'
            }
        }
    }
    catch {
        Write-Warning "Unable to parse XML for record $($EventRecord.RecordId): $($_.Exception.Message)"
    }
    return $fields
}

Write-Host "Windows IR read-only triage: $env:COMPUTERNAME"
Write-Host "Window: $($start.ToString('s')) to $($end.ToString('s')) (host local time)"
Write-Host "Event count limit per query: $MaxEventsPerQuery; recent events only"
Write-Host "WARNING: A missing event is NOT proof the activity did not occur."

# 1) Authentication: 4624 successful logon, 4625 failed logon,
# 4634 logoff, 4672 special privileges assigned (not proof of use).
Write-Host "`n=== SECURITY: AUTHENTICATION (4624, 4625, 4634, 4672) ==="
$auth = Read-LogEvents -LogName 'Security' -Ids @(4624, 4625, 4634, 4672)
$authRows = foreach ($event in $auth) {
    $f = Get-EventFields -EventRecord $event
    [pscustomobject]@{
        TimeCreated    = $event.TimeCreated
        Id             = $event.Id
        RecordId       = $event.RecordId
        Account        = $f['TargetUserName']
        LogonType      = $f['LogonType']
        LogonId        = $f['TargetLogonId']
        IpAddress      = $f['IpAddress']
        Workstation    = $f['WorkstationName']
        Status         = $f['Status']
    }
}
if ($SuspectedSourceIp) {
    $authRows | Where-Object { $_.IpAddress -eq $SuspectedSourceIp } |
        Format-Table -AutoSize -Wrap
} else {
    $authRows | Format-Table -AutoSize -Wrap
}
Write-Host "Interpretation: 4624 LogonType 10 suggests remote interactive (RDP); corroborate with RDP session logs."

# 2) Process creation: command line and parent information depend on
# audit policy and configuration. 4688 alone does not establish maliciousness.
Write-Host "`n=== SECURITY: PROCESS CREATION (4688) ==="
$processes = Read-LogEvents -LogName 'Security' -Ids @(4688)
$processRows = foreach ($event in $processes) {
    $f = Get-EventFields -EventRecord $event
    [pscustomobject]@{
        TimeCreated  = $event.TimeCreated
        RecordId     = $event.RecordId
        NewProcess   = $f['NewProcessName']
        CommandLine  = $f['CommandLine']
        Parent       = $f['ParentProcessName']
        SubjectLogon = $f['SubjectLogonId']
        ProcessId    = $f['NewProcessId']
    }
}
$processRows | Format-Table -AutoSize -Wrap

# 3) PowerShell Script Block Logging: 4104 is logged only when enabled
# or otherwise triggered; seeing text does not prove successful execution.
Write-Host "`n=== POWERSHELL OPERATIONAL: SCRIPT BLOCKS (4104) ==="
$powerShellEvents = Read-LogEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4104)
$powerShellEvents | Select-Object TimeCreated, Id, RecordId,
    @{Name='MessagePreview'; Expression={
        if ($_.Message -and $_.Message.Length -gt 350) { $_.Message.Substring(0, 350) + ' ...' }
        else { $_.Message }
    }} | Format-List

# 4) Service installation: 7045 documents installation, not startup.
# Service Control Manager 7036 documents a state transition, not current state.
Write-Host "`n=== SYSTEM: SERVICE INSTALL AND STATE (7045, 7036) ==="
$services = Read-LogEvents -LogName 'System' -Ids @(7045, 7036)
$services | Select-Object TimeCreated, Id, RecordId,
    @{Name='MessagePreview'; Expression={
        if ($_.Message -and $_.Message.Length -gt 350) { $_.Message.Substring(0, 350) + ' ...' }
        else { $_.Message }
    }} | Format-List

# 5) RDP session corroboration: 1149 is authentication, and 21, 24,
# and 25 refer to session logon/disconnect/reconnect respectively.
Write-Host "`n=== RDP: REMOTE CONNECTION AUTHENTICATION (1149) ==="
Read-LogEvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Ids @(1149) |
    Select-Object TimeCreated, Id, RecordId, Message | Format-List

Write-Host "`n=== RDP: SESSION LOGON / DISCONNECT / RECONNECT (21, 24, 25) ==="
Read-LogEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Ids @(21, 24, 25) |
    Select-Object TimeCreated, Id, RecordId, Message | Format-List

Write-Host "`n=== ANALYST NEXT STEPS ==="
Write-Host '1. Correlate host, account, source IP, Logon ID, process ancestry, and time.'
Write-Host '2. Validate process/service paths, hashes and signatures using authorized procedures.'
Write-Host '3. Check log retention, channel configuration, and collection gaps.'
Write-Host '4. Compare activity with change tickets, baseline, and system owner confirmation.'
Write-Host '5. Record observed facts, hypotheses, confidence, and reasons for escalation.'
Write-Host '6. This tool is triage support—not an automated compromise verdict.'
