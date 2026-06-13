<#
.SYNOPSIS
    Collects AD computer inventory (with derived risk flags) and ALL computer-related
    audit events (who/what/when), displays summaries on terminal, and outputs two JSON
    payloads ready for API submission.

.NOTES
    Requires:
      - ActiveDirectory module (RSAT)
      - For audit events: "Computer Account Management" and "Directory Service Changes"
        audit subcategories enabled on Domain Controllers
      - Read access to Security event log on DCs (Event Log Readers group or Domain Admin)
#>

Import-Module ActiveDirectory

# ====================================================
# CONFIGURATION
# ====================================================

# --- Stale / password anomaly thresholds ---
$pwdAnomalyThreshold = 60   # days

# --- EOL OS patterns ---
$eolOSPatterns = @(
    'Windows 7', 'Windows XP', 'Windows Vista', 'Windows 8\b',
    'Server 2003', 'Server 2008', 'Server 2012\b'
)

# --- Naming convention ---
# Expected: DEPT-FirstName-LastInitial-HRID  (e.g., IT-Henok-M-1203)
# If full name would exceed 15 chars, FirstName gets truncated (e.g., IT-Sale-M-1204)
# We validate the *shape* of the name (Dept-Name-Initial-HRID) rather than the exact
# truncation logic, and separately flag names over 15 chars as informational.
$namingConventionRegex = '^[A-Za-z]+-[A-Za-z]+-[A-Z]-\d+$'
$namingMaxLength = 15

# --- Audit event IDs to collect ---
$auditEventIDs = 4741, 4742, 4743, 4722, 4724, 4725, 4781, 5136, 5137, 5141

# --- Output file paths (for local testing) ---
$inventoryOutputPath = "C:\Temp\ad_computers_inventory.json"
$auditOutputPath     = "C:\Temp\ad_computers_audit_events.json"

$now = Get-Date

# ====================================================
# PART 1: AD COMPUTER INVENTORY
# ====================================================

Write-Host "Collecting AD computer objects..." -ForegroundColor Cyan

$computers = Get-ADComputer -Filter * -Properties Name, DNSHostName, OperatingSystem, `
    OperatingSystemVersion, OperatingSystemServicePack, Enabled, LastLogonTimestamp, `
    whenCreated, PasswordLastSet, Description, DistinguishedName, IPv4Address

function Get-OUPath {
    param($dn)
    $parts = $dn -split ','
    $ouParts = $parts | Where-Object { $_ -match '^(OU|DC)=' }
    return ($ouParts -join ',')
}

function Test-EOL($osName) {
    foreach ($pattern in $eolOSPatterns) {
        if ($osName -match $pattern) { return $true }
    }
    return $false
}

$records = foreach ($c in $computers) {

    $lastLogon = if ($c.LastLogonTimestamp) {
        [DateTime]::FromFileTime($c.LastLogonTimestamp)
    } else { $null }

    $pwdLastSet = if ($c.PasswordLastSet) {
        Get-Date $c.PasswordLastSet
    } else { $null }

    $daysSinceLogon = if ($lastLogon) { ($now - $lastLogon).Days } else { $null }
    $pwdAgeDays     = if ($pwdLastSet) { ($now - $pwdLastSet).Days } else { $null }

    $arch = if ($c.OperatingSystem -match '64-bit' -or $c.OperatingSystemVersion -match '64') {
        '64-bit'
    } elseif ($c.OperatingSystem) {
        '32-bit'
    } else {
        'Unknown'
    }

    $type = if ($c.OperatingSystem -match 'Server') { 'Server' }
            elseif ($c.OperatingSystem) { 'Workstation' }
            else { 'Unknown' }

    $isEOL = ($c.Enabled -eq $true) -and (Test-EOL $c.OperatingSystem)

    $isStale30 = ($daysSinceLogon -ne $null -and $daysSinceLogon -ge 30)
    $isStale60 = ($daysSinceLogon -ne $null -and $daysSinceLogon -ge 60)
    $isStale90 = ($daysSinceLogon -ne $null -and $daysSinceLogon -ge 90)
    $neverLoggedOn = ($lastLogon -eq $null)

    $likelyBrokenTrust = ($c.Enabled -eq $true) -and
                         ($pwdAgeDays -ne $null -and $pwdAgeDays -gt 90) -and
                         ($daysSinceLogon -ne $null -and $daysSinceLogon -gt 90)

    $isConflictObject = $c.DistinguishedName -match 'CNF:'

    # --- Naming convention check ---
    # Expected shape: DEPT-Name-Initial-HRID
    $nameLength = $c.Name.Length
    $matchesShape = $c.Name -match $namingConventionRegex
    $exceedsMaxLength = $nameLength -gt $namingMaxLength

    $namingStatus = if (-not $matchesShape) {
        'Violation'
    } elseif ($exceedsMaxLength) {
        'Truncated'   # matches shape but is long enough that truncation likely occurred
    } else {
        'Compliant'
    }

    [PSCustomObject]@{
        Name                   = $c.Name
        DNSHostName            = $c.DNSHostName
        OperatingSystem        = $c.OperatingSystem
        OperatingSystemVersion = $c.OperatingSystemVersion
        ServicePack            = $c.OperatingSystemServicePack
        Architecture           = $arch
        ComputerType           = $type
        Enabled                = $c.Enabled
        LastLogonTimestamp     = $lastLogon
        DaysSinceLastLogon     = $daysSinceLogon
        WhenCreated            = $c.whenCreated
        PasswordLastSet        = $pwdLastSet
        PasswordAgeDays        = $pwdAgeDays
        Description            = $c.Description
        DistinguishedName      = $c.DistinguishedName
        OU                     = Get-OUPath $c.DistinguishedName
        IPv4Address            = $c.IPv4Address

        # Derived risk flags
        IsEOL                  = $isEOL
        IsStale30              = $isStale30
        IsStale60              = $isStale60
        IsStale90              = $isStale90
        NeverLoggedOn          = $neverLoggedOn
        LikelyBrokenTrust      = $likelyBrokenTrust
        IsConflictObject       = $isConflictObject
        NamingStatus           = $namingStatus
    }
}

# ====================================================
# DASHBOARD METRICS
# ====================================================

$totalComputers = $records.Count

$osBreakdown = $records | Group-Object OperatingSystem | Select-Object Name, Count |
    Sort-Object Count -Descending

$ouBreakdown = $records | Group-Object OU | Select-Object Name, Count |
    Sort-Object Count -Descending

$stale30 = $records | Where-Object { $_.IsStale30 }
$stale60 = $records | Where-Object { $_.IsStale60 }
$stale90 = $records | Where-Object { $_.IsStale90 }
$neverLoggedOnList = $records | Where-Object { $_.NeverLoggedOn }

$eolMachines = $records | Where-Object { $_.IsEOL }
$eolBreakdown = $eolMachines | Group-Object OperatingSystem | Select-Object Name, Count

$enabledCount  = ($records | Where-Object { $_.Enabled -eq $true }).Count
$disabledCount = ($records | Where-Object { $_.Enabled -eq $false }).Count

$disabledButActive = $records | Where-Object {
    $_.Enabled -eq $false -and $_.DaysSinceLastLogon -ne $null -and $_.DaysSinceLastLogon -le 30
}

$pwdAnomalies = $records | Where-Object {
    $_.PasswordAgeDays -ne $null -and $_.PasswordAgeDays -gt $pwdAnomalyThreshold
}

$new7  = $records | Where-Object { $_.WhenCreated -ge $now.AddDays(-7) }
$new30 = $records | Where-Object { $_.WhenCreated -ge $now.AddDays(-30) }

$serverCount      = ($records | Where-Object { $_.ComputerType -eq 'Server' }).Count
$workstationCount = ($records | Where-Object { $_.ComputerType -eq 'Workstation' }).Count
$unknownTypeCount = ($records | Where-Object { $_.ComputerType -eq 'Unknown' }).Count

$brokenTrustList   = $records | Where-Object { $_.LikelyBrokenTrust }
$conflictObjects   = $records | Where-Object { $_.IsConflictObject }
$namingViolations  = $records | Where-Object { $_.NamingStatus -eq 'Violation' }
$namingTruncated   = $records | Where-Object { $_.NamingStatus -eq 'Truncated' }

# ====================================================
# BUILD INVENTORY PAYLOAD
# ====================================================

$inventoryPayload = [PSCustomObject]@{
    CollectedAt = $now
    Summary = [PSCustomObject]@{
        TotalComputers    = $totalComputers
        Enabled           = $enabledCount
        Disabled          = $disabledCount
        ServerCount       = $serverCount
        WorkstationCount  = $workstationCount
        UnknownTypeCount  = $unknownTypeCount
        OSBreakdown       = $osBreakdown
        OUBreakdown       = $ouBreakdown
    }
    Stale = [PSCustomObject]@{
        NoLogon30Days  = $stale30.Count
        NoLogon60Days  = $stale60.Count
        NoLogon90Days  = $stale90.Count
        NeverLoggedOn  = $neverLoggedOnList.Count
        Machines30Plus = $stale30 | Select-Object Name, OU, DaysSinceLastLogon, Enabled
    }
    EOLRisk = [PSCustomObject]@{
        Count     = $eolMachines.Count
        Breakdown = $eolBreakdown
        Machines  = $eolMachines | Select-Object Name, OperatingSystem, OU, Enabled
    }
    DisabledButActive = $disabledButActive | Select-Object Name, OU, DaysSinceLastLogon
    PasswordAnomalies = [PSCustomObject]@{
        ThresholdDays = $pwdAnomalyThreshold
        Count         = $pwdAnomalies.Count
        Machines      = $pwdAnomalies | Select-Object Name, OU, PasswordAgeDays, Enabled
    }
    NewComputers = [PSCustomObject]@{
        Last7Days  = $new7  | Select-Object Name, OU, WhenCreated
        Last30Days = $new30 | Select-Object Name, OU, WhenCreated
    }
    BrokenTrustRisk = [PSCustomObject]@{
        Count    = $brokenTrustList.Count
        Machines = $brokenTrustList | Select-Object Name, OU, DaysSinceLastLogon, PasswordAgeDays
    }
    ConflictObjects = [PSCustomObject]@{
        Count    = $conflictObjects.Count
        Machines = $conflictObjects | Select-Object Name, DistinguishedName
    }
    NamingConvention = [PSCustomObject]@{
        Pattern          = $namingConventionRegex
        MaxLength        = $namingMaxLength
        ViolationCount   = $namingViolations.Count
        TruncatedCount   = $namingTruncated.Count
        Violations       = $namingViolations | Select-Object Name, OU, Enabled
        TruncatedNames   = $namingTruncated  | Select-Object Name, OU, Enabled
    }
    AllComputers = $records
}

# ====================================================
# PART 2: AUDIT EVENTS (who / what / when) — ALL EVENTS
# Note: No StartTime filter — retrieves everything retained in the Security log.
# On busy DCs this may take a while. Check log size first with:
#   Get-WinEvent -ListLog Security -ComputerName <dc> | Select-Object MaximumSizeInBytes, RecordCount
# ====================================================

Write-Host "`nCollecting ALL audit events from Domain Controllers (no time limit)..." -ForegroundColor Cyan

$dcList = (Get-ADDomainController -Filter *).HostName

$auditEvents = foreach ($dc in $dcList) {

    Write-Host "  - Querying $dc..." -ForegroundColor DarkGray

    try {
        $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName = 'Security'
            Id      = $auditEventIDs
        } -ErrorAction Stop

    } catch {
        Write-Host "    Could not query $dc : $($_.Exception.Message)" -ForegroundColor Yellow
        continue
    }

    foreach ($evt in $events) {

        $xml  = [xml]$evt.ToXml()
        $data = $xml.Event.EventData.Data

        function Get-Field($name) {
            ($data | Where-Object { $_.Name -eq $name }).'#text'
        }

        $who    = Get-Field 'SubjectUserName'
        $whoDom = Get-Field 'SubjectDomainName'
        $whoSid = Get-Field 'SubjectUserSid'

        $target = switch ($evt.Id) {
            { $_ -in 4741,4742,4743,4722,4724,4725,4781 } { Get-Field 'TargetUserName' }
            { $_ -in 5136,5137,5141 }                     { Get-Field 'ObjectDN' }
            default { $null }
        }

        $objectClass = Get-Field 'ObjectClass'

        $action = switch ($evt.Id) {
            4741 { 'Computer created' }
            4742 { 'Computer modified' }
            4743 { 'Computer deleted' }
            4722 { 'Account enabled' }
            4725 { 'Account disabled' }
            4724 { 'Password reset' }
            4781 { 'Computer renamed' }
            5137 { 'Object created' }
            5141 { 'Object deleted' }
            5136 {
                $attr = Get-Field 'AttributeLDAPDisplayName'
                $val  = Get-Field 'AttributeValue'
                "Attribute changed: $attr -> $val"
            }
        }

        # Filter to computer-like objects:
        #   - sAMAccountName ends in $  (4741/4742/etc.)
        #   - ObjectClass = computer    (5136/5137/5141)
        #   - DN contains an OU and looks like a computer object
        $looksLikeComputer = ($target -match '\$$') -or
                              ($objectClass -eq 'computer') -or
                              ($target -match 'CN=.*,OU=')

        if ($looksLikeComputer) {
            [PSCustomObject]@{
                TimeCreated      = $evt.TimeCreated
                DomainController = $dc
                EventID          = $evt.Id
                Action           = $action
                TargetObject     = $target
                ObjectClass      = $objectClass
                PerformedBy      = if ($who) { "$whoDom\$who" } else { $null }
                PerformedBySid   = $whoSid
            }
        }
    }
}

$auditEvents = $auditEvents | Sort-Object TimeCreated -Descending

# Separate human-driven vs system/replication actions
$systemAccounts = @('SYSTEM', 'ANONYMOUS LOGON')
$humanEvents  = $auditEvents | Where-Object {
    $_.PerformedBy -and ($_.PerformedBy -notmatch '\$$') -and
    ($systemAccounts -notcontains ($_.PerformedBy -split '\\')[-1])
}
$systemEvents = $auditEvents | Where-Object { $_ -notin $humanEvents }

# ====================================================
# BUILD AUDIT PAYLOAD
# ====================================================

$auditPayload = [PSCustomObject]@{
    CollectedAt   = $now
    LookbackHours = 'All available (no time limit)'
    Summary = [PSCustomObject]@{
        TotalEvents  = $auditEvents.Count
        HumanEvents  = $humanEvents.Count
        SystemEvents = $systemEvents.Count
        ByAction     = $auditEvents | Group-Object Action | Select-Object Name, Count | Sort-Object Count -Descending
        ByPerformer  = $humanEvents | Group-Object PerformedBy | Select-Object Name, Count | Sort-Object Count -Descending
    }
    Events      = $auditEvents
    HumanEvents = $humanEvents
}

# ====================================================
# DISPLAY RESULTS ON TERMINAL
# ====================================================

Write-Host "`n===== INVENTORY SUMMARY =====" -ForegroundColor Cyan
$inventoryPayload.Summary | Format-List

Write-Host "`n--- OS Breakdown ---" -ForegroundColor Cyan
$inventoryPayload.Summary.OSBreakdown | Format-Table -AutoSize

Write-Host "`n--- OU Breakdown ---" -ForegroundColor Cyan
$inventoryPayload.Summary.OUBreakdown | Format-Table -AutoSize

Write-Host "`n===== STALE MACHINES =====" -ForegroundColor Cyan
Write-Host "No logon 30+ days : $($inventoryPayload.Stale.NoLogon30Days)"
Write-Host "No logon 60+ days : $($inventoryPayload.Stale.NoLogon60Days)"
Write-Host "No logon 90+ days : $($inventoryPayload.Stale.NoLogon90Days)"
Write-Host "Never logged on   : $($inventoryPayload.Stale.NeverLoggedOn)"
$inventoryPayload.Stale.Machines30Plus | Format-Table -AutoSize

Write-Host "`n===== EOL OS RISK =====" -ForegroundColor Cyan
Write-Host "Total EOL machines: $($inventoryPayload.EOLRisk.Count)"
$inventoryPayload.EOLRisk.Breakdown | Format-Table -AutoSize
$inventoryPayload.EOLRisk.Machines | Format-Table -AutoSize

Write-Host "`n===== DISABLED BUT ACTIVE =====" -ForegroundColor Cyan
$inventoryPayload.DisabledButActive | Format-Table -AutoSize

Write-Host "`n===== PASSWORD AGE ANOMALIES (>$($inventoryPayload.PasswordAnomalies.ThresholdDays) days) =====" -ForegroundColor Cyan
Write-Host "Count: $($inventoryPayload.PasswordAnomalies.Count)"
$inventoryPayload.PasswordAnomalies.Machines | Format-Table -AutoSize

Write-Host "`n===== NEW COMPUTERS =====" -ForegroundColor Cyan
Write-Host "--- Last 7 days ---"
$inventoryPayload.NewComputers.Last7Days | Format-Table -AutoSize
Write-Host "--- Last 30 days ---"
$inventoryPayload.NewComputers.Last30Days | Format-Table -AutoSize

Write-Host "`n===== SERVER vs WORKSTATION =====" -ForegroundColor Cyan
Write-Host "Servers     : $($inventoryPayload.Summary.ServerCount)"
Write-Host "Workstations: $($inventoryPayload.Summary.WorkstationCount)"
Write-Host "Unknown     : $($inventoryPayload.Summary.UnknownTypeCount)"

Write-Host "`n===== LIKELY BROKEN TRUST (enabled, pwd>90d, logon>90d) =====" -ForegroundColor Cyan
Write-Host "Count: $($inventoryPayload.BrokenTrustRisk.Count)"
$inventoryPayload.BrokenTrustRisk.Machines | Format-Table -AutoSize

Write-Host "`n===== CONFLICT OBJECTS (replication conflicts) =====" -ForegroundColor Cyan
Write-Host "Count: $($inventoryPayload.ConflictObjects.Count)"
$inventoryPayload.ConflictObjects.Machines | Format-Table -AutoSize

Write-Host "`n===== NAMING CONVENTION =====" -ForegroundColor Cyan
Write-Host "Pattern        : $($inventoryPayload.NamingConvention.Pattern)"
Write-Host "Violations     : $($inventoryPayload.NamingConvention.ViolationCount)"
Write-Host "Truncated names: $($inventoryPayload.NamingConvention.TruncatedCount)"
Write-Host "--- Violations ---"
$inventoryPayload.NamingConvention.Violations | Format-Table -AutoSize
Write-Host "--- Truncated (matches shape, but >15 chars) ---"
$inventoryPayload.NamingConvention.TruncatedNames | Format-Table -AutoSize

Write-Host "`n===== AUDIT EVENTS (ALL available in Security log) =====" -ForegroundColor Cyan
Write-Host "Total events  : $($auditPayload.Summary.TotalEvents)"
Write-Host "Human events  : $($auditPayload.Summary.HumanEvents)"
Write-Host "System events : $($auditPayload.Summary.SystemEvents)"

Write-Host "`n--- By Action ---" -ForegroundColor Cyan
$auditPayload.Summary.ByAction | Format-Table -AutoSize

Write-Host "`n--- By Performer (human only) ---" -ForegroundColor Cyan
$auditPayload.Summary.ByPerformer | Format-Table -AutoSize

Write-Host "`n--- Recent human-driven events ---" -ForegroundColor Cyan
$auditPayload.HumanEvents | Select-Object TimeCreated, Action, TargetObject, PerformedBy |
    Format-Table -AutoSize -Wrap

# ====================================================
# JSON / API SEND (commented out for testing)
# ====================================================

$inventoryJson = $inventoryPayload | ConvertTo-Json -Depth 6 -Compress
$auditJson     = $auditPayload     | ConvertTo-Json -Depth 6 -Compress

# --- API endpoints ---
# $inventoryApiEndpoint = "https://your-api-server/api/computers/inventory"
# $auditApiEndpoint     = "https://your-api-server/api/computers/audit-events"

# Invoke-RestMethod -Uri $inventoryApiEndpoint -Method Post -Body $inventoryJson -ContentType "application/json"
# Invoke-RestMethod -Uri $auditApiEndpoint     -Method Post -Body $auditJson     -ContentType "application/json"

# Optionally save JSON locally too:
# $inventoryJson | Out-File -FilePath $inventoryOutputPath -Encoding utf8
# $auditJson     | Out-File -FilePath $auditOutputPath     -Encoding utf8
