# AD Computers Dashboard — Data Collection Script

PowerShell script that collects Active Directory computer inventory and
computer-related audit events, computes dashboard-ready metrics and risk
flags, and outputs JSON payloads for ingestion into an API/backend.

## What it collects

### 1. Computer inventory
For every computer object in AD:
- Name, DNS hostname, OU / Distinguished Name
- Operating system, version, service pack, architecture
- Enabled/disabled status
- Last logon timestamp, account creation date, password last set date
- IPv4 address, description

### 2. Derived risk flags
Computed per computer, no extra data sources required:
- **IsEOL** — enabled machine running an end-of-life OS (Windows 7/XP/Vista,
  Server 2003/2008/2012)
- **IsStale30 / IsStale60 / IsStale90 / NeverLoggedOn** — based on last logon
  timestamp
- **LikelyBrokenTrust** — enabled, password age > 90 days, and no logon in
  90+ days (possible secure channel issue)
- **IsConflictObject** — AD replication conflict object (`CNF:` in DN)
- **NamingStatus** — whether the computer name matches the expected naming
  convention (see Configuration)

### 3. Dashboard summary metrics
- Total / enabled / disabled counts
- Server vs workstation split
- OS breakdown, OU breakdown
- Stale machine counts (30/60/90+ days, never logged on)
- EOL OS breakdown
- Password age anomalies (configurable threshold)
- New computers (last 7 / 30 days)
- Broken trust candidates
- Conflict objects
- Naming convention violations

### 4. Audit events — who / what / when
Pulled from the Security log on all Domain Controllers:

| Event ID | Action |
|---|---|
| 4741 | Computer account created |
| 4742 | Computer account modified |
| 4743 | Computer account deleted |
| 4722 | Account enabled |
| 4725 | Account disabled |
| 4724 | Password reset |
| 4781 | Computer renamed |
| 5136 | Directory object attribute changed |
| 5137 | Directory object created |
| 5141 | Directory object deleted |

Each event includes timestamp, performing user (domain\username), target
computer object, and action description. Events are split into
**human-driven** vs **system/replication** activity.

## Requirements

- **ActiveDirectory PowerShell module** (RSAT)
  ```powershell
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  ```
- **Read access to AD** — any domain user can run the inventory portion
- **Read access to Security event log on Domain Controllers** for audit
  events — account must be in the **Event Log Readers** group on each DC
  (or be a Domain Admin)
- **Advanced Audit Policy enabled on Domain Controllers**:
  - "Computer Account Management" → Success
  - "Directory Service Changes" → Success

  Check current state:
  ```powershell
  auditpol /get /subcategory:"Computer Account Management"
  auditpol /get /subcategory:"Directory Service Changes"
  ```

  If not enabled, configure via Group Policy:
  `Computer Configuration > Policies > Windows Settings > Security Settings >
  Advanced Audit Policy Configuration > DS Access / Account Management`

  > Note: only events occurring *after* the audit policy is enabled will be
  > captured — there's no retroactive history.

## Configuration

All tunables are at the top of the script:

| Setting | Description | Default |
|---|---|---|
| `$pwdAnomalyThreshold` | Days before password age is flagged | `60` |
| `$eolOSPatterns` | Regex patterns for end-of-life OS detection | Windows 7/XP/Vista, Server 2003/2008/2012 |
| `$namingConventionRegex` | Expected computer name pattern | `^[A-Za-z]+-[A-Za-z]+-[A-Z]-\d+$` |
| `$namingMaxLength` | Length above which truncation may have occurred | `15` |
| `$auditLookbackHours` | How far back to query audit events | `24` |
| `$auditEventIDs` | Which event IDs to collect | See table above |

### Naming convention
Expected format: `DEPT-FirstName-LastInitial-HRID`
(e.g., `IT-Henok-M-1203`). If the full name would exceed 15 characters,
Windows truncates the computer name, so the first name portion may be
shortened (e.g., `IT-Sale-M-1204` for `Saleamlak`).

The script checks whether the name matches the overall shape via regex.
Names that don't match are flagged as `Violation`. This is a best-effort
check — adjust the regex/exclusions for your environment, especially for
infrastructure, test, and non-Windows machines that don't follow this
convention (e.g., domain controllers, Linux hosts, test OUs).

## Output

The script produces:

1. **Terminal output** — formatted summary tables for all metrics, suitable
   for interactive review/testing
2. **`$inventoryJson`** — full inventory + summary metrics + risk flags
3. **`$auditJson`** — audit events + summary

Both are built as compressed JSON via `ConvertTo-Json -Depth 6`. The
`Invoke-RestMethod` calls to send these to an API are included but commented
out — uncomment and set `$inventoryApiEndpoint` / `$auditApiEndpoint` once
your backend is ready.

## Running

```powershell
.\Get-ADComputersFull.ps1
```

For initial testing, consider:
- Shortening `$auditLookbackHours` or narrowing `$auditEventIDs` (especially
  dropping `5136`, which can be high-volume) if running against a busy DC
- Reviewing the `NamingConvention.Violations` output and refining the regex /
  adding OU-based exclusions before relying on it

## Scheduling

Intended to run on a schedule (e.g., daily via Task Scheduler) from a
domain-joined host with the required permissions. Each run sends a fresh
snapshot — historical trending depends on the backend storing each
submission rather than overwriting.

## Roadmap / ideas not yet implemented

- LAPS status (local admin password rotation)
- Privileged group membership flags
- Site/subnet-based location mapping
- Time-series trend views (requires backend history storage)
