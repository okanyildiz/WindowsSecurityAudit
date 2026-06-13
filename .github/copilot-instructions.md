# Windows Security Audit Module – Copilot Instructions

## Overview

This is a pure PowerShell security auditing module (`WindowsSecurityAudit`) for Windows. It has **zero external dependencies** — everything is built on native Windows/PowerShell APIs. It requires PowerShell 5.1+ and Windows 10 1809+ / Server 2016+. Most functions require Local Administrator privileges; Active Directory functions need Domain Admin; Cloud Security functions need Global Admin.

## Loading and Testing

```powershell
# Load the module
Import-Module .\WindowsSecurityAudit.psd1 -Force

# Run the built-in test script (loads module + runs Get-SecurityBaseline)
.\Test-Module.ps1

# Run a single function
Get-SecurityBaseline
Find-SuspiciousProcesses -CheckSignatures -CheckNetwork
```

> No formal test suite exists yet — the `Tests/` folder is scaffolded but empty. `Test-Module.ps1` is the current integration smoke test.

## Architecture

The module loader (`WindowsSecurityAudit.psm1`) dot-sources every `.ps1` file from all 14 subdirectories and exports all of them as public functions. Adding a new **public** function means creating a `.ps1` file in the appropriate subdirectory — no registration elsewhere is needed (the manifest uses `FunctionsToExport = '*'`). **Private/non-exported helpers** belong in `Private/` — they are dot-sourced but intentionally excluded from `Export-ModuleMember`.

**Module map:**

| Directory | Purpose |
|---|---|
| `Core/` | System info, security baseline, integrity checks |
| `Detection/` | Real-time threat detection (processes, auth, network, persistence) |
| `Analysis/` | Deep-dive analysis of event logs, registry, filesystem, memory |
| `ThreatHunting/` | APT indicators, lateral movement, MITRE ATT&CK mapping |
| `Forensics/` | Evidence collection, memory dumps, forensic timelines |
| `Response/` | Incident response, forensic collection, report export |
| `Hardening/` | Applying security baselines, audit policies, PS security |
| `Compliance/` | CIS Benchmark, NIST, PCI-DSS testing; compliance evidence export |
| `Vulnerability/` | Patch compliance, misconfigurations, exposed services, EOL software |
| `ActiveDirectory/` | AD backdoors, vulnerabilities, stale objects, privileged accounts |
| `CloudSecurity/` | Azure AD risky sign-ins, M365 security posture |
| `WindowsDefender/` | Defender status, scanning, configuration |
| `Enterprise/` | Multi-system audits, enterprise-wide security assessments |
| `Reporting/` | Security metrics, executive reports, dashboards |

## Function Conventions

**Naming follows PowerShell approved verbs with consistent domain patterns:**
- `Get-*` — read-only retrieval (status, info, metrics)
- `Find-*` — search/detection functions that return threat findings
- `Test-*` — compliance/validation checks that return pass/fail results
- `Set-*` / `Enable-*` — configuration changes (hardening)
- `Invoke-*` — active operations (scans, incident response)
- `New-*` / `Export-*` — report and artifact generation

**Every function follows this structure:**

```powershell
function Verb-Noun {
    <#
    .SYNOPSIS     One-line description
    .DESCRIPTION  Full description
    .PARAMETER    Each parameter documented
    .EXAMPLE      At minimum one usage example
    .OUTPUTS      PSCustomObject with ...
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [string]$ExportPath        # Optional JSON export path — present on most functions
    )

    begin   { ... }   # Initialize result object, validate params
    process { ... }   # Main logic, wrapped in try/catch
    end     { ... }   # Export JSON if $ExportPath, return result
}
```

**Result objects** are always `[PSCustomObject]` with consistent fields. Functions that scan multiple items return arrays of `PSCustomObject`.

**Output / error handling:**
- `Write-Host` — progress banners and summary output visible to the user (used in Detection/Analysis functions; cannot be suppressed)
- `Write-Verbose` — internal diagnostic messages (used in Core functions like `Get-SecurityBaseline`)
- `Write-Warning` — non-fatal failures (e.g., a single sub-check fails)
- `Write-Error` / `throw` — fatal errors that abort the function
- Individual sub-checks are wrapped in their own `try/catch` so one failure doesn't abort the entire scan

**JSON export pattern** — when `-ExportPath` is provided, functions create the directory if missing. Filenames use the noun part of the function name, not the full name. Functions with a `ComputerName` parameter include it in the filename; others omit it:
```
SecurityBaseline_<ComputerName>_<yyyyMMdd_HHmmss>.json   # Get-SecurityBaseline
EventLogAnalysis_<yyyyMMdd_HHmmss>.json                  # Get-EventLogAnalysis (no ComputerName)
```

**Scoring** — assessment functions (`Get-SecurityBaseline`, `Test-*`) accumulate a `SecurityScore` capped at 100 via `[Math]::Min(...)`. Detection functions (`Find-*`) use `SuspicionScore` with no cap — scores can exceed 100 when multiple indicators fire. Both include a `Reasons` string listing why points were added.
