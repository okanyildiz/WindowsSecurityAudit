function Invoke-SecurityRemediation {
    <#
    .SYNOPSIS
        Applies automated remediations for findings produced by Invoke-SecurityAssessment
    .DESCRIPTION
        Closes the loop from finding to fix: consumes a saved assessment JSON file (or a piped
        assessment/findings object), filters findings by severity, matches each finding against a
        curated map of safe, automatable remediations, and applies the fix with SupportsShouldProcess
        (-WhatIf/-Confirm). Findings with no matching remediation are reported as ManualReview and
        are never improvised. Optionally writes a rollback script capturing pre-change state.
    .PARAMETER AssessmentPath
        Path to a JSON file previously saved by Invoke-SecurityAssessment
    .PARAMETER InputObject
        Assessment object (or findings array / single finding) accepted from the pipeline
    .PARAMETER MaxSeverity
        Only remediate findings at or above this severity: Critical, High, Medium, or Low (default: High)
    .PARAMETER GenerateRollback
        Write a rollback .ps1 script that captures current values BEFORE they are changed
    .PARAMETER RollbackDirectory
        Directory where the rollback script is written (default: current location)
    .EXAMPLE
        Invoke-SecurityRemediation -AssessmentPath "C:\Assessments\AssessmentResults.json" -WhatIf
        Preview every remediation that would be applied without changing any state
    .EXAMPLE
        Invoke-SecurityRemediation -AssessmentPath "C:\Assessments\AssessmentResults.json" -MaxSeverity Critical -GenerateRollback
        Remediate only Critical findings and write a rollback script with pre-change values
    .EXAMPLE
        Invoke-SecurityAssessment -OutputPath "C:\Assessments" | Invoke-SecurityRemediation -GenerateRollback -Confirm
        Pipe an assessment object directly into remediation with confirmation prompts
    .OUTPUTS
        PSCustomObject with FindingsProcessed, Remediated, ManualReview, Failed, and RollbackPath
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File', Position = 0)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$AssessmentPath,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$MaxSeverity = 'High',

        [Parameter()]
        [switch]$GenerateRollback,

        [Parameter()]
        [string]$RollbackDirectory = (Get-Location).Path
    )

    begin {
        Write-Host "=== AUTOMATED SECURITY REMEDIATION ===" -ForegroundColor Cyan
        Write-Host "Max Severity: $MaxSeverity" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

        if ($WhatIfPreference) {
            Write-Host "MODE: WhatIf (no changes will be made)" -ForegroundColor Magenta
        }

        # Check for admin privileges
        $isAdmin = $false
        try {
            $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            Write-Warning "Could not determine elevation status on this platform; remediation cmdlets may fail without Administrator privileges."
            $isAdmin = $true
        }
        if (-not $isAdmin) {
            Write-Error "Invoke-SecurityRemediation requires Administrator privileges. Re-run from an elevated PowerShell session."
            throw "This function requires Administrator privileges!"
        }

        $severityRank = @{
            Critical = 4
            High     = 3
            Medium   = 2
            Low      = 1
        }
        $threshold = $severityRank[$MaxSeverity]

        $collectedFindings = @()

        $results = [PSCustomObject]@{
            RemediationDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            MaxSeverity           = $MaxSeverity
            WhatIf                = [bool]$WhatIfPreference
            FindingsProcessed     = 0
            SkippedBelowThreshold = 0
            Remediated            = @()
            ManualReview          = @()
            Failed                = @()
            RollbackPath          = $null
        }

        $rollbackScriptLines = @()

        # Remediation map: curated, safe, automatable fixes. Anything unmatched -> ManualReview.
        $uacRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

        $remediationMap = @(
            [PSCustomObject]@{
                Name           = 'Enable Windows Firewall profiles'
                FindingPattern = 'firewall'
                RequiresAdmin  = $true
                Action         = {
                    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction Stop
                }
                Verify         = {
                    $disabled = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
                    return (@($disabled).Count -eq 0)
                }
                Rollback       = {
                    $lines = @()
                    $fwProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled)
                    foreach ($fwProfile in $fwProfiles) {
                        $lines += "Set-NetFirewallProfile -Profile '$($fwProfile.Name)' -Enabled `$$($fwProfile.Enabled)"
                    }
                    return $lines
                }
            }
            [PSCustomObject]@{
                Name           = 'Enable User Account Control (UAC)'
                FindingPattern = 'user account control|\buac\b'
                RequiresAdmin  = $true
                Action         = {
                    Set-ItemProperty -Path $uacRegistryPath -Name "EnableLUA" -Value 1 -Type DWord -Force -ErrorAction Stop
                }
                Verify         = {
                    $current = Get-ItemProperty -Path $uacRegistryPath -Name "EnableLUA" -ErrorAction Stop
                    return ($current.EnableLUA -eq 1)
                }
                Rollback       = {
                    $previous = 0
                    try {
                        $current = Get-ItemProperty -Path $uacRegistryPath -Name "EnableLUA" -ErrorAction Stop
                        if ($null -ne $current.EnableLUA) { $previous = $current.EnableLUA }
                    }
                    catch {
                        $previous = 'NOT_PRESENT'
                    }
                    if ($previous -eq 'NOT_PRESENT') {
                        return @("Remove-ItemProperty -Path '$uacRegistryPath' -Name 'EnableLUA' -ErrorAction SilentlyContinue")
                    }
                    return @("Set-ItemProperty -Path '$uacRegistryPath' -Name 'EnableLUA' -Value $previous -Type DWord -Force")
                }
            }
            [PSCustomObject]@{
                Name           = 'Enable Defender real-time protection'
                FindingPattern = 'real-?time protection|realtimemonitoring'
                RequiresAdmin  = $true
                Action         = {
                    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                }
                Verify         = {
                    $prefs = Get-MpPreference -ErrorAction Stop
                    return (-not $prefs.DisableRealtimeMonitoring)
                }
                Rollback       = {
                    $previous = $false
                    try {
                        $prefs = Get-MpPreference -ErrorAction Stop
                        if ($null -ne $prefs.DisableRealtimeMonitoring) { $previous = [bool]$prefs.DisableRealtimeMonitoring }
                    }
                    catch {
                        $previous = $false
                    }
                    return @("Set-MpPreference -DisableRealtimeMonitoring `$$previous")
                }
            }
            [PSCustomObject]@{
                Name           = 'Disable SMBv1 protocol'
                FindingPattern = 'smb\s?v1|smb version 1|smb 1\.0'
                RequiresAdmin  = $true
                Action         = {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                }
                Verify         = {
                    $config = Get-SmbServerConfiguration -ErrorAction Stop
                    return (-not $config.EnableSMB1Protocol)
                }
                Rollback       = {
                    $previous = $true
                    try {
                        $config = Get-SmbServerConfiguration -ErrorAction Stop
                        if ($null -ne $config.EnableSMB1Protocol) { $previous = [bool]$config.EnableSMB1Protocol }
                    }
                    catch {
                        $previous = $true
                    }
                    return @("Set-SmbServerConfiguration -EnableSMB1Protocol `$$previous -Force")
                }
            }
            [PSCustomObject]@{
                Name           = 'Disable Guest account'
                FindingPattern = 'guest account|guest user'
                RequiresAdmin  = $true
                Action         = {
                    Disable-LocalUser -Name "Guest" -ErrorAction Stop
                }
                Verify         = {
                    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
                    return (-not $guest.Enabled)
                }
                Rollback       = {
                    $wasEnabled = $false
                    try {
                        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
                        $wasEnabled = [bool]$guest.Enabled
                    }
                    catch {
                        $wasEnabled = $false
                    }
                    if ($wasEnabled) {
                        return @("Enable-LocalUser -Name 'Guest'")
                    }
                    return @("# Guest account was already disabled; no rollback action required")
                }
            }
            [PSCustomObject]@{
                Name           = 'Enable PowerShell script block logging'
                FindingPattern = 'script block logging|scriptblocklogging|powershell logging'
                RequiresAdmin  = $true
                Action         = {
                    if (-not (Test-Path $psLoggingPath)) {
                        New-Item -Path $psLoggingPath -Force -ErrorAction Stop | Out-Null
                    }
                    Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force -ErrorAction Stop
                }
                Verify         = {
                    $current = Get-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -ErrorAction Stop
                    return ($current.EnableScriptBlockLogging -eq 1)
                }
                Rollback       = {
                    $previous = 0
                    $existed = $false
                    try {
                        $current = Get-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -ErrorAction Stop
                        if ($null -ne $current.EnableScriptBlockLogging) {
                            $previous = $current.EnableScriptBlockLogging
                            $existed = $true
                        }
                    }
                    catch {
                        $existed = $false
                    }
                    if ($existed) {
                        return @("Set-ItemProperty -Path '$psLoggingPath' -Name 'EnableScriptBlockLogging' -Value $previous -Type DWord -Force")
                    }
                    return @("Remove-ItemProperty -Path '$psLoggingPath' -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue")
                }
            }
            [PSCustomObject]@{
                Name           = 'Enable RDP Network Level Authentication'
                FindingPattern = 'network level authentication|\bnla\b'
                RequiresAdmin  = $true
                Action         = {
                    Set-ItemProperty -Path $rdpTcpPath -Name "UserAuthentication" -Value 1 -Type DWord -Force -ErrorAction Stop
                }
                Verify         = {
                    $current = Get-ItemProperty -Path $rdpTcpPath -Name "UserAuthentication" -ErrorAction Stop
                    return ($current.UserAuthentication -eq 1)
                }
                Rollback       = {
                    $previous = 0
                    try {
                        $current = Get-ItemProperty -Path $rdpTcpPath -Name "UserAuthentication" -ErrorAction Stop
                        if ($null -ne $current.UserAuthentication) { $previous = $current.UserAuthentication }
                    }
                    catch {
                        $previous = 0
                    }
                    return @("Set-ItemProperty -Path '$rdpTcpPath' -Name 'UserAuthentication' -Value $previous -Type DWord -Force")
                }
            }
        )
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Object') {
            if ($null -ne $InputObject) {
                $collectedFindings += $InputObject
            }
        }
    }

    end {
        try {
            # --- Gather findings ---
            $rawInput = @()
            if ($PSCmdlet.ParameterSetName -eq 'File') {
                Write-Host "`n[LOAD] Reading assessment from: $AssessmentPath" -ForegroundColor Cyan
                try {
                    $rawInput = @(Get-Content -Path $AssessmentPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
                }
                catch {
                    Write-Error "Failed to read or parse assessment file '$AssessmentPath': $_"
                    throw
                }
            }
            else {
                $rawInput = $collectedFindings
            }

            # Unwrap: an assessment object carries a Findings array; a bare finding carries Finding text
            $allFindings = @()
            foreach ($item in $rawInput) {
                if ($null -eq $item) { continue }
                if ($null -ne $item.PSObject.Properties['Findings'] -and $null -ne $item.Findings) {
                    $allFindings += @($item.Findings)
                }
                elseif ($null -ne $item.PSObject.Properties['Finding']) {
                    $allFindings += $item
                }
            }

            $results.FindingsProcessed = @($allFindings).Count
            Write-Host "[LOAD] Findings loaded: $($results.FindingsProcessed)" -ForegroundColor Yellow

            # --- Per-finding remediation ---
            $findingIndex = 0
            foreach ($finding in $allFindings) {
                $findingIndex++

                $findingText = ''
                if ($null -ne $finding.PSObject.Properties['Finding'] -and $null -ne $finding.Finding) {
                    $findingText = [string]$finding.Finding
                }

                $severityText = ''
                if ($null -ne $finding.PSObject.Properties['Severity'] -and $null -ne $finding.Severity) {
                    $severityText = [string]$finding.Severity
                }

                # Severity gate: findings with unrecognized severity are never auto-remediated
                if ([string]::IsNullOrWhiteSpace($severityText) -or -not $severityRank.ContainsKey($severityText)) {
                    Write-Host "`n[$findingIndex] Unrecognized severity - routed to manual review: $findingText" -ForegroundColor Yellow
                    $results.ManualReview += [PSCustomObject]@{
                        Finding = $findingText
                        Severity = $severityText
                        Reason  = 'Severity missing or unrecognized; not eligible for automated remediation'
                    }
                    continue
                }

                if ($severityRank[$severityText] -lt $threshold) {
                    $results.SkippedBelowThreshold++
                    Write-Verbose "[$findingIndex] Skipped (severity $severityText below threshold $MaxSeverity): $findingText"
                    continue
                }

                # Match against the curated remediation map - first match wins
                $matched = $null
                if (-not [string]::IsNullOrWhiteSpace($findingText)) {
                    foreach ($entry in $remediationMap) {
                        if ($findingText -match $entry.FindingPattern) {
                            $matched = $entry
                            break
                        }
                    }
                }

                if ($null -eq $matched) {
                    Write-Host "`n[$findingIndex] No automated remediation available: $findingText" -ForegroundColor Yellow
                    $results.ManualReview += [PSCustomObject]@{
                        Finding = $findingText
                        Severity = $severityText
                        Reason  = 'No matching remediation in the curated map; manual review required'
                    }
                    continue
                }

                Write-Host "`n[$findingIndex] [$severityText] $findingText" -ForegroundColor Cyan
                Write-Host "    Remediation: $($matched.Name) (RequiresAdmin: $($matched.RequiresAdmin))" -ForegroundColor White

                if (-not $PSCmdlet.ShouldProcess($findingText, "Apply remediation '$($matched.Name)'")) {
                    Write-Host "    WhatIf: would apply '$($matched.Name)'" -ForegroundColor Magenta
                    continue
                }

                # Capture pre-change state BEFORE applying the fix (for the rollback script)
                $capturedRollback = @()
                if ($GenerateRollback) {
                    try {
                        $capturedRollback = @(& $matched.Rollback)
                    }
                    catch {
                        Write-Warning "    Could not capture pre-change state for rollback: $_"
                        $capturedRollback = @("# WARNING: pre-change state could not be captured: $($_.Exception.Message)")
                    }
                }

                try {
                    & $matched.Action

                    # Verify-after-fix where cheap (re-read the setting)
                    $verified = $false
                    try {
                        $verified = [bool](& $matched.Verify)
                    }
                    catch {
                        Write-Verbose "    Verification check failed: $_"
                        $verified = $false
                    }

                    $results.Remediated += [PSCustomObject]@{
                        Finding     = $findingText
                        Severity    = $severityText
                        Remediation = $matched.Name
                        Verified    = $verified
                    }

                    if ($verified) {
                        Write-Host "    + Remediated and verified" -ForegroundColor Green
                    }
                    else {
                        Write-Host "    + Remediated (verification inconclusive)" -ForegroundColor Yellow
                    }

                    if ($GenerateRollback -and @($capturedRollback).Count -gt 0) {
                        $rollbackScriptLines += "# Rollback for: $findingText"
                        $rollbackScriptLines += "# Remediation applied: $($matched.Name) on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        $rollbackScriptLines += $capturedRollback
                        $rollbackScriptLines += ""
                    }
                }
                catch {
                    $results.Failed += [PSCustomObject]@{
                        Finding     = $findingText
                        Severity    = $severityText
                        Remediation = $matched.Name
                        Error       = $_.Exception.Message
                    }
                    Write-Warning "    Remediation failed: $($_.Exception.Message)"
                }
            }

            # --- Write rollback script (captured pre-change values only) ---
            if ($GenerateRollback -and @($rollbackScriptLines).Count -gt 0) {
                try {
                    if (-not (Test-Path -Path $RollbackDirectory)) {
                        New-Item -Path $RollbackDirectory -ItemType Directory -Force | Out-Null
                    }
                    $rollbackFile = Join-Path -Path $RollbackDirectory -ChildPath "SecurityRemediation_Rollback_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"

                    $header = @(
                        "#Requires -RunAsAdministrator"
                        "# Rollback script generated by Invoke-SecurityRemediation"
                        "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        "# Restores the pre-remediation state captured BEFORE changes were applied"
                        ""
                    )

                    if ($PSCmdlet.ShouldProcess($rollbackFile, "Write rollback script")) {
                        Set-Content -Path $rollbackFile -Value (($header + $rollbackScriptLines) -join [Environment]::NewLine) -Encoding UTF8 -ErrorAction Stop
                        $results.RollbackPath = $rollbackFile
                        Write-Host "`n[ROLLBACK] Rollback script written: $rollbackFile" -ForegroundColor Green
                    }
                    else {
                        Write-Host "`n[ROLLBACK] WhatIf: would write rollback script to $rollbackFile" -ForegroundColor Magenta
                    }
                }
                catch {
                    Write-Warning "Failed to write rollback script: $_"
                }
            }
            elseif ($GenerateRollback) {
                Write-Host "`n[ROLLBACK] No changes were applied; rollback script not needed" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "Error during security remediation: $_"
            throw
        }

        Write-Host "`n=== REMEDIATION COMPLETE ===" -ForegroundColor Green

        Write-Host "`nFindings Processed: $($results.FindingsProcessed)" -ForegroundColor Cyan
        Write-Host "  Remediated: $(@($results.Remediated).Count)" -ForegroundColor Green
        Write-Host "  Manual Review: $(@($results.ManualReview).Count)" -ForegroundColor Yellow
        Write-Host "  Failed: $(@($results.Failed).Count)" -ForegroundColor Red
        Write-Host "  Skipped (below $MaxSeverity): $($results.SkippedBelowThreshold)" -ForegroundColor White

        if (@($results.ManualReview).Count -gt 0) {
            Write-Host "`nFindings requiring manual review:" -ForegroundColor Yellow
            $results.ManualReview | ForEach-Object {
                Write-Host "  - [$($_.Severity)] $($_.Finding)" -ForegroundColor White
            }
        }

        if (@($results.Failed).Count -gt 0) {
            Write-Host "`nFailed remediations:" -ForegroundColor Red
            $results.Failed | ForEach-Object {
                Write-Host "  - $($_.Finding): $($_.Error)" -ForegroundColor Red
            }
        }

        if ($null -ne $results.RollbackPath) {
            Write-Host "`nRollback script: $($results.RollbackPath)" -ForegroundColor Cyan
            Write-Host "  Run it from an elevated session to restore pre-remediation state" -ForegroundColor White
        }

        Write-Host "`nRecommendations:" -ForegroundColor Cyan
        Write-Host "  1. Review the ManualReview findings - no automated fix was attempted for them" -ForegroundColor White
        Write-Host "  2. Test system and application functionality after remediation" -ForegroundColor White
        Write-Host "  3. Keep the rollback script until changes are validated" -ForegroundColor White
        Write-Host "  4. Re-run Invoke-SecurityAssessment to confirm findings are resolved" -ForegroundColor White
        Write-Host "  5. Some changes (e.g. SMBv1) may require a reboot to take full effect" -ForegroundColor White

        return $results
    }
}
