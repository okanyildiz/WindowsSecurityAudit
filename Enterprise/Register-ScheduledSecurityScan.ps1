function Register-ScheduledSecurityScan {
    <#
    .SYNOPSIS
        Registers an automated recurring security scan with optional alerting
    .DESCRIPTION
        Creates a PowerShell scan script under the output path that imports the
        WindowsSecurityAudit module, runs Invoke-SecurityAssessment, and sends an
        alert (Teams/Slack-style incoming webhook and/or email) when Critical
        findings are detected. The script is then registered as a Scheduled Task
        running as SYSTEM at the chosen cadence (Daily, Weekly on Monday, or
        Monthly on the 1st). Use -Unregister to remove the scheduled task.
        The generated script embeds the webhook URL (a shared secret), so on
        Windows its file permissions are restricted to Administrators and SYSTEM.

        Alert deduplication is enabled by default: the generated script persists a
        stable SHA256 fingerprint (first 16 hex chars over Category + Finding text)
        of each finding to State\last-findings.json under the output path. On
        subsequent runs findings are classified as New, Persisting, or Resolved.
        An alarm is sent only for new Critical/High findings or persisting
        Critical/High findings older than -RealertAfterDays; a quiet resolved note
        (no alarm tone) is sent when findings disappear. The first run, a broken or
        missing state file, and -DisableAlertDedup all fall back to alerting on any
        Critical finding. State write failures never suppress alerts.
    .PARAMETER ScanType
        Type of scan to schedule: Quick, Standard, or Full (default: Standard).
        Mapped to Invoke-SecurityAssessment as Quick=Basic, Standard=Standard, Full=Advanced.
    .PARAMETER Frequency
        How often the scan runs: Daily, Weekly (Monday), or Monthly (1st of month) (default: Weekly)
    .PARAMETER Time
        Time of day to run the scan, as a datetime or string such as '09:00' (default: 09:00)
    .PARAMETER OutputPath
        Path where the scan script and per-run reports are stored
        (default: "$env:ProgramData\WindowsSecurityAudit\Scans")
    .PARAMETER WebhookUrl
        Optional incoming webhook URL (Microsoft Teams or Slack style) that receives
        an adaptive-card JSON POST when Critical findings exist
    .PARAMETER EmailTo
        Optional recipient address for email alerts (requires EmailFrom and SmtpServer)
    .PARAMETER EmailFrom
        Optional sender address for email alerts (requires EmailTo and SmtpServer)
    .PARAMETER SmtpServer
        Optional SMTP server for email alerts (requires EmailTo and EmailFrom)
    .PARAMETER DisableAlertDedup
        Turns off alert deduplication in the generated scan script. With dedup
        disabled the script alerts on every run whenever a Critical finding
        exists (the pre-dedup behavior)
    .PARAMETER RealertAfterDays
        Number of days after which a persisting Critical/High finding (first seen
        this many days ago or more) triggers a repeat alert (default: 7, range
        1-3650). Only used when alert deduplication is enabled
    .PARAMETER Unregister
        Removes the scheduled security scan task and exits without registering anything
    .PARAMETER WhatIf
        Shows what would happen if the command runs (SupportsShouldProcess)
    .PARAMETER Confirm
        Prompts for confirmation before registering or unregistering the task
    .EXAMPLE
        Register-ScheduledSecurityScan -ScanType Standard -Frequency Weekly -Time '09:00'
        Registers a weekly (Monday 09:00) Standard scan running as SYSTEM
    .EXAMPLE
        Register-ScheduledSecurityScan -ScanType Full -Frequency Daily -Time '22:30' -WebhookUrl 'https://outlook.office.com/webhook/...'
        Registers a nightly Full scan that posts an adaptive card to a Teams webhook on Critical findings
    .EXAMPLE
        Register-ScheduledSecurityScan -ScanType Quick -Frequency Monthly -EmailTo secops@contoso.com -EmailFrom audit@contoso.com -SmtpServer smtp.contoso.com
        Registers a monthly Quick scan that emails an alert when Critical findings exist
    .EXAMPLE
        Register-ScheduledSecurityScan -Frequency Daily -WebhookUrl 'https://outlook.office.com/webhook/...' -RealertAfterDays 14
        Registers a daily scan with alert deduplication (on by default) that re-alerts on Critical/High findings persisting for 14 days or more
    .EXAMPLE
        Register-ScheduledSecurityScan -Unregister -Confirm:$false
        Removes the scheduled security scan task
    .OUTPUTS
        PSCustomObject with the registration (or unregistration) result
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [ValidateSet('Quick', 'Standard', 'Full')]
        [string]$ScanType = 'Standard',

        [Parameter()]
        [ValidateSet('Daily', 'Weekly', 'Monthly')]
        [string]$Frequency = 'Weekly',

        [Parameter()]
        [datetime]$Time = '09:00',

        [Parameter()]
        [string]$OutputPath = "$env:ProgramData\WindowsSecurityAudit\Scans",

        [Parameter()]
        [string]$WebhookUrl,

        [Parameter()]
        [string]$EmailTo,

        [Parameter()]
        [string]$EmailFrom,

        [Parameter()]
        [string]$SmtpServer,

        [Parameter()]
        [switch]$DisableAlertDedup,

        [Parameter()]
        [ValidateRange(1, 3650)]
        [int]$RealertAfterDays = 7,

        [Parameter()]
        [switch]$Unregister
    )

    begin {
        Write-Host "=== SCHEDULED SECURITY SCAN REGISTRATION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

        $taskName = 'WindowsSecurityAudit-ScheduledScan'
        $machineName = [System.Environment]::MachineName
        $scanResult = $null

        # Resolve the module manifest so the generated script can import it standalone
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        $moduleManifest = Join-Path $moduleRoot 'WindowsSecurityAudit.psd1'
        if (-not (Test-Path $moduleManifest)) {
            Write-Warning "Module manifest not found at '$moduleManifest'. The generated script may fail to import the module."
        }

        # Map the public scan type to the Invoke-SecurityAssessment assessment type
        $assessmentType = switch ($ScanType) {
            'Quick'    { 'Basic' }
            'Standard' { 'Standard' }
            'Full'     { 'Advanced' }
        }

        # Email alerting requires the full triplet
        $emailPartsProvided = @($EmailTo, $EmailFrom, $SmtpServer | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
        $emailConfigured = ($emailPartsProvided -eq 3)
        if ($emailPartsProvided -gt 0 -and -not $emailConfigured) {
            Write-Warning "Email alerting requires EmailTo, EmailFrom, and SmtpServer together. Email alerts will be disabled."
        }

        $webhookConfigured = (-not [string]::IsNullOrWhiteSpace($WebhookUrl))

        # Alert dedup is opt-out; the generated script embeds both values
        $alertDedupEnabled = (-not $DisableAlertDedup)
        if ($DisableAlertDedup -and $PSBoundParameters.ContainsKey('RealertAfterDays')) {
            Write-Warning "RealertAfterDays is ignored because alert deduplication is disabled."
        }
    }

    process {
        # ----- Unregister path: remove the task and exit -----
        if ($Unregister) {
            Write-Host "`nRemoving scheduled security scan..." -ForegroundColor Cyan

            try {
                $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

                if ($null -eq $existingTask) {
                    Write-Warning "Scheduled task '$taskName' was not found - nothing to remove."
                    $scanResult = [PSCustomObject]@{
                        ActionDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        TaskName = $taskName
                        Action = 'Unregister'
                        Status = 'NotFound'
                        ComputerName = $machineName
                    }
                    return
                }

                if ($PSCmdlet.ShouldProcess($machineName, "Unregister scheduled task '$taskName'")) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                    Write-Host "Scheduled task '$taskName' removed." -ForegroundColor Green
                    $scanResult = [PSCustomObject]@{
                        ActionDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        TaskName = $taskName
                        Action = 'Unregister'
                        Status = 'Unregistered'
                        ComputerName = $machineName
                    }
                }
                else {
                    $scanResult = [PSCustomObject]@{
                        ActionDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        TaskName = $taskName
                        Action = 'Unregister'
                        Status = 'WhatIf'
                        ComputerName = $machineName
                    }
                }
            }
            catch {
                Write-Error "Failed to unregister scheduled task '$taskName': $_"
                throw
            }

            return
        }

        # ----- Registration path -----
        Write-Host "`nScan Type: $ScanType ($assessmentType assessment)" -ForegroundColor Yellow
        Write-Host "Frequency: $Frequency at $($Time.ToString('HH:mm'))" -ForegroundColor Yellow
        Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
        Write-Host "Webhook Alerts: $webhookConfigured" -ForegroundColor Yellow
        Write-Host "Email Alerts: $emailConfigured" -ForegroundColor Yellow
        Write-Host "Alert Dedup: $(if ($alertDedupEnabled) { "True (re-alert after $RealertAfterDays days)" } else { 'False' })" -ForegroundColor Yellow

        $scriptPath = Join-Path $OutputPath 'Invoke-ScheduledSecurityScan.ps1'

        # Escape single quotes in values embedded into the generated script
        $safeModuleManifest = if ($null -ne $moduleManifest) { $moduleManifest -replace "'", "''" } else { '' }
        $safeOutputPath = if ($null -ne $OutputPath) { $OutputPath -replace "'", "''" } else { '' }
        $safeWebhookUrl = if ($webhookConfigured) { $WebhookUrl -replace "'", "''" } else { '' }
        $safeEmailTo = if ($emailConfigured) { $EmailTo -replace "'", "''" } else { '' }
        $safeEmailFrom = if ($emailConfigured) { $EmailFrom -replace "'", "''" } else { '' }
        $safeSmtpServer = if ($emailConfigured) { $SmtpServer -replace "'", "''" } else { '' }
        $safeAlertDedup = if ($alertDedupEnabled) { '$true' } else { '$false' }
        $safeRealertAfterDays = "$RealertAfterDays"

        $scanScriptTemplate = @'
# ============================================================================
# WindowsSecurityAudit - Scheduled Security Scan
# Generated by Register-ScheduledSecurityScan on __GENERATED_ON__
# Re-run Register-ScheduledSecurityScan to modify this script.
# Run Register-ScheduledSecurityScan -Unregister to remove the scheduled task.
# ============================================================================

$ErrorActionPreference = 'Continue'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Verbose "Could not enforce TLS 1.2: $_"
}

$modulePath       = '__MODULE_PATH__'
$scanOutputRoot   = '__OUTPUT_PATH__'
$assessmentType   = '__ASSESSMENT_TYPE__'
$webhookUrl       = '__WEBHOOK_URL__'
$emailTo          = '__EMAIL_TO__'
$emailFrom        = '__EMAIL_FROM__'
$smtpServer       = '__SMTP_SERVER__'
$alertDedup       = __ALERT_DEDUP__
$realertAfterDays = __REALERT_AFTER_DAYS__

$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runPath = Join-Path $scanOutputRoot "Scan_$runStamp"

# Stable fingerprint of a finding: first 16 hex chars of SHA256 over Category + Finding text
function Get-FindingFingerprint {
    param(
        [string]$Category,
        [string]$Finding
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Category`n$Finding"))
        return (([System.BitConverter]::ToString($hashBytes)) -replace '-', '').Substring(0, 16).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

try {
    if (-not (Test-Path $runPath)) {
        New-Item -Path $runPath -ItemType Directory -Force | Out-Null
    }

    Import-Module $modulePath -Force -ErrorAction Stop

    $assessment = Invoke-SecurityAssessment -AssessmentType $assessmentType -OutputPath $runPath

    $findings = @()
    if ($null -ne $assessment -and $null -ne $assessment.PSObject.Properties['Findings'] -and $null -ne $assessment.Findings) {
        $findings = @($assessment.Findings)
    }

    $criticalFindings = @($findings | Where-Object { $_.Severity -eq 'Critical' })
    $highFindings = @($findings | Where-Object { $_.Severity -eq 'High' })

    $overallScore = 'N/A'
    if ($null -ne $assessment -and $null -ne $assessment.PSObject.Properties['OverallScore'] -and $null -ne $assessment.OverallScore) {
        $overallScore = "$($assessment.OverallScore)"
    }

    $runNow = Get-Date
    $runStampText = $runNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Fingerprint the current findings (first occurrence wins for duplicates)
    $currentFingerprints = @{}
    foreach ($finding in $findings) {
        $fCat = ''
        $fTxt = ''
        $fSev = ''
        if ($null -ne $finding.PSObject.Properties['Category']) { $fCat = "$($finding.Category)" }
        if ($null -ne $finding.PSObject.Properties['Finding']) { $fTxt = "$($finding.Finding)" }
        if ($null -ne $finding.PSObject.Properties['Severity']) { $fSev = "$($finding.Severity)" }
        $fingerprint = Get-FindingFingerprint -Category $fCat -Finding $fTxt
        if (-not $currentFingerprints.ContainsKey($fingerprint)) {
            $currentFingerprints[$fingerprint] = [PSCustomObject]@{
                Fingerprint = $fingerprint
                Category = $fCat
                Finding = $fTxt
                Severity = $fSev
            }
        }
    }

    # Load the previous dedup state; a missing or broken state degrades to normal alerting
    $stateDir = Join-Path $scanOutputRoot 'State'
    $stateFile = Join-Path $stateDir 'last-findings.json'
    $previousState = @{}
    $stateLoaded = $false

    if ($alertDedup -and (Test-Path $stateFile)) {
        try {
            $parsedState = Get-Content -Path $stateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $parsedState -or $null -eq $parsedState.PSObject.Properties['Findings'] -or $null -eq $parsedState.Findings) {
                Write-Warning "Alert dedup state file '$stateFile' has no findings data. Alerting without dedup for this run."
            }
            else {
                foreach ($stateEntry in @($parsedState.Findings)) {
                    if ($null -eq $stateEntry.PSObject.Properties['Fingerprint'] -or [string]::IsNullOrWhiteSpace("$($stateEntry.Fingerprint)")) { continue }
                    $sCat = ''
                    $sTxt = ''
                    $sSev = ''
                    $sFirstSeen = $null
                    if ($null -ne $stateEntry.PSObject.Properties['Category']) { $sCat = "$($stateEntry.Category)" }
                    if ($null -ne $stateEntry.PSObject.Properties['Finding']) { $sTxt = "$($stateEntry.Finding)" }
                    if ($null -ne $stateEntry.PSObject.Properties['Severity']) { $sSev = "$($stateEntry.Severity)" }
                    if ($null -ne $stateEntry.PSObject.Properties['FirstSeen'] -and -not [string]::IsNullOrWhiteSpace("$($stateEntry.FirstSeen)")) {
                        $parsedDate = [datetime]::MinValue
                        if ([datetime]::TryParseExact("$($stateEntry.FirstSeen)", 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
                            $sFirstSeen = $parsedDate
                        }
                    }
                    $previousState["$($stateEntry.Fingerprint)"] = [PSCustomObject]@{
                        Fingerprint = "$($stateEntry.Fingerprint)"
                        Category = $sCat
                        Finding = $sTxt
                        Severity = $sSev
                        FirstSeen = $sFirstSeen
                    }
                }
                $stateLoaded = $true
            }
        }
        catch {
            Write-Warning "Could not load alert dedup state file '$stateFile': $($_.Exception.Message). Alerting without dedup for this run."
        }
    }

    # Classify current findings against the previous state
    $newFindings = @()
    $persistingFindings = @()
    $resolvedFindings = @()

    if ($alertDedup) {
        foreach ($fingerprint in @($currentFingerprints.Keys)) {
            if ($stateLoaded -and $previousState.ContainsKey($fingerprint)) {
                $persistingFindings += [PSCustomObject]@{
                    Fingerprint = $fingerprint
                    Category = $currentFingerprints[$fingerprint].Category
                    Finding = $currentFingerprints[$fingerprint].Finding
                    Severity = $currentFingerprints[$fingerprint].Severity
                    FirstSeen = $previousState[$fingerprint].FirstSeen
                }
            }
            else {
                $newFindings += $currentFingerprints[$fingerprint]
            }
        }
        if ($stateLoaded) {
            foreach ($fingerprint in @($previousState.Keys)) {
                if (-not $currentFingerprints.ContainsKey($fingerprint)) {
                    $resolvedFindings += $previousState[$fingerprint]
                }
            }
        }
    }

    # Decide whether and how to alert
    $alertFindings = @()
    $alertReason = 'None'

    if ($alertDedup -and $stateLoaded) {
        $newAlerts = @($newFindings | Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' })
        $realerts = @($persistingFindings | Where-Object {
            if ($_.Severity -ne 'Critical' -and $_.Severity -ne 'High') { return $false }
            if ($null -eq $_.FirstSeen) { return $true }
            return (($runNow - $_.FirstSeen).TotalDays -ge $realertAfterDays)
        })
        $alertFindings = @($newAlerts) + @($realerts)
        if ($alertFindings.Count -gt 0) {
            $alertReason = 'Alarm'
        }
        elseif ($resolvedFindings.Count -gt 0) {
            $alertReason = 'Resolved'
        }
    }
    else {
        # First run, dedup disabled, or unreadable state: alert on any Critical finding
        $alertFindings = $criticalFindings
        if ($criticalFindings.Count -gt 0) {
            $alertReason = 'Alarm'
        }
    }

    $runSummary = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        RunDate = $runStampText
        AssessmentType = $assessmentType
        OverallScore = $overallScore
        TotalFindings = $findings.Count
        CriticalFindings = $criticalFindings.Count
        HighFindings = $highFindings.Count
        NewFindings = $newFindings.Count
        PersistingFindings = $persistingFindings.Count
        ResolvedFindings = $resolvedFindings.Count
        AlertDedup = $alertDedup
        RealertAfterDays = $realertAfterDays
        AlertReason = $alertReason
        ReportPath = $runPath
        AlertSent = $false
    }

    if ($alertReason -eq 'Alarm') {
        # ---------- Webhook alert (Teams/Slack-style incoming webhook) ----------
        if (-not [string]::IsNullOrWhiteSpace($webhookUrl)) {
            try {
                $factBlocks = @($alertFindings | ForEach-Object {
                    $cat = ''
                    $txt = ''
                    if ($null -ne $_.PSObject.Properties['Category']) { $cat = "$($_.Category)" }
                    if ($null -ne $_.PSObject.Properties['Finding']) { $txt = "$($_.Finding)" }
                    @{ title = $cat; value = $txt }
                })

                $alertFacts = @(
                    @{ title = 'Computer'; value = "$env:COMPUTERNAME" }
                    @{ title = 'Scan Time'; value = $runStampText }
                    @{ title = 'Overall Score'; value = $overallScore }
                    @{ title = 'Critical'; value = "$($criticalFindings.Count)" }
                    @{ title = 'High'; value = "$($highFindings.Count)" }
                    @{ title = 'Report'; value = "$runPath" }
                )
                if ($alertDedup) {
                    $alertFacts += @{ title = 'Since Last Run: New'; value = "$($newFindings.Count)" }
                    $alertFacts += @{ title = 'Since Last Run: Persisting'; value = "$($persistingFindings.Count)" }
                    $alertFacts += @{ title = 'Since Last Run: Resolved'; value = "$($resolvedFindings.Count)" }
                }

                $payload = @{
                    type = 'message'
                    attachments = @(
                        @{
                            contentType = 'application/vnd.microsoft.card.adaptive'
                            content = @{
                                '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                                type = 'AdaptiveCard'
                                version = '1.2'
                                body = @(
                                    @{ type = 'TextBlock'; size = 'Large'; weight = 'Bolder'; color = 'Attention'; text = "CRITICAL Security Findings - $env:COMPUTERNAME" }
                                    @{ type = 'TextBlock'; text = "Scheduled $assessmentType security scan completed with $($alertFindings.Count) critical/high finding(s) requiring attention."; wrap = $true }
                                    @{ type = 'FactSet'; facts = @($alertFacts) + $factBlocks }
                                    @{ type = 'TextBlock'; text = 'Review the full report and remediate the critical findings as soon as possible.'; wrap = $true }
                                )
                            }
                        }
                    )
                }

                $jsonBody = $payload | ConvertTo-Json -Depth 12
                Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonBody -ContentType 'application/json; charset=utf-8' -ErrorAction Stop
                $runSummary.AlertSent = $true
            }
            catch {
                Write-Warning "Failed to send webhook alert: $($_.Exception.Message)"
            }
        }

        # ---------- Email alert ----------
        if (-not [string]::IsNullOrWhiteSpace($emailTo) -and -not [string]::IsNullOrWhiteSpace($emailFrom) -and -not [string]::IsNullOrWhiteSpace($smtpServer)) {
            try {
                $mailRows = ($alertFindings | ForEach-Object {
                    $cat = ''
                    $txt = ''
                    if ($null -ne $_.PSObject.Properties['Category']) { $cat = "$($_.Category)" }
                    if ($null -ne $_.PSObject.Properties['Finding']) { $txt = "$($_.Finding)" }
                    "<tr><td style='padding:6px;border:1px solid #ccc;'>$cat</td><td style='padding:6px;border:1px solid #ccc;'>$txt</td></tr>"
                }) -join "`n"

                $dedupSummaryHtml = ''
                if ($alertDedup) {
                    $dedupSummaryHtml = "<p>Since last run: <b>$($newFindings.Count)</b> new, <b>$($persistingFindings.Count)</b> persisting, <b>$($resolvedFindings.Count)</b> resolved finding(s).</p>"
                }

                $mailBody = @"
<html><body style='font-family:Arial;'>
<h2 style='color:#c00;'>Critical Security Findings - $env:COMPUTERNAME</h2>
<p>Scheduled <b>$assessmentType</b> scan on <b>$runStampText</b> found <b>$($criticalFindings.Count)</b> critical and <b>$($highFindings.Count)</b> high finding(s). Overall score: <b>$overallScore</b>.</p>
$dedupSummaryHtml
<table style='border-collapse:collapse;'>
<tr><th style='padding:6px;border:1px solid #ccc;background:#333;color:#fff;'>Category</th><th style='padding:6px;border:1px solid #ccc;background:#333;color:#fff;'>Finding</th></tr>
$mailRows
</table>
<p>Full report: $runPath</p>
</body></html>
"@

                Send-MailMessage -To $emailTo -From $emailFrom -SmtpServer $smtpServer -Subject "[SECURITY ALERT] $($alertFindings.Count) critical/high finding(s) on $env:COMPUTERNAME" -Body $mailBody -BodyAsHtml -Encoding UTF8 -ErrorAction Stop
                $runSummary.AlertSent = $true
            }
            catch {
                Write-Warning "Failed to send email alert: $($_.Exception.Message)"
            }
        }
    }
    elseif ($alertReason -eq 'Resolved') {
        # ---------- Resolved note (informational, no alarm tone) ----------
        if (-not [string]::IsNullOrWhiteSpace($webhookUrl)) {
            try {
                $resolvedFacts = @(
                    @{ title = 'Computer'; value = "$env:COMPUTERNAME" }
                    @{ title = 'Scan Time'; value = $runStampText }
                    @{ title = 'Overall Score'; value = $overallScore }
                    @{ title = 'Since Last Run: New'; value = "$($newFindings.Count)" }
                    @{ title = 'Since Last Run: Persisting'; value = "$($persistingFindings.Count)" }
                    @{ title = 'Since Last Run: Resolved'; value = "$($resolvedFindings.Count)" }
                    @{ title = 'Report'; value = "$runPath" }
                )

                $payload = @{
                    type = 'message'
                    attachments = @(
                        @{
                            contentType = 'application/vnd.microsoft.card.adaptive'
                            content = @{
                                '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                                type = 'AdaptiveCard'
                                version = '1.2'
                                body = @(
                                    @{ type = 'TextBlock'; size = 'Large'; weight = 'Bolder'; color = 'Good'; text = "Security Findings Resolved - $env:COMPUTERNAME" }
                                    @{ type = 'TextBlock'; text = "Scheduled $assessmentType security scan: $($resolvedFindings.Count) finding(s) resolved since the last run. No new critical or high findings."; wrap = $true }
                                    @{ type = 'FactSet'; facts = $resolvedFacts }
                                )
                            }
                        }
                    )
                }

                $jsonBody = $payload | ConvertTo-Json -Depth 12
                Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonBody -ContentType 'application/json; charset=utf-8' -ErrorAction Stop
                $runSummary.AlertSent = $true
            }
            catch {
                Write-Warning "Failed to send webhook alert: $($_.Exception.Message)"
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($emailTo) -and -not [string]::IsNullOrWhiteSpace($emailFrom) -and -not [string]::IsNullOrWhiteSpace($smtpServer)) {
            try {
                $resolvedRows = ($resolvedFindings | ForEach-Object {
                    $cat = ''
                    $txt = ''
                    if ($null -ne $_.PSObject.Properties['Category']) { $cat = "$($_.Category)" }
                    if ($null -ne $_.PSObject.Properties['Finding']) { $txt = "$($_.Finding)" }
                    "<tr><td style='padding:6px;border:1px solid #ccc;'>$cat</td><td style='padding:6px;border:1px solid #ccc;'>$txt</td></tr>"
                }) -join "`n"

                $mailBody = @"
<html><body style='font-family:Arial;'>
<h2 style='color:#080;'>Security Findings Resolved - $env:COMPUTERNAME</h2>
<p>Scheduled <b>$assessmentType</b> scan on <b>$runStampText</b>: <b>$($resolvedFindings.Count)</b> finding(s) resolved since the last run. No new critical or high findings. Overall score: <b>$overallScore</b>.</p>
<p>Since last run: <b>$($newFindings.Count)</b> new, <b>$($persistingFindings.Count)</b> persisting, <b>$($resolvedFindings.Count)</b> resolved finding(s).</p>
<table style='border-collapse:collapse;'>
<tr><th style='padding:6px;border:1px solid #ccc;background:#333;color:#fff;'>Category</th><th style='padding:6px;border:1px solid #ccc;background:#333;color:#fff;'>Resolved Finding</th></tr>
$resolvedRows
</table>
<p>Full report: $runPath</p>
</body></html>
"@

                Send-MailMessage -To $emailTo -From $emailFrom -SmtpServer $smtpServer -Subject "[SECURITY UPDATE] $($resolvedFindings.Count) finding(s) resolved on $env:COMPUTERNAME" -Body $mailBody -BodyAsHtml -Encoding UTF8 -ErrorAction Stop
                $runSummary.AlertSent = $true
            }
            catch {
                Write-Warning "Failed to send email alert: $($_.Exception.Message)"
            }
        }
    }

    # Persist the dedup state after every run; write failures never suppress alerts
    if ($alertDedup) {
        try {
            if (-not (Test-Path $stateDir)) {
                New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            }
            $stateFindings = @()
            foreach ($fingerprint in @($currentFingerprints.Keys)) {
                $currentEntry = $currentFingerprints[$fingerprint]
                $firstSeenText = $runStampText
                if ($previousState.ContainsKey($fingerprint) -and $null -ne $previousState[$fingerprint].FirstSeen) {
                    $firstSeenText = $previousState[$fingerprint].FirstSeen.ToString('yyyy-MM-dd HH:mm:ss')
                }
                $stateFindings += [PSCustomObject]@{
                    Fingerprint = $fingerprint
                    Category = $currentEntry.Category
                    Finding = $currentEntry.Finding
                    Severity = $currentEntry.Severity
                    FirstSeen = $firstSeenText
                    LastSeen = $runStampText
                }
            }
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                RunTimestamp = $runStampText
                Findings = $stateFindings
            } | ConvertTo-Json -Depth 5 | Out-File -FilePath $stateFile -Encoding UTF8 -Force
        }
        catch {
            Write-Warning "Could not write alert dedup state file '$stateFile': $($_.Exception.Message). Alerting is not affected."
        }
    }

    $runSummary | ConvertTo-Json -Depth 5 | Out-File (Join-Path $runPath 'RunSummary.json') -Encoding UTF8
}
catch {
    try {
        if (-not (Test-Path $scanOutputRoot)) {
            New-Item -Path $scanOutputRoot -ItemType Directory -Force | Out-Null
        }
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            RunDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Status = 'Failed'
            Error = $_.Exception.Message
        } | ConvertTo-Json | Out-File (Join-Path $scanOutputRoot "ScanError_$runStamp.json") -Encoding UTF8
    }
    catch {
        # Best-effort error persistence only
    }
    exit 1
}

exit 0
'@

        if ($PSCmdlet.ShouldProcess($machineName, "Register scheduled security scan '$taskName' ($Frequency at $($Time.ToString('HH:mm')))")) {
            # Section 1: Create the scan script
            try {
                Write-Host "`nCreating scan script..." -ForegroundColor Cyan

                if (-not (Test-Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }

                $scanScript = $scanScriptTemplate.
                    Replace('__GENERATED_ON__', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')).
                    Replace('__MODULE_PATH__', $safeModuleManifest).
                    Replace('__OUTPUT_PATH__', $safeOutputPath).
                    Replace('__ASSESSMENT_TYPE__', $assessmentType).
                    Replace('__WEBHOOK_URL__', $safeWebhookUrl).
                    Replace('__EMAIL_TO__', $safeEmailTo).
                    Replace('__EMAIL_FROM__', $safeEmailFrom).
                    Replace('__SMTP_SERVER__', $safeSmtpServer).
                    Replace('__ALERT_DEDUP__', $safeAlertDedup).
                    Replace('__REALERT_AFTER_DAYS__', $safeRealertAfterDays)

                # The script embeds the webhook URL (a shared secret) and runs as SYSTEM,
                # so it must never exist world-readable: create the file EMPTY, restrict
                # it to Administrators and SYSTEM, and only then write the content into
                # the locked file (avoids the permissive ProgramData default between
                # creation and lockdown)
                if ($env:OS -eq 'Windows_NT') {
                    if (-not (Test-Path $scriptPath)) {
                        New-Item -Path $scriptPath -ItemType File -Force | Out-Null
                    }
                    try {
                        $scriptAcl = Get-Acl -Path $scriptPath -ErrorAction Stop
                        $scriptAcl.SetAccessRuleProtection($true, $false)
                        foreach ($existingRule in @($scriptAcl.Access)) {
                            $null = $scriptAcl.RemoveAccessRule($existingRule)
                        }
                        $aclIdentities = @(
                            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),
                            (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))
                        )
                        foreach ($identity in $aclIdentities) {
                            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                $identity,
                                [System.Security.AccessControl.FileSystemRights]::FullControl,
                                [System.Security.AccessControl.AccessControlType]::Allow)
                            $scriptAcl.AddAccessRule($accessRule)
                        }
                        Set-Acl -Path $scriptPath -AclObject $scriptAcl -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Could not restrict permissions on '$scriptPath'; the file contains the webhook URL and may be readable by other local users: $_"
                    }
                }

                $scanScript | Out-File $scriptPath -Encoding UTF8 -Force

                Write-Host "Scan script created: $scriptPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to create scan script at '$scriptPath': $_"
                throw
            }

            # Section 2: Register the scheduled task
            try {
                Write-Host "`nRegistering scheduled task..." -ForegroundColor Cyan

                $trigger = $null
                switch ($Frequency) {
                    'Daily' {
                        $trigger = New-ScheduledTaskTrigger -Daily -At $Time
                    }
                    'Weekly' {
                        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $Time
                    }
                    'Monthly' {
                        # New-ScheduledTaskTrigger has no -Monthly in PS 5.1; build the CIM trigger directly
                        $triggerClass = Get-CimClass -ClassName 'MSFT_TaskMonthlyTrigger' -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ErrorAction Stop
                        $trigger = New-CimInstance -CimClass $triggerClass -ClientOnly -Property @{
                            DaysOfMonth = 1
                            MonthsOfYear = 4095
                            StartBoundary = $Time.ToString("yyyy-MM-dd'T'HH:mm:ss")
                            Enabled = $true
                        } -ErrorAction Stop
                    }
                }

                $actionArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
                $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

                $frequencyNote = switch ($Frequency) {
                    'Daily'   { 'every day' }
                    'Weekly'  { 'every Monday' }
                    'Monthly' { 'on the 1st of every month' }
                }
                $dedupNote = if ($alertDedupEnabled) { "on, re-alert after $RealertAfterDays days" } else { 'off' }
                $taskDescription = "WindowsSecurityAudit $ScanType scan ($assessmentType) runs $frequencyNote at $($Time.ToString('HH:mm')). Alerts on Critical findings (alert dedup: $dedupNote). Managed by Register-ScheduledSecurityScan."

                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force -ErrorAction Stop | Out-Null

                Write-Host "Scheduled task '$taskName' registered (runs as SYSTEM)." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to register scheduled task '$taskName': $_"
                throw
            }

            $scanResult = [PSCustomObject]@{
                RegistrationDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                TaskName = $taskName
                Action = 'Register'
                Status = 'Registered'
                ComputerName = $machineName
                ScanType = $ScanType
                AssessmentType = $assessmentType
                Frequency = $Frequency
                ScheduledTime = $Time.ToString('HH:mm')
                RunAs = 'SYSTEM'
                ScriptPath = $scriptPath
                OutputPath = $OutputPath
                WebhookAlertEnabled = $webhookConfigured
                EmailAlertEnabled = $emailConfigured
                AlertDedupEnabled = $alertDedupEnabled
                RealertAfterDays = $RealertAfterDays
            }
        }
        else {
            $scanResult = [PSCustomObject]@{
                RegistrationDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                TaskName = $taskName
                Action = 'Register'
                Status = 'WhatIf'
                ComputerName = $machineName
                ScanType = $ScanType
                AssessmentType = $assessmentType
                Frequency = $Frequency
                ScheduledTime = $Time.ToString('HH:mm')
                RunAs = 'SYSTEM'
                ScriptPath = $scriptPath
                OutputPath = $OutputPath
                WebhookAlertEnabled = $webhookConfigured
                EmailAlertEnabled = $emailConfigured
                AlertDedupEnabled = $alertDedupEnabled
                RealertAfterDays = $RealertAfterDays
            }
        }
    }

    end {
        if ($null -ne $scanResult) {
            Write-Host "`n=== REGISTRATION COMPLETE ===" -ForegroundColor Green
            Write-Host "Task Name: $($scanResult.TaskName)" -ForegroundColor Cyan
            Write-Host "Action: $($scanResult.Action)" -ForegroundColor Cyan
            Write-Host "Status: $($scanResult.Status)" -ForegroundColor $(if ($scanResult.Status -in @('Registered', 'Unregistered')) { 'Green' } else { 'Yellow' })

            if ($null -ne $scanResult.PSObject.Properties['Frequency'] -and $scanResult.Action -eq 'Register') {
                Write-Host "Schedule: $($scanResult.Frequency) at $($scanResult.ScheduledTime)" -ForegroundColor Cyan
                Write-Host "Script: $($scanResult.ScriptPath)" -ForegroundColor Cyan
                Write-Host "Reports: $($scanResult.OutputPath)" -ForegroundColor Cyan
                Write-Host "Alert Dedup: $($scanResult.AlertDedupEnabled)" -ForegroundColor Cyan

                if ($scanResult.Status -eq 'Registered' -and -not $scanResult.WebhookAlertEnabled -and -not $scanResult.EmailAlertEnabled) {
                    Write-Warning "No alerting configured. Critical findings will be logged but no webhook or email alert will be sent."
                }
            }

            return $scanResult
        }
    }
}
