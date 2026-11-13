function Get-CloudComplianceStatus {
    <#
    .SYNOPSIS
        Retrieves cloud compliance status and live Azure security telemetry

    .DESCRIPTION
        Reports cloud environment compliance against various frameworks:
        CIS, ISO27001, NIST, GDPR, HIPAA, SOC2, AzureSecurityBenchmark.

        When Microsoft Graph is connected, retrieves the latest Secure Score
        through Microsoft Graph. When an Azure subscription is available, also
        queries the latest Azure Policy states and summarizes compliance by
        policy assignment. These aggregate measurements are additive and are
        never treated as proof that an individual framework control is compliant.

        Catalog controls without a control-specific query remain NotEvaluated.
        ComplianceScore covers evaluated catalog controls only and stays $null
        when no catalog control was evaluated. EvaluatedCount instead reports
        how many independent live data queries produced usable results.

    .PARAMETER Framework
        Compliance framework (Default: CIS)

    .PARAMETER IncludeRemediation
        Include remediation steps

    .PARAMETER SubscriptionId
        Azure subscription for Policy Insights. If omitted, uses the current
        Az context subscription when one is available.

    .PARAMETER ExportPath
        Path to save compliance report

    .PARAMETER Format
        Report format: HTML, JSON, CSV, or All (Default: HTML)

    .EXAMPLE
        Get-CloudComplianceStatus -Framework CIS

    .EXAMPLE
        Get-CloudComplianceStatus -Framework CIS -SubscriptionId '00000000-0000-0000-0000-000000000000'

    .OUTPUTS
        PSCustomObject with Framework, Controls, Summary, ComplianceScore,
        SecureScore, SecureScoreMax, PolicyCompliant, PolicyNonCompliant,
        EvaluatedCount, and Source. ComplianceScore is $null when no catalog
        controls were evaluated.
    #>

    [CmdletBinding()]
    param(
        [ValidateSet('CIS', 'ISO27001', 'NIST', 'GDPR', 'HIPAA', 'SOC2', 'AzureSecurityBenchmark')]
        [string]$Framework = 'CIS',
        [switch]$IncludeRemediation,
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,
        [string]$ExportPath,
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML'
    )

    begin {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  CLOUD COMPLIANCE ASSESSMENT" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Framework: $Framework" -ForegroundColor Yellow

        $graphConnected = $false
        $graphContextCommand = Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue
        if ($null -ne $graphContextCommand) {
            try {
                $graphContext = Get-MgContext -ErrorAction Stop
                if ($null -ne $graphContext) {
                    $graphConnected = $true
                }
            }
            catch {
                Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"
            }
        }

        $graphConnectInstruction = "Connect-MgGraph -Scopes 'SecurityEvents.Read.All'"
        $policyAuthorizationInstruction = "Azure Policy requires Azure Resource Manager scope https://management.azure.com/user_impersonation and Reader or Microsoft.PolicyInsights/policyStates/read on the subscription. Install Az.Accounts, then run Connect-AzAccount."
        if (-not $graphConnected) {
            Write-Warning "Not connected to Microsoft Graph. Secure Score and Azure Policy will be NotEvaluated. Run $graphConnectInstruction. $policyAuthorizationInstruction"
        }

        # Initialize results. Null numeric fields mean unknown, never zero.
        $results = [PSCustomObject]@{
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Framework = $Framework
            FrameworkVersion = "Latest"
            Controls = @()
            ComplianceScore = $null
            SecureScore = $null
            SecureScoreMax = $null
            SecureScorePercentage = $null
            SecureScoreStatus = 'NotEvaluated'
            SecureScoreNote = 'Not evaluated.'
            PolicyCompliant = $null
            PolicyNonCompliant = $null
            PolicyOther = $null
            PolicyAssignments = @()
            PolicyComplianceStatus = 'NotEvaluated'
            PolicyComplianceNote = 'Not evaluated.'
            PolicyTransport = $null
            SubscriptionId = $SubscriptionId
            EvaluatedCount = 0
            Source = 'Graph'
            Summary = @{
                TotalControls = 0
                Evaluated = 0
                NotEvaluated = 0
                Compliant = 0
                NonCompliant = 0
                PartiallyCompliant = 0
            }
        }
    }

    process {
        try {
            Write-Host "`nLoading $Framework control catalog..." -ForegroundColor Cyan

            $catalog = @()

            # Catalog of framework control references. These entries identify the
            # controls only; their compliance status is NOT evaluated (see below).
            switch ($Framework) {
                'CIS' {
                    $catalog = @(
                        @{
                            ControlId = "1.1.1"
                            Title = "Ensure multifactor authentication is enabled"
                            Category = "Identity"
                            Severity = "Critical"
                            Remediation = "Enable MFA via Conditional Access"
                        },
                        @{
                            ControlId = "1.1.2"
                            Title = "Ensure global admins are limited"
                            Category = "Identity"
                            Severity = "High"
                            Remediation = "N/A"
                        }
                    )
                }

                'GDPR' {
                    $catalog = @(
                        @{
                            ControlId = "Art. 32"
                            Title = "Security of processing"
                            Category = "Technical Measures"
                            Severity = "Critical"
                            Remediation = "N/A"
                        }
                    )
                }

                'NIST' {
                    $catalog = @(
                        @{
                            ControlId = "ID.AM-1"
                            Title = "Physical devices inventoried"
                            Category = "Identify"
                            Severity = "Medium"
                            Remediation = "N/A"
                        }
                    )
                }

                default {
                    $catalog = @()
                }
            }

            if (@($catalog).Count -eq 0) {
                Write-Warning "No control catalog is defined for framework '$Framework'."
            }

            if ($graphConnected) {
                Write-Host "`nRetrieving Microsoft Secure Score..." -ForegroundColor Cyan
                try {
                    $secureScoreCommand = Get-Command -Name 'Get-MgSecuritySecureScore' -ErrorAction SilentlyContinue
                    $graphRequestCommand = Get-Command -Name 'Invoke-MgGraphRequest' -ErrorAction SilentlyContinue

                    if ($null -ne $secureScoreCommand) {
                        $scoreResponse = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop
                    }
                    elseif ($null -ne $graphRequestCommand) {
                        $scoreResponse = Invoke-MgGraphRequest -Method GET -Uri '/beta/security/secureScores?$top=1' -ErrorAction Stop
                    }
                    else {
                        throw 'Neither Get-MgSecuritySecureScore nor Invoke-MgGraphRequest is available. Install the Microsoft.Graph.Security or Microsoft.Graph.Authentication module.'
                    }

                    $scoreValueProperty = Get-CloudDataProperty -InputObject $scoreResponse -Name 'value'
                    if ($scoreValueProperty.Exists) {
                        $secureScores = @($scoreValueProperty.Value)
                    }
                    elseif ($null -ne $scoreResponse) {
                        $secureScores = @($scoreResponse)
                    }
                    else {
                        $secureScores = @()
                    }

                    $latestScore = @($secureScores | Where-Object { $null -ne $_ } | Select-Object -First 1)
                    if ($latestScore.Count -eq 0) {
                        throw 'Microsoft Graph returned no Secure Score records.'
                    }

                    $currentScoreProperty = Get-CloudDataProperty -InputObject $latestScore[0] -Name 'currentScore'
                    $maxScoreProperty = Get-CloudDataProperty -InputObject $latestScore[0] -Name 'maxScore'
                    if (-not $currentScoreProperty.Exists -or $null -eq $currentScoreProperty.Value -or
                        -not $maxScoreProperty.Exists -or $null -eq $maxScoreProperty.Value) {
                        throw 'The Secure Score record did not contain numeric currentScore and maxScore fields.'
                    }

                    $currentScore = [double]$currentScoreProperty.Value
                    $maxScore = [double]$maxScoreProperty.Value
                    $results.SecureScore = $currentScore
                    $results.SecureScoreMax = $maxScore
                    if ($maxScore -gt 0) {
                        $results.SecureScorePercentage = [Math]::Round(($currentScore / $maxScore) * 100, 1)
                    }
                    $results.SecureScoreStatus = 'Evaluated'
                    $results.SecureScoreNote = 'Latest Microsoft Graph secureScore record requested with top 1 (REST equivalent: GET /beta/security/secureScores?$top=1). This is a Microsoft Secure Score, not a framework compliance percentage.'
                    $results.EvaluatedCount++
                }
                catch {
                    $results.SecureScore = $null
                    $results.SecureScoreMax = $null
                    $results.SecureScorePercentage = $null
                    $results.SecureScoreStatus = 'NotEvaluated'
                    $results.SecureScoreNote = "Not evaluated: Secure Score query failed: $($_.Exception.Message). Requires Microsoft Graph scope SecurityEvents.Read.All; run $graphConnectInstruction."
                    Write-Warning $results.SecureScoreNote
                }

                Write-Host "`nRetrieving Azure Policy compliance..." -ForegroundColor Cyan
                $effectiveSubscriptionId = $SubscriptionId
                $subscriptionDiscoveryError = $null
                if ([string]::IsNullOrWhiteSpace($effectiveSubscriptionId)) {
                    $azContextCommand = Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue
                    if ($null -ne $azContextCommand) {
                        try {
                            $azContext = Get-AzContext -ErrorAction Stop
                            $azSubscriptionProperty = Get-CloudDataProperty -InputObject $azContext -Name 'Subscription'
                            if ($azSubscriptionProperty.Exists) {
                                $azSubscriptionIdProperty = Get-CloudDataProperty -InputObject $azSubscriptionProperty.Value -Name 'Id'
                                if ($azSubscriptionIdProperty.Exists -and $null -ne $azSubscriptionIdProperty.Value) {
                                    $effectiveSubscriptionId = [string]$azSubscriptionIdProperty.Value
                                }
                            }
                        }
                        catch {
                            $subscriptionDiscoveryError = $_.Exception.Message
                        }
                    }
                }
                $results.SubscriptionId = $effectiveSubscriptionId

                if ([string]::IsNullOrWhiteSpace($effectiveSubscriptionId)) {
                    $results.PolicyComplianceNote = "Not evaluated: no Azure subscription was supplied or selected. Pass -SubscriptionId or run Connect-AzAccount followed by Select-AzSubscription. $policyAuthorizationInstruction"
                    if ($subscriptionDiscoveryError) {
                        $results.PolicyComplianceNote += " Azure context discovery failed: $subscriptionDiscoveryError"
                    }
                    Write-Warning $results.PolicyComplianceNote
                }
                else {
                    try {
                        $policyResult = Invoke-CloudPolicyInsightsQuery -SubscriptionId $effectiveSubscriptionId
                        $results.PolicyTransport = $policyResult.Transport
                        $results.PolicyCompliant = 0
                        $results.PolicyNonCompliant = 0
                        $results.PolicyOther = 0
                        $assignmentSummaries = @{}

                        foreach ($policyState in @($policyResult.States)) {
                            if ($null -eq $policyState) {
                                continue
                            }

                            $assignmentProperty = Get-CloudDataProperty -InputObject $policyState -Name 'policyAssignmentId'
                            $assignmentId = [string]$assignmentProperty.Value
                            if ([string]::IsNullOrWhiteSpace($assignmentId)) {
                                $assignmentId = '(unknown policy assignment)'
                            }

                            if (-not $assignmentSummaries.ContainsKey($assignmentId)) {
                                $assignmentSummaries[$assignmentId] = [ordered]@{
                                    PolicyAssignmentId = $assignmentId
                                    Compliant = 0
                                    NonCompliant = 0
                                    Other = 0
                                }
                            }

                            $complianceProperty = Get-CloudDataProperty -InputObject $policyState -Name 'complianceState'
                            $complianceState = [string]$complianceProperty.Value
                            if ($complianceState.Equals('Compliant', [System.StringComparison]::OrdinalIgnoreCase)) {
                                $results.PolicyCompliant++
                                $assignmentSummaries[$assignmentId].Compliant++
                            }
                            elseif ($complianceState.Equals('NonCompliant', [System.StringComparison]::OrdinalIgnoreCase)) {
                                $results.PolicyNonCompliant++
                                $assignmentSummaries[$assignmentId].NonCompliant++
                            }
                            else {
                                $results.PolicyOther++
                                $assignmentSummaries[$assignmentId].Other++
                            }
                        }

                        $results.PolicyAssignments = @(
                            $assignmentSummaries.Values |
                                Sort-Object -Property PolicyAssignmentId |
                                ForEach-Object { [PSCustomObject]$_ }
                        )
                        $policyStateCount = @($policyResult.States).Count
                        $results.PolicyComplianceStatus = 'Evaluated'
                        $results.PolicyComplianceNote = "Evaluated $policyStateCount latest policy-state record(s) in subscription $effectiveSubscriptionId using $($policyResult.Transport). Counts are grouped by policyAssignmentId and are not framework-control results."
                        if ($results.PolicyOther -gt 0) {
                            $results.PolicyComplianceNote += " $($results.PolicyOther) record(s) had Exempt, Unknown, missing, or other compliance states and were counted separately."
                        }
                        $results.EvaluatedCount++
                    }
                    catch {
                        $results.PolicyCompliant = $null
                        $results.PolicyNonCompliant = $null
                        $results.PolicyOther = $null
                        $results.PolicyAssignments = @()
                        $results.PolicyComplianceStatus = 'NotEvaluated'
                        $results.PolicyComplianceNote = "Not evaluated: Azure Policy Insights query failed: $($_.Exception.Message). $policyAuthorizationInstruction Invoke-MgGraphRequest is a Microsoft Graph transport and cannot be assumed to authorize management.azure.com."
                        Write-Warning $results.PolicyComplianceNote
                    }
                }
            }
            else {
                $notConnectedReason = "Not evaluated: no Microsoft Graph context. Run $graphConnectInstruction."
                $results.SecureScoreNote = $notConnectedReason
                $results.PolicyComplianceNote = "Not evaluated: live queries were skipped because there is no Microsoft Graph context. Run $graphConnectInstruction. $policyAuthorizationInstruction"
            }

            if (@($catalog).Count -gt 0) {
                Write-Warning "Aggregate Secure Score and Azure Policy results do not establish compliance for individual $Framework controls. Catalog controls without a control-specific query remain NotEvaluated and are excluded from ComplianceScore."
            }

            foreach ($control in $catalog) {
                if (-not $graphConnected) {
                    $notEvaluatedNote = "Not evaluated: no Microsoft Graph context. Run $graphConnectInstruction."
                }
                else {
                    switch ($control.ControlId) {
                        '1.1.1' {
                            $notEvaluatedNote = "Not evaluated: aggregate Secure Score and Azure Policy counts cannot prove MFA coverage for CIS 1.1.1. Use the org-wide MFA result from Test-M365SecurityPosture with AuditLog.Read.All and perform the framework mapping separately."
                        }
                        '1.1.2' {
                            $notEvaluatedNote = "Not evaluated: CIS 1.1.2 requires correlation of active and eligible directory role assignments through /beta/roleManagement/directory/roleAssignments and roleEligibilitySchedules; no control-specific query is mapped here."
                        }
                        'Art. 32' {
                            $notEvaluatedNote = "Not evaluated: GDPR Article 32 requires evidence across identity, encryption, resilience, restoration, and testing. Aggregate Secure Score and Azure Policy counts are insufficient evidence."
                        }
                        'ID.AM-1' {
                            $notEvaluatedNote = "Not evaluated: NIST ID.AM-1 requires device inventory evidence, for example Azure Resource Graph /providers/Microsoft.ResourceGraph/resources correlated with device inventory. No control-specific inventory query is mapped here."
                        }
                        default {
                            $notEvaluatedNote = "Not evaluated: no control-specific API query and compliance mapping are implemented for this catalog entry."
                        }
                    }
                }

                $results.Controls += [PSCustomObject]@{
                    ControlId = $control.ControlId
                    Title = $control.Title
                    Category = $control.Category
                    Status = "NotEvaluated"
                    Severity = $control.Severity
                    Note = $notEvaluatedNote
                    Remediation = if ($IncludeRemediation) { $control.Remediation } else { $null }
                }

                $results.Summary.TotalControls++
                $results.Summary.NotEvaluated++
            }

            # ComplianceScore covers catalog controls, not the additive live queries.
            $evaluatedControlCount = $results.Summary.Compliant + $results.Summary.NonCompliant + $results.Summary.PartiallyCompliant
            $results.Summary.Evaluated = $evaluatedControlCount

            if ($evaluatedControlCount -gt 0) {
                $compliantCount = $results.Summary.Compliant + ($results.Summary.PartiallyCompliant * 0.5)
                $results.ComplianceScore = [Math]::Round(($compliantCount / $evaluatedControlCount) * 100, 1)
            }

            # Export if requested
            if ($ExportPath) {
                Write-Host "`nExporting reports..." -ForegroundColor Cyan

                if (-not (Test-Path $ExportPath)) {
                    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
                }

                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $ExportPath "Compliance_${Framework}_$timestamp.json"
                    $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "Exported JSON: $jsonPath" -ForegroundColor Green
                }

                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $ExportPath "Compliance_${Framework}_$timestamp.csv"
                    $results.Controls | ConvertTo-CsvSafeObject | Export-Csv $csvPath -NoTypeInformation
                    Write-Host "Exported CSV: $csvPath" -ForegroundColor Green
                }

                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $ExportPath "Compliance_${Framework}_$timestamp.html"
                    $htmlContent = Generate-CloudComplianceHTML -Results $results
                    $htmlContent | Out-File $htmlPath -Encoding UTF8
                    Write-Host "Exported HTML: $htmlPath" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Error "Error during assessment: $_"
            throw
        }
    }

    end {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "  COMPLIANCE ASSESSMENT COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green

        if ($null -ne $results.ComplianceScore) {
            $scoreColor = if ($results.ComplianceScore -ge 80) { 'Green' }
                          elseif ($results.ComplianceScore -ge 60) { 'Yellow' }
                          else { 'Red' }
            Write-Host "`nCompliance Score: $($results.ComplianceScore)%" -ForegroundColor $scoreColor
        }
        else {
            Write-Host "`nCompliance Score: N/A (no controls were evaluated)" -ForegroundColor Yellow
        }

        Write-Host "Framework: $($results.Framework)" -ForegroundColor Cyan
        Write-Host "Total Controls: $($results.Summary.TotalControls)" -ForegroundColor White
        Write-Host "Evaluated Controls: $($results.Summary.Evaluated)" -ForegroundColor White
        Write-Host "Not Evaluated Controls: $($results.Summary.NotEvaluated)" -ForegroundColor Yellow
        Write-Host "Compliant: $($results.Summary.Compliant)" -ForegroundColor Green
        Write-Host "Non-Compliant: $($results.Summary.NonCompliant)" -ForegroundColor Red
        Write-Host "Live Queries Evaluated: $($results.EvaluatedCount)" -ForegroundColor White
        if ($results.SecureScoreStatus -eq 'Evaluated') {
            Write-Host "Secure Score: $($results.SecureScore) / $($results.SecureScoreMax)" -ForegroundColor Cyan
        }
        else {
            Write-Host "Secure Score: NotEvaluated" -ForegroundColor Yellow
        }
        if ($results.PolicyComplianceStatus -eq 'Evaluated') {
            Write-Host "Azure Policy States: $($results.PolicyCompliant) compliant, $($results.PolicyNonCompliant) non-compliant, $($results.PolicyOther) other" -ForegroundColor Cyan
        }
        else {
            Write-Host "Azure Policy States: NotEvaluated" -ForegroundColor Yellow
        }

        return $results
    }
}

function Generate-CloudComplianceHTML {
    param($Results)

    $hasScore = ($null -ne $Results) -and ($null -ne $Results.ComplianceScore)

    if ($hasScore) {
        $scoreColor = if ($Results.ComplianceScore -ge 80) { '#107c10' }
                      elseif ($Results.ComplianceScore -ge 60) { '#f7630c' }
                      else { '#d13438' }
        $scoreDisplay = "$($Results.ComplianceScore)%"
    }
    else {
        $scoreColor = '#605e5c'
        $scoreDisplay = "N/A"
    }

    $html = @'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cloud Compliance Status Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .compliant { color: #107c10; font-weight: bold; }
        .non-compliant { color: #d13438; font-weight: bold; }
        .partial { color: #f7630c; font-weight: bold; }
        .not-evaluated { color: #605e5c; font-weight: bold; }
        .score-box { text-align: center; padding: 30px; margin: 20px 0; border-radius: 10px; color: white; }
        .score-value { font-size: 48px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cloud Compliance Status Report</h1>
'@

    $html += @"
        <div class="score-box" style="background: $scoreColor;">
            <div class="score-value">$scoreDisplay</div>
            <div>Compliance Score</div>
        </div>

        <h2>Framework Information</h2>
        <p><strong>Framework:</strong> $($Results.Framework)</p>
        <p><strong>Version:</strong> $($Results.FrameworkVersion)</p>
        <p><strong>Assessment Date:</strong> $($Results.AssessmentDate)</p>

        <h2>Live Azure Security Telemetry</h2>
        <p><strong>Source:</strong> $($Results.Source); <strong>Live queries evaluated:</strong> $($Results.EvaluatedCount)</p>
        <p><strong>Secure Score:</strong> $(if ($Results.SecureScoreStatus -eq 'Evaluated') { "$($Results.SecureScore) / $($Results.SecureScoreMax)" } else { 'N/A' })</p>
        <p>$(ConvertTo-HtmlEncoded $Results.SecureScoreNote)</p>
        <p><strong>Azure Policy states:</strong> $(if ($Results.PolicyComplianceStatus -eq 'Evaluated') { "$($Results.PolicyCompliant) compliant, $($Results.PolicyNonCompliant) non-compliant, $($Results.PolicyOther) other" } else { 'N/A' })</p>
        <p>$(ConvertTo-HtmlEncoded $Results.PolicyComplianceNote)</p>

        <h2>Control Summary</h2>
        <p><strong>Total Controls:</strong> $($Results.Summary.TotalControls)</p>
        <p><strong>Evaluated:</strong> $($Results.Summary.Evaluated)</p>
        <p><strong>Not Evaluated:</strong> $($Results.Summary.NotEvaluated)</p>
        <p><strong>Compliant:</strong> $($Results.Summary.Compliant)</p>
        <p><strong>Non-Compliant:</strong> $($Results.Summary.NonCompliant)</p>

        <h2>Compliance Controls</h2>
        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($control in $Results.Controls) {
        $statusClass = switch ($control.Status) {
            'Compliant' { 'compliant' }
            'Non-Compliant' { 'non-compliant' }
            'Partially Compliant' { 'partial' }
            default { 'not-evaluated' }
        }

        $html += @"
                <tr>
                    <td>$($control.ControlId)</td>
                    <td>$($control.Title)</td>
                    <td>$($control.Category)</td>
                    <td>$($control.Severity)</td>
                    <td class="$statusClass">$($control.Status)</td>
                </tr>
"@
    }

    $html += @'
            </tbody>
        </table>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #605e5c; font-size: 12px;">
            <p>Generated by WindowsSecurityAudit Module</p>
        </div>
    </div>
</body>
</html>
'@

    return $html
}
