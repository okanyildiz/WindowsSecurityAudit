function Get-CloudComplianceStatus {
    <#
    .SYNOPSIS
        Retrieves cloud compliance status against regulatory frameworks

    .DESCRIPTION
        Reports cloud environment compliance against various frameworks:
        CIS, ISO27001, NIST, GDPR, HIPAA, SOC2, AzureSecurityBenchmark.

        Automated evaluation of these controls requires framework-specific
        Microsoft Graph/API queries that are not yet implemented. Controls in
        the built-in catalog are therefore returned with Status 'NotEvaluated'
        and the ComplianceScore is $null when no control was actually evaluated.

    .PARAMETER Framework
        Compliance framework (Default: CIS)

    .PARAMETER IncludeRemediation
        Include remediation steps

    .PARAMETER ExportPath
        Path to save compliance report

    .PARAMETER Format
        Report format: HTML, JSON, CSV, or All (Default: HTML)

    .EXAMPLE
        Get-CloudComplianceStatus -Framework CIS

    .OUTPUTS
        PSCustomObject with Framework, Controls, Summary, and ComplianceScore
        ($null when no controls were evaluated).
    #>

    [CmdletBinding()]
    param(
        [ValidateSet('CIS', 'ISO27001', 'NIST', 'GDPR', 'HIPAA', 'SOC2', 'AzureSecurityBenchmark')]
        [string]$Framework = 'CIS',
        [switch]$IncludeRemediation,
        [string]$ExportPath,
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML'
    )

    begin {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  CLOUD COMPLIANCE ASSESSMENT" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Framework: $Framework" -ForegroundColor Yellow

        # Initialize results
        $results = [PSCustomObject]@{
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Framework = $Framework
            FrameworkVersion = "Latest"
            Controls = @()
            ComplianceScore = $null
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

            Write-Warning "Automated evaluation of $Framework controls is not implemented: it requires framework-specific Microsoft Graph/API queries. All listed controls are returned with Status 'NotEvaluated' and are excluded from the compliance score."

            # Process controls
            $notEvaluatedNote = "Not evaluated: automated cloud compliance evaluation of this control requires framework-specific Microsoft Graph/API queries that are not yet implemented."

            foreach ($control in $catalog) {
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

            # Calculate score from evaluated controls only; with none evaluated the
            # score stays $null instead of implying a pass rate that was never measured.
            $evaluatedCount = $results.Summary.Compliant + $results.Summary.NonCompliant + $results.Summary.PartiallyCompliant
            $results.Summary.Evaluated = $evaluatedCount

            if ($evaluatedCount -gt 0) {
                $compliantCount = $results.Summary.Compliant + ($results.Summary.PartiallyCompliant * 0.5)
                $results.ComplianceScore = [Math]::Round(($compliantCount / $evaluatedCount) * 100, 1)
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
        Write-Host "Evaluated: $($results.Summary.Evaluated)" -ForegroundColor White
        Write-Host "Not Evaluated: $($results.Summary.NotEvaluated)" -ForegroundColor Yellow
        Write-Host "Compliant: $($results.Summary.Compliant)" -ForegroundColor Green
        Write-Host "Non-Compliant: $($results.Summary.NonCompliant)" -ForegroundColor Red

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
