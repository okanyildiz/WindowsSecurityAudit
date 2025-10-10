function Get-ComplianceReport {
    <#
    .SYNOPSIS
        Generates comprehensive compliance report across multiple frameworks
    .DESCRIPTION
        Runs CIS, NIST, and PCI-DSS compliance tests and generates unified report
        with executive summary, gap analysis, and remediation priorities
    .PARAMETER Frameworks
        Compliance frameworks to test: CIS, NIST, PCIDSS, or All
    .PARAMETER OutputPath
        Path to save the compliance report
    .PARAMETER Format
        Report format: HTML, JSON, CSV, or All (default: HTML)
    .PARAMETER IncludeEvidence
        Include detailed evidence in the report
    .EXAMPLE
        Get-ComplianceReport -OutputPath "C:\Reports"
        Get-ComplianceReport -Frameworks CIS,NIST -Format JSON -OutputPath "C:\Reports"
    .OUTPUTS
        PSCustomObject with unified compliance results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('All', 'CIS', 'NIST', 'PCIDSS')]
        [string[]]$Frameworks = @('All'),
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML',
        
        [Parameter()]
        [switch]$IncludeEvidence
    )
    
    begin {
        Write-Host "=== COMPREHENSIVE COMPLIANCE REPORT ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Frameworks: $($Frameworks -join ', ')" -ForegroundColor Yellow
        
        if ($Frameworks -contains 'All') {
            $Frameworks = @('CIS', 'NIST', 'PCIDSS')
        }
        
        $report = [PSCustomObject]@{
            ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Frameworks = @()
            ExecutiveSummary = @{
                OverallCompliance = 0
                TotalControls = 0
                CompliantControls = 0
                NonCompliantControls = 0
                CriticalGaps = 0
                HighGaps = 0
                MediumGaps = 0
            }
            CrossFrameworkAnalysis = @()
            RemediationPriorities = @()
            Recommendations = @()
        }
    }
    
    process {
        try {
            $frameworkResults = @()
            
            # 1. CIS BENCHMARK
            if ($Frameworks -contains 'CIS') {
                Write-Host "`n[1/3] Running CIS Benchmark compliance test..." -ForegroundColor Cyan
                
                try {
                    $cisResult = Test-CISBenchmark -Level 1
                    
                    $frameworkSummary = [PSCustomObject]@{
                        Framework = 'CIS Benchmark Level 1'
                        CompliancePercentage = $cisResult.Summary.CompliancePercentage
                        TotalControls = $cisResult.Summary.TotalControls
                        Passed = $cisResult.Summary.Passed
                        Failed = $cisResult.Summary.Failed
                        NotApplicable = $cisResult.Summary.NotApplicable
                        CriticalGaps = @($cisResult.Controls | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
                        HighGaps = @($cisResult.Controls | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'High' }).Count
                        Controls = $cisResult.Controls
                        Status = if ($cisResult.Summary.CompliancePercentage -ge 80) { 'Pass' } 
                                 elseif ($cisResult.Summary.CompliancePercentage -ge 60) { 'Marginal' } 
                                 else { 'Fail' }
                    }
                    
                    $report.Frameworks += $frameworkSummary
                    $frameworkResults += $cisResult
                    
                    Write-Host "  CIS Compliance: $($cisResult.Summary.CompliancePercentage)%" -ForegroundColor $(
                        if ($cisResult.Summary.CompliancePercentage -ge 80) { 'Green' } 
                        elseif ($cisResult.Summary.CompliancePercentage -ge 60) { 'Yellow' } 
                        else { 'Red' }
                    )
                }
                catch {
                    Write-Warning "Error running CIS test: $_"
                }
            }
            
            # 2. NIST 800-53
            if ($Frameworks -contains 'NIST') {
                Write-Host "`n[2/3] Running NIST 800-53 compliance test..." -ForegroundColor Cyan
                
                try {
                    $nistResult = Test-NISTCompliance
                    
                    $frameworkSummary = [PSCustomObject]@{
                        Framework = 'NIST 800-53 Rev 5'
                        CompliancePercentage = $nistResult.Summary.CompliancePercentage
                        TotalControls = $nistResult.Summary.TotalControls
                        Passed = $nistResult.Summary.Compliant
                        Failed = $nistResult.Summary.NonCompliant
                        NotApplicable = $nistResult.Summary.NotApplicable
                        CriticalGaps = @($nistResult.Controls | Where-Object { $_.Status -eq 'NonCompliant' -and $_.Impact -eq 'Critical' }).Count
                        HighGaps = @($nistResult.Controls | Where-Object { $_.Status -eq 'NonCompliant' -and $_.Impact -eq 'High' }).Count
                        Controls = $nistResult.Controls
                        Status = if ($nistResult.Summary.CompliancePercentage -ge 80) { 'Pass' } 
                                 elseif ($nistResult.Summary.CompliancePercentage -ge 60) { 'Marginal' } 
                                 else { 'Fail' }
                    }
                    
                    $report.Frameworks += $frameworkSummary
                    $frameworkResults += $nistResult
                    
                    Write-Host "  NIST Compliance: $($nistResult.Summary.CompliancePercentage)%" -ForegroundColor $(
                        if ($nistResult.Summary.CompliancePercentage -ge 80) { 'Green' } 
                        elseif ($nistResult.Summary.CompliancePercentage -ge 60) { 'Yellow' } 
                        else { 'Red' }
                    )
                }
                catch {
                    Write-Warning "Error running NIST test: $_"
                }
            }
            
            # 3. PCI-DSS
            if ($Frameworks -contains 'PCIDSS') {
                Write-Host "`n[3/3] Running PCI-DSS compliance test..." -ForegroundColor Cyan
                
                try {
                    $pciResult = Test-PCI-DSS -Version 4.0
                    
                    $frameworkSummary = [PSCustomObject]@{
                        Framework = 'PCI-DSS v4.0'
                        CompliancePercentage = $pciResult.Summary.CompliancePercentage
                        TotalControls = $pciResult.Summary.TotalRequirements
                        Passed = $pciResult.Summary.InPlace
                        Failed = $pciResult.Summary.NotInPlace
                        NotApplicable = $pciResult.Summary.NotApplicable
                        CriticalGaps = @($pciResult.Requirements | Where-Object { $_.Status -eq 'NotInPlace' -and $_.Priority -eq 'Critical' }).Count
                        HighGaps = @($pciResult.Requirements | Where-Object { $_.Status -eq 'NotInPlace' -and $_.Priority -eq 'High' }).Count
                        Controls = $pciResult.Requirements
                        Status = if ($pciResult.Summary.CompliancePercentage -eq 100) { 'Pass' } 
                                 elseif ($pciResult.Summary.CompliancePercentage -ge 80) { 'Marginal' } 
                                 else { 'Fail' }
                    }
                    
                    $report.Frameworks += $frameworkSummary
                    $frameworkResults += $pciResult
                    
                    Write-Host "  PCI-DSS Compliance: $($pciResult.Summary.CompliancePercentage)%" -ForegroundColor $(
                        if ($pciResult.Summary.CompliancePercentage -eq 100) { 'Green' } 
                        elseif ($pciResult.Summary.CompliancePercentage -ge 80) { 'Yellow' } 
                        else { 'Red' }
                    )
                }
                catch {
                    Write-Warning "Error running PCI-DSS test: $_"
                }
            }
            
            # Calculate Executive Summary
            Write-Host "`n[*] Generating executive summary..." -ForegroundColor Cyan
            
            if ($report.Frameworks.Count -gt 0) {
                $report.ExecutiveSummary.OverallCompliance = [math]::Round(
                    ($report.Frameworks | Measure-Object -Property CompliancePercentage -Average).Average, 2
                )
                $report.ExecutiveSummary.TotalControls = ($report.Frameworks | Measure-Object -Property TotalControls -Sum).Sum
                $report.ExecutiveSummary.CompliantControls = ($report.Frameworks | Measure-Object -Property Passed -Sum).Sum
                $report.ExecutiveSummary.NonCompliantControls = ($report.Frameworks | Measure-Object -Property Failed -Sum).Sum
                $report.ExecutiveSummary.CriticalGaps = ($report.Frameworks | Measure-Object -Property CriticalGaps -Sum).Sum
                $report.ExecutiveSummary.HighGaps = ($report.Frameworks | Measure-Object -Property HighGaps -Sum).Sum
            }
            
            # Cross-Framework Analysis
            Write-Host "[*] Performing cross-framework analysis..." -ForegroundColor Cyan
            
            # Find common security areas across frameworks
            $commonAreas = @{
                'Firewall' = @('CIS-9', 'SC-7', '1.2.1')
                'Password Policy' = @('CIS-1.1', 'IA-2', '8.2.3')
                'Audit Logging' = @('CIS-17', 'AU-2', '10.2.1')
                'Encryption' = @('CIS-2.3.11', 'SC-28', '3.5.1')
                'Access Control' = @('CIS-2.3.1', 'AC-2', '7.1.1')
            }
            
            foreach ($area in $commonAreas.Keys) {
                $areaStatus = [PSCustomObject]@{
                    SecurityArea = $area
                    AffectedFrameworks = @()
                    OverallStatus = 'Compliant'
                    GapCount = 0
                }
                
                foreach ($framework in $report.Frameworks) {
                    $relatedControls = @($framework.Controls | Where-Object { 
                        # FIXED: Safe property access with PSObject
                        $currentControl = $_
                        $controlId = if ($null -ne $currentControl.PSObject.Properties['ControlID']) { 
                            $currentControl.ControlID 
                        } elseif ($null -ne $currentControl.PSObject.Properties['RequirementID']) { 
                            $currentControl.RequirementID 
                        } else { 
                            '' 
                        }
                        
                        $commonAreas[$area] | Where-Object { $controlId -like "*$_*" }
                    })
                    
                    if ($relatedControls.Count -gt 0) {
                        # FIXED: Wrap in @() to ensure array
                        $hasGap = @($relatedControls | Where-Object { 
                            $status = $_.Status
                            $status -in @('Fail', 'NonCompliant', 'NotInPlace')
                        })
                        
                        if ($hasGap.Count -gt 0) {
                            $areaStatus.AffectedFrameworks += $framework.Framework
                            $areaStatus.OverallStatus = 'Non-Compliant'
                            $areaStatus.GapCount += $hasGap.Count
                        }
                    }
                }
                
                if ($areaStatus.GapCount -gt 0) {
                    $report.CrossFrameworkAnalysis += $areaStatus
                }
            }
            
            # Remediation Priorities
            Write-Host "[*] Prioritizing remediation actions..." -ForegroundColor Cyan
            
            $allGaps = @()
            foreach ($framework in $report.Frameworks) {
                foreach ($control in $framework.Controls) {
                    $status = $control.Status
                    
                    # FIXED: Safe property access with PSObject
                    $severity = if ($null -ne $control.PSObject.Properties['Severity']) { 
                        $control.Severity 
                    } elseif ($null -ne $control.PSObject.Properties['Impact']) { 
                        $control.Impact 
                    } elseif ($null -ne $control.PSObject.Properties['Priority']) { 
                        $control.Priority 
                    } else { 
                        'Medium' 
                    }
                    
                    if ($status -in @('Fail', 'NonCompliant', 'NotInPlace')) {
                        # FIXED: Safe property access with PSObject
                        $controlID = if ($null -ne $control.PSObject.Properties['ControlID']) { 
                            $control.ControlID 
                        } elseif ($null -ne $control.PSObject.Properties['RequirementID']) { 
                            $control.RequirementID 
                        } else { 
                            'Unknown' 
                        }
                        
                        $controlName = if ($null -ne $control.PSObject.Properties['ControlName']) { 
                            $control.ControlName 
                        } elseif ($null -ne $control.PSObject.Properties['RequirementName']) { 
                            $control.RequirementName 
                        } else { 
                            'Unknown Control' 
                        }
                        
                        $gap = [PSCustomObject]@{
                            Framework = $framework.Framework
                            ControlID = $controlID
                            ControlName = $controlName
                            Severity = $severity
                            Remediation = $control.Remediation
                            Priority = switch ($severity) {
                                'Critical' { 1 }
                                'High' { 2 }
                                'Medium' { 3 }
                                'Low' { 4 }
                                default { 5 }
                            }
                        }
                        $allGaps += $gap
                    }
                }
            }
            
            $report.RemediationPriorities = $allGaps | Sort-Object Priority, Framework | Select-Object -First 10
            
            # Generate Recommendations
            if ($report.ExecutiveSummary.CriticalGaps -gt 0) {
                $report.Recommendations += "CRITICAL: Address $($report.ExecutiveSummary.CriticalGaps) critical security gap(s) immediately"
            }
            
            if ($report.ExecutiveSummary.HighGaps -gt 0) {
                $report.Recommendations += "HIGH: Remediate $($report.ExecutiveSummary.HighGaps) high-priority gap(s) within 30 days"
            }
            
            if ($report.ExecutiveSummary.OverallCompliance -lt 80) {
                $report.Recommendations += "Overall compliance below 80% - implement comprehensive remediation plan"
            }
            
            $report.Recommendations += "Conduct regular compliance assessments (quarterly recommended)"
            $report.Recommendations += "Maintain documentation for all compliance controls"
            $report.Recommendations += "Consider engaging third-party assessor for validation"
            
            # Export Reports
            if ($OutputPath) {
                Write-Host "`n[*] Exporting compliance reports..." -ForegroundColor Cyan
                
                if (-not (Test-Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $reportName = "ComplianceReport_$timestamp"
                
                # Export JSON
                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $OutputPath "$reportName.json"
                    $report | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "  JSON report saved: $jsonPath" -ForegroundColor Green
                }
                
                # Export CSV (Summary)
                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $OutputPath "$reportName.csv"
                    $report.Frameworks | Export-Csv $csvPath -NoTypeInformation
                    Write-Host "  CSV report saved: $csvPath" -ForegroundColor Green
                }
                
                # Export HTML
                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $OutputPath "$reportName.html"
                    $html = Generate-ComplianceHTML -Report $report
                    $html | Out-File $htmlPath -Encoding UTF8
                    Write-Host "  HTML report saved: $htmlPath" -ForegroundColor Green
                }
            }
            
        }
        catch {
            Write-Error "Error generating compliance report: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== COMPLIANCE REPORT COMPLETE ===" -ForegroundColor $(
            if ($report.ExecutiveSummary.OverallCompliance -ge 80) { 'Green' }
            elseif ($report.ExecutiveSummary.OverallCompliance -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        
        Write-Host "`nExecutive Summary:" -ForegroundColor Cyan
        Write-Host "  Overall Compliance: $($report.ExecutiveSummary.OverallCompliance)%" -ForegroundColor White
        Write-Host "  Total Controls: $($report.ExecutiveSummary.TotalControls)" -ForegroundColor White
        Write-Host "  Compliant: $($report.ExecutiveSummary.CompliantControls)" -ForegroundColor Green
        Write-Host "  Non-Compliant: $($report.ExecutiveSummary.NonCompliantControls)" -ForegroundColor Red
        Write-Host "  Critical Gaps: $($report.ExecutiveSummary.CriticalGaps)" -ForegroundColor Red
        Write-Host "  High Gaps: $($report.ExecutiveSummary.HighGaps)" -ForegroundColor Yellow
        
        Write-Host "`nFramework Results:" -ForegroundColor Cyan
        foreach ($framework in $report.Frameworks) {
            Write-Host "  $($framework.Framework): $($framework.CompliancePercentage)% [$($framework.Status)]" -ForegroundColor $(
                if ($framework.Status -eq 'Pass') { 'Green' }
                elseif ($framework.Status -eq 'Marginal') { 'Yellow' }
                else { 'Red' }
            )
        }
        
        if ($report.CrossFrameworkAnalysis.Count -gt 0) {
            Write-Host "`nCross-Framework Gaps:" -ForegroundColor Cyan
            $report.CrossFrameworkAnalysis | ForEach-Object {
                Write-Host "  $($_.SecurityArea): $($_.GapCount) gap(s) across $($_.AffectedFrameworks.Count) framework(s)" -ForegroundColor Yellow
            }
        }
        
        if ($report.RemediationPriorities.Count -gt 0) {
            Write-Host "`nTop Remediation Priorities:" -ForegroundColor Cyan
            $report.RemediationPriorities | Select-Object -First 5 | ForEach-Object {
                Write-Host "  [$($_.Severity)] $($_.ControlID) - $($_.ControlName)" -ForegroundColor White
            }
        }
        
        if ($report.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $report.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $report
    }
}

# Helper function to generate HTML report
function Generate-ComplianceHTML {
    param($Report)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - $($Report.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-label { font-weight: bold; color: #7f8c8d; }
        .metric-value { font-size: 24px; font-weight: bold; }
        .pass { color: #27ae60; }
        .marginal { color: #f39c12; }
        .fail { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .critical { background: #e74c3c; color: white; padding: 2px 8px; border-radius: 3px; }
        .high { background: #e67e22; color: white; padding: 2px 8px; border-radius: 3px; }
        .medium { background: #f39c12; color: white; padding: 2px 8px; border-radius: 3px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Assessment Report</h1>
        <p><strong>Computer:</strong> $($Report.ComputerName) | <strong>Date:</strong> $($Report.ReportDate)</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-label">Overall Compliance</div>
                <div class="metric-value $(if($Report.ExecutiveSummary.OverallCompliance -ge 80){'pass'}elseif($Report.ExecutiveSummary.OverallCompliance -ge 60){'marginal'}else{'fail'})">
                    $($Report.ExecutiveSummary.OverallCompliance)%
                </div>
            </div>
            <div class="metric">
                <div class="metric-label">Total Controls</div>
                <div class="metric-value">$($Report.ExecutiveSummary.TotalControls)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Compliant</div>
                <div class="metric-value pass">$($Report.ExecutiveSummary.CompliantControls)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Non-Compliant</div>
                <div class="metric-value fail">$($Report.ExecutiveSummary.NonCompliantControls)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Critical Gaps</div>
                <div class="metric-value fail">$($Report.ExecutiveSummary.CriticalGaps)</div>
            </div>
        </div>
        
        <h2>Framework Results</h2>
        <table>
            <tr>
                <th>Framework</th>
                <th>Compliance</th>
                <th>Total Controls</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Status</th>
            </tr>
"@
    
    foreach ($fw in $Report.Frameworks) {
        $statusClass = if ($fw.Status -eq 'Pass') { 'pass' } elseif ($fw.Status -eq 'Marginal') { 'marginal' } else { 'fail' }
        $html += @"
            <tr>
                <td><strong>$($fw.Framework)</strong></td>
                <td class="$statusClass"><strong>$($fw.CompliancePercentage)%</strong></td>
                <td>$($fw.TotalControls)</td>
                <td class="pass">$($fw.Passed)</td>
                <td class="fail">$($fw.Failed)</td>
                <td class="$statusClass">$($fw.Status)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <h2>Top Remediation Priorities</h2>
        <table>
            <tr>
                <th>Priority</th>
                <th>Framework</th>
                <th>Control</th>
                <th>Remediation</th>
            </tr>
"@
    
    foreach ($priority in ($Report.RemediationPriorities | Select-Object -First 10)) {
        $severityClass = $priority.Severity.ToLower()
        $html += @"
            <tr>
                <td><span class="$severityClass">$($priority.Severity)</span></td>
                <td>$($priority.Framework)</td>
                <td><strong>$($priority.ControlID)</strong><br/>$($priority.ControlName)</td>
                <td>$($priority.Remediation)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <h2>Recommendations</h2>
        <ul>
"@
    
    foreach ($rec in $Report.Recommendations) {
        $html += "            <li>$rec</li>`n"
    }
    
    $html += @"
        </ul>
        
        <div class="footer">
            Generated by WindowsSecurityAudit Module | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}