function Export-SecurityReport {
    <#
    .SYNOPSIS
        Generates comprehensive security assessment reports
    .DESCRIPTION
        Creates detailed security reports in multiple formats (HTML, PDF, CSV, JSON)
        with findings, recommendations, and executive summaries
    .PARAMETER ReportType
        Type of report: Executive, Technical, or Compliance
    .PARAMETER Format
        Output format: HTML, JSON, CSV, or All
    .PARAMETER OutputPath
        Path to save the report
    .PARAMETER IncludeCharts
        Include visual charts and graphs in HTML reports
    .EXAMPLE
        Export-SecurityReport -ReportType Technical -Format HTML -OutputPath "C:\Reports"
        Export-SecurityReport -ReportType Executive -Format All -IncludeCharts
    .OUTPUTS
        String path to generated report
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Executive', 'Technical', 'Compliance')]
        [string]$ReportType,
        
        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML',
        
        [Parameter()]
        [string]$OutputPath = "C:\SecurityReports",
        
        [Parameter()]
        [switch]$IncludeCharts
    )
    
    begin {
        Write-Host "Generating $ReportType Security Report..." -ForegroundColor Cyan
        
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $reportBaseName = "SecurityReport_${ReportType}_$timestamp"
    }
    
    process {
        try {
            Write-Host "Collecting security data..." -ForegroundColor Yellow
            
            # Collect all security data
            $baseline = Get-SecurityBaseline
            $systemInfo = Get-SystemInfo
            $persistence = Find-PersistenceMechanisms
            $processes = Find-SuspiciousProcesses
            $network = Find-NetworkAnomalies -IncludeEstablished
            $auth = Find-SuspiciousAuthentication -Hours 168
            $eventLog = Get-EventLogAnalysis -Hours 168
            $registry = Get-RegistryAnalysis -IncludeAutoRun
            
            # Build report data structure
            $reportData = [PSCustomObject]@{
                ReportType = $ReportType
                GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                ComputerName = $env:COMPUTERNAME
                GeneratedBy = $env:USERNAME
                SecurityScore = $baseline.SecurityScore
                Summary = @{
                    CriticalFindings = 0
                    HighFindings = 0
                    MediumFindings = 0
                    LowFindings = 0
                }
                Findings = @()
                Recommendations = @()
                Details = @{
                    Baseline = $baseline
                    SystemInfo = $systemInfo
                    Persistence = $persistence
                    Processes = $processes
                    Network = $network
                    Authentication = $auth
                    EventLog = $eventLog
                    Registry = $registry
                }
            }
            
            # Analyze findings and create recommendations
            Write-Host "Analyzing findings..." -ForegroundColor Yellow
            
            # Critical findings
            if ($baseline.SecurityScore -lt 50) {
                $reportData.Summary.CriticalFindings++
                $reportData.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Category = 'Security Baseline'
                    Finding = "Security score is critically low: $($baseline.SecurityScore)/100"
                    Impact = 'System is highly vulnerable to attacks'
                    Recommendation = 'Immediate remediation required'
                }
            }
            
            if ($persistence.SuspiciousCount -gt 5) {
                $reportData.Summary.HighFindings++
                $reportData.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'Persistence'
                    Finding = "$($persistence.SuspiciousCount) suspicious persistence mechanisms detected"
                    Impact = 'Potential malware or unauthorized software present'
                    Recommendation = 'Review and remove unauthorized persistence mechanisms'
                }
            }
            
            if ($processes.Count -gt 0) {
               $processArray = @($processes)
$highSeverityProcs = @($processArray | Where-Object { $_.SuspicionScore -ge 70 })
if ($highSeverityProcs.Count -gt 0) {
    $reportData.Summary.HighFindings++
    $reportData.Findings += [PSCustomObject]@{
        Severity = 'High'
        Category = 'Processes'
        Finding = "$($highSeverityProcs.Count) highly suspicious processes running"
        Impact = 'Potential active threat on system'
        Recommendation = 'Investigate and terminate malicious processes'
    }
}
            }
            
            if ($auth.Statistics.TotalLockouts -gt 0) {
                $reportData.Summary.MediumFindings++
                $reportData.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Authentication'
                    Finding = "$($auth.Statistics.TotalLockouts) account lockouts detected"
                    Impact = 'Possible brute force attempts'
                    Recommendation = 'Review failed authentication events and implement MFA'
                }
            }
            
            if ($network.TotalAnomalies -gt 10) {
                $reportData.Summary.MediumFindings++
                $reportData.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Network'
                    Finding = "$($network.TotalAnomalies) network anomalies detected"
                    Impact = 'Unusual network activity may indicate compromise'
                    Recommendation = 'Review network connections and implement network monitoring'
                }
            }
            
            # Generate recommendations based on report type
            if ($ReportType -eq 'Executive') {
                $reportData.Recommendations = @(
                    "Overall Security Score: $($baseline.SecurityScore)/100 - $(if ($baseline.SecurityScore -ge 80) { 'Good' } elseif ($baseline.SecurityScore -ge 60) { 'Fair' } else { 'Poor' })",
                    "Critical Issues: $($reportData.Summary.CriticalFindings)",
                    "High Priority Issues: $($reportData.Summary.HighFindings)",
                    "Immediate action required on critical and high priority items",
                    "Regular security assessments recommended"
                )
            }
            elseif ($ReportType -eq 'Technical') {
                $reportData.Recommendations = @(
                    "Enable PowerShell logging and monitoring",
                    "Implement application whitelisting",
                    "Review and harden security baselines",
                    "Enable Windows Defender real-time protection",
                    "Implement network segmentation",
                    "Deploy EDR solution for advanced threat detection",
                    "Regular vulnerability assessments",
                    "Incident response plan testing"
                )
            }
            else {  # Compliance
                $reportData.Recommendations = @(
                    "Document all security controls",
                    "Implement continuous compliance monitoring",
                    "Regular audit log reviews",
                    "Access control reviews",
                    "Patch management process",
                    "Security awareness training",
                    "Incident response procedures",
                    "Business continuity planning"
                )
            }
            
            # Generate reports in requested formats
            $generatedFiles = @()
            
            if ($Format -in @('JSON', 'All')) {
                Write-Host "Generating JSON report..." -ForegroundColor Yellow
                $jsonPath = Join-Path $OutputPath "$reportBaseName.json"
                $reportData | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                $generatedFiles += $jsonPath
            }
            
            if ($Format -in @('CSV', 'All')) {
                Write-Host "Generating CSV reports..." -ForegroundColor Yellow
                $csvPath = Join-Path $OutputPath "${reportBaseName}_Findings.csv"
                $reportData.Findings | Export-Csv $csvPath -NoTypeInformation
                $generatedFiles += $csvPath
            }
            
            if ($Format -in @('HTML', 'All')) {
                Write-Host "Generating HTML report..." -ForegroundColor Yellow
                
                # Create HTML report
                $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportType Security Report - $($reportData.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .score { font-size: 48px; font-weight: bold; color: #3498db; }
        .finding { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #e67e22; }
        .medium { border-left-color: #f39c12; }
        .low { border-left-color: #95a5a6; }
        table { width: 100%; border-collapse: collapse; background-color: white; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        .recommendation { background-color: #ecf0f1; padding: 10px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>$ReportType Security Assessment Report</h1>
        <p>Computer: $($reportData.ComputerName)</p>
        <p>Generated: $($reportData.GeneratedDate)</p>
        <p>Generated By: $($reportData.GeneratedBy)</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="score">Security Score: $($reportData.SecurityScore)/100</div>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>Critical</td>
                <td style="color: #e74c3c; font-weight: bold;">$($reportData.Summary.CriticalFindings)</td>
            </tr>
            <tr>
                <td>High</td>
                <td style="color: #e67e22; font-weight: bold;">$($reportData.Summary.HighFindings)</td>
            </tr>
            <tr>
                <td>Medium</td>
                <td style="color: #f39c12; font-weight: bold;">$($reportData.Summary.MediumFindings)</td>
            </tr>
            <tr>
                <td>Low</td>
                <td style="color: #95a5a6;">$($reportData.Summary.LowFindings)</td>
            </tr>
        </table>
    </div>
    
    <div class="summary">
        <h2>Key Findings</h2>
        $($reportData.Findings | ForEach-Object {
            $class = $_.Severity.ToLower()
            "<div class='finding $class'>
                <h3>[$($_.Severity)] $($_.Category)</h3>
                <p><strong>Finding:</strong> $($_.Finding)</p>
                <p><strong>Impact:</strong> $($_.Impact)</p>
                <p><strong>Recommendation:</strong> $($_.Recommendation)</p>
            </div>"
        } | Out-String)
    </div>
    
    <div class="summary">
        <h2>Recommendations</h2>
        $($reportData.Recommendations | ForEach-Object {
            "<div class='recommendation'>$_</div>"
        } | Out-String)
    </div>
    
    <div class="summary">
        <h2>System Details</h2>
        <table>
            <tr><th>Component</th><th>Status</th></tr>
            <tr><td>Windows Defender</td><td>$($baseline.WindowsDefender.RealTimeProtectionEnabled)</td></tr>
            <tr><td>Firewall</td><td>$($baseline.Firewall[0].Enabled)</td></tr>
            <tr><td>UAC</td><td>$($baseline.UAC.EnableLUA -eq 1)</td></tr>
            <tr><td>Persistence Mechanisms</td><td>$($persistence.TotalFindings) total ($($persistence.SuspiciousCount) suspicious)</td></tr>
            <tr><td>Network Anomalies</td><td>$($network.TotalAnomalies)</td></tr>
            <tr><td>Failed Logons</td><td>$($auth.Statistics.TotalFailedLogons)</td></tr>
        </table>
    </div>
    
    <div class="summary">
        <p><em>This report was generated by WindowsSecurityAudit PowerShell Module</em></p>
    </div>
</body>
</html>
"@
                
                $htmlPath = Join-Path $OutputPath "$reportBaseName.html"
                $htmlContent | Out-File $htmlPath -Encoding UTF8
                $generatedFiles += $htmlPath
            }
            
        }
        catch {
            Write-Error "Error generating report: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== REPORT GENERATION COMPLETE ===" -ForegroundColor Green
        Write-Host "Generated Files:" -ForegroundColor Cyan
        foreach ($file in $generatedFiles) {
            Write-Host "  - $file" -ForegroundColor White
        }
        
        # Open HTML report if generated
        if ($generatedFiles -match '\.html$') {
            $htmlFile = $generatedFiles | Where-Object { $_ -match '\.html$' } | Select-Object -First 1
            Start-Process $htmlFile
        }
        
        return $generatedFiles
    }
}