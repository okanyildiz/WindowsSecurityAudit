function Export-SecurityReport {
    <#
    .SYNOPSIS
        Generates comprehensive security assessment reports
    .DESCRIPTION
        Creates detailed security reports in multiple formats (HTML, JSON, CSV, NDJSON, CEF)
        with findings, recommendations, and executive summaries. NDJSON and CEF formats
        produce SIEM-ready finding exports via ConvertTo-SiemEvent (.ndjson / .cef files).
        When -StreamTo is specified, findings are additionally streamed live to a SIEM
        HTTP endpoint (Splunk HEC, Microsoft Sentinel, or a generic webhook) via
        Send-SiemEvent after the report files are written. A streaming failure never
        fails report generation; the outcome is noted on the console and in the
        StreamResult property of the output.
    .PARAMETER ReportType
        Type of report: Executive, Technical, or Compliance
    .PARAMETER Format
        Output format: HTML, JSON, CSV, NDJSON, CEF, or All
    .PARAMETER OutputPath
        Path to save the report
    .PARAMETER IncludeCharts
        Include visual charts and graphs in HTML reports
    .PARAMETER NoAutoOpen
        Do not automatically open the HTML report after generation.
        Use for headless or SYSTEM-context runs where no interactive session exists.
    .PARAMETER StreamTo
        Optional SIEM destination type to stream findings to after the report files are
        written: SplunkHEC, Sentinel, or GenericWebhook. Requires -StreamUri.
    .PARAMETER StreamUri
        SIEM endpoint URL used with -StreamTo.
    .PARAMETER StreamToken
        Credential for the streaming endpoint (Splunk HEC token or Sentinel shared key).
        Sent only in request headers, never logged in full.
    .PARAMETER StreamFormat
        Event format for streaming: NDJSON (default) or CEF.
    .EXAMPLE
        Export-SecurityReport -ReportType Technical -Format HTML -OutputPath "C:\Reports"
        Export-SecurityReport -ReportType Executive -Format All -IncludeCharts
        Export-SecurityReport -ReportType Technical -Format NDJSON -NoAutoOpen
        Export-SecurityReport -ReportType Technical -Format JSON -NoAutoOpen -StreamTo SplunkHEC -StreamUri "https://splunk.contoso.com:8088/services/collector" -StreamToken $hecToken
    .OUTPUTS
        String path(s) to generated report files. When -StreamTo is specified, returns a
        PSCustomObject with Files (string array) and StreamResult (PSCustomObject with
        BatchesSent, EventsSent, Failed, DurationSec; $null if streaming did not run)
        properties.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Executive', 'Technical', 'Compliance')]
        [string]$ReportType,
        
        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'NDJSON', 'CEF', 'All')]
        [string]$Format = 'HTML',
        
        [Parameter()]
        [string]$OutputPath = "C:\SecurityReports",
        
        [Parameter()]
        [switch]$IncludeCharts,
        
        [Parameter()]
        [switch]$NoAutoOpen,

        [Parameter()]
        [ValidateSet('SplunkHEC', 'Sentinel', 'GenericWebhook')]
        [string]$StreamTo,

        [Parameter()]
        [string]$StreamUri,

        [Parameter()]
        [string]$StreamToken,

        [Parameter()]
        [ValidateSet('NDJSON', 'CEF')]
        [string]$StreamFormat = 'NDJSON'
    )
    
    begin {
        Write-Host "Generating $ReportType Security Report..." -ForegroundColor Cyan
        
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $reportBaseName = "SecurityReport_${ReportType}_$timestamp"
        $streamResult = $null
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
            
            if (@($processes).Count -gt 0) {
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
            
            if ($Format -in @('NDJSON', 'All')) {
                Write-Host "Generating NDJSON SIEM export..." -ForegroundColor Yellow
                try {
                    $ndjsonPath = Join-Path $OutputPath "${reportBaseName}_findings.ndjson"
                    $ndjsonLines = @($reportData.Findings | ConvertTo-SiemEvent -Format NDJSON)
                    $ndjsonLines | Out-File $ndjsonPath -Encoding UTF8
                    $generatedFiles += $ndjsonPath
                }
                catch {
                    Write-Warning "Could not generate NDJSON export: $_"
                }
            }
            
            if ($Format -in @('CEF', 'All')) {
                Write-Host "Generating CEF SIEM export..." -ForegroundColor Yellow
                try {
                    $cefPath = Join-Path $OutputPath "${reportBaseName}_findings.cef"
                    $cefLines = @($reportData.Findings | ConvertTo-SiemEvent -Format CEF)
                    $cefLines | Out-File $cefPath -Encoding UTF8
                    $generatedFiles += $cefPath
                }
                catch {
                    Write-Warning "Could not generate CEF export: $_"
                }
            }
            
            if ($Format -in @('HTML', 'All')) {
                Write-Host "Generating HTML report..." -ForegroundColor Yellow
                
                # Build findings-by-severity bar chart (inline SVG) if requested
                $chartHtml = ''
                if ($IncludeCharts) {
                    $severityData = @(
                        @{ Label = 'Critical'; Count = $reportData.Summary.CriticalFindings; Color = '#e74c3c' }
                        @{ Label = 'High';     Count = $reportData.Summary.HighFindings;     Color = '#e67e22' }
                        @{ Label = 'Medium';   Count = $reportData.Summary.MediumFindings;   Color = '#f39c12' }
                        @{ Label = 'Low';      Count = $reportData.Summary.LowFindings;      Color = '#95a5a6' }
                    )
                    
                    $maxCount = ($severityData | ForEach-Object { $_.Count } | Measure-Object -Maximum).Maximum
                    if ($null -eq $maxCount -or $maxCount -lt 1) { $maxCount = 1 }
                    
                    $chartWidth = 500
                    $barHeight = 30
                    $barSpacing = 15
                    $labelWidth = 80
                    $maxBarWidth = $chartWidth - $labelWidth - 50
                    $chartHeight = ($barHeight + $barSpacing) * $severityData.Count + 10
                    
                    $chartHtml = "<div class='summary'><h2>Findings by Severity</h2>`n"
                    $chartHtml += "<svg width='$chartWidth' height='$chartHeight' xmlns='http://www.w3.org/2000/svg' role='img' aria-label='Findings by severity bar chart'>`n"
                    
                    $barY = 5
                    foreach ($item in $severityData) {
                        $barWidth = [math]::Round(($item.Count / $maxCount) * $maxBarWidth)
                        if ($item.Count -gt 0 -and $barWidth -lt 2) { $barWidth = 2 }
                        if ($barWidth -lt 0) { $barWidth = 0 }
                        
                        $chartHtml += "<text x='0' y='$($barY + 20)' font-size='13' fill='#333'>$($item.Label)</text>`n"
                        $chartHtml += "<rect x='$labelWidth' y='$barY' width='$barWidth' height='$barHeight' fill='$($item.Color)' rx='3' />`n"
                        $chartHtml += "<text x='$($labelWidth + $barWidth + 8)' y='$($barY + 20)' font-size='13' font-weight='bold' fill='#333'>$($item.Count)</text>`n"
                        
                        $barY += $barHeight + $barSpacing
                    }
                    
                    $chartHtml += "</svg></div>"
                }
                
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
    
    $chartHtml
    
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
            <tr><td>Windows Defender</td><td>$(if ($null -ne $baseline.WindowsDefender -and $baseline.WindowsDefender.PSObject.Properties['RealTimeProtectionEnabled']) { $baseline.WindowsDefender.RealTimeProtectionEnabled } else { $baseline.WindowsDefender })</td></tr>
            <tr><td>Firewall</td><td>$(if ($baseline.Firewall -is [array] -and $baseline.Firewall.Count -gt 0) { $baseline.Firewall[0].Enabled } else { $baseline.Firewall })</td></tr>
            <tr><td>UAC</td><td>$(if ($null -ne $baseline.UAC -and $baseline.UAC.PSObject.Properties['EnableLUA']) { $baseline.UAC.EnableLUA -eq 1 } else { $baseline.UAC })</td></tr>
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

            if (-not [string]::IsNullOrWhiteSpace($StreamTo)) {
                Write-Host "Streaming findings to $StreamTo endpoint..." -ForegroundColor Yellow
                try {
                    if ([string]::IsNullOrWhiteSpace($StreamUri)) {
                        Write-Warning "StreamTo was specified without StreamUri; skipping SIEM streaming."
                    }
                    else {
                        $streamParams = @{
                            Destination = $StreamTo
                            Uri         = $StreamUri
                            Format      = $StreamFormat
                        }
                        if (-not [string]::IsNullOrWhiteSpace($StreamToken)) {
                            $streamParams['Token'] = $StreamToken
                        }
                        $streamResult = @($reportData.Findings) | Send-SiemEvent @streamParams
                        Write-Host "Streamed $($streamResult.EventsSent) of $(@($reportData.Findings).Count) finding event(s) to $StreamTo ($($streamResult.Failed) failed)." -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "SIEM streaming failed; report files were still generated: $_"
                }
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

        if (-not [string]::IsNullOrWhiteSpace($StreamTo)) {
            if ($null -ne $streamResult) {
                Write-Host "SIEM Stream ($StreamTo): $($streamResult.EventsSent) event(s) sent in $($streamResult.BatchesSent) batch(es), $($streamResult.Failed) failed, $($streamResult.DurationSec)s" -ForegroundColor Cyan
            }
            else {
                Write-Host "SIEM Stream ($StreamTo): not delivered (see warnings above)" -ForegroundColor Yellow
            }
        }
        
        # Open HTML report if generated
        if (-not $NoAutoOpen -and @($generatedFiles | Where-Object { $_ -match '\.html$' }).Count -gt 0) {
            $htmlFile = @($generatedFiles | Where-Object { $_ -match '\.html$' }) | Select-Object -First 1
            try {
                Start-Process $htmlFile
            }
            catch {
                Write-Warning "Could not auto-open HTML report: $_"
            }
        }
        
        if (-not [string]::IsNullOrWhiteSpace($StreamTo)) {
            return [PSCustomObject]@{
                Files        = $generatedFiles
                StreamResult = $streamResult
            }
        }

        return $generatedFiles
    }
}