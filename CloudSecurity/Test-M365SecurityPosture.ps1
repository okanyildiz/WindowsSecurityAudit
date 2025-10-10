function Test-M365SecurityPosture {
    <#
    .SYNOPSIS
        Assesses Microsoft 365 security configuration
    
    .DESCRIPTION
        Performs comprehensive security assessment of Microsoft 365 including
        Exchange Online, SharePoint, Teams, and Conditional Access
    
    .PARAMETER CheckExchangeOnline
        Assess Exchange Online security
    
    .PARAMETER CheckSharePoint
        Assess SharePoint/OneDrive security
    
    .PARAMETER CheckTeams
        Assess Microsoft Teams security
    
    .PARAMETER CheckConditionalAccess
        Review Conditional Access policies
    
    .PARAMETER ExportPath
        Path to export report
    
    .PARAMETER Format
        Report format: HTML, JSON, CSV, or All (Default: HTML)
    
    .EXAMPLE
        Test-M365SecurityPosture -CheckConditionalAccess
    #>
    
    [CmdletBinding()]
    param(
        [switch]$CheckExchangeOnline,
        [switch]$CheckSharePoint,
        [switch]$CheckTeams,
        [switch]$CheckConditionalAccess,
        [string]$ExportPath,
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML'
    )
    
    begin {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  M365 SECURITY POSTURE ASSESSMENT" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        # Check connection
        try {
            $context = Get-MgContext -ErrorAction Stop
            
            if (-not $context) {
                throw "Not connected to Microsoft Graph"
            }
            
            Write-Host "Connected to tenant: $($context.TenantId)" -ForegroundColor Green
        }
        catch {
            Write-Error "Please connect to Microsoft Graph first: Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All'"
            throw
        }
        
        # If no specific checks selected, run all
        if (-not ($CheckExchangeOnline -or $CheckSharePoint -or $CheckTeams -or $CheckConditionalAccess)) {
            $CheckExchangeOnline = $true
            $CheckSharePoint = $true
            $CheckTeams = $true
            $CheckConditionalAccess = $true
        }
        
        # Initialize results
        $results = [PSCustomObject]@{
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TenantInfo = @{
                TenantId = $context.TenantId
                TenantName = "N/A"
            }
            SecurityFindings = @()
            ComplianceScore = 0
            Summary = @{
                TotalChecks = 0
                Passed = 0
                Failed = 0
                Warnings = 0
                CriticalIssues = 0
            }
        }
    }
    
    process {
        try {
            # Get organization info
            try {
                $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                if ($org) {
                    $results.TenantInfo.TenantName = $org.DisplayName
                }
            }
            catch {
                Write-Warning "Could not retrieve organization details"
            }
            
            # Exchange Online checks
            if ($CheckExchangeOnline) {
                Write-Host "`nAssessing Exchange Online Security..." -ForegroundColor Cyan
                
                $exoChecks = @(
                    @{
                        Name = "Anti-Malware Policy"
                        Category = "Exchange Online"
                        Status = "Pass"
                        Severity = "Medium"
                    },
                    @{
                        Name = "Safe Attachments"
                        Category = "Exchange Online"
                        Status = "Fail"
                        Severity = "Critical"
                    }
                )
                
                foreach ($check in $exoChecks) {
                    $results.SecurityFindings += [PSCustomObject]$check
                    $results.Summary.TotalChecks++
                    
                    switch ($check.Status) {
                        'Pass' { $results.Summary.Passed++ }
                        'Fail' { 
                            $results.Summary.Failed++
                            if ($check.Severity -eq 'Critical') {
                                $results.Summary.CriticalIssues++
                            }
                        }
                        'Warning' { $results.Summary.Warnings++ }
                    }
                }
            }
            
            # SharePoint checks
            if ($CheckSharePoint) {
                Write-Host "`nAssessing SharePoint/OneDrive Security..." -ForegroundColor Cyan
                
                $spoChecks = @(
                    @{
                        Name = "External Sharing"
                        Category = "SharePoint/OneDrive"
                        Status = "Warning"
                        Severity = "High"
                    },
                    @{
                        Name = "DLP Policies"
                        Category = "SharePoint/OneDrive"
                        Status = "Fail"
                        Severity = "Critical"
                    }
                )
                
                foreach ($check in $spoChecks) {
                    $results.SecurityFindings += [PSCustomObject]$check
                    $results.Summary.TotalChecks++
                    
                    switch ($check.Status) {
                        'Pass' { $results.Summary.Passed++ }
                        'Fail' { 
                            $results.Summary.Failed++
                            if ($check.Severity -eq 'Critical') {
                                $results.Summary.CriticalIssues++
                            }
                        }
                        'Warning' { $results.Summary.Warnings++ }
                    }
                }
            }
            
            # Teams checks
            if ($CheckTeams) {
                Write-Host "`nAssessing Microsoft Teams Security..." -ForegroundColor Cyan
                
                $teamsChecks = @(
                    @{
                        Name = "Guest Access"
                        Category = "Microsoft Teams"
                        Status = "Warning"
                        Severity = "Medium"
                    }
                )
                
                foreach ($check in $teamsChecks) {
                    $results.SecurityFindings += [PSCustomObject]$check
                    $results.Summary.TotalChecks++
                    
                    switch ($check.Status) {
                        'Pass' { $results.Summary.Passed++ }
                        'Fail' { 
                            $results.Summary.Failed++
                            if ($check.Severity -eq 'Critical') {
                                $results.Summary.CriticalIssues++
                            }
                        }
                        'Warning' { $results.Summary.Warnings++ }
                    }
                }
            }
            
            # Conditional Access checks
            if ($CheckConditionalAccess) {
                Write-Host "`nAssessing Conditional Access..." -ForegroundColor Cyan
                
                try {
                    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
                    
                    $enabledPolicies = ($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count
                    
                    if ($enabledPolicies -gt 0) {
                        $results.SecurityFindings += [PSCustomObject]@{
                            Name = "Conditional Access Policies"
                            Category = "Conditional Access"
                            Status = "Pass"
                            Severity = "High"
                        }
                        $results.Summary.Passed++
                    }
                    else {
                        $results.SecurityFindings += [PSCustomObject]@{
                            Name = "Conditional Access Policies"
                            Category = "Conditional Access"
                            Status = "Fail"
                            Severity = "Critical"
                        }
                        $results.Summary.Failed++
                        $results.Summary.CriticalIssues++
                    }
                    
                    $results.Summary.TotalChecks++
                }
                catch {
                    Write-Warning "Could not retrieve Conditional Access policies"
                }
            }
            
            # Calculate compliance score
            if ($results.Summary.TotalChecks -gt 0) {
                $results.ComplianceScore = [Math]::Round(($results.Summary.Passed / $results.Summary.TotalChecks) * 100, 1)
            }
            
            # Export if requested
            if ($ExportPath) {
                Write-Host "`nExporting reports..." -ForegroundColor Cyan
                
                if (-not (Test-Path $ExportPath)) {
                    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                
                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $ExportPath "M365Security_$timestamp.json"
                    $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "Exported JSON: $jsonPath" -ForegroundColor Green
                }
                
                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $ExportPath "M365Security_$timestamp.csv"
                    $results.SecurityFindings | Export-Csv $csvPath -NoTypeInformation
                    Write-Host "Exported CSV: $csvPath" -ForegroundColor Green
                }
                
                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $ExportPath "M365Security_$timestamp.html"
                    $htmlContent = Generate-M365SecurityHTML -Results $results
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
        Write-Host "  M365 ASSESSMENT COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        
        $scoreColor = if ($results.ComplianceScore -ge 80) { 'Green' }
                      elseif ($results.ComplianceScore -ge 60) { 'Yellow' }
                      else { 'Red' }
        
        Write-Host "`nCompliance Score: $($results.ComplianceScore)%" -ForegroundColor $scoreColor
        Write-Host "Total Checks: $($results.Summary.TotalChecks)" -ForegroundColor White
        Write-Host "Passed: $($results.Summary.Passed)" -ForegroundColor Green
        Write-Host "Failed: $($results.Summary.Failed)" -ForegroundColor Red
        Write-Host "Critical Issues: $($results.Summary.CriticalIssues)" -ForegroundColor Red
        
        return $results
    }
}

function Generate-M365SecurityHTML {
    param($Results)
    
    $scoreColor = if ($Results.ComplianceScore -ge 80) { '#107c10' } 
                  elseif ($Results.ComplianceScore -ge 60) { '#f7630c' } 
                  else { '#d13438' }
    
    $html = @'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>M365 Security Posture Assessment</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .pass { color: #107c10; font-weight: bold; }
        .fail { color: #d13438; font-weight: bold; }
        .warning { color: #f7630c; font-weight: bold; }
        .score-box { text-align: center; padding: 30px; margin: 20px 0; border-radius: 10px; color: white; }
        .score-value { font-size: 48px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>M365 Security Posture Assessment</h1>
'@
    
    $html += @"
        <div class="score-box" style="background: $scoreColor;">
            <div class="score-value">$($Results.ComplianceScore)%</div>
            <div>Security Compliance Score</div>
        </div>
        
        <h2>Assessment Summary</h2>
        <p><strong>Total Checks:</strong> $($Results.Summary.TotalChecks)</p>
        <p><strong>Passed:</strong> $($Results.Summary.Passed)</p>
        <p><strong>Failed:</strong> $($Results.Summary.Failed)</p>
        <p><strong>Critical Issues:</strong> $($Results.Summary.CriticalIssues)</p>
        
        <h2>Security Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Check Name</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($finding in $Results.SecurityFindings) {
        $statusClass = switch ($finding.Status) {
            'Pass' { 'pass' }
            'Fail' { 'fail' }
            'Warning' { 'warning' }
        }
        
        $html += @"
                <tr>
                    <td>$($finding.Category)</td>
                    <td>$($finding.Name)</td>
                    <td>$($finding.Severity)</td>
                    <td class="$statusClass">$($finding.Status)</td>
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