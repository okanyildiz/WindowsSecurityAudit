function Add-M365Finding {
    <#
    .SYNOPSIS
        Records a single M365 posture finding and updates summary counters.
        'NotEvaluated' findings are tracked separately and never enter the score.
    #>
    param(
        [Parameter(Mandatory)]
        $Results,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'NotEvaluated')]
        [string]$Status,

        [string]$Actual = "",
        [string]$Expected = ""
    )

    $Results.SecurityFindings += [PSCustomObject]@{
        Name     = $Name
        Category = $Category
        Status   = $Status
        Severity = $Severity
        Actual   = $Actual
        Expected = $Expected
    }

    if ($Status -eq 'NotEvaluated') {
        $Results.Summary.NotEvaluated++
        return
    }

    $Results.Summary.TotalChecks++
    switch ($Status) {
        'Pass' { $Results.Summary.Passed++ }
        'Fail' {
            $Results.Summary.Failed++
            if ($Severity -eq 'Critical') {
                $Results.Summary.CriticalIssues++
            }
        }
        'Warning' { $Results.Summary.Warnings++ }
    }
}

function Test-M365SecurityPosture {
    <#
    .SYNOPSIS
        Assesses Microsoft 365 security configuration
    
    .DESCRIPTION
        Performs a security assessment of Microsoft 365 against live tenant data
        retrieved via Microsoft Graph (Conditional Access policies, security
        defaults). Checks whose configuration is not exposed through Microsoft
        Graph (Exchange Online, SharePoint, Teams workload settings) are reported
        as NotEvaluated with the API required to assess them — results are never
        fabricated. The compliance score is computed over evaluated checks only;
        if no check could be evaluated, OverallScore is $null and OverallStatus
        is 'NotEvaluated'.
    
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
        
        # Live tenant data requires a Microsoft Graph connection. Without one the
        # function must not invent results: every check degrades to NotEvaluated.
        $graphConnected = $false
        $tenantId = 'NotConnected'
        try {
            $context = Get-MgContext -ErrorAction Stop
            if ($context) {
                $graphConnected = $true
                if ($context.TenantId) { $tenantId = $context.TenantId }
                Write-Host "Connected to tenant: $tenantId" -ForegroundColor Green
            }
        }
        catch {
            Write-Verbose "Get-MgContext failed: $_"
        }
        
        if (-not $graphConnected) {
            Write-Warning "Not connected to Microsoft Graph. No tenant data will be queried and every check will be reported as NotEvaluated. Connect first: Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All'"
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
                TenantId = $tenantId
                TenantName = "N/A"
            }
            SecurityFindings = @()
            ComplianceScore = $null
            OverallScore = $null
            OverallStatus = 'NotEvaluated'
            EvaluatedCount = 0
            NotEvaluatedCount = 0
            Summary = @{
                TotalChecks = 0
                Passed = 0
                Failed = 0
                Warnings = 0
                CriticalIssues = 0
                NotEvaluated = 0
            }
        }
    }
    
    process {
        try {
            $notConnectedReason = "Not evaluated — not connected to Microsoft Graph (run Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All')"
            
            # Get organization info (live query, non-fatal)
            if ($graphConnected) {
                try {
                    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                    if ($org) {
                        $results.TenantInfo.TenantName = $org.DisplayName
                    }
                }
                catch {
                    Write-Warning "Could not retrieve organization details: $($_.Exception.Message)"
                }
            }
            
            # Exchange Online checks. Exchange/Defender policy configuration is not
            # exposed through the Microsoft Graph cmdlets used by this module, so
            # these checks are honestly reported as NotEvaluated with the API that
            # would be required — never fabricated.
            if ($CheckExchangeOnline) {
                Write-Host "`nAssessing Exchange Online Security..." -ForegroundColor Cyan
                
                if ($graphConnected) {
                    Add-M365Finding -Results $results -Name "Anti-Malware Policy" -Category "Exchange Online" -Severity "Medium" -Status "NotEvaluated" -Actual "Not evaluated — requires Exchange Online PowerShell (Get-MalwareFilterPolicy); not exposed via Microsoft Graph" -Expected "Default anti-malware policy enabled"
                    Add-M365Finding -Results $results -Name "Safe Attachments" -Category "Exchange Online" -Severity "Critical" -Status "NotEvaluated" -Actual "Not evaluated — requires Exchange Online PowerShell (Get-SafeAttachmentPolicy / Get-SafeAttachmentRule); not exposed via Microsoft Graph" -Expected "Safe Attachments policy covering all users"
                }
                else {
                    Add-M365Finding -Results $results -Name "Anti-Malware Policy" -Category "Exchange Online" -Severity "Medium" -Status "NotEvaluated" -Actual $notConnectedReason
                    Add-M365Finding -Results $results -Name "Safe Attachments" -Category "Exchange Online" -Severity "Critical" -Status "NotEvaluated" -Actual $notConnectedReason
                }
            }
            
            # SharePoint checks
            if ($CheckSharePoint) {
                Write-Host "`nAssessing SharePoint/OneDrive Security..." -ForegroundColor Cyan
                
                if ($graphConnected) {
                    Add-M365Finding -Results $results -Name "External Sharing" -Category "SharePoint/OneDrive" -Severity "High" -Status "NotEvaluated" -Actual "Not evaluated — requires SharePoint Online Management Shell (Get-SPOTenant) or SharePoint admin API; not exposed via Microsoft Graph" -Expected "External sharing restricted to existing guests or disabled"
                    Add-M365Finding -Results $results -Name "DLP Policies" -Category "SharePoint/OneDrive" -Severity "Critical" -Status "NotEvaluated" -Actual "Not evaluated — requires Purview compliance PowerShell (Get-DlpCompliancePolicy); not exposed via Microsoft Graph" -Expected "At least one DLP policy covering SharePoint/OneDrive locations"
                }
                else {
                    Add-M365Finding -Results $results -Name "External Sharing" -Category "SharePoint/OneDrive" -Severity "High" -Status "NotEvaluated" -Actual $notConnectedReason
                    Add-M365Finding -Results $results -Name "DLP Policies" -Category "SharePoint/OneDrive" -Severity "Critical" -Status "NotEvaluated" -Actual $notConnectedReason
                }
            }
            
            # Teams checks
            if ($CheckTeams) {
                Write-Host "`nAssessing Microsoft Teams Security..." -ForegroundColor Cyan
                
                if ($graphConnected) {
                    Add-M365Finding -Results $results -Name "Guest Access" -Category "Microsoft Teams" -Severity "Medium" -Status "NotEvaluated" -Actual "Not evaluated — requires Microsoft Teams PowerShell (Get-CsTeamsClientConfiguration); not exposed via Microsoft Graph" -Expected "Guest access disabled or restricted per policy"
                }
                else {
                    Add-M365Finding -Results $results -Name "Guest Access" -Category "Microsoft Teams" -Severity "Medium" -Status "NotEvaluated" -Actual $notConnectedReason
                }
            }
            
            # Conditional Access checks (live Microsoft Graph queries)
            if ($CheckConditionalAccess) {
                Write-Host "`nAssessing Conditional Access..." -ForegroundColor Cyan
                
                if ($graphConnected) {
                    try {
                        $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
                        
                        $enabledPolicies = @($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count
                        
                        if ($enabledPolicies -gt 0) {
                            Add-M365Finding -Results $results -Name "Conditional Access Policies" -Category "Conditional Access" -Severity "High" -Status "Pass" -Actual "$enabledPolicies of $(@($caPolicies).Count) Conditional Access policies enabled" -Expected "At least one enabled Conditional Access policy"
                        }
                        else {
                            Add-M365Finding -Results $results -Name "Conditional Access Policies" -Category "Conditional Access" -Severity "Critical" -Status "Fail" -Actual "No enabled Conditional Access policies found ($( @($caPolicies).Count) total, none enabled)" -Expected "At least one enabled Conditional Access policy"
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve Conditional Access policies: $($_.Exception.Message)"
                        Add-M365Finding -Results $results -Name "Conditional Access Policies" -Category "Conditional Access" -Severity "Critical" -Status "NotEvaluated" -Actual "Not evaluated — Conditional Access query failed: $($_.Exception.Message)"
                    }
                    
                    try {
                        $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
                        
                        if ($secDefaults -and $secDefaults.IsEnabled) {
                            Add-M365Finding -Results $results -Name "Security Defaults" -Category "Conditional Access" -Severity "High" -Status "Pass" -Actual "Security Defaults are enabled" -Expected "Enabled, unless Conditional Access policies are in use"
                        }
                        else {
                            Add-M365Finding -Results $results -Name "Security Defaults" -Category "Conditional Access" -Severity "High" -Status "Warning" -Actual "Security Defaults are disabled" -Expected "Enabled, unless Conditional Access policies are in use"
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve Security Defaults policy: $($_.Exception.Message)"
                        Add-M365Finding -Results $results -Name "Security Defaults" -Category "Conditional Access" -Severity "High" -Status "NotEvaluated" -Actual "Not evaluated — Security Defaults query failed: $($_.Exception.Message)"
                    }
                }
                else {
                    Add-M365Finding -Results $results -Name "Conditional Access Policies" -Category "Conditional Access" -Severity "Critical" -Status "NotEvaluated" -Actual $notConnectedReason
                    Add-M365Finding -Results $results -Name "Security Defaults" -Category "Conditional Access" -Severity "High" -Status "NotEvaluated" -Actual $notConnectedReason
                }
            }
            
            # Calculate compliance score over evaluated checks only
            $results.EvaluatedCount = $results.Summary.TotalChecks
            $results.NotEvaluatedCount = $results.Summary.NotEvaluated
            
            if ($results.Summary.TotalChecks -gt 0) {
                $results.ComplianceScore = [Math]::Round(($results.Summary.Passed / $results.Summary.TotalChecks) * 100, 1)
                $results.OverallScore = $results.ComplianceScore
                $results.OverallStatus = if ($results.Summary.Failed -gt 0) { 'AttentionRequired' }
                                         elseif ($results.Summary.Warnings -gt 0) { 'Warning' }
                                         else { 'Pass' }
                
                if ($results.Summary.NotEvaluated -gt 0) {
                    Write-Warning "$($results.Summary.NotEvaluated) check(s) could not be evaluated and were excluded from the score. The score covers only the $($results.Summary.TotalChecks) evaluated check(s)."
                }
            }
            else {
                $results.ComplianceScore = $null
                $results.OverallScore = $null
                $results.OverallStatus = 'NotEvaluated'
                
                if (-not $graphConnected) {
                    Write-Warning "No security checks could be evaluated because there is no Microsoft Graph connection. OverallScore is null — no compliance score was computed."
                }
                else {
                    Write-Warning "No security checks could be evaluated (all queries failed). OverallScore is null — no compliance score was computed."
                }
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
        
        if ($null -ne $results.ComplianceScore) {
            $scoreColor = if ($results.ComplianceScore -ge 80) { 'Green' }
                          elseif ($results.ComplianceScore -ge 60) { 'Yellow' }
                          else { 'Red' }
            
            Write-Host "`nCompliance Score: $($results.ComplianceScore)% (over $($results.EvaluatedCount) evaluated check(s))" -ForegroundColor $scoreColor
        }
        else {
            Write-Host "`nCompliance Score: N/A — no checks could be evaluated" -ForegroundColor Yellow
        }
        
        Write-Host "Overall Status: $($results.OverallStatus)" -ForegroundColor White
        Write-Host "Total Checks: $($results.Summary.TotalChecks)" -ForegroundColor White
        Write-Host "Passed: $($results.Summary.Passed)" -ForegroundColor Green
        Write-Host "Failed: $($results.Summary.Failed)" -ForegroundColor Red
        Write-Host "Critical Issues: $($results.Summary.CriticalIssues)" -ForegroundColor Red
        Write-Host "Not Evaluated: $($results.Summary.NotEvaluated)" -ForegroundColor Yellow
        
        return $results
    }
}

function Generate-M365SecurityHTML {
    param($Results)
    
    $scoreColor = if ($null -eq $Results.ComplianceScore) { '#605e5c' }
                  elseif ($Results.ComplianceScore -ge 80) { '#107c10' } 
                  elseif ($Results.ComplianceScore -ge 60) { '#f7630c' } 
                  else { '#d13438' }
    
    $scoreDisplay = if ($null -eq $Results.ComplianceScore) { 'N/A' } else { "$($Results.ComplianceScore)%" }
    
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
        .noteval { color: #605e5c; font-weight: bold; }
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
            <div class="score-value">$scoreDisplay</div>
            <div>Security Compliance Score (evaluated checks only)</div>
        </div>
        
        <h2>Assessment Summary</h2>
        <p><strong>Overall Status:</strong> $($Results.OverallStatus)</p>
        <p><strong>Total Checks (evaluated):</strong> $($Results.Summary.TotalChecks)</p>
        <p><strong>Passed:</strong> $($Results.Summary.Passed)</p>
        <p><strong>Failed:</strong> $($Results.Summary.Failed)</p>
        <p><strong>Critical Issues:</strong> $($Results.Summary.CriticalIssues)</p>
        <p><strong>Not Evaluated:</strong> $($Results.Summary.NotEvaluated)</p>
        
        <h2>Security Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Check Name</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($finding in $Results.SecurityFindings) {
        $statusClass = switch ($finding.Status) {
            'Pass' { 'pass' }
            'Fail' { 'fail' }
            'Warning' { 'warning' }
            default { 'noteval' }
        }
        
        $html += @"
                <tr>
                    <td>$($finding.Category)</td>
                    <td>$($finding.Name)</td>
                    <td>$($finding.Severity)</td>
                    <td class="$statusClass">$($finding.Status)</td>
                    <td>$($finding.Actual)</td>
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
