function Get-AzureADRiskySignIns {
    <#
    .SYNOPSIS
        Analyzes risky sign-in events from Azure AD/Entra ID
    
    .DESCRIPTION
        Retrieves and analyzes risky sign-in attempts, anomalous locations,
        impossible travel scenarios, and other identity protection alerts from
        Azure AD Identity Protection.
    
    .PARAMETER DaysBack
        Number of days to look back for risky sign-ins (Default: 30)
    
    .PARAMETER RiskLevel
        Filter by risk level: Low, Medium, High, or All (Default: All)
    
    .PARAMETER IncludeRiskyUsers
        Also retrieve risky user information
    
    .PARAMETER ExportPath
        Path to export detailed report
    
    .PARAMETER Format
        Export format: HTML, JSON, CSV, or All (Default: HTML)
    
    .EXAMPLE
        Get-AzureADRiskySignIns -DaysBack 7 -RiskLevel High
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 90)]
        [int]$DaysBack = 30,
        
        [Parameter()]
        [ValidateSet('Low', 'Medium', 'High', 'All')]
        [string]$RiskLevel = 'All',
        
        [Parameter()]
        [switch]$IncludeRiskyUsers,
        
        [Parameter()]
        [string]$ExportPath,
        
        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML'
    )
    
    begin {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  AZURE AD RISKY SIGN-INS ANALYSIS" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        # Check Microsoft Graph connection
        try {
            $context = Get-MgContext -ErrorAction Stop
            
            if (-not $context) {
                throw "Not connected to Microsoft Graph"
            }
            
            Write-Host "Connected to tenant: $($context.TenantId)" -ForegroundColor Green
        }
        catch {
            Write-Error "Please connect to Microsoft Graph first: Connect-MgGraph -Scopes 'IdentityRiskEvent.Read.All'"
            throw
        }
        
        # Initialize results
        $results = [PSCustomObject]@{
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TenantInfo = @{
                TenantId = $context.TenantId
                TenantName = "N/A"
            }
            RiskySignIns = @()
            RiskyUsers = @()
            Summary = @{
                TotalRiskySignIns = 0
                HighRisk = 0
                MediumRisk = 0
                LowRisk = 0
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
            
            # Get risky sign-ins
            Write-Host "`nRetrieving risky sign-in events..." -ForegroundColor Cyan
            
            $startDate = (Get-Date).AddDays(-$DaysBack)
            $filterDate = $startDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
            
            $riskyDetections = Get-MgRiskDetection -Filter "detectedDateTime ge $filterDate" -All -ErrorAction Stop
            
            if ($riskyDetections) {
                Write-Host "Found $($riskyDetections.Count) risk detections" -ForegroundColor Yellow
                
                foreach ($detection in $riskyDetections) {
                    if ($RiskLevel -ne 'All' -and $detection.RiskLevel -ne $RiskLevel.ToLower()) {
                        continue
                    }
                    
                    $results.RiskySignIns += [PSCustomObject]@{
                        DetectionId = $detection.Id
                        CreatedDateTime = $detection.DetectedDateTime
                        UserPrincipalName = $detection.UserPrincipalName
                        RiskLevel = $detection.RiskLevel
                        RiskState = $detection.RiskState
                        RiskEventType = $detection.RiskEventType
                        IPAddress = $detection.IPAddress
                    }
                }
            }
            else {
                Write-Host "No risky sign-ins found" -ForegroundColor Green
            }
            
            # Get risky users if requested
            if ($IncludeRiskyUsers) {
                Write-Host "`nRetrieving risky users..." -ForegroundColor Cyan
                
                $riskyUsersData = Get-MgRiskyUser -All -ErrorAction SilentlyContinue
                
                if ($riskyUsersData) {
                    foreach ($user in $riskyUsersData) {
                        $results.RiskyUsers += [PSCustomObject]@{
                            UserPrincipalName = $user.UserPrincipalName
                            RiskLevel = $user.RiskLevel
                            RiskState = $user.RiskState
                        }
                    }
                }
            }
            
            # Calculate summary
            $results.Summary.TotalRiskySignIns = $results.RiskySignIns.Count
            $results.Summary.HighRisk = ($results.RiskySignIns | Where-Object { $_.RiskLevel -eq 'high' }).Count
            $results.Summary.MediumRisk = ($results.RiskySignIns | Where-Object { $_.RiskLevel -eq 'medium' }).Count
            $results.Summary.LowRisk = ($results.RiskySignIns | Where-Object { $_.RiskLevel -eq 'low' }).Count
            
            # Export if requested
            if ($ExportPath -and $results.RiskySignIns.Count -gt 0) {
                Write-Host "`nExporting reports..." -ForegroundColor Cyan
                
                if (-not (Test-Path $ExportPath)) {
                    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                
                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $ExportPath "RiskySignIns_$timestamp.json"
                    $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "Exported JSON: $jsonPath" -ForegroundColor Green
                }
                
                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $ExportPath "RiskySignIns_$timestamp.csv"
                    $results.RiskySignIns | Export-Csv $csvPath -NoTypeInformation
                    Write-Host "Exported CSV: $csvPath" -ForegroundColor Green
                }
                
                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $ExportPath "RiskySignIns_$timestamp.html"
                    $htmlContent = Generate-RiskySignInsHTML -Results $results
                    $htmlContent | Out-File $htmlPath -Encoding UTF8
                    Write-Host "Exported HTML: $htmlPath" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Error "Error during analysis: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "  ANALYSIS COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        
        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "  Total Risky Sign-Ins: $($results.Summary.TotalRiskySignIns)" -ForegroundColor White
        Write-Host "  High Risk: $($results.Summary.HighRisk)" -ForegroundColor Red
        Write-Host "  Medium Risk: $($results.Summary.MediumRisk)" -ForegroundColor Yellow
        Write-Host "  Low Risk: $($results.Summary.LowRisk)" -ForegroundColor Gray
        
        return $results
    }
}

function Generate-RiskySignInsHTML {
    param($Results)
    
    $html = @'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Azure AD Risky Sign-Ins Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .high { color: #d13438; font-weight: bold; }
        .medium { color: #f7630c; font-weight: bold; }
        .low { color: #107c10; font-weight: bold; }
        .summary { background: #e6f2ff; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 36px; font-weight: bold; }
        .metric-label { font-size: 14px; color: #605e5c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure AD Risky Sign-Ins Report</h1>
        
        <div class="summary">
            <h2>Summary Statistics</h2>
'@
    
    $html += @"
            <div class="metric">
                <div class="metric-value">$($Results.Summary.TotalRiskySignIns)</div>
                <div class="metric-label">Total Detections</div>
            </div>
            <div class="metric">
                <div class="metric-value high">$($Results.Summary.HighRisk)</div>
                <div class="metric-label">High Risk</div>
            </div>
            <div class="metric">
                <div class="metric-value medium">$($Results.Summary.MediumRisk)</div>
                <div class="metric-label">Medium Risk</div>
            </div>
            <div class="metric">
                <div class="metric-value low">$($Results.Summary.LowRisk)</div>
                <div class="metric-label">Low Risk</div>
            </div>
        </div>
        
        <h2>Risky Sign-In Events</h2>
        <table>
            <thead>
                <tr>
                    <th>Date/Time</th>
                    <th>User</th>
                    <th>Risk Level</th>
                    <th>IP Address</th>
                    <th>Event Type</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($signIn in ($Results.RiskySignIns | Sort-Object CreatedDateTime -Descending)) {
        $riskClass = $signIn.RiskLevel.ToLower()
        $dateTime = $signIn.CreatedDateTime.ToString('yyyy-MM-dd HH:mm:ss')
        
        $html += @"
                <tr>
                    <td>$dateTime</td>
                    <td>$($signIn.UserPrincipalName)</td>
                    <td class="$riskClass">$($signIn.RiskLevel.ToUpper())</td>
                    <td>$($signIn.IPAddress)</td>
                    <td>$($signIn.RiskEventType)</td>
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