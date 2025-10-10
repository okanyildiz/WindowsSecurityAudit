function Get-MultiSystemAudit {
    <#
    .SYNOPSIS
        Audits multiple systems and generates comparative analysis
    .DESCRIPTION
        Performs security audits on multiple computers and creates comparative reports
        showing security posture across the enterprise
    .PARAMETER ComputerName
        Array of computer names to audit
    .PARAMETER Credential
        Credentials for remote access
    .PARAMETER OutputPath
        Path to save audit results
    .PARAMETER GenerateReport
        Generate HTML comparison report
    .EXAMPLE
        Get-MultiSystemAudit -ComputerName "SERVER01","SERVER02","WS001" -GenerateReport
        Get-MultiSystemAudit -ComputerName (Get-Content servers.txt) -Credential $cred -OutputPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with multi-system audit results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [string]$OutputPath = "C:\MultiSystemAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
        
        [Parameter()]
        [switch]$GenerateReport
    )
    
    begin {
        Write-Host "=== MULTI-SYSTEM SECURITY AUDIT ===" -ForegroundColor Cyan
        Write-Host "Target Systems: $($ComputerName.Count)" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $auditResults = [PSCustomObject]@{
            AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TotalSystems = $ComputerName.Count
            SystemAudits = @()
            ComparativeAnalysis = @{
                AverageSecurityScore = 0
                HighestScore = 0
                LowestScore = 100
                MostSecureSystem = ""
                LeastSecureSystem = ""
                CommonFindings = @()
                CriticalSystems = @()
            }
            Summary = @{
                TotalFindings = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
                SystemsAudited = 0
                SystemsFailed = 0
            }
        }
    }
    
    process {
        try {
            Write-Host "`nAuditing systems..." -ForegroundColor Cyan
            $progress = 0
            
            foreach ($computer in $ComputerName) {
                $progress++
                Write-Progress -Activity "Multi-System Audit" -Status "Auditing: $computer" -PercentComplete (($progress / $ComputerName.Count) * 100)
                
                Write-Host "`n[$progress/$($ComputerName.Count)] Auditing: $computer" -ForegroundColor Yellow
                
                $systemAudit = [PSCustomObject]@{
                    ComputerName = $computer
                    Status = 'Success'
                    SecurityScore = 0
                    SecurityLevel = 'Unknown'
                    Findings = @()
                    Details = @{}
                    AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                try {
                    # Test connectivity
                    $pingTest = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
                    
                    if (-not $pingTest) {
                        $systemAudit.Status = 'Unreachable'
                        $systemAudit.Details.Error = 'System is unreachable'
                        $auditResults.Summary.SystemsFailed++
                        $auditResults.SystemAudits += $systemAudit
                        continue
                    }
                    
                    # Collect basic system information
                    $sysInfo = if ($Credential) {
                        Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                            [PSCustomObject]@{
                                OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                                LastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                                TotalMemory = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
                                DiskSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | 
                                    Select-Object DeviceID, @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,2)}}, 
                                    @{N='TotalGB';E={[math]::Round($_.Size/1GB,2)}})
                            }
                        } -ErrorAction Stop
                    } else {
                        Invoke-Command -ComputerName $computer -ScriptBlock {
                            [PSCustomObject]@{
                                OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                                LastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                                TotalMemory = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
                                DiskSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | 
                                    Select-Object DeviceID, @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,2)}}, 
                                    @{N='TotalGB';E={[math]::Round($_.Size/1GB,2)}})
                            }
                        } -ErrorAction Stop
                    }
                    
                    $systemAudit.Details = $sysInfo
                    
                    # Security checks
                    $securityChecks = if ($Credential) {
                        Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                            $score = 0
                            $findings = @()
                            
                            # Windows Defender
                            $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                            if ($defender -and $defender.RealTimeProtectionEnabled) {
                                $score += 25
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'Critical'
                                    Finding = 'Windows Defender disabled'
                                }
                            }
                            
                            # Firewall
                            $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                            $enabledProfiles = @($firewall | Where-Object { $_.Enabled }).Count
                            if ($enabledProfiles -eq 3) {
                                $score += 25
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'High'
                                    Finding = "Only $enabledProfiles firewall profiles enabled"
                                }
                            }
                            
                            # UAC
                            $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
                            if ($uac -eq 1) {
                                $score += 15
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'High'
                                    Finding = 'UAC disabled'
                                }
                            }
                            
                            # Updates
                            try {
                                $updateSession = New-Object -ComObject Microsoft.Update.Session
                                $updateSearcher = $updateSession.CreateUpdateSearcher()
                                $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates.Count
                                
                                if ($pendingUpdates -eq 0) {
                                    $score += 20
                                } else {
                                    $findings += [PSCustomObject]@{
                                        Severity = 'Medium'
                                        Finding = "$pendingUpdates pending updates"
                                    }
                                }
                            } catch {
                                $findings += [PSCustomObject]@{
                                    Severity = 'Low'
                                    Finding = 'Cannot check updates'
                                }
                            }
                            
                            # Admin accounts
                            $admins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
                            if ($admins.Count -le 2) {
                                $score += 15
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'Medium'
                                    Finding = "$($admins.Count) administrator accounts"
                                }
                            }
                            
                            [PSCustomObject]@{
                                Score = $score
                                Findings = $findings
                            }
                        } -ErrorAction Stop
                    } else {
                        Invoke-Command -ComputerName $computer -ScriptBlock {
                            $score = 0
                            $findings = @()
                            
                            # Windows Defender
                            $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                            if ($defender -and $defender.RealTimeProtectionEnabled) {
                                $score += 25
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'Critical'
                                    Finding = 'Windows Defender disabled'
                                }
                            }
                            
                            # Firewall
                            $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                            $enabledProfiles = @($firewall | Where-Object { $_.Enabled }).Count
                            if ($enabledProfiles -eq 3) {
                                $score += 25
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'High'
                                    Finding = "Only $enabledProfiles firewall profiles enabled"
                                }
                            }
                            
                            # UAC
                            $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
                            if ($uac -eq 1) {
                                $score += 15
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'High'
                                    Finding = 'UAC disabled'
                                }
                            }
                            
                            # Updates
                            try {
                                $updateSession = New-Object -ComObject Microsoft.Update.Session
                                $updateSearcher = $updateSession.CreateUpdateSearcher()
                                $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates.Count
                                
                                if ($pendingUpdates -eq 0) {
                                    $score += 20
                                } else {
                                    $findings += [PSCustomObject]@{
                                        Severity = 'Medium'
                                        Finding = "$pendingUpdates pending updates"
                                    }
                                }
                            } catch {
                                $findings += [PSCustomObject]@{
                                    Severity = 'Low'
                                    Finding = 'Cannot check updates'
                                }
                            }
                            
                            # Admin accounts
                            $admins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
                            if ($admins.Count -le 2) {
                                $score += 15
                            } else {
                                $findings += [PSCustomObject]@{
                                    Severity = 'Medium'
                                    Finding = "$($admins.Count) administrator accounts"
                                }
                            }
                            
                            [PSCustomObject]@{
                                Score = $score
                                Findings = $findings
                            }
                        } -ErrorAction Stop
                    }
                    
                    $systemAudit.SecurityScore = $securityChecks.Score
                    $systemAudit.Findings = $securityChecks.Findings
                    
                    # Determine security level
                    if ($systemAudit.SecurityScore -ge 80) {
                        $systemAudit.SecurityLevel = 'High'
                    } elseif ($systemAudit.SecurityScore -ge 60) {
                        $systemAudit.SecurityLevel = 'Medium'
                    } elseif ($systemAudit.SecurityScore -ge 40) {
                        $systemAudit.SecurityLevel = 'Low'
                    } else {
                        $systemAudit.SecurityLevel = 'Critical'
                        $auditResults.ComparativeAnalysis.CriticalSystems += $computer
                    }
                    
                    $auditResults.Summary.SystemsAudited++
                    $auditResults.Summary.TotalFindings += $systemAudit.Findings.Count
                    
                    # Count findings by severity
                    foreach ($finding in $systemAudit.Findings) {
                        switch ($finding.Severity) {
                            'Critical' { $auditResults.Summary.CriticalFindings++ }
                            'High' { $auditResults.Summary.HighFindings++ }
                            'Medium' { $auditResults.Summary.MediumFindings++ }
                        }
                    }
                    
                    Write-Host "  Security Score: $($systemAudit.SecurityScore)/100" -ForegroundColor $(
                        if ($systemAudit.SecurityScore -ge 80) { 'Green' }
                        elseif ($systemAudit.SecurityScore -ge 60) { 'Yellow' }
                        else { 'Red' }
                    )
                    
                }
                catch {
                    $systemAudit.Status = 'Failed'
                    $systemAudit.Details.Error = $_.Exception.Message
                    $auditResults.Summary.SystemsFailed++
                    Write-Warning "  Failed to audit $computer : $_"
                }
                
                $auditResults.SystemAudits += $systemAudit
            }
            
            Write-Progress -Activity "Multi-System Audit" -Completed
            
            # Comparative analysis
            Write-Host "`nPerforming comparative analysis..." -ForegroundColor Cyan
            
            $successfulAudits = @($auditResults.SystemAudits | Where-Object { $_.Status -eq 'Success' })
            
            if ($successfulAudits.Count -gt 0) {
                $auditResults.ComparativeAnalysis.AverageSecurityScore = [math]::Round(($successfulAudits | Measure-Object -Property SecurityScore -Average).Average, 2)
                $auditResults.ComparativeAnalysis.HighestScore = ($successfulAudits | Measure-Object -Property SecurityScore -Maximum).Maximum
                $auditResults.ComparativeAnalysis.LowestScore = ($successfulAudits | Measure-Object -Property SecurityScore -Minimum).Minimum
                
                $bestSystem = $successfulAudits | Sort-Object -Property SecurityScore -Descending | Select-Object -First 1
                $worstSystem = $successfulAudits | Sort-Object -Property SecurityScore | Select-Object -First 1
                
                $auditResults.ComparativeAnalysis.MostSecureSystem = $bestSystem.ComputerName
                $auditResults.ComparativeAnalysis.LeastSecureSystem = $worstSystem.ComputerName
                
                # Find common findings
                $allFindings = $successfulAudits | ForEach-Object { $_.Findings.Finding }
                $commonFindings = $allFindings | Group-Object | Where-Object { $_.Count -ge ($successfulAudits.Count / 2) } | 
                    Select-Object -ExpandProperty Name
                
                $auditResults.ComparativeAnalysis.CommonFindings = $commonFindings
            }
            
        }
        catch {
            Write-Error "Error during multi-system audit: $_"
            throw
        }
    }
    
    end {
        # Display summary
        Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
        Write-Host "Total Systems: $($auditResults.TotalSystems)" -ForegroundColor Cyan
        Write-Host "Successfully Audited: $($auditResults.Summary.SystemsAudited)" -ForegroundColor Green
        Write-Host "Failed: $($auditResults.Summary.SystemsFailed)" -ForegroundColor Red
        
        Write-Host "`nComparative Analysis:" -ForegroundColor Cyan
        Write-Host "  Average Security Score: $($auditResults.ComparativeAnalysis.AverageSecurityScore)/100" -ForegroundColor White
        Write-Host "  Highest Score: $($auditResults.ComparativeAnalysis.HighestScore)/100 ($($auditResults.ComparativeAnalysis.MostSecureSystem))" -ForegroundColor Green
        Write-Host "  Lowest Score: $($auditResults.ComparativeAnalysis.LowestScore)/100 ($($auditResults.ComparativeAnalysis.LeastSecureSystem))" -ForegroundColor Red
        
        if ($auditResults.ComparativeAnalysis.CriticalSystems.Count -gt 0) {
            Write-Host "`nCritical Systems (Score < 40):" -ForegroundColor Red
            $auditResults.ComparativeAnalysis.CriticalSystems | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Red
            }
        }
        
        Write-Host "`nFindings Summary:" -ForegroundColor Cyan
        Write-Host "  Total Findings: $($auditResults.Summary.TotalFindings)" -ForegroundColor White
        Write-Host "  Critical: $($auditResults.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($auditResults.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($auditResults.Summary.MediumFindings)" -ForegroundColor Yellow
        
        if ($auditResults.ComparativeAnalysis.CommonFindings.Count -gt 0) {
            Write-Host "`nCommon Issues (affecting 50%+ of systems):" -ForegroundColor Yellow
            $auditResults.ComparativeAnalysis.CommonFindings | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Yellow
            }
        }
        
        # Save results
        $auditResults | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputPath "MultiSystemAudit.json")
        
        # Export system summary
        $auditResults.SystemAudits | Select-Object ComputerName, Status, SecurityScore, SecurityLevel, @{N='FindingsCount';E={$_.Findings.Count}} |
            Export-Csv (Join-Path $OutputPath "SystemSummary.csv") -NoTypeInformation
        
        # Export all findings
        $allFindings = @($auditResults.SystemAudits | ForEach-Object {
            $computer = $_.ComputerName
            $_.Findings | Select-Object @{N='Computer';E={$computer}}, Severity, Finding
        })
        
        if ($allFindings.Count -gt 0) {
            $allFindings | Export-Csv (Join-Path $OutputPath "AllFindings.csv") -NoTypeInformation
        }
        
        # Generate HTML report if requested
        if ($GenerateReport) {
            Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan
            
            $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Multi-System Security Audit</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Multi-System Security Audit Report</h1>
        <p>Date: $($auditResults.AuditDate)</p>
        <p>Systems Audited: $($auditResults.Summary.SystemsAudited) / $($auditResults.TotalSystems)</p>
    </div>
    
    <div class="summary">
        <h2>Comparative Analysis</h2>
        <p>Average Security Score: $($auditResults.ComparativeAnalysis.AverageSecurityScore)/100</p>
        <p>Most Secure: $($auditResults.ComparativeAnalysis.MostSecureSystem) ($($auditResults.ComparativeAnalysis.HighestScore)/100)</p>
        <p>Least Secure: $($auditResults.ComparativeAnalysis.LeastSecureSystem) ($($auditResults.ComparativeAnalysis.LowestScore)/100)</p>
    </div>
    
    <div class="summary">
        <h2>System Audit Results</h2>
        <table>
            <tr>
                <th>Computer</th>
                <th>Status</th>
                <th>Security Score</th>
                <th>Security Level</th>
                <th>Findings</th>
            </tr>
            $($auditResults.SystemAudits | ForEach-Object {
                "<tr>
                    <td>$($_.ComputerName)</td>
                    <td>$($_.Status)</td>
                    <td>$($_.SecurityScore)/100</td>
                    <td class='$($_.SecurityLevel.ToLower())'>$($_.SecurityLevel)</td>
                    <td>$($_.Findings.Count)</td>
                </tr>"
            } | Out-String)
        </table>
    </div>
    
    <div class="summary">
        <h2>Findings Summary</h2>
        <p class="critical">Critical: $($auditResults.Summary.CriticalFindings)</p>
        <p class="high">High: $($auditResults.Summary.HighFindings)</p>
        <p class="medium">Medium: $($auditResults.Summary.MediumFindings)</p>
    </div>
</body>
</html>
"@
            
            $htmlPath = Join-Path $OutputPath "MultiSystemAudit.html"
            $htmlReport | Out-File $htmlPath -Encoding UTF8
            Write-Host "HTML report generated: $htmlPath" -ForegroundColor Green
            Start-Process $htmlPath
        }
        
        Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
        
        return $auditResults
    }
}