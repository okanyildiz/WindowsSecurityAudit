function Invoke-EnterpriseSecurityScan {
    <#
    .SYNOPSIS
        Performs security scans across multiple systems in an enterprise environment
    .DESCRIPTION
        Executes comprehensive security assessments on multiple remote computers simultaneously,
        collecting and aggregating results for enterprise-wide security analysis
    .PARAMETER ComputerName
        Array of computer names or IP addresses to scan
    .PARAMETER Credential
        PSCredential object for remote authentication
    .PARAMETER ScanType
        Type of scan: Quick, Standard, or Comprehensive
    .PARAMETER MaxThreads
        Maximum number of concurrent scans (default: 10)
    .PARAMETER OutputPath
        Path to save scan results
    .EXAMPLE
        Invoke-EnterpriseSecurityScan -ComputerName "SERVER01","SERVER02" -ScanType Standard
        Invoke-EnterpriseSecurityScan -ComputerName (Get-Content servers.txt) -Credential $cred -MaxThreads 20
    .OUTPUTS
        PSCustomObject with enterprise scan results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [ValidateSet('Quick', 'Standard', 'Comprehensive')]
        [string]$ScanType = 'Standard',
        
        [Parameter()]
        [int]$MaxThreads = 10,
        
        [Parameter()]
        [string]$OutputPath = "C:\EnterpriseScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    begin {
        Write-Host "=== ENTERPRISE SECURITY SCAN ===" -ForegroundColor Cyan
        Write-Host "Target Systems: $($ComputerName.Count)" -ForegroundColor Yellow
        Write-Host "Scan Type: $ScanType" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check if testing locally
        $isLocalTest = $ComputerName.Count -eq 1 -and ($ComputerName[0] -eq $env:COMPUTERNAME -or $ComputerName[0] -eq 'localhost' -or $ComputerName[0] -eq '127.0.0.1')
        
        if ($isLocalTest) {
            Write-Warning "Local testing detected. Ensure PSRemoting is enabled with 'Enable-PSRemoting -Force'"
        }
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScanType = $ScanType
            TotalSystems = $ComputerName.Count
            SystemResults = @()
            Summary = @{
                Successful = 0
                Failed = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
                LowFindings = 0
            }
            FailedSystems = @()
        }
        
        # Script block for remote execution
        $scanScriptBlock = {
            param($ScanType)
            
            $result = [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Status = 'Success'
                SecurityScore = 0
                Findings = @()
                Details = @{}
            }
            
            try {
                # Quick baseline check
                $baseline = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($baseline) {
                    $result.SecurityScore += if ($baseline.RealTimeProtectionEnabled) { 20 } else { 0 }
                    $result.Details.WindowsDefender = $baseline.RealTimeProtectionEnabled
                    
                    if (-not $baseline.RealTimeProtectionEnabled) {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Critical'
                            Category = 'Windows Defender'
                            Finding = 'Real-time protection is disabled'
                        }
                    }
                }
                
                # Firewall check
                $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $firewallEnabled = @($firewall | Where-Object { $_.Enabled -eq $true }).Count
                $result.SecurityScore += ($firewallEnabled * 10)
                $result.Details.FirewallProfiles = $firewallEnabled
                
                if ($firewallEnabled -lt 3) {
                    $result.Findings += [PSCustomObject]@{
                        Severity = 'High'
                        Category = 'Firewall'
                        Finding = "Only $firewallEnabled firewall profiles enabled"
                    }
                }
                
                # UAC check
                $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $uacEnabled = (Get-ItemProperty -Path $uacKey -ErrorAction SilentlyContinue).EnableLUA
                $result.SecurityScore += if ($uacEnabled -eq 1) { 15 } else { 0 }
                $result.Details.UACEnabled = ($uacEnabled -eq 1)
                
                if ($uacEnabled -ne 1) {
                    $result.Findings += [PSCustomObject]@{
                        Severity = 'High'
                        Category = 'UAC'
                        Finding = 'User Account Control is disabled'
                    }
                }
                
                # Windows Update check
                try {
                    $updateSession = New-Object -ComObject Microsoft.Update.Session
                    $updateSearcher = $updateSession.CreateUpdateSearcher()
                    $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates.Count
                    $result.Details.PendingUpdates = $pendingUpdates
                    
                    if ($pendingUpdates -eq 0) {
                        $result.SecurityScore += 15
                    } else {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Medium'
                            Category = 'Updates'
                            Finding = "$pendingUpdates pending Windows updates"
                        }
                    }
                } catch {
                    $result.Details.PendingUpdates = "Unable to check"
                }
                
                # Additional checks for Standard/Comprehensive scans
                if ($ScanType -in @('Standard', 'Comprehensive')) {
                    # Check for admin accounts
                    $adminCount = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Count
                    $result.Details.AdminAccounts = $adminCount
                    
                    if ($adminCount -gt 3) {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Medium'
                            Category = 'Accounts'
                            Finding = "$adminCount administrator accounts (excessive)"
                        }
                    }
                    
                    # Check for suspicious services
                    $suspiciousServices = @(Get-Service | Where-Object {
                        $_.StartType -eq 'Automatic' -and 
                        $_.Status -eq 'Running' -and
                        $_.ServiceName -notmatch '^(Win|Dhcp|Dns|W3SVC|MSSQL|SQL)'
                    })
                    
                    if ($suspiciousServices.Count -gt 50) {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Low'
                            Category = 'Services'
                            Finding = "$($suspiciousServices.Count) non-standard services running"
                        }
                    }
                }
                
                # Comprehensive scan additions
                if ($ScanType -eq 'Comprehensive') {
                    # Check event logs
                    $recentErrors = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'System'
                        Level = 2
                        StartTime = (Get-Date).AddDays(-1)
                    } -MaxEvents 100 -ErrorAction SilentlyContinue)
                    
                    $result.Details.RecentErrors = $recentErrors.Count
                    
                    # Check disk space
                    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
                    foreach ($drive in $drives) {
                        $freePercent = ($drive.FreeSpace / $drive.Size) * 100
                        if ($freePercent -lt 10) {
                            $result.Findings += [PSCustomObject]@{
                                Severity = 'High'
                                Category = 'Disk Space'
                                Finding = "Drive $($drive.DeviceID) has less than 10% free space"
                            }
                        }
                    }
                }
                
                # Calculate final score
                $result.SecurityScore = [Math]::Min($result.SecurityScore, 100)
                
            }
            catch {
                $result.Status = 'Error'
                $result.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Category = 'Scan Error'
                    Finding = $_.Exception.Message
                }
            }
            
            return $result
        }
    }
    
    process {
        try {
            Write-Host "`nStarting parallel scan of $($ComputerName.Count) systems..." -ForegroundColor Cyan
            
            # Create runspace pool for parallel execution
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
            $runspacePool.Open()
            $jobs = @()
            
            foreach ($computer in $ComputerName) {
                Write-Verbose "Queuing scan for: $computer"
                
                # Test connectivity first
                $pingTest = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
                
                if (-not $pingTest) {
                    Write-Warning "Cannot reach $computer - skipping"
                    $results.FailedSystems += [PSCustomObject]@{
                        ComputerName = $computer
                        Reason = 'Unreachable'
                    }
                    $results.Summary.Failed++
                    continue
                }
                
                # Create PowerShell instance
                $powershell = [powershell]::Create()
                $powershell.RunspacePool = $runspacePool
                
                # Add script and parameters
                if ($Credential) {
                    $powershell.AddScript({
                        param($Computer, $Cred, $ScriptBlock, $ScanType)
                        try {
                            Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock $ScriptBlock -ArgumentList $ScanType -ErrorAction Stop
                        } catch {
                            [PSCustomObject]@{
                                ComputerName = $Computer
                                Status = 'Failed'
                                SecurityScore = 0
                                Findings = @([PSCustomObject]@{
                                    Severity = 'Critical'
                                    Category = 'Connection'
                                    Finding = $_.Exception.Message
                                })
                                Details = @{}
                            }
                        }
                    }).AddArgument($computer).AddArgument($Credential).AddArgument($scanScriptBlock).AddArgument($ScanType) | Out-Null
                }
                else {
                    $powershell.AddScript({
                        param($Computer, $ScriptBlock, $ScanType)
                        try {
                            Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $ScanType -ErrorAction Stop
                        } catch {
                            [PSCustomObject]@{
                                ComputerName = $Computer
                                Status = 'Failed'
                                SecurityScore = 0
                                Findings = @([PSCustomObject]@{
                                    Severity = 'Critical'
                                    Category = 'Connection'
                                    Finding = $_.Exception.Message
                                })
                                Details = @{}
                            }
                        }
                    }).AddArgument($computer).AddArgument($scanScriptBlock).AddArgument($ScanType) | Out-Null
                }
                
                # Start async execution
                $jobs += [PSCustomObject]@{
                    Computer = $computer
                    Pipeline = $powershell
                    Status = $powershell.BeginInvoke()
                }
            }
            
            # Wait for all jobs to complete
            Write-Host "Scanning in progress..." -ForegroundColor Yellow
            $completed = 0
            $totalJobs = @($jobs).Count
            
            while (@($jobs | Where-Object { -not $_.Status.IsCompleted }).Count -gt 0) {
                $completedNow = @($jobs | Where-Object { $_.Status.IsCompleted }).Count
                if ($completedNow -ne $completed) {
                    $completed = $completedNow
                    if ($totalJobs -gt 0) {
                        Write-Progress -Activity "Enterprise Security Scan" -Status "Completed: $completed / $totalJobs" -PercentComplete (($completed / $totalJobs) * 100)
                    }
                }
                Start-Sleep -Milliseconds 500
            }
            
            Write-Progress -Activity "Enterprise Security Scan" -Completed
            
            # Collect results
            Write-Host "Collecting results..." -ForegroundColor Yellow
            
            foreach ($job in $jobs) {
                try {
                    $result = $job.Pipeline.EndInvoke($job.Status)
                    
                    if ($result.Status -eq 'Success') {
                        $results.Summary.Successful++
                        
                        # Count findings by severity
                        foreach ($finding in $result.Findings) {
                            switch ($finding.Severity) {
                                'Critical' { $results.Summary.CriticalFindings++ }
                                'High' { $results.Summary.HighFindings++ }
                                'Medium' { $results.Summary.MediumFindings++ }
                                'Low' { $results.Summary.LowFindings++ }
                            }
                        }
                    }
                    else {
                        $results.Summary.Failed++
                        $results.FailedSystems += [PSCustomObject]@{
                            ComputerName = $job.Computer
                            Reason = 'Scan failed'
                        }
                    }
                    
                    $results.SystemResults += $result
                }
                catch {
                    Write-Warning "Error collecting results from $($job.Computer): $_"
                    $results.Summary.Failed++
                }
                finally {
                    $job.Pipeline.Dispose()
                }
            }
            
            # Close runspace pool
            $runspacePool.Close()
            $runspacePool.Dispose()
            
        }
        catch {
            Write-Error "Error during enterprise scan: $_"
            throw
        }
    }
    
    end {
        # Generate summary report
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
        Write-Host "Total Systems: $($results.TotalSystems)" -ForegroundColor Cyan
        Write-Host "Successful: $($results.Summary.Successful)" -ForegroundColor Green
        Write-Host "Failed: $($results.Summary.Failed)" -ForegroundColor Red
        Write-Host "`nFindings Summary:" -ForegroundColor Cyan
        Write-Host "  Critical: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumFindings)" -ForegroundColor Yellow
        Write-Host "  Low: $($results.Summary.LowFindings)" -ForegroundColor White
        
        # Save results
        $results | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputPath "EnterpriseScan_Results.json")
        
        # Create CSV summary
        $results.SystemResults | Select-Object ComputerName, Status, SecurityScore, @{N='FindingsCount';E={$_.Findings.Count}} |
            Export-Csv (Join-Path $OutputPath "EnterpriseScan_Summary.csv") -NoTypeInformation
        
        # Export detailed findings
        $allFindings = @($results.SystemResults | ForEach-Object {
            $computer = $_.ComputerName
            $_.Findings | Select-Object @{N='Computer';E={$computer}}, Severity, Category, Finding
        })
        
        if ($allFindings.Count -gt 0) {
            $allFindings | Export-Csv (Join-Path $OutputPath "EnterpriseScan_Findings.csv") -NoTypeInformation
        }
        
        Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
        
        return $results
    }
}