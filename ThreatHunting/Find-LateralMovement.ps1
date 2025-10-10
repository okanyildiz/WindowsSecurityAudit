function Find-LateralMovement {
    <#
    .SYNOPSIS
        Detects lateral movement indicators in the environment
    .DESCRIPTION
        Identifies signs of lateral movement including remote connections,
        pass-the-hash, PSRemoting, RDP, SMB shares, and credential access
    .PARAMETER CheckNetworkConnections
        Check for suspicious network connections
    .PARAMETER CheckRemoteExecution
        Check for remote execution indicators
    .PARAMETER CheckAuthentication
        Check authentication logs for lateral movement
    .PARAMETER CheckSMBShares
        Check SMB share access
    .PARAMETER Days
        Number of days to check in event logs (default: 7)
    .EXAMPLE
        Find-LateralMovement -CheckNetworkConnections -CheckAuthentication
        Find-LateralMovement -CheckNetworkConnections -CheckRemoteExecution -CheckAuthentication -Days 1
    .OUTPUTS
        PSCustomObject with lateral movement indicators
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckNetworkConnections,
        
        [Parameter()]
        [switch]$CheckRemoteExecution,
        
        [Parameter()]
        [switch]$CheckAuthentication,
        
        [Parameter()]
        [switch]$CheckSMBShares,
        
        [Parameter()]
        [int]$Days = 7
    )
    
    begin {
        Write-Host "=== LATERAL MOVEMENT DETECTION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Analysis Period: Last $Days days" -ForegroundColor Yellow
        
        if (-not ($CheckNetworkConnections -or $CheckRemoteExecution -or $CheckAuthentication -or $CheckSMBShares)) {
            $CheckNetworkConnections = $true
            $CheckAuthentication = $true
            Write-Host "No specific check selected - enabling default checks" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            AnalysisPeriod = $Days
            Indicators = @{
                NetworkConnections = @()
                RemoteExecution = @()
                SuspiciousAuthentication = @()
                SMBAccess = @()
            }
            Summary = @{
                TotalIndicators = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
            }
            Recommendations = @()
        }
        
        $startDate = (Get-Date).AddDays(-$Days)
    }
    
    process {
        try {
            # 1. Check Network Connections for Lateral Movement
            if ($CheckNetworkConnections) {
                Write-Host "`n[1/4] Checking network connections..." -ForegroundColor Cyan
                
                try {
                    # Check for established connections to internal IPs on suspicious ports
                    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                    
                    $suspiciousPorts = @{
                        445 = 'SMB'
                        135 = 'RPC'
                        139 = 'NetBIOS'
                        5985 = 'WinRM HTTP'
                        5986 = 'WinRM HTTPS'
                        3389 = 'RDP'
                    }
                    
                    $foundCount = 0
                    
                    foreach ($conn in $connections) {
                        if ($conn.RemotePort -in $suspiciousPorts.Keys) {
                            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                            
                            # Skip if it's a standard system process in expected scenarios
                            if ($process.Name -in @('svchost', 'System')) {
                                continue
                            }
                            
                            $indicator = [PSCustomObject]@{
                                Type = 'NetworkConnection'
                                Process = $process.Name
                                ProcessId = $conn.OwningProcess
                                LocalAddress = "$($conn.LocalAddress):$($conn.LocalPort)"
                                RemoteAddress = "$($conn.RemoteAddress):$($conn.RemotePort)"
                                Protocol = $suspiciousPorts[$conn.RemotePort]
                                Severity = 'Medium'
                                Description = "Connection to $($suspiciousPorts[$conn.RemotePort]) port from $($process.Name)"
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            
                            $results.Indicators.NetworkConnections += $indicator
                            $results.Summary.MediumFindings++
                            $foundCount++
                            
                            if ($foundCount -le 5) {
                                Write-Host "  [!] $($process.Name) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($suspiciousPorts[$conn.RemotePort])]" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    if ($foundCount -gt 5) {
                        Write-Host "  ... and $($foundCount - 5) more connections" -ForegroundColor Gray
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No suspicious network connections detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking network connections: $_"
                }
            }
            
            # 2. Check Remote Execution Indicators
            if ($CheckRemoteExecution) {
                Write-Host "`n[2/4] Checking remote execution indicators..." -ForegroundColor Cyan
                
                try {
                    # Check for PSRemoting activity (Event ID 4648 - Explicit credential logon)
                    $remoteEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4648
                        StartTime = $startDate
                    } -MaxEvents 100 -ErrorAction SilentlyContinue
                    
                    if ($remoteEvents) {
                        $groupedEvents = $remoteEvents | Group-Object -Property { 
                            $_.Properties[5].Value 
                        } | Sort-Object Count -Descending
                        
                        foreach ($group in $groupedEvents | Select-Object -First 5) {
                            $event = $group.Group[0]
                            
                            $indicator = [PSCustomObject]@{
                                Type = 'RemoteExecution'
                                Process = 'N/A'
                                ProcessId = 'N/A'
                                TargetServer = $event.Properties[5].Value
                                Account = $event.Properties[1].Value
                                Count = $group.Count
                                Severity = if ($group.Count -gt 10) { 'High' } else { 'Medium' }
                                Description = "Explicit credential logon to $($event.Properties[5].Value) - $($group.Count) times"
                                Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                            
                            $results.Indicators.RemoteExecution += $indicator
                            
                            if ($group.Count -gt 10) {
                                $results.Summary.HighFindings++
                            } else {
                                $results.Summary.MediumFindings++
                            }
                            
                            Write-Host "  [!] Explicit credential logon: $($event.Properties[5].Value) ($($group.Count) times)" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "  No remote execution indicators detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking remote execution: $_"
                }
            }
            
            # 3. Check Authentication Logs for Lateral Movement
            if ($CheckAuthentication) {
                Write-Host "`n[3/4] Checking authentication logs..." -ForegroundColor Cyan
                
                try {
                    # Event ID 4624 - Successful logon (Type 3 = Network, Type 10 = RemoteInteractive/RDP)
                    $logonEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4624
                        StartTime = $startDate
                    } -MaxEvents 500 -ErrorAction SilentlyContinue
                    
                    if ($logonEvents) {
                        # Filter for Type 3 (Network) and Type 10 (RemoteInteractive)
                        $suspiciousLogons = $logonEvents | Where-Object {
                            $logonType = $_.Properties[8].Value
                            $logonType -in @(3, 10)
                        }
                        
                        if ($suspiciousLogons) {
                            # Group by source IP
                            $groupedByIP = $suspiciousLogons | Group-Object -Property { 
                                $_.Properties[18].Value 
                            } | Where-Object { $_.Name -ne '-' -and $_.Name -ne '127.0.0.1' } |
                            Sort-Object Count -Descending
                            
                            foreach ($group in $groupedByIP | Select-Object -First 5) {
                                $event = $group.Group[0]
                                $logonType = $event.Properties[8].Value
                                $logonTypeName = switch ($logonType) {
                                    3 { 'Network' }
                                    10 { 'RemoteInteractive/RDP' }
                                    default { "Type $logonType" }
                                }
                                
                                $indicator = [PSCustomObject]@{
                                    Type = 'SuspiciousAuthentication'
                                    Process = 'N/A'
                                    ProcessId = 'N/A'
                                    SourceIP = $group.Name
                                    Account = $event.Properties[5].Value
                                    LogonType = $logonTypeName
                                    Count = $group.Count
                                    Severity = if ($group.Count -gt 20) { 'High' } else { 'Medium' }
                                    Description = "$logonTypeName logon from $($group.Name) - $($group.Count) times"
                                    Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                                }
                                
                                $results.Indicators.SuspiciousAuthentication += $indicator
                                
                                if ($group.Count -gt 20) {
                                    $results.Summary.HighFindings++
                                } else {
                                    $results.Summary.MediumFindings++
                                }
                                
                                Write-Host "  [!] $logonTypeName from $($group.Name): $($group.Count) times" -ForegroundColor Yellow
                            }
                        }
                        else {
                            Write-Host "  No suspicious authentication events detected" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "  No authentication events found in specified period" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Error checking authentication logs: $_"
                }
            }
            
            # 4. Check SMB Share Access
            if ($CheckSMBShares) {
                Write-Host "`n[4/4] Checking SMB share access..." -ForegroundColor Cyan
                
                try {
                    # Event ID 5140 - Network share object accessed
                    $shareEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 5140
                        StartTime = $startDate
                    } -MaxEvents 200 -ErrorAction SilentlyContinue
                    
                    if ($shareEvents) {
                        # Filter for non-admin shares
                        $suspiciousShares = $shareEvents | Where-Object {
                            $shareName = $_.Properties[3].Value
                            $shareName -notmatch 'IPC\$|ADMIN\$|C\$'
                        }
                        
                        if ($suspiciousShares) {
                            $groupedShares = $suspiciousShares | Group-Object -Property {
                                "$($_.Properties[1].Value)|$($_.Properties[3].Value)"
                            } | Sort-Object Count -Descending
                            
                            foreach ($group in $groupedShares | Select-Object -First 5) {
                                $parts = $group.Name -split '\|'
                                $event = $group.Group[0]
                                
                                $indicator = [PSCustomObject]@{
                                    Type = 'SMBAccess'
                                    Process = 'N/A'
                                    ProcessId = 'N/A'
                                    Account = $parts[0]
                                    ShareName = $parts[1]
                                    Count = $group.Count
                                    Severity = 'Low'
                                    Description = "SMB share access: $($parts[1]) by $($parts[0]) - $($group.Count) times"
                                    Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                                }
                                
                                $results.Indicators.SMBAccess += $indicator
                                
                                Write-Host "  [!] Share: $($parts[1]) by $($parts[0]) ($($group.Count) times)" -ForegroundColor Yellow
                            }
                        }
                        else {
                            Write-Host "  No suspicious SMB share access detected" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "  No SMB share access events found" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Error checking SMB share access: $_"
                }
            }
            
            # Calculate summary
            $results.Summary.TotalIndicators = 
                $results.Indicators.NetworkConnections.Count +
                $results.Indicators.RemoteExecution.Count +
                $results.Indicators.SuspiciousAuthentication.Count +
                $results.Indicators.SMBAccess.Count
            
            # Generate recommendations
            if ($results.Summary.TotalIndicators -gt 0) {
                if ($results.Summary.HighFindings -gt 0) {
                    $results.Recommendations += "HIGH: Investigate high-severity lateral movement indicators immediately"
                }
                
                $results.Recommendations += "Review source IPs and accounts for suspicious activity"
                $results.Recommendations += "Check for compromised credentials"
                $results.Recommendations += "Enable enhanced logging (Sysmon, PowerShell logging)"
                $results.Recommendations += "Implement network segmentation"
                $results.Recommendations += "Deploy EDR solution for behavioral detection"
                
                if ($results.Indicators.RemoteExecution.Count -gt 0) {
                    $results.Recommendations += "Review PSRemoting and WinRM usage policies"
                }
                
                if ($results.Indicators.SuspiciousAuthentication.Count -gt 0) {
                    $results.Recommendations += "Investigate authentication patterns for pass-the-hash indicators"
                }
            }
            
        }
        catch {
            Write-Error "Error during lateral movement detection: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor $(
            if ($results.Summary.HighFindings -gt 0) { 'Red' }
            elseif ($results.Summary.TotalIndicators -gt 0) { 'Yellow' }
            else { 'Green' }
        )
        
        Write-Host "`nDetection Summary:" -ForegroundColor Cyan
        Write-Host "  Total Indicators: $($results.Summary.TotalIndicators)" -ForegroundColor White
        Write-Host "  Critical: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumFindings)" -ForegroundColor Yellow
        
        if ($results.Summary.TotalIndicators -gt 0) {
            Write-Host "`nIndicator Breakdown:" -ForegroundColor Cyan
            if ($results.Indicators.NetworkConnections.Count -gt 0) {
                Write-Host "  Network Connections: $($results.Indicators.NetworkConnections.Count)" -ForegroundColor White
            }
            if ($results.Indicators.RemoteExecution.Count -gt 0) {
                Write-Host "  Remote Execution: $($results.Indicators.RemoteExecution.Count)" -ForegroundColor White
            }
            if ($results.Indicators.SuspiciousAuthentication.Count -gt 0) {
                Write-Host "  Suspicious Authentication: $($results.Indicators.SuspiciousAuthentication.Count)" -ForegroundColor White
            }
            if ($results.Indicators.SMBAccess.Count -gt 0) {
                Write-Host "  SMB Access: $($results.Indicators.SMBAccess.Count)" -ForegroundColor White
            }
        }
        else {
            Write-Host "`nNo lateral movement indicators detected" -ForegroundColor Green
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | Select-Object -Unique | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $results
    }
}