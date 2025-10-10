function Find-SuspiciousAuthentication {
    <#
    .SYNOPSIS
        Detects suspicious authentication events and patterns
    .DESCRIPTION
        Analyzes Windows Security event logs for suspicious authentication activities including
        brute force attempts, unusual logon patterns, credential dumping, and privilege escalation
    .PARAMETER Hours
        Number of hours to look back in event logs (default: 24)
    .PARAMETER IncludeSuccessful
        Include successful authentications in analysis
    .PARAMETER ExportPath
        Path to export detailed results
    .EXAMPLE
        Find-SuspiciousAuthentication
        Find-SuspiciousAuthentication -Hours 48 -IncludeSuccessful -ExportPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with authentication analysis results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Hours = 24,
        
        [Parameter()]
        [switch]$IncludeSuccessful,
        
        [Parameter()]
        [string]$ExportPath
    )
    
    begin {
        Write-Host "Analyzing authentication events (last $Hours hours)..." -ForegroundColor Cyan
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TimeRange = "$Hours hours"
            FailedLogons = @()
            AccountLockouts = @()
            PrivilegeEscalations = @()
            UnusualLogons = @()
            ExplicitCredentials = @()
            BruteForceIndicators = @()
            Statistics = @{
                TotalFailedLogons = 0
                TotalLockouts = 0
                TotalPrivilegeUse = 0
                TotalExplicitCreds = 0
                UniqueFailedAccounts = 0
                UniqueSourceIPs = 0
            }
        }
        
        $startTime = (Get-Date).AddHours(-$Hours)
    }
    
    process {
        try {
            # Event IDs to analyze
            # 4625 - Failed logon
            # 4740 - Account lockout
            # 4672 - Special privileges assigned
            # 4648 - Logon with explicit credentials
            # 4624 - Successful logon
            # 4634 - Logoff
            
            # 1. Analyze Failed Logons (Event ID 4625)
            Write-Verbose "Analyzing failed logon attempts..."
            $failedLogons = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4625
                StartTime = $startTime
            } -ErrorAction SilentlyContinue
            
            if ($failedLogons) {
                $results.Statistics.TotalFailedLogons = $failedLogons.Count
                
                foreach ($event in $failedLogons) {
                    $xml = [xml]$event.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    
                    $targetAccount = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $targetDomain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
                    $workstation = ($eventData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                    $sourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                    $status = ($eventData | Where-Object { $_.Name -eq 'Status' }).'#text'
                    $subStatus = ($eventData | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
                    
                    $results.FailedLogons += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        Account = "$targetDomain\$targetAccount"
                        Workstation = $workstation
                        SourceIP = $sourceIP
                        LogonType = $logonType
                        FailureReason = switch ($subStatus) {
                            '0xC0000064' { 'User name does not exist' }
                            '0xC000006A' { 'Correct user name but wrong password' }
                            '0xC000006D' { 'Bad user name or password' }
                            '0xC000006E' { 'Account restriction' }
                            '0xC000006F' { 'Logon outside allowed time' }
                            '0xC0000070' { 'Workstation restriction' }
                            '0xC0000071' { 'Password expired' }
                            '0xC0000072' { 'Account disabled' }
                            '0xC0000193' { 'Account expiration' }
                            '0xC0000224' { 'Password must change' }
                            '0xC0000234' { 'Account locked out' }
                            default { "Unknown ($subStatus)" }
                        }
                    }
                }
                
                # Detect brute force patterns
                $failuresByAccount = $results.FailedLogons | Group-Object -Property Account
                foreach ($group in $failuresByAccount) {
                    if ($group.Count -ge 5) {
                        $timeSpan = ($group.Group | Measure-Object -Property TimeCreated -Maximum -Minimum)
                        $duration = ($timeSpan.Maximum - $timeSpan.Minimum).TotalMinutes
                        
                        $results.BruteForceIndicators += [PSCustomObject]@{
                            Account = $group.Name
                            FailureCount = $group.Count
                            TimeSpan = [math]::Round($duration, 2)
                            SourceIPs = ($group.Group.SourceIP | Select-Object -Unique) -join ', '
                            Severity = if ($group.Count -ge 10) { 'High' } elseif ($group.Count -ge 5) { 'Medium' } else { 'Low' }
                        }
                    }
                }
                
      # Calculate statistics safely
             # ESKI SATIRLARI SİLİN, BUNLARI KOYUN:
try {
    $failedArray = @($results.FailedLogons)
    if ($failedArray.Count -gt 0) {
        $results.Statistics.UniqueFailedAccounts = (@($failedArray.Account | Select-Object -Unique)).Count
        $results.Statistics.UniqueSourceIPs = (@($failedArray | Where-Object { $_.SourceIP -ne '-' } | Select-Object -ExpandProperty SourceIP -Unique)).Count
    }
} catch {
    Write-Verbose "Could not calculate unique statistics"
}
            }
            
            # 2. Account Lockouts (Event ID 4740)
            Write-Verbose "Checking account lockouts..."
            $lockouts = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4740
                StartTime = $startTime
            } -ErrorAction SilentlyContinue
            
            if ($lockouts) {
                $results.Statistics.TotalLockouts = $lockouts.Count
                
                foreach ($event in $lockouts) {
                    $xml = [xml]$event.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    
                    $targetAccount = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $callerComputer = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
                    
                    $results.AccountLockouts += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        Account = $targetAccount
                        CallerComputer = $callerComputer
                    }
                }
            }
            
            # 3. Special Privileges Assigned (Event ID 4672)
            Write-Verbose "Analyzing privilege escalations..."
            $privEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4672
                StartTime = $startTime
            } -ErrorAction SilentlyContinue
            
            if ($privEvents) {
                $results.Statistics.TotalPrivilegeUse = $privEvents.Count
                
                # Look for unusual privilege assignments
                foreach ($event in $privEvents) {
                    $xml = [xml]$event.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    
                    $subjectAccount = ($eventData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                    $subjectDomain = ($eventData | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
                    $privileges = ($eventData | Where-Object { $_.Name -eq 'PrivilegeList' }).'#text'
                    
                    # Flag if not a well-known admin account
                    if ($subjectAccount -notmatch '(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrator|DWM-\d+|UMFD-\d+)') {
                        $results.PrivilegeEscalations += [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated
                            Account = "$subjectDomain\$subjectAccount"
                            Privileges = $privileges
                        }
                    }
                }
            }
            
            # 4. Explicit Credentials Usage (Event ID 4648)
            Write-Verbose "Checking explicit credential usage..."
            $explicitCreds = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4648
                StartTime = $startTime
            } -ErrorAction SilentlyContinue
            
            if ($explicitCreds) {
                $results.Statistics.TotalExplicitCreds = $explicitCreds.Count
                
                foreach ($event in $explicitCreds) {
                    $xml = [xml]$event.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    
                    $subjectAccount = ($eventData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                    $targetAccount = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $targetServer = ($eventData | Where-Object { $_.Name -eq 'TargetServerName' }).'#text'
                    $processName = ($eventData | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
                    
                    $results.ExplicitCredentials += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        SourceAccount = $subjectAccount
                        TargetAccount = $targetAccount
                        TargetServer = $targetServer
                        Process = $processName
                    }
                }
            }
            
            # 5. Successful Logons Analysis (if requested)
            if ($IncludeSuccessful) {
                Write-Verbose "Analyzing successful logons..."
                $successfulLogons = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4624
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue
                
                if ($successfulLogons) {
                    foreach ($event in $successfulLogons) {
                        $xml = [xml]$event.ToXml()
                        $eventData = $xml.Event.EventData.Data
                        
                        $targetAccount = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                        $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                        $sourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                        $workstation = ($eventData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                        
                        # Flag unusual logon types or times
                        $hour = $event.TimeCreated.Hour
                        $isUnusual = $false
                        $reason = ""
                        
                        # Check for after-hours logon (outside 7 AM - 7 PM)
                        if ($hour -lt 7 -or $hour -gt 19) {
                            $isUnusual = $true
                            $reason = "After-hours logon"
                        }
                        
                        # Type 10 = RemoteInteractive (RDP)
                        if ($logonType -eq '10' -and $sourceIP -ne '127.0.0.1' -and $sourceIP -ne '-') {
                            $isUnusual = $true
                            $reason += "; Remote desktop logon from $sourceIP"
                        }
                        
                        # Type 3 = Network logon to admin shares
                        if ($logonType -eq '3' -and $targetAccount -match 'admin') {
                            $isUnusual = $true
                            $reason += "; Network logon with admin account"
                        }
                        
                        if ($isUnusual) {
                            $results.UnusualLogons += [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                Account = $targetAccount
                                LogonType = $logonType
                                SourceIP = $sourceIP
                                Workstation = $workstation
                                Reason = $reason.TrimStart('; ')
                            }
                        }
                    }
                }
            }
            
        }
        catch {
            Write-Error "Error during authentication analysis: $_"
            throw
        }
    }
    
    end {
        # Display summary
        Write-Host "`nAuthentication Analysis Complete!" -ForegroundColor Green
        Write-Host "`n=== Statistics ===" -ForegroundColor Cyan
        Write-Host "Failed logon attempts: $($results.Statistics.TotalFailedLogons)" -ForegroundColor Yellow
        Write-Host "Account lockouts: $($results.Statistics.TotalLockouts)" -ForegroundColor $(if ($results.Statistics.TotalLockouts -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Privilege escalations: $($results.PrivilegeEscalations.Count)" -ForegroundColor Yellow
        Write-Host "Explicit credential usage: $($results.Statistics.TotalExplicitCreds)" -ForegroundColor Yellow
        Write-Host "Brute force indicators: $($results.BruteForceIndicators.Count)" -ForegroundColor $(if ($results.BruteForceIndicators.Count -gt 0) { 'Red' } else { 'Green' })
        
        if ($IncludeSuccessful) {
            Write-Host "Unusual successful logons: $($results.UnusualLogons.Count)" -ForegroundColor Yellow
        }
        
        # Export if requested
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "AuthenticationAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Host "`nResults exported to: $exportFile" -ForegroundColor Cyan
        }
        
        return $results
    }
}