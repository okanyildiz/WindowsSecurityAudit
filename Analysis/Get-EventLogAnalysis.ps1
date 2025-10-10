function Get-EventLogAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive analysis of Windows Event Logs
    .DESCRIPTION
        Analyzes Security, System, and Application event logs for security-relevant events,
        anomalies, and patterns indicating potential compromise
    .PARAMETER Hours
        Number of hours to analyze (default: 24)
    .PARAMETER LogNames
        Specific log names to analyze (default: Security, System, Application)
    .PARAMETER IncludeWarnings
        Include warning-level events in analysis
    .PARAMETER ExportPath
        Path to export detailed results
    .EXAMPLE
        Get-EventLogAnalysis
        Get-EventLogAnalysis -Hours 48 -IncludeWarnings -ExportPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with event log analysis results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Hours = 24,
        
        [Parameter()]
        [string[]]$LogNames = @('Security', 'System', 'Application'),
        
        [Parameter()]
        [switch]$IncludeWarnings,
        
        [Parameter()]
        [string]$ExportPath
    )
    
    begin {
        Write-Host "Analyzing event logs (last $Hours hours)..." -ForegroundColor Cyan
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TimeRange = "$Hours hours"
            SecurityEvents = @()
            SystemEvents = @()
            ApplicationEvents = @()
            CriticalErrors = @()
            ServiceChanges = @()
            PolicyChanges = @()
            AccountChanges = @()
            Statistics = @{
                TotalEventsAnalyzed = 0
                CriticalEvents = 0
                ErrorEvents = 0
                WarningEvents = 0
                SecurityAlerts = 0
            }
        }
        
        $startTime = (Get-Date).AddHours(-$Hours)
        
        # Critical Event IDs to monitor
        $criticalEventIDs = @{
            # Security Events
            1102 = 'Audit log cleared'
            4719 = 'System audit policy changed'
            4720 = 'User account created'
            4722 = 'User account enabled'
            4724 = 'Password reset attempted'
            4725 = 'User account disabled'
            4726 = 'User account deleted'
            4732 = 'Member added to security group'
            4733 = 'Member removed from security group'
            4738 = 'User account changed'
            4740 = 'User account locked out'
            4756 = 'Member added to universal security group'
            4625 = 'Failed logon'
            4648 = 'Logon with explicit credentials'
            4697 = 'Service installed'
            4698 = 'Scheduled task created'
            4699 = 'Scheduled task deleted'
            4700 = 'Scheduled task enabled'
            4701 = 'Scheduled task disabled'
            
            # System Events
            7045 = 'Service installed'
            7040 = 'Service start type changed'
            7036 = 'Service state changed'
            6005 = 'Event log service started'
            6006 = 'Event log service stopped'
            1074 = 'System shutdown/restart'
            6008 = 'Unexpected shutdown'
            41 = 'System rebooted without clean shutdown'
        }
    }
    
    process {
        try {
            foreach ($logName in $LogNames) {
                Write-Verbose "Analyzing $logName log..."
                
                # Get events based on severity
                $filterLevels = @(1, 2)  # Critical and Error
                if ($IncludeWarnings) {
                    $filterLevels += 3  # Warning
                }
                
                try {
                    $events = Get-WinEvent -FilterHashtable @{
                        LogName = $logName
                        Level = $filterLevels
                        StartTime = $startTime
                    } -ErrorAction SilentlyContinue
                    
                    if ($events) {
                        $results.Statistics.TotalEventsAnalyzed += $events.Count
                        
                        foreach ($event in $events) {
                            # Count by level
                            switch ($event.Level) {
                                1 { $results.Statistics.CriticalEvents++ }
                                2 { $results.Statistics.ErrorEvents++ }
                                3 { $results.Statistics.WarningEvents++ }
                            }
                            
                            # Check if this is a critical event ID
                            $isCritical = $criticalEventIDs.ContainsKey($event.Id)
                            
                            $eventObj = [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                LogName = $event.LogName
                                Source = $event.ProviderName
                                EventId = $event.Id
                                Level = switch ($event.Level) {
                                    1 { 'Critical' }
                                    2 { 'Error' }
                                    3 { 'Warning' }
                                    4 { 'Information' }
                                    default { 'Unknown' }
                                }
                                Message = $event.Message
                                Description = if ($isCritical) { $criticalEventIDs[$event.Id] } else { $null }
                                IsCritical = $isCritical
                            }
                            
                            # Categorize events
                            if ($logName -eq 'Security') {
                                $results.SecurityEvents += $eventObj
                                
                                # Specific categorization for security events
                                switch ($event.Id) {
                                    { $_ -in @(4720, 4722, 4724, 4725, 4726, 4738, 4740) } {
                                        $results.AccountChanges += $eventObj
                                        $results.Statistics.SecurityAlerts++
                                    }
                                    { $_ -in @(4719, 1102) } {
                                        $results.PolicyChanges += $eventObj
                                        $results.Statistics.SecurityAlerts++
                                    }
                                    { $_ -in @(4697, 7045) } {
                                        $results.ServiceChanges += $eventObj
                                        $results.Statistics.SecurityAlerts++
                                    }
                                }
                            }
                            elseif ($logName -eq 'System') {
                                $results.SystemEvents += $eventObj
                                
                                # Service changes
                                if ($event.Id -in @(7045, 7040, 7036)) {
                                    $results.ServiceChanges += $eventObj
                                }
                            }
                            elseif ($logName -eq 'Application') {
                                $results.ApplicationEvents += $eventObj
                            }
                            
                            # Critical errors
                            if ($event.Level -eq 1 -or $isCritical) {
                                $results.CriticalErrors += $eventObj
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Could not access $logName log: $_"
                }
            }
            
        }
        catch {
            Write-Error "Error during event log analysis: $_"
            throw
        }
    }
    
    end {
        # Display summary
        Write-Host "`nEvent Log Analysis Complete!" -ForegroundColor Green
        Write-Host "`n=== Statistics ===" -ForegroundColor Cyan
        Write-Host "Total events analyzed: $($results.Statistics.TotalEventsAnalyzed)" -ForegroundColor Yellow
        Write-Host "Critical events: $($results.Statistics.CriticalEvents)" -ForegroundColor Red
        Write-Host "Error events: $($results.Statistics.ErrorEvents)" -ForegroundColor Yellow
        Write-Host "Warning events: $($results.Statistics.WarningEvents)" -ForegroundColor Yellow
        Write-Host "Security alerts: $($results.Statistics.SecurityAlerts)" -ForegroundColor $(if ($results.Statistics.SecurityAlerts -gt 0) { 'Red' } else { 'Green' })
        
        Write-Host "`n=== Critical Findings ===" -ForegroundColor Cyan
        Write-Host "Account changes: $($results.AccountChanges.Count)" -ForegroundColor Yellow
        Write-Host "Policy changes: $($results.PolicyChanges.Count)" -ForegroundColor Yellow
        Write-Host "Service changes: $($results.ServiceChanges.Count)" -ForegroundColor Yellow
        
        # Export if requested
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "EventLogAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Host "`nResults exported to: $exportFile" -ForegroundColor Cyan
        }
        
        return $results
    }
}