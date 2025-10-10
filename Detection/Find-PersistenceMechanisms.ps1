function Find-PersistenceMechanisms {
    <#
    .SYNOPSIS
        Detects common Windows persistence mechanisms used by malware
    .DESCRIPTION
        Scans for suspicious persistence mechanisms including Registry Run keys,
        Startup folder items, Scheduled Tasks, Services, WMI subscriptions, and more
    .PARAMETER IncludeKnownGood
        Include known legitimate persistence mechanisms in results
    .PARAMETER ExportPath
        Path to export detailed results
    .EXAMPLE
        Find-PersistenceMechanisms
        Find-PersistenceMechanisms -IncludeKnownGood -ExportPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with detected persistence mechanisms
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeKnownGood,
        
        [Parameter()]
        [string]$ExportPath
    )
    
    begin {
        Write-Host "Scanning for persistence mechanisms..." -ForegroundColor Cyan
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            RegistryRunKeys = @()
            StartupFolder = @()
            ScheduledTasks = @()
            Services = @()
            WMISubscriptions = @()
            AppInitDLLs = @()
            LSAProviders = @()
            PrintMonitors = @()
            TotalFindings = 0
            SuspiciousCount = 0
        }
        
        # Known good paths/patterns to filter (if not including known good)
        $knownGoodPatterns = @(
            "Microsoft",
            "Windows Defender",
            "OneDrive",
            "Adobe",
            "Google\\Update",
            "Intel",
            "NVIDIA"
        )
    }
    
    process {
        try {
            # 1. Registry Run Keys
            Write-Verbose "Checking Registry Run keys..."
            $runKeyPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            
            foreach ($keyPath in $runKeyPaths) {
                if (Test-Path $keyPath) {
                    $items = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                    if ($items) {
                        $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                            $isSuspicious = $true
                            if (-not $IncludeKnownGood) {
                                foreach ($pattern in $knownGoodPatterns) {
                                    if ($_.Value -match $pattern) {
                                        $isSuspicious = $false
                                        break
                                    }
                                }
                            }
                            
                            if ($isSuspicious -or $IncludeKnownGood) {
                                $results.RegistryRunKeys += [PSCustomObject]@{
                                    Location = $keyPath
                                    Name = $_.Name
                                    Value = $_.Value
                                    Suspicious = $isSuspicious
                                }
                                if ($isSuspicious) { $results.SuspiciousCount++ }
                            }
                        }
                    }
                }
            }
            
            # 2. Startup Folders
            Write-Verbose "Checking Startup folders..."
            $startupPaths = @(
                "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            )
            
            foreach ($path in $startupPaths) {
                if (Test-Path $path) {
                    $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        $isSuspicious = -not ($item.Name -match ($knownGoodPatterns -join '|'))
                        
                        if ($isSuspicious -or $IncludeKnownGood) {
                            $results.StartupFolder += [PSCustomObject]@{
                                Location = $path
                                Name = $item.Name
                                FullPath = $item.FullName
                                Target = if ($item.LinkType -eq 'SymbolicLink') { $item.Target } else { 'N/A' }
                                CreationTime = $item.CreationTime
                                Suspicious = $isSuspicious
                            }
                            if ($isSuspicious) { $results.SuspiciousCount++ }
                        }
                    }
                }
            }
            
            # 3. Scheduled Tasks
            Write-Verbose "Checking Scheduled Tasks..."
            $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
            
            foreach ($task in $tasks) {
                try {
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
                    $actions = $task.Actions | ForEach-Object { 
                        if ($_.Execute) { $_.Execute } 
                    }
                    
                    $isSuspicious = $false
                    # Check for suspicious indicators
                    if ($task.Principal.UserId -eq 'SYSTEM' -and $task.TaskPath -notmatch '\\Microsoft\\') {
                        $isSuspicious = $true
                    }
                    if ($actions -match '(powershell|cmd|wscript|cscript|mshta)' -and $task.TaskPath -notmatch '\\Microsoft\\') {
                        $isSuspicious = $true
                    }
                    
                    if ($isSuspicious -or $IncludeKnownGood) {
                        $results.ScheduledTasks += [PSCustomObject]@{
                            Name = $task.TaskName
                            Path = $task.TaskPath
                            State = $task.State
                            Actions = if ($actions) { ($actions -join '; ') } else { 'N/A' }
                            RunAsUser = $task.Principal.UserId
                            LastRunTime = if ($taskInfo -and $taskInfo.LastRunTime) { $taskInfo.LastRunTime } else { 'Never' }
                            NextRunTime = if ($taskInfo -and $taskInfo.NextRunTime) { $taskInfo.NextRunTime } else { 'Not scheduled' }
                            Suspicious = $isSuspicious
                        }
                        if ($isSuspicious) { $results.SuspiciousCount++ }
                    }
                }
                catch {
                    Write-Verbose "Could not process task: $($task.TaskName)"
                }
            }
            
            # 4. Services
            Write-Verbose "Checking Services..."
            $services = Get-CimInstance -ClassName Win32_Service
            
            foreach ($service in $services) {
                $isSuspicious = $false
                
                # Check for suspicious indicators
                if ($service.PathName -match '(temp|appdata|programdata.*\\.\\)' -and $service.PathName -notmatch 'Microsoft') {
                    $isSuspicious = $true
                }
                if ($service.StartMode -eq 'Auto' -and $service.PathName -notmatch '(System32|Program Files)') {
                    $isSuspicious = $true
                }
                
                if ($isSuspicious -or $IncludeKnownGood) {
                    $results.Services += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        PathName = $service.PathName
                        StartMode = $service.StartMode
                        State = $service.State
                        StartName = $service.StartName
                        Suspicious = $isSuspicious
                    }
                    if ($isSuspicious) { $results.SuspiciousCount++ }
                }
            }
            
            # 5. WMI Event Subscriptions
            Write-Verbose "Checking WMI Event Subscriptions..."
            try {
                $wmiFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
                $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
                $wmiBindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
                
                foreach ($binding in $wmiBindings) {
                    $results.WMISubscriptions += [PSCustomObject]@{
                        Filter = $binding.Filter
                        Consumer = $binding.Consumer
                        Suspicious = $true  # All non-Microsoft WMI subscriptions are suspicious
                    }
                    $results.SuspiciousCount++
                }
            }
            catch {
                Write-Warning "Could not check WMI subscriptions: $_"
            }
            
            # 6. AppInit DLLs
            Write-Verbose "Checking AppInit DLLs..."
            $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            if (Test-Path $appInitPath) {
                $appInit = Get-ItemProperty -Path $appInitPath -ErrorAction SilentlyContinue
                if ($appInit.AppInit_DLLs) {
                    $results.AppInitDLLs += [PSCustomObject]@{
                        Value = $appInit.AppInit_DLLs
                        LoadAppInit = $appInit.LoadAppInit_DLLs
                        Suspicious = $true
                    }
                    $results.SuspiciousCount++
                }
            }
            
            # 7. LSA Authentication Packages
            Write-Verbose "Checking LSA providers..."
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (Test-Path $lsaPath) {
                $lsa = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue
                
                # Check Authentication Packages
                if ($lsa.'Authentication Packages') {
                    foreach ($pkg in $lsa.'Authentication Packages') {
                        if ($pkg -notmatch '^msv1_0$') {
                            $results.LSAProviders += [PSCustomObject]@{
                                Type = "Authentication Package"
                                Value = $pkg
                                Suspicious = $true
                            }
                            $results.SuspiciousCount++
                        }
                    }
                }
                
                # Check Notification Packages
                if ($lsa.'Notification Packages') {
                    foreach ($pkg in $lsa.'Notification Packages') {
                        if ($pkg -notmatch '^(scecli|rassfm)$') {
                            $results.LSAProviders += [PSCustomObject]@{
                                Type = "Notification Package"
                                Value = $pkg
                                Suspicious = $true
                            }
                            $results.SuspiciousCount++
                        }
                    }
                }
            }
            
            # 8. Print Monitors
            Write-Verbose "Checking Print Monitors..."
            $monitorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
            if (Test-Path $monitorPath) {
                $monitors = Get-ChildItem -Path $monitorPath -ErrorAction SilentlyContinue
                foreach ($monitor in $monitors) {
                    $driverValue = (Get-ItemProperty -Path $monitor.PSPath -ErrorAction SilentlyContinue).Driver
                    if ($driverValue -and $driverValue -notmatch '(Microsoft|Windows)') {
                        $results.PrintMonitors += [PSCustomObject]@{
                            Name = $monitor.PSChildName
                            Driver = $driverValue
                            Suspicious = $true
                        }
                        $results.SuspiciousCount++
                    }
                }
            }
            
            # Calculate total findings
            $results.TotalFindings = ($results.RegistryRunKeys.Count +
                                     $results.StartupFolder.Count +
                                     $results.ScheduledTasks.Count +
                                     $results.Services.Count +
                                     $results.WMISubscriptions.Count +
                                     $results.AppInitDLLs.Count +
                                     $results.LSAProviders.Count +
                                     $results.PrintMonitors.Count)
            
        }
        catch {
            Write-Error "Error during persistence scan: $_"
            throw
        }
    }
    
    end {
        Write-Host "`nScan complete!" -ForegroundColor Green
        Write-Host "Total findings: $($results.TotalFindings)" -ForegroundColor Yellow
        Write-Host "Suspicious items: $($results.SuspiciousCount)" -ForegroundColor $(if ($results.SuspiciousCount -gt 0) { 'Red' } else { 'Green' })
        
        # Export if requested
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "PersistenceScan_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Host "Results exported to: $exportFile" -ForegroundColor Cyan
        }
        
        return $results
    }
}