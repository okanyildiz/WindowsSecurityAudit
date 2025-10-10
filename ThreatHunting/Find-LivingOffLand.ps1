function Find-LivingOffLand {
    <#
    .SYNOPSIS
        Detects Living Off The Land (LOLBins) abuse
    .DESCRIPTION
        Identifies suspicious use of legitimate Windows binaries (LOLBins/LOLBas)
        that are commonly abused by attackers for execution, download, and evasion
    .PARAMETER CheckRunningProcesses
        Scan currently running processes
    .PARAMETER CheckRecentExecution
        Check recent process execution history
    .PARAMETER CheckScheduledTasks
        Check scheduled tasks for LOLBins
    .EXAMPLE
        Find-LivingOffLand -CheckRunningProcesses
        Find-LivingOffLand -CheckRunningProcesses -CheckRecentExecution -CheckScheduledTasks
    .OUTPUTS
        PSCustomObject with LOLBins detection results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckRunningProcesses,
        
        [Parameter()]
        [switch]$CheckRecentExecution,
        
        [Parameter()]
        [switch]$CheckScheduledTasks
    )
    
    begin {
        Write-Host "=== LIVING OFF THE LAND (LOLBins) DETECTION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        if (-not ($CheckRunningProcesses -or $CheckRecentExecution -or $CheckScheduledTasks)) {
            $CheckRunningProcesses = $true
            Write-Host "No specific check selected - defaulting to CheckRunningProcesses" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            DetectedLOLBins = @()
            Summary = @{
                TotalDetections = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
            }
            Recommendations = @()
        }
        
        # LOLBins Database with suspicious usage patterns
        $lolbinsDB = @{
            'certutil.exe' = @{
                Description = 'Certificate utility - can download files and encode/decode'
                SuspiciousPatterns = @(
                    '-urlcache.*http',
                    '-decode',
                    '-encode',
                    'split.*http'
                )
                Severity = 'High'
            }
            'bitsadmin.exe' = @{
                Description = 'Background Intelligent Transfer Service - can download files'
                SuspiciousPatterns = @(
                    '/transfer',
                    '/download',
                    '/addfile'
                )
                Severity = 'High'
            }
            'mshta.exe' = @{
                Description = 'Microsoft HTML Application host - executes HTA/scripts'
                SuspiciousPatterns = @(
                    'http',
                    'javascript:',
                    'vbscript:',
                    '\.hta'
                )
                Severity = 'Critical'
            }
            'regsvr32.exe' = @{
                Description = 'Register Server - can execute scriptlets'
                SuspiciousPatterns = @(
                    '/u /s /i:http',
                    '/i:http',
                    '\.sct',
                    'scrobj.dll'
                )
                Severity = 'Critical'
            }
            'rundll32.exe' = @{
                Description = 'Run DLL - can execute DLL functions'
                SuspiciousPatterns = @(
                    'javascript:',
                    'http',
                    'mshtml',
                    'url\.dll.*OpenURL',
                    'advpack\.dll.*LaunchINFSection'
                )
                Severity = 'High'
            }
            'msiexec.exe' = @{
                Description = 'Windows Installer - can download and execute MSI'
                SuspiciousPatterns = @(
                    '/i.*http',
                    '/quiet.*http',
                    '/qn.*http'
                )
                Severity = 'High'
            }
            'wmic.exe' = @{
                Description = 'Windows Management Instrumentation - can execute commands'
                SuspiciousPatterns = @(
                    'process call create',
                    'os get',
                    '/node:',
                    '/format:.*http'
                )
                Severity = 'High'
            }
            'cscript.exe' = @{
                Description = 'Windows Script Host - executes scripts'
                SuspiciousPatterns = @(
                    '\.vbs.*http',
                    '\.js.*http',
                    '//e:jscript'
                )
                Severity = 'Medium'
            }
            'wscript.exe' = @{
                Description = 'Windows Script Host - executes scripts'
                SuspiciousPatterns = @(
                    '\.vbs.*http',
                    '\.js.*http'
                )
                Severity = 'Medium'
            }
            'regasm.exe' = @{
                Description = 'Assembly Registration Tool - can execute code'
                SuspiciousPatterns = @(
                    '/u',
                    '\.dll'
                )
                Severity = 'Medium'
            }
            'regsvcs.exe' = @{
                Description = '.NET Services Installation Tool - can execute code'
                SuspiciousPatterns = @(
                    '/u',
                    '\.dll'
                )
                Severity = 'Medium'
            }
            'installutil.exe' = @{
                Description = '.NET Installer Tool - can execute code'
                SuspiciousPatterns = @(
                    '/logfile=',
                    '/logtoconsole=false',
                    '\.dll'
                )
                Severity = 'Medium'
            }
            'odbcconf.exe' = @{
                Description = 'ODBC Configuration - can execute DLLs'
                SuspiciousPatterns = @(
                    '/a.*regsvr'
                )
                Severity = 'Medium'
            }
            'mavinject.exe' = @{
                Description = 'Windows process injector'
                SuspiciousPatterns = @(
                    '/injectrunning'
                )
                Severity = 'Critical'
            }
            'forfiles.exe' = @{
                Description = 'Execute commands on files - can run arbitrary commands'
                SuspiciousPatterns = @(
                    '/c',
                    'cmd'
                )
                Severity = 'Medium'
            }
        }
    }
    
    process {
        try {
            # 1. Check Running Processes
            if ($CheckRunningProcesses) {
                Write-Host "`n[1/3] Scanning running processes..." -ForegroundColor Cyan
                
                try {
                    $processes = Get-CimInstance Win32_Process | 
                        Where-Object { $_.CommandLine -ne $null } |
                        Select-Object Name, ProcessId, ExecutablePath, CommandLine
                    
                    foreach ($process in $processes) {
                        $processName = $process.Name.ToLower()
                        
                        if ($lolbinsDB.ContainsKey($processName)) {
                            $lolbin = $lolbinsDB[$processName]
                            $commandLine = $process.CommandLine
                            
                            # Check for suspicious patterns
                            $matchedPatterns = @()
                            foreach ($pattern in $lolbin.SuspiciousPatterns) {
                                if ($commandLine -match $pattern) {
                                    $matchedPatterns += $pattern
                                }
                            }
                            
                            if ($matchedPatterns.Count -gt 0) {
                                $detection = [PSCustomObject]@{
                                    DetectionType = 'RunningProcess'
                                    Binary = $processName
                                    ProcessId = $process.ProcessId
                                    Description = $lolbin.Description
                                    CommandLine = if ($commandLine.Length -gt 300) { $commandLine.Substring(0, 300) + "..." } else { $commandLine }
                                    MatchedPatterns = $matchedPatterns -join ', '
                                    Severity = $lolbin.Severity
                                    Path = $process.ExecutablePath
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.DetectedLOLBins += $detection
                                
                                switch ($lolbin.Severity) {
                                    'Critical' { $results.Summary.CriticalFindings++ }
                                    'High' { $results.Summary.HighFindings++ }
                                    'Medium' { $results.Summary.MediumFindings++ }
                                }
                                
                                Write-Host "  [!] Detected: $processName (PID: $($process.ProcessId))" -ForegroundColor $(
                                    if ($lolbin.Severity -eq 'Critical') { 'Red' }
                                    elseif ($lolbin.Severity -eq 'High') { 'Red' }
                                    else { 'Yellow' }
                                )
                                Write-Host "      Severity: $($lolbin.Severity)" -ForegroundColor Gray
                                Write-Host "      Pattern: $($matchedPatterns -join ', ')" -ForegroundColor Gray
                            }
                        }
                    }
                    
                    if ($results.DetectedLOLBins.Count -eq 0) {
                        Write-Host "  No suspicious LOLBins detected in running processes" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking running processes: $_"
                }
            }
            
            # 2. Check Recent Execution (Prefetch)
            if ($CheckRecentExecution) {
                Write-Host "`n[2/3] Checking recent execution history..." -ForegroundColor Cyan
                
                try {
                    # Check prefetch folder for LOLBins execution
                    $prefetchPath = "$env:SystemRoot\Prefetch"
                    
                    if (Test-Path $prefetchPath) {
                        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
                            Sort-Object LastWriteTime -Descending |
                            Select-Object -First 100
                        
                        $foundCount = 0
                        
                        foreach ($file in $prefetchFiles) {
                            $fileName = $file.Name.ToLower()
                            
                            foreach ($lolbin in $lolbinsDB.Keys) {
                                $binaryName = $lolbin.Replace('.exe', '')
                                
                                if ($fileName -like "$binaryName-*") {
                                    $detection = [PSCustomObject]@{
                                        DetectionType = 'RecentExecution'
                                        Binary = $lolbin
                                        ProcessId = 'N/A'
                                        Description = $lolbinsDB[$lolbin].Description
                                        CommandLine = "N/A (Prefetch evidence only)"
                                        MatchedPatterns = "Execution detected via Prefetch"
                                        Severity = 'Low'
                                        Path = $file.FullName
                                        Timestamp = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                    }
                                    
                                    $results.DetectedLOLBins += $detection
                                    $foundCount++
                                    
                                    Write-Host "  [!] Recent execution: $lolbin" -ForegroundColor Yellow
                                    Write-Host "      Last executed: $($file.LastWriteTime)" -ForegroundColor Gray
                                    break
                                }
                            }
                        }
                        
                        if ($foundCount -eq 0) {
                            Write-Host "  No LOLBins detected in recent execution history" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "  Prefetch folder not accessible" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Error checking recent execution: $_"
                }
            }
            
            # 3. Check Scheduled Tasks
            if ($CheckScheduledTasks) {
                Write-Host "`n[3/3] Checking scheduled tasks..." -ForegroundColor Cyan
                
                try {
                    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
                    $foundCount = 0
                    
                    foreach ($task in $tasks) {
                        foreach ($action in $task.Actions) {
                            if ($action.PSObject.Properties.Name -contains 'Execute' -and $action.Execute) {
                                # Safe executable name extraction - FIX: Handle environment variables and illegal characters
                                $executable = $null
                                try {
                                    # Try to expand environment variables
                                    $expandedPath = [Environment]::ExpandEnvironmentVariables($action.Execute)
                                    $executable = [System.IO.Path]::GetFileName($expandedPath).ToLower()
                                }
                                catch {
                                    # If path parsing fails, try regex extraction
                                    if ($action.Execute -match '([^\\/:*?"<>|]+\.exe)') {
                                        $executable = $matches[1].ToLower()
                                    }
                                }
                                
                                if (-not $executable) {
                                    continue
                                }
                                
                                if ($lolbinsDB.ContainsKey($executable)) {
                                    $lolbin = $lolbinsDB[$executable]
                                    $arguments = if ($action.Arguments) { $action.Arguments } else { "" }
                                    
                                    # Check for suspicious patterns
                                    $matchedPatterns = @()
                                    foreach ($pattern in $lolbin.SuspiciousPatterns) {
                                        if ($arguments -match $pattern) {
                                            $matchedPatterns += $pattern
                                        }
                                    }
                                    
                                    if ($matchedPatterns.Count -gt 0) {
                                        $detection = [PSCustomObject]@{
                                            DetectionType = 'ScheduledTask'
                                            Binary = $executable
                                            ProcessId = 'N/A'
                                            Description = $lolbin.Description
                                            CommandLine = "$($action.Execute) $arguments"
                                            MatchedPatterns = $matchedPatterns -join ', '
                                            Severity = $lolbin.Severity
                                            Path = "Scheduled Task: $($task.TaskName)"
                                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                        }
                                        
                                        $results.DetectedLOLBins += $detection
                                        $foundCount++
                                        
                                        switch ($lolbin.Severity) {
                                            'Critical' { $results.Summary.CriticalFindings++ }
                                            'High' { $results.Summary.HighFindings++ }
                                            'Medium' { $results.Summary.MediumFindings++ }
                                        }
                                        
                                        Write-Host "  [!] Detected in task: $($task.TaskName)" -ForegroundColor Red
                                        Write-Host "      Binary: $executable" -ForegroundColor Gray
                                        Write-Host "      Severity: $($lolbin.Severity)" -ForegroundColor Gray
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No suspicious LOLBins detected in scheduled tasks" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking scheduled tasks: $_"
                }
            }
            
            # Calculate total detections
            $results.Summary.TotalDetections = $results.DetectedLOLBins.Count
            
            # Generate recommendations
            if ($results.Summary.TotalDetections -gt 0) {
                if ($results.Summary.CriticalFindings -gt 0) {
                    $results.Recommendations += "CRITICAL: Investigate critical LOLBins detections immediately"
                    $results.Recommendations += "Isolate affected systems from network"
                }
                
                $results.Recommendations += "Review command lines and execution context"
                $results.Recommendations += "Check for lateral movement indicators"
                $results.Recommendations += "Enable Sysmon or enhanced process logging"
                $results.Recommendations += "Implement application whitelisting (AppLocker/WDAC)"
                $results.Recommendations += "Monitor LOLBins usage with behavioral analytics"
            }
            
        }
        catch {
            Write-Error "Error during LOLBins detection: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor $(
            if ($results.Summary.CriticalFindings -gt 0) { 'Red' }
            elseif ($results.Summary.HighFindings -gt 0) { 'Yellow' }
            else { 'Green' }
        )
        
        Write-Host "`nDetection Summary:" -ForegroundColor Cyan
        Write-Host "  Total Detections: $($results.Summary.TotalDetections)" -ForegroundColor White
        Write-Host "  Critical: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumFindings)" -ForegroundColor Yellow
        
        if ($results.DetectedLOLBins.Count -gt 0) {
            Write-Host "`nDetected LOLBins:" -ForegroundColor Cyan
            $results.DetectedLOLBins | 
                Group-Object Binary | 
                Sort-Object Count -Descending | 
                ForEach-Object {
                    Write-Host "  $($_.Name): $($_.Count) detection(s)" -ForegroundColor White
                }
            
            Write-Host "`nTop Detections by Severity:" -ForegroundColor Cyan
            $results.DetectedLOLBins | 
                Sort-Object { 
                    switch ($_.Severity) {
                        'Critical' { 1 }
                        'High' { 2 }
                        'Medium' { 3 }
                        'Low' { 4 }
                    }
                } |
                Select-Object -First 5 |
                ForEach-Object {
                    Write-Host "  [$($_.Severity)] $($_.Binary) - $($_.DetectionType)" -ForegroundColor White
                }
        }
        else {
            Write-Host "`nNo suspicious LOLBins activity detected" -ForegroundColor Green
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nLOLBAS Project: https://lolbas-project.github.io/" -ForegroundColor Gray
        
        return $results
    }
}