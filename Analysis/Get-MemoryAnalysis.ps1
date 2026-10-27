function Get-MemoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes process memory for suspicious indicators
    .DESCRIPTION
        Examines running processes for memory-based threats including code injection,
        hollowing, and suspicious memory patterns. The hollowing check is a
        name/location heuristic: without reading process memory it cannot compare
        in-memory code against the on-disk image, so it flags well-known Windows
        system process names (svchost, lsass, csrss, ...) whose main module image
        resides outside the expected %SystemRoot% location instead.
    .PARAMETER ProcessId
        Specific process ID to analyze (optional)
    .PARAMETER CheckAllProcesses
        Analyze all running processes
    .PARAMETER IncludeStrings
        Extract suspicious strings from process memory
    .EXAMPLE
        Get-MemoryAnalysis -CheckAllProcesses
        Get-MemoryAnalysis -ProcessId 1234 -IncludeStrings
    .OUTPUTS
        PSCustomObject with memory analysis results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$ProcessId,
        
        [Parameter()]
        [switch]$CheckAllProcesses,
        
        [Parameter()]
        [switch]$IncludeStrings
    )
    
    begin {
        Write-Host "Analyzing process memory..." -ForegroundColor Cyan
        
        # Check for admin privileges (the Windows principal API is unavailable
        # on non-Windows platforms - skip the check there instead of throwing)
        $isAdmin = $false
        $adminCheckAvailable = $true
        try {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            $adminCheckAvailable = $false
            Write-Verbose "Administrator privilege check not available on this platform: $_"
        }
        if ($adminCheckAvailable -and -not $isAdmin) {
            Write-Warning "Administrator privileges recommended for complete memory analysis"
        }
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ProcessAnalysis = @()
            InjectionIndicators = @()
            HollowingIndicators = @()
            SuspiciousModules = @()
            Statistics = @{
                ProcessesAnalyzed = 0
                InjectionIndicators = 0
                HollowingIndicators = 0
                SuspiciousModules = 0
            }
        }
        
        # Suspicious module names
        $suspiciousModulePatterns = @(
            'inject', 'hook', 'reflective', 'payload', 'shellcode',
            'mimikatz', 'meterpreter', 'cobalt', 'beacon'
        )
        
        # Expected on-disk image for well-known Windows system process names.
        # A process using one of these names whose main module lives elsewhere is a
        # masquerading / process-hollowing heuristic signal (no memory is read).
        # Empty when %SystemRoot% is unavailable (non-Windows platforms).
        $expectedSystemImages = @{}
        if (-not [string]::IsNullOrEmpty($env:SystemRoot)) {
            $expectedSystemImages = @{
                'svchost'       = "$env:SystemRoot\System32\svchost.exe"
                'lsass'         = "$env:SystemRoot\System32\lsass.exe"
                'csrss'         = "$env:SystemRoot\System32\csrss.exe"
                'smss'          = "$env:SystemRoot\System32\smss.exe"
                'wininit'       = "$env:SystemRoot\System32\wininit.exe"
                'winlogon'      = "$env:SystemRoot\System32\winlogon.exe"
                'services'      = "$env:SystemRoot\System32\services.exe"
                'spoolsv'       = "$env:SystemRoot\System32\spoolsv.exe"
                'lsm'           = "$env:SystemRoot\System32\lsm.exe"
                'dwm'           = "$env:SystemRoot\System32\dwm.exe"
                'sihost'        = "$env:SystemRoot\System32\sihost.exe"
                'taskhostw'     = "$env:SystemRoot\System32\taskhostw.exe"
                'runtimebroker' = "$env:SystemRoot\System32\RuntimeBroker.exe"
                'explorer'      = "$env:SystemRoot\explorer.exe"
            }
        }
    }
    
    process {
        try {
            $processesToAnalyze = @()
            
            if ($ProcessId) {
                $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    $processesToAnalyze += $proc
                }
                else {
                    Write-Error "Process with ID $ProcessId not found"
                    return
                }
            }
            elseif ($CheckAllProcesses) {
                $processesToAnalyze = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
            }
            else {
                Write-Warning "No process specified. Use -ProcessId or -CheckAllProcesses"
                return
            }
            
            foreach ($process in $processesToAnalyze) {
                try {
                    $results.Statistics.ProcessesAnalyzed++
                    Write-Verbose "Analyzing process: $($process.ProcessName) (PID: $($process.Id))"
                    
                    $processAnalysis = [PSCustomObject]@{
                        ProcessName = $process.ProcessName
                        ProcessId = $process.Id
                        Path = $process.Path
                        StartTime = $process.StartTime
                        Threads = $process.Threads.Count
                        Modules = @()
                        MemorySize = [math]::Round($process.WorkingSet64 / 1MB, 2)
                        VirtualMemorySize = [math]::Round($process.VirtualMemorySize64 / 1MB, 2)
                        PrivateMemorySize = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
                        Findings = @()
                    }
                    
                    # Get loaded modules
                    try {
                        $modules = $process.Modules
                        foreach ($module in $modules) {
                            $moduleName = $module.ModuleName.ToLower()
                            $modulePath = $module.FileName
                            
                            # Check for suspicious modules
                            $isSuspicious = $false
                            $reason = ""
                            
                            foreach ($pattern in $suspiciousModulePatterns) {
                                if ($moduleName -match $pattern) {
                                    $isSuspicious = $true
                                    $reason = "Module name matches suspicious pattern: $pattern"
                                    break
                                }
                            }
                            
                            # Check for modules loaded from suspicious locations
                            if ($modulePath -match '(temp|appdata\\local\\temp|users\\public)') {
                                $isSuspicious = $true
                                $reason = "Module loaded from suspicious location"
                            }
                            
                            if ($isSuspicious) {
                                $results.SuspiciousModules += [PSCustomObject]@{
                                    ProcessName = $process.ProcessName
                                    ProcessId = $process.Id
                                    ModuleName = $moduleName
                                    ModulePath = $modulePath
                                    Reason = $reason
                                }
                                $results.Statistics.SuspiciousModules++
                            }
                            
                            $processAnalysis.Modules += [PSCustomObject]@{
                                Name = $moduleName
                                Path = $modulePath
                                Size = [math]::Round($module.ModuleMemorySize / 1KB, 2)
                                Suspicious = $isSuspicious
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not enumerate modules for $($process.ProcessName): $_"
                    }
                    
                    # Process hollowing / masquerading heuristic.
                    # Process.Path IS MainModule.FileName in the .NET Process API, so
                    # comparing the two (as this check previously did) is structurally
                    # false and can never fire. Without reading process memory there is
                    # no reliable hollowing check, so instead flag well-known Windows
                    # system process names whose main module image does not reside at
                    # the expected system location (e.g. a process named 'svchost'
                    # whose image is not %SystemRoot%\System32\svchost.exe).
                    $processNameLower = $process.ProcessName.ToLower()
                    if ($expectedSystemImages.ContainsKey($processNameLower)) {
                        $actualImagePath = $null
                        try {
                            $mainModule = $process.MainModule
                            if ($null -ne $mainModule) { $actualImagePath = $mainModule.FileName }
                        }
                        catch {
                            Write-Verbose "Could not read main module for $($process.ProcessName)"
                        }
                        
                        if (-not [string]::IsNullOrWhiteSpace($actualImagePath)) {
                            # Tolerate the SysWOW64 twin of System32 images (32-bit services)
                            $expectedImagePath = $expectedSystemImages[$processNameLower]
                            $expectedImagePaths = @($expectedImagePath)
                            if ($expectedImagePath -match '\\System32\\') {
                                $expectedImagePaths += ($expectedImagePath -replace '\\System32\\', '\SysWOW64\')
                            }
                            
                            $imagePathMatches = $false
                            foreach ($expectedPath in $expectedImagePaths) {
                                if ($actualImagePath.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $imagePathMatches = $true
                                    break
                                }
                            }
                            
                            if (-not $imagePathMatches) {
                                $results.HollowingIndicators += [PSCustomObject]@{
                                    ProcessName = $process.ProcessName
                                    ProcessId = $process.Id
                                    ExpectedPath = $expectedImagePath
                                    ActualPath = $actualImagePath
                                    Reason = "Well-known system process name running from an unexpected image location - masquerading/hollowing heuristic (image paths compared, memory contents NOT compared)"
                                }
                                $results.Statistics.HollowingIndicators++
                                $processAnalysis.Findings += "System process name with unexpected image location: $actualImagePath (masquerade/hollowing heuristic)"
                            }
                        }
                    }
                    
                    # Check for code injection indicators
                    # Unusual memory characteristics
                    $memoryRatio = if ($process.VirtualMemorySize64 -gt 0) {
                        $process.WorkingSet64 / $process.VirtualMemorySize64
                    } else { 0 }
                    
                    if ($memoryRatio -gt 0.9) {
                        $results.InjectionIndicators += [PSCustomObject]@{
                            ProcessName = $process.ProcessName
                            ProcessId = $process.Id
                            Indicator = "High memory ratio"
                            Value = [math]::Round($memoryRatio, 2)
                            Reason = "Unusually high working set to virtual memory ratio - possible injection"
                        }
                        $results.Statistics.InjectionIndicators++
                        $processAnalysis.Findings += "Unusual memory characteristics"
                    }
                    
                    # Check for suspicious thread count
                    $threadCount = $process.Threads.Count
                    if ($threadCount -gt 100) {
                        $processAnalysis.Findings += "Unusually high thread count: $threadCount"
                    }
                    
                    # Check for remote threads
                    try {
                        foreach ($thread in $process.Threads) {
                            # Remote threads often have start addresses outside main module
                            if ($thread.StartAddress -and $process.MainModule) {
                                $moduleBase = $process.MainModule.BaseAddress.ToInt64()
                                $moduleEnd = $moduleBase + $process.MainModule.ModuleMemorySize
                                $startAddr = $thread.StartAddress.ToInt64()
                                
                                if ($startAddr -lt $moduleBase -or $startAddr -gt $moduleEnd) {
                                    $results.InjectionIndicators += [PSCustomObject]@{
                                        ProcessName = $process.ProcessName
                                        ProcessId = $process.Id
                                        Indicator = "Remote thread detected"
                                        ThreadId = $thread.Id
                                        Reason = "Thread start address outside main module - possible remote injection"
                                    }
                                    $results.Statistics.InjectionIndicators++
                                    break  # Only report once per process
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not analyze threads for $($process.ProcessName)"
                    }
                    
                    # Extract strings from memory if requested (basic implementation)
                    if ($IncludeStrings) {
                        try {
                            # This is a simplified version - full string extraction requires more complex memory reading
                            $processAnalysis.Findings += "String extraction requires external tools like Sysinternals Strings"
                        }
                        catch {
                            Write-Verbose "Could not extract strings from $($process.ProcessName)"
                        }
                    }
                    
                    $results.ProcessAnalysis += $processAnalysis
                }
                catch {
                    Write-Verbose "Error analyzing process $($process.ProcessName): $_"
                }
            }
            
        }
        catch {
            Write-Error "Error during memory analysis: $_"
            throw
        }
    }
    
    end {
        Write-Host "`nMemory Analysis Complete!" -ForegroundColor Green
        Write-Host "`n=== Statistics ===" -ForegroundColor Cyan
        Write-Host "Processes analyzed: $($results.Statistics.ProcessesAnalyzed)" -ForegroundColor Yellow
        Write-Host "Injection indicators: $($results.Statistics.InjectionIndicators)" -ForegroundColor $(if ($results.Statistics.InjectionIndicators -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Hollowing indicators: $($results.Statistics.HollowingIndicators)" -ForegroundColor $(if ($results.Statistics.HollowingIndicators -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Suspicious modules: $($results.Statistics.SuspiciousModules)" -ForegroundColor $(if ($results.Statistics.SuspiciousModules -gt 0) { 'Red' } else { 'Green' })
        
        return $results
    }
}