function Get-MemoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes process memory for suspicious indicators
    .DESCRIPTION
        Examines running processes for memory-based threats including code injection,
        hollowing, and suspicious memory patterns
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
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
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
                                Size = [math]::Round($module.Size / 1KB, 2)
                                Suspicious = $isSuspicious
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not enumerate modules for $($process.ProcessName): $_"
                    }
                    
                    # Check for process hollowing indicators
                    # Look for mismatches between process image and memory
                    if ($process.Path) {
                        try {
                            $mainModule = $process.MainModule
                            
                            # Compare main module with process path
                            if ($mainModule.FileName -ne $process.Path) {
                                $results.HollowingIndicators += [PSCustomObject]@{
                                    ProcessName = $process.ProcessName
                                    ProcessId = $process.Id
                                    ExpectedPath = $process.Path
                                    ActualPath = $mainModule.FileName
                                    Reason = "Main module path mismatch - possible process hollowing"
                                }
                                $results.Statistics.HollowingIndicators++
                                $processAnalysis.Findings += "Possible process hollowing detected"
                            }
                        }
                        catch {
                            Write-Verbose "Could not check main module for $($process.ProcessName)"
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