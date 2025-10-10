function Find-SuspiciousProcesses {
    <#
    .SYNOPSIS
        Detects suspicious running processes on the system
    .DESCRIPTION
        Identifies potentially malicious processes based on various indicators including
        unsigned binaries, unusual locations, suspicious names, and abnormal behavior
    .PARAMETER CheckSignatures
        Verify digital signatures of process executables
    .PARAMETER CheckNetwork
        Include network connection analysis
    .EXAMPLE
        Find-SuspiciousProcesses
        Find-SuspiciousProcesses -CheckSignatures -CheckNetwork
    .OUTPUTS
        Array of suspicious process objects
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckSignatures,
        
        [Parameter()]
        [switch]$CheckNetwork
    )
    
    begin {
        Write-Host "Scanning for suspicious processes..." -ForegroundColor Cyan
        
        $suspiciousProcesses = @()
        
        # Suspicious process names and patterns
        $suspiciousNames = @(
            'mimikatz', 'procdump', 'pwdump', 'htran', 'psexec',
            'netcat', 'ncat', 'nc64', 'nmap', 'tcpdump',
            'wireshark', 'ettercap', 'cain', 'john', 'hashcat',
            'meterpreter', 'cobalt', 'beacon', 'empire', 'covenant'
        )
        
        # Suspicious paths
        $suspiciousPaths = @(
            '\\Temp\\',
            '\\AppData\\Local\\Temp\\',
            '\\Users\\Public\\',
            '\\ProgramData\\.*\\.\\',
            '\\Windows\\Tasks\\'
        )
        
        # Legitimate system processes that should only run from System32
        $systemProcesses = @(
            'svchost', 'lsass', 'services', 'csrss', 'winlogon',
            'smss', 'wininit', 'taskhost', 'dwm', 'explorer'
        )
    }
    
    process {
        try {
            # Get all running processes with detailed info
            $processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                $suspicionScore = 0
                $suspicionReasons = @()
                
                try {
                    $processPath = $proc.Path
                    $processName = $proc.ProcessName.ToLower()
                    
                    # Skip if no path (system processes)
                    if (-not $processPath) {
                        continue
                    }
                    
                    # Check 1: Suspicious process names
                    foreach ($suspName in $suspiciousNames) {
                        if ($processName -match $suspName) {
                            $suspicionScore += 50
                            $suspicionReasons += "Matches known suspicious tool name: $suspName"
                            break
                        }
                    }
                    
                    # Check 2: System process in wrong location
                    if ($systemProcesses -contains $processName) {
                        if ($processPath -notmatch '\\Windows\\System32\\') {
                            $suspicionScore += 80
                            $suspicionReasons += "System process running from non-standard location"
                        }
                    }
                    
                    # Check 3: Running from suspicious paths
                    foreach ($suspPath in $suspiciousPaths) {
                        if ($processPath -match $suspPath) {
                            $suspicionScore += 40
                            $suspicionReasons += "Running from suspicious location: $suspPath"
                            break
                        }
                    }
                    
                    # Check 4: No file description
                    try {
                        $fileInfo = Get-Item -Path $processPath -ErrorAction Stop
                        if (-not $fileInfo.VersionInfo.FileDescription) {
                            $suspicionScore += 20
                            $suspicionReasons += "No file description"
                        }
                        
                        # Check 5: Very recent file creation (last 24 hours)
                        if ($fileInfo.CreationTime -gt (Get-Date).AddDays(-1)) {
                            $suspicionScore += 30
                            $suspicionReasons += "Executable created within last 24 hours"
                        }
                    }
                    catch {
                        $suspicionScore += 30
                        $suspicionReasons += "Cannot access executable file"
                    }
                    
                    # Check 6: Unusual parent-child relationship
                    try {
                        $parentProcess = Get-Process -Id $proc.Parent.Id -ErrorAction Stop
                        
                        # PowerShell/cmd spawned by Office apps
                        if ($parentProcess.ProcessName -match '(WINWORD|EXCEL|POWERPNT|OUTLOOK)' -and 
                            $processName -match '(powershell|cmd|wscript|cscript|mshta)') {
                            $suspicionScore += 60
                            $suspicionReasons += "Scripting engine spawned by Office application"
                        }
                        
                        # Browser spawning suspicious processes
                        if ($parentProcess.ProcessName -match '(chrome|firefox|iexplore|msedge)' -and
                            $processName -match '(powershell|cmd|wscript|cscript)') {
                            $suspicionScore += 50
                            $suspicionReasons += "Scripting engine spawned by browser"
                        }
                    }
                    catch {
                        # Parent process no longer exists or inaccessible
                    }
                    
                    # Check 7: High CPU or memory usage for unknown process
                    if ($proc.CPU -gt 50 -and $processPath -notmatch '(Microsoft|Windows|Program Files)') {
                        $suspicionScore += 20
                        $suspicionReasons += "High CPU usage for non-standard process"
                    }
                    
                    # Check 8: Multiple instances of same process with different paths
                    $sameNameProcs = $processes | Where-Object { 
                        $_.ProcessName -eq $proc.ProcessName -and $_.Path -ne $proc.Path 
                    }
                    if ($sameNameProcs) {
                        $suspicionScore += 30
                        $suspicionReasons += "Multiple instances with different paths"
                    }
                    
                    # Check 9: Digital signature verification (if requested)
                    if ($CheckSignatures) {
                        try {
                            $signature = Get-AuthenticodeSignature -FilePath $processPath -ErrorAction Stop
                            if ($signature.Status -ne 'Valid') {
                                $suspicionScore += 40
                                $suspicionReasons += "Invalid or missing digital signature: $($signature.Status)"
                            }
                        }
                        catch {
                            $suspicionScore += 30
                            $suspicionReasons += "Could not verify signature"
                        }
                    }
                    
                    # Check 10: Network connections (if requested)
                    if ($CheckNetwork) {
                        try {
                            $connections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                                Where-Object { $_.State -eq 'Established' }
                            
                            if ($connections) {
                                # Check for connections to uncommon ports
                                $uncommonPorts = $connections | Where-Object { 
                                    $_.RemotePort -notin @(80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389)
                                }
                                
                                if ($uncommonPorts) {
                                    $suspicionScore += 25
                                    $suspicionReasons += "Network connections to uncommon ports: $(($uncommonPorts.RemotePort -join ', '))"
                                }
                            }
                        }
                        catch {
                            # Could not get network connections
                        }
                    }
                    
                    # If suspicion score is high enough, add to results
                    if ($suspicionScore -ge 40) {
                        $suspiciousProcesses += [PSCustomObject]@{
                            ProcessName = $proc.ProcessName
                            ProcessId = $proc.Id
                            Path = $processPath
                            CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                            UserName = $proc.UserName
                            StartTime = $proc.StartTime
                            CPU = [math]::Round($proc.CPU, 2)
                            WorkingSet = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                            SuspicionScore = $suspicionScore
                            Reasons = ($suspicionReasons -join '; ')
                            ParentProcess = try { (Get-Process -Id $proc.Parent.Id -ErrorAction Stop).ProcessName } catch { 'N/A' }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error processing process $($proc.ProcessName): $_"
                }
            }
            
        }
        catch {
            Write-Error "Error during process scan: $_"
            throw
        }
    }
    
    end {
        Write-Host "`nFound $($suspiciousProcesses.Count) suspicious processes" -ForegroundColor $(if ($suspiciousProcesses.Count -gt 0) { 'Red' } else { 'Green' })
        
        return $suspiciousProcesses | Sort-Object -Property SuspicionScore -Descending
    }
}