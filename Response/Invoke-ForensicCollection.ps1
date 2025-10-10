function Invoke-ForensicCollection {
    <#
    .SYNOPSIS
        Collects comprehensive forensic evidence from the system
    .DESCRIPTION
        Performs detailed forensic data collection including memory dumps, disk artifacts,
        registry hives, event logs, and system state information
    .PARAMETER CollectionType
        Type of collection: Quick, Standard, or Comprehensive
    .PARAMETER OutputPath
        Path to save collected evidence
    .PARAMETER IncludeMemoryDump
        Include memory dump (requires large disk space)
    .PARAMETER IncludeDiskArtifacts
        Collect disk-based artifacts (MFT, prefetch, etc.)
    .EXAMPLE
        Invoke-ForensicCollection -CollectionType Standard -OutputPath "C:\Forensics"
        Invoke-ForensicCollection -CollectionType Comprehensive -IncludeMemoryDump -OutputPath "D:\Evidence"
    .OUTPUTS
        PSCustomObject with collection results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Quick', 'Standard', 'Comprehensive')]
        [string]$CollectionType,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$IncludeMemoryDump,
        
        [Parameter()]
        [switch]$IncludeDiskArtifacts
    )
    
    begin {
        Write-Host "=== FORENSIC EVIDENCE COLLECTION ===" -ForegroundColor Cyan
        Write-Host "Collection Type: $CollectionType" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "Forensic collection requires Administrator privileges!"
        }
        
        # Create output directory with timestamp
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $collectionPath = Join-Path $OutputPath "ForensicCollection_$timestamp"
        New-Item -Path $collectionPath -ItemType Directory -Force | Out-Null
        
        # Create subdirectories
        $directories = @(
            'SystemInfo',
            'EventLogs',
            'Registry',
            'Network',
            'Processes',
            'FileSystem',
            'Memory',
            'Timeline'
        )
        
        foreach ($dir in $directories) {
            New-Item -Path (Join-Path $collectionPath $dir) -ItemType Directory -Force | Out-Null
        }
        
        $results = [PSCustomObject]@{
            CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            CollectionType = $CollectionType
            ComputerName = $env:COMPUTERNAME
            OutputPath = $collectionPath
            ArtifactsCollected = @()
            Errors = @()
            TotalSize = 0
            Status = 'In Progress'
        }
        
        $logFile = Join-Path $collectionPath "Collection.log"
        
        function Write-CollectionLog {
            param([string]$Message, [string]$Level = 'INFO')
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "[$timestamp] [$Level] $Message"
            Add-Content -Path $logFile -Value $logMessage
            Write-Verbose $Message
        }
        
        Write-CollectionLog "Forensic collection initiated - Type: $CollectionType"
    }
    
    process {
        try {
            # Collection 1: System Information (All types)
            Write-Host "`n[1/10] Collecting system information..." -ForegroundColor Cyan
            try {
                $sysInfoPath = Join-Path $collectionPath 'SystemInfo'
                
                # Basic system info
                $sysInfo = Get-SystemInfo -IncludeInstalledSoftware -IncludeHotfixes
                $sysInfo | ConvertTo-Json -Depth 5 | Out-File (Join-Path $sysInfoPath "SystemInfo.json")
                
                # Computer information
                Get-ComputerInfo | ConvertTo-Json -Depth 5 | Out-File (Join-Path $sysInfoPath "ComputerInfo.json")
                
                # Environment variables
                Get-ChildItem Env: | Export-Csv (Join-Path $sysInfoPath "EnvironmentVariables.csv") -NoTypeInformation
                
                # Local users and groups
                Get-LocalUser | Export-Csv (Join-Path $sysInfoPath "LocalUsers.csv") -NoTypeInformation
                Get-LocalGroup | Export-Csv (Join-Path $sysInfoPath "LocalGroups.csv") -NoTypeInformation
                
                $results.ArtifactsCollected += "System Information"
                Write-CollectionLog "Collected system information"
            }
            catch {
                $results.Errors += "System Info: $_"
                Write-CollectionLog "Error collecting system info: $_" 'ERROR'
            }
            
            # Collection 2: Running Processes (All types)
            Write-Host "[2/10] Collecting process information..." -ForegroundColor Cyan
            try {
                $procPath = Join-Path $collectionPath 'Processes'
                
                # Process list with details
                Get-Process | Select-Object Name, Id, Path, CommandLine, StartTime, CPU, WorkingSet64, Threads |
                    Export-Csv (Join-Path $procPath "Processes.csv") -NoTypeInformation
                
                # Process modules
                $procModules = Get-Process | ForEach-Object {
                    try {
                        $_.Modules | Select-Object @{N='ProcessName';E={$_.ProcessName}}, 
                                                   @{N='ProcessId';E={$_.Id}},
                                                   ModuleName, FileName, Size
                    } catch {}
                }
                $procModules | Export-Csv (Join-Path $procPath "ProcessModules.csv") -NoTypeInformation
                
                # Services
                Get-Service | Export-Csv (Join-Path $procPath "Services.csv") -NoTypeInformation
                Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName |
                    Export-Csv (Join-Path $procPath "ServicesDetailed.csv") -NoTypeInformation
                
                # Scheduled tasks
                Get-ScheduledTask | Export-Csv (Join-Path $procPath "ScheduledTasks.csv") -NoTypeInformation
                
                $results.ArtifactsCollected += "Process Information"
                Write-CollectionLog "Collected process information"
            }
            catch {
                $results.Errors += "Processes: $_"
                Write-CollectionLog "Error collecting processes: $_" 'ERROR'
            }
            
            # Collection 3: Network Information (All types)
            Write-Host "[3/10] Collecting network information..." -ForegroundColor Cyan
            try {
                $netPath = Join-Path $collectionPath 'Network'
                
                # Network adapters
                Get-NetAdapter | Export-Csv (Join-Path $netPath "NetworkAdapters.csv") -NoTypeInformation
                Get-NetIPAddress | Export-Csv (Join-Path $netPath "IPAddresses.csv") -NoTypeInformation
                Get-NetRoute | Export-Csv (Join-Path $netPath "Routes.csv") -NoTypeInformation
                
                # Active connections
                Get-NetTCPConnection | Export-Csv (Join-Path $netPath "TCPConnections.csv") -NoTypeInformation
                Get-NetUDPEndpoint | Export-Csv (Join-Path $netPath "UDPEndpoints.csv") -NoTypeInformation
                
                # DNS cache
                Get-DnsClientCache | Export-Csv (Join-Path $netPath "DNSCache.csv") -NoTypeInformation
                
                # Firewall rules
                Get-NetFirewallRule | Export-Csv (Join-Path $netPath "FirewallRules.csv") -NoTypeInformation
                Get-NetFirewallProfile | Export-Csv (Join-Path $netPath "FirewallProfiles.csv") -NoTypeInformation
                
                # ARP cache
                Get-NetNeighbor | Export-Csv (Join-Path $netPath "ARPCache.csv") -NoTypeInformation
                
                # Network shares
                Get-SmbShare | Export-Csv (Join-Path $netPath "Shares.csv") -NoTypeInformation
                Get-SmbSession | Export-Csv (Join-Path $netPath "SMBSessions.csv") -NoTypeInformation
                
                $results.ArtifactsCollected += "Network Information"
                Write-CollectionLog "Collected network information"
            }
            catch {
                $results.Errors += "Network: $_"
                Write-CollectionLog "Error collecting network info: $_" 'ERROR'
            }
            
            # Collection 4: Event Logs (Standard and Comprehensive)
            if ($CollectionType -in @('Standard', 'Comprehensive')) {
                Write-Host "[4/10] Collecting event logs..." -ForegroundColor Cyan
                try {
                    $eventPath = Join-Path $collectionPath 'EventLogs'
                    
                    # Security events (last 7 days)
                    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10000 -ErrorAction SilentlyContinue |
                        Select-Object TimeCreated, Id, LevelDisplayName, Message |
                        Export-Csv (Join-Path $eventPath "Security_Recent.csv") -NoTypeInformation
                    
                    # System events (last 7 days)
                    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10000 -ErrorAction SilentlyContinue |
                        Select-Object TimeCreated, Id, LevelDisplayName, Message |
                        Export-Csv (Join-Path $eventPath "System_Recent.csv") -NoTypeInformation
                    
                    # Application events (last 7 days)
                    Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10000 -ErrorAction SilentlyContinue |
                        Select-Object TimeCreated, Id, LevelDisplayName, Message |
                        Export-Csv (Join-Path $eventPath "Application_Recent.csv") -NoTypeInformation
                    
                    # PowerShell logs
                    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 5000 -ErrorAction SilentlyContinue |
                        Select-Object TimeCreated, Id, Message |
                        Export-Csv (Join-Path $eventPath "PowerShell_Recent.csv") -NoTypeInformation
                    
                    $results.ArtifactsCollected += "Event Logs"
                    Write-CollectionLog "Collected event logs"
                }
                catch {
                    $results.Errors += "Event Logs: $_"
                    Write-CollectionLog "Error collecting event logs: $_" 'ERROR'
                }
            }
            else {
                Write-Host "[4/10] Event logs: SKIPPED (Quick mode)" -ForegroundColor Yellow
            }
            
            # Collection 5: Registry Artifacts (Standard and Comprehensive)
            if ($CollectionType -in @('Standard', 'Comprehensive')) {
                Write-Host "[5/10] Collecting registry artifacts..." -ForegroundColor Cyan
                try {
                    $regPath = Join-Path $collectionPath 'Registry'
                    
                    # Run keys
                    $runKeys = @(
                        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
                    )
                    
                    $runEntries = foreach ($key in $runKeys) {
                        if (Test-Path $key) {
                            Get-ItemProperty -Path $key | Select-Object PSPath, PSChildName, *
                        }
                    }
                    $runEntries | Export-Csv (Join-Path $regPath "RunKeys.csv") -NoTypeInformation
                    
                    # Installed software
                    $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                        Where-Object { $_.DisplayName } |
                        Select-Object DisplayName, Publisher, InstallDate, DisplayVersion
                    $software | Export-Csv (Join-Path $regPath "InstalledSoftware.csv") -NoTypeInformation
                    
                    # USB history
                    $usb = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\* -ErrorAction SilentlyContinue |
                        Select-Object PSChildName, FriendlyName
                    $usb | Export-Csv (Join-Path $regPath "USBHistory.csv") -NoTypeInformation
                    
                    $results.ArtifactsCollected += "Registry Artifacts"
                    Write-CollectionLog "Collected registry artifacts"
                }
                catch {
                    $results.Errors += "Registry: $_"
                    Write-CollectionLog "Error collecting registry: $_" 'ERROR'
                }
            }
            else {
                Write-Host "[5/10] Registry artifacts: SKIPPED (Quick mode)" -ForegroundColor Yellow
            }
            
            # Collection 6: File System Artifacts (Comprehensive only)
            if ($CollectionType -eq 'Comprehensive' -or $IncludeDiskArtifacts) {
                Write-Host "[6/10] Collecting file system artifacts..." -ForegroundColor Cyan
                try {
                    $fsPath = Join-Path $collectionPath 'FileSystem'
                    
                    # Recent files in temp directories
                    $tempPaths = @("$env:TEMP", "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp")
                    $recentFiles = foreach ($temp in $tempPaths) {
                        if (Test-Path $temp) {
                            Get-ChildItem -Path $temp -File -Recurse -ErrorAction SilentlyContinue |
                                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
                                Select-Object FullName, Name, Length, CreationTime, LastWriteTime
                        }
                    }
                    $recentFiles | Export-Csv (Join-Path $fsPath "RecentTempFiles.csv") -NoTypeInformation
                    
                    # Prefetch files
                    if (Test-Path "$env:SystemRoot\Prefetch") {
                        Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf |
                            Select-Object Name, Length, CreationTime, LastWriteTime, LastAccessTime |
                            Export-Csv (Join-Path $fsPath "Prefetch.csv") -NoTypeInformation
                    }
                    
                    # Recent downloads
                    $downloadsPath = "$env:USERPROFILE\Downloads"
                    if (Test-Path $downloadsPath) {
                        Get-ChildItem $downloadsPath -File -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                            Select-Object FullName, Name, Length, CreationTime, LastWriteTime |
                            Export-Csv (Join-Path $fsPath "RecentDownloads.csv") -NoTypeInformation
                    }
                    
                    $results.ArtifactsCollected += "File System Artifacts"
                    Write-CollectionLog "Collected file system artifacts"
                }
                catch {
                    $results.Errors += "File System: $_"
                    Write-CollectionLog "Error collecting file system: $_" 'ERROR'
                }
            }
            else {
                Write-Host "[6/10] File system artifacts: SKIPPED" -ForegroundColor Yellow
            }
            
            # Collection 7: Security Analysis (Standard and Comprehensive)
            if ($CollectionType -in @('Standard', 'Comprehensive')) {
                Write-Host "[7/10] Running security analysis..." -ForegroundColor Cyan
                try {
                    $secPath = Join-Path $collectionPath 'SecurityAnalysis'
                    New-Item -Path $secPath -ItemType Directory -Force | Out-Null
                    
                    # Persistence mechanisms
                    $persistence = Find-PersistenceMechanisms
                    $persistence | ConvertTo-Json -Depth 5 | Out-File (Join-Path $secPath "Persistence.json")
                    
                    # Network anomalies
                    $network = Find-NetworkAnomalies -IncludeEstablished
                    $network | ConvertTo-Json -Depth 5 | Out-File (Join-Path $secPath "NetworkAnomalies.json")
                    
                    # Authentication analysis
                    $auth = Find-SuspiciousAuthentication -Hours 168
                    $auth | ConvertTo-Json -Depth 5 | Out-File (Join-Path $secPath "Authentication.json")
                    
                    $results.ArtifactsCollected += "Security Analysis"
                    Write-CollectionLog "Completed security analysis"
                }
                catch {
                    $results.Errors += "Security Analysis: $_"
                    Write-CollectionLog "Error in security analysis: $_" 'ERROR'
                }
            }
            else {
                Write-Host "[7/10] Security analysis: SKIPPED (Quick mode)" -ForegroundColor Yellow
            }
            
            # Collection 8: Memory Dump (if requested)
            if ($IncludeMemoryDump) {
                Write-Host "[8/10] Creating memory dump..." -ForegroundColor Cyan
                Write-Warning "Memory dump requires significant disk space and time"
                try {
                    $memPath = Join-Path $collectionPath 'Memory'
                    Write-CollectionLog "Memory dump requested but requires external tools (e.g., WinPMEM, DumpIt)" 'WARNING'
                    
                    # Note: Full memory dump requires external tools
                    $note = @"
Memory dump collection requires external tools such as:
- WinPMEM (Rekall)
- DumpIt (Comae)
- Magnet RAM Capture
- FTK Imager

Please use appropriate forensic tools for memory acquisition.
"@
                    $note | Out-File (Join-Path $memPath "MemoryDump_Instructions.txt")
                    
                    $results.ArtifactsCollected += "Memory Dump Instructions"
                }
                catch {
                    $results.Errors += "Memory: $_"
                    Write-CollectionLog "Memory dump: $_" 'ERROR'
                }
            }
            else {
                Write-Host "[8/10] Memory dump: SKIPPED" -ForegroundColor Yellow
            }
            
            # Collection 9: Timeline Generation
            Write-Host "[9/10] Generating timeline..." -ForegroundColor Cyan
            try {
                $timelinePath = Join-Path $collectionPath 'Timeline'
                
                $timeline = @()
                
                # Process start times
                Get-Process | Where-Object { $_.StartTime } | ForEach-Object {
                    $timeline += [PSCustomObject]@{
                        Timestamp = $_.StartTime
                        Type = 'ProcessStart'
                        Description = "$($_.ProcessName) (PID: $($_.Id))"
                        Details = $_.Path
                    }
                }
                
                # Recent file modifications
           
  # Recent file modifications
if ($null -ne (Get-Variable -Name 'recentFiles' -ErrorAction SilentlyContinue) -and $recentFiles) {
    $recentFiles | Where-Object { $_ } | ForEach-Object {
        $timeline += [PSCustomObject]@{
            Timestamp = $_.LastWriteTime
            Type = 'FileModified'
            Description = $_.Name
            Details = $_.FullName
        }
    }
}

                
                $timeline | Sort-Object Timestamp -Descending |
                    Export-Csv (Join-Path $timelinePath "Timeline.csv") -NoTypeInformation
                
                $results.ArtifactsCollected += "Timeline"
                Write-CollectionLog "Generated timeline"
            }
            catch {
                $results.Errors += "Timeline: $_"
                Write-CollectionLog "Error generating timeline: $_" 'ERROR'
            }
            
            # Collection 10: Collection Summary
            Write-Host "[10/10] Finalizing collection..." -ForegroundColor Cyan
            
            # Calculate total size
            $totalSize = (Get-ChildItem $collectionPath -Recurse -File | Measure-Object -Property Length -Sum).Sum
            $results.TotalSize = [math]::Round($totalSize / 1MB, 2)
            $results.Status = 'Completed'
            
            # Create hash manifest for integrity
            $hashManifest = Get-ChildItem $collectionPath -Recurse -File | ForEach-Object {
                [PSCustomObject]@{
                    Path = $_.FullName.Replace($collectionPath, '')
                    SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
                    Size = $_.Length
                }
            }
            $hashManifest | Export-Csv (Join-Path $collectionPath "HashManifest.csv") -NoTypeInformation
            
            Write-CollectionLog "Collection completed successfully"
            
        }
        catch {
            $results.Status = 'Failed'
            $results.Errors += "Fatal: $_"
            Write-CollectionLog "Collection failed: $_" 'ERROR'
            throw
        }
    }
    
    end {
        # Generate collection report
        $report = @"
=== FORENSIC COLLECTION REPORT ===
Collection Date: $($results.CollectionDate)
Collection Type: $($results.CollectionType)
Computer Name: $($results.ComputerName)
Status: $($results.Status)

ARTIFACTS COLLECTED:
$($results.ArtifactsCollected | ForEach-Object { "  - $_" } | Out-String)

TOTAL SIZE: $($results.TotalSize) MB

ERRORS: $($results.Errors.Count)
$($results.Errors | ForEach-Object { "  - $_" } | Out-String)

OUTPUT PATH: $($results.OutputPath)

CHAIN OF CUSTODY:
- Collected by: $env:USERNAME
- Computer: $env:COMPUTERNAME
- Date/Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
- Hash manifest created for integrity verification

NEXT STEPS:
1. Review HashManifest.csv for file integrity
2. Preserve evidence using write-blocker if needed
3. Create forensic image of collected data
4. Document chain of custody
5. Begin analysis using appropriate forensic tools
"@
        
        $report | Out-File (Join-Path $collectionPath "CollectionReport.txt")
        
        Write-Host "`n=== FORENSIC COLLECTION COMPLETE ===" -ForegroundColor Green
        Write-Host "Status: $($results.Status)" -ForegroundColor $(if ($results.Status -eq 'Completed') { 'Green' } else { 'Red' })
        Write-Host "Total Size: $($results.TotalSize) MB" -ForegroundColor Cyan
        Write-Host "Artifacts: $($results.ArtifactsCollected.Count)" -ForegroundColor Cyan
        Write-Host "Errors: $($results.Errors.Count)" -ForegroundColor $(if ($results.Errors.Count -eq 0) { 'Green' } else { 'Yellow' })
        Write-Host "Output: $($results.OutputPath)" -ForegroundColor Cyan
        
        return $results
    }
}