function Get-ArtifactCollection {
    <#
    .SYNOPSIS
        Collects comprehensive forensic artifacts from Windows systems
    .DESCRIPTION
        KAPE-style artifact collection tool that gathers system information,
        event logs, registry hives, browser history, execution artifacts,
        and other forensic evidence for incident response and investigation.
    .PARAMETER OutputPath
        Root path for artifact collection (default: C:\ForensicCollection)
    .PARAMETER CollectionProfile
        Predefined collection profile: Quick, Standard, Full, or Custom
    .PARAMETER IncludeEventLogs
        Collect Windows event logs
    .PARAMETER IncludeRegistry
        Collect registry hives
    .PARAMETER IncludeBrowserHistory
        Collect browser artifacts
    .PARAMETER IncludeExecutionArtifacts
        Collect prefetch, UserAssist, etc.
    .PARAMETER IncludeNetworkInfo
        Collect network configuration and connections
    .PARAMETER CompressOutput
        Create ZIP archive of collected artifacts
    .PARAMETER RemoveSource
        Remove original files after compression
    .EXAMPLE
        Get-ArtifactCollection -CollectionProfile Standard
        Get-ArtifactCollection -OutputPath "E:\Evidence" -CollectionProfile Full -CompressOutput
    .OUTPUTS
        PSCustomObject with collection results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = "C:\ForensicCollection",
        
        [Parameter()]
        [ValidateSet('Quick', 'Standard', 'Full', 'Custom')]
        [string]$CollectionProfile = 'Standard',
        
        [Parameter()]
        [switch]$IncludeEventLogs,
        
        [Parameter()]
        [switch]$IncludeRegistry,
        
        [Parameter()]
        [switch]$IncludeBrowserHistory,
        
        [Parameter()]
        [switch]$IncludeExecutionArtifacts,
        
        [Parameter()]
        [switch]$IncludeNetworkInfo,
        
        [Parameter()]
        [switch]$CompressOutput,
        
        [Parameter()]
        [switch]$RemoveSource
    )
    
    begin {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  FORENSIC ARTIFACT COLLECTION TOOL" -ForegroundColor Cyan
        Write-Host "  KAPE-Style Evidence Gathering" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Collection Profile: $CollectionProfile" -ForegroundColor Yellow
        Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Warning "Administrator privileges recommended for complete collection!"
        }
        
        # Set collection flags based on profile
        switch ($CollectionProfile) {
            'Quick' {
                $IncludeEventLogs = $false
                $IncludeRegistry = $false
                $IncludeBrowserHistory = $false
                $IncludeExecutionArtifacts = $true
                $IncludeNetworkInfo = $true
            }
            'Standard' {
                $IncludeEventLogs = $true
                $IncludeRegistry = $false
                $IncludeBrowserHistory = $true
                $IncludeExecutionArtifacts = $true
                $IncludeNetworkInfo = $true
            }
            'Full' {
                $IncludeEventLogs = $true
                $IncludeRegistry = $true
                $IncludeBrowserHistory = $true
                $IncludeExecutionArtifacts = $true
                $IncludeNetworkInfo = $true
            }
        }
        
        # Create collection structure
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $collectionRoot = Join-Path $OutputPath "Collection_$timestamp"
        
        $paths = @{
            Root = $collectionRoot
            SystemInfo = Join-Path $collectionRoot "1_SystemInfo"
            EventLogs = Join-Path $collectionRoot "2_EventLogs"
            Registry = Join-Path $collectionRoot "3_Registry"
            FileSystem = Join-Path $collectionRoot "4_FileSystem"
            Browser = Join-Path $collectionRoot "5_Browser"
            Network = Join-Path $collectionRoot "6_Network"
            Execution = Join-Path $collectionRoot "7_Execution"
            Users = Join-Path $collectionRoot "8_Users"
        }
        
        foreach ($path in $paths.Values) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
            }
        }
        
        Write-Host "Collection directory created: $collectionRoot" -ForegroundColor Green
        
        $results = [PSCustomObject]@{
            CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Profile = $CollectionProfile
            OutputPath = $collectionRoot
            ArtifactsCollected = @()
            Summary = @{
                TotalFiles = 0
                TotalSize = 0
                Errors = 0
            }
            CompressedArchive = $null
        }
    }
    
    process {
        try {
            # 1. COLLECT SYSTEM INFORMATION
            Write-Host "`n[1/8] Collecting System Information..." -ForegroundColor Cyan
            
            try {
                # Computer info
                $computerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
                $computerInfo | ConvertTo-Json -Depth 5 | Out-File (Join-Path $paths.SystemInfo "ComputerInfo.json")
                
                # OS Info
                Get-CimInstance Win32_OperatingSystem | 
                    Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime |
                    ConvertTo-Json | Out-File (Join-Path $paths.SystemInfo "OSInfo.json")
                
                # Hardware Info
                Get-CimInstance Win32_ComputerSystem |
                    Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfProcessors |
                    ConvertTo-Json | Out-File (Join-Path $paths.SystemInfo "Hardware.json")
                
                # Disk Info
                Get-PSDrive -PSProvider FileSystem |
                    Select-Object Name, Used, Free, @{N='TotalGB';E={[Math]::Round($_.Used/1GB + $_.Free/1GB,2)}} |
                    ConvertTo-Json | Out-File (Join-Path $paths.SystemInfo "Disks.json")
                
                # Installed Software
                Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                    Where-Object { $_.DisplayName } |
                    ConvertTo-Json | Out-File (Join-Path $paths.SystemInfo "InstalledSoftware.json")
                
                # Environment Variables
                Get-ChildItem Env: | ConvertTo-Json | Out-File (Join-Path $paths.SystemInfo "Environment.json")
                
                Write-Host "  System information collected" -ForegroundColor Green
                $results.ArtifactsCollected += "System Information"
            }
            catch {
                Write-Warning "Error collecting system info: $_"
                $results.Summary.Errors++
            }
            
            # 2. COLLECT EVENT LOGS
            if ($IncludeEventLogs) {
                Write-Host "`n[2/8] Collecting Event Logs..." -ForegroundColor Cyan
                
                $logNames = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
                
                foreach ($logName in $logNames) {
                    try {
                        Write-Host "  Exporting: $logName..." -ForegroundColor Gray
                        
                        $safeName = $logName -replace '/', '-'
                        $logPath = Join-Path $paths.EventLogs "$safeName.evtx"
                        
                        # Export using wevtutil
                        wevtutil epl $logName $logPath /ow:true 2>&1 | Out-Null
                        
                        if (Test-Path $logPath) {
                            Write-Host "    Exported successfully" -ForegroundColor Green
                        }
                    }
                    catch {
                        Write-Warning "Could not export log $logName"
                    }
                }
                
                $results.ArtifactsCollected += "Event Logs"
            }
            
            # 3. COLLECT REGISTRY ARTIFACTS
            if ($IncludeRegistry) {
                Write-Host "`n[3/8] Collecting Registry Artifacts..." -ForegroundColor Cyan
                
                try {
                    # Export key registry hives
                    $registryKeys = @(
                        @{Path='HKLM:\SOFTWARE'; Name='SOFTWARE'},
                        @{Path='HKLM:\SYSTEM'; Name='SYSTEM'},
                        @{Path='HKLM:\SAM'; Name='SAM'},
                        @{Path='HKLM:\SECURITY'; Name='SECURITY'},
                        @{Path='HKCU:\'; Name='NTUSER'}
                    )
                    
                    foreach ($key in $registryKeys) {
                        try {
                            Write-Host "  Exporting: $($key.Name)..." -ForegroundColor Gray
                            
                            $exportPath = Join-Path $paths.Registry "$($key.Name).reg"
                            
                            # Export using reg.exe
                            if ($key.Path -like 'HKLM*') {
                                $regPath = $key.Path -replace 'HKLM:\\', 'HKLM\'
                                reg export $regPath $exportPath /y 2>&1 | Out-Null
                            }
                            elseif ($key.Path -like 'HKCU*') {
                                $regPath = $key.Path -replace 'HKCU:\\', 'HKCU\'
                                reg export $regPath $exportPath /y 2>&1 | Out-Null
                            }
                            
                            if (Test-Path $exportPath) {
                                Write-Host "    Exported successfully" -ForegroundColor Green
                            }
                        }
                        catch {
                            Write-Warning "Could not export registry key: $($key.Name)"
                        }
                    }
                    
                    $results.ArtifactsCollected += "Registry Hives"
                }
                catch {
                    Write-Warning "Error collecting registry: $_"
                    $results.Summary.Errors++
                }
            }
            
            # 4. COLLECT FILE SYSTEM ARTIFACTS
            Write-Host "`n[4/8] Collecting File System Artifacts..." -ForegroundColor Cyan
            
            try {
                # Prefetch files
                $prefetchPath = "$env:SystemRoot\Prefetch"
                if (Test-Path $prefetchPath) {
                    $prefetchDest = Join-Path $paths.FileSystem "Prefetch"
                    New-Item -Path $prefetchDest -ItemType Directory -Force | Out-Null
                    Copy-Item "$prefetchPath\*.pf" -Destination $prefetchDest -Force -ErrorAction SilentlyContinue
                    Write-Host "  Prefetch files collected" -ForegroundColor Green
                }
                
                # Recent files
                $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
                if (Test-Path $recentPath) {
                    $recentDest = Join-Path $paths.FileSystem "Recent"
                    New-Item -Path $recentDest -ItemType Directory -Force | Out-Null
                    Copy-Item "$recentPath\*" -Destination $recentDest -Force -Recurse -ErrorAction SilentlyContinue
                    Write-Host "  Recent files collected" -ForegroundColor Green
                }
                
                $results.ArtifactsCollected += "File System Artifacts"
            }
            catch {
                Write-Warning "Error collecting file system artifacts: $_"
                $results.Summary.Errors++
            }
            
            # 5. COLLECT BROWSER ARTIFACTS
            if ($IncludeBrowserHistory) {
                Write-Host "`n[5/8] Collecting Browser Artifacts..." -ForegroundColor Cyan
                
                try {
                    # Chrome
                    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
                    if (Test-Path $chromePath) {
                        $chromeDest = Join-Path $paths.Browser "Chrome"
                        New-Item -Path $chromeDest -ItemType Directory -Force | Out-Null
                        
                        # Copy History, Cookies, etc.
                        $chromeFiles = @('History', 'Cookies', 'Web Data', 'Login Data')
                        foreach ($file in $chromeFiles) {
                            $srcFile = Join-Path $chromePath $file
                            if (Test-Path $srcFile) {
                                Copy-Item $srcFile -Destination $chromeDest -Force -ErrorAction SilentlyContinue
                            }
                        }
                        Write-Host "  Chrome artifacts collected" -ForegroundColor Green
                    }
                    
                    # Edge
                    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
                    if (Test-Path $edgePath) {
                        $edgeDest = Join-Path $paths.Browser "Edge"
                        New-Item -Path $edgeDest -ItemType Directory -Force | Out-Null
                        
                        $edgeFiles = @('History', 'Cookies', 'Web Data')
                        foreach ($file in $edgeFiles) {
                            $srcFile = Join-Path $edgePath $file
                            if (Test-Path $srcFile) {
                                Copy-Item $srcFile -Destination $edgeDest -Force -ErrorAction SilentlyContinue
                            }
                        }
                        Write-Host "  Edge artifacts collected" -ForegroundColor Green
                    }
                    
                    $results.ArtifactsCollected += "Browser Artifacts"
                }
                catch {
                    Write-Warning "Error collecting browser artifacts: $_"
                    $results.Summary.Errors++
                }
            }
            
            # 6. COLLECT NETWORK INFORMATION
            if ($IncludeNetworkInfo) {
                Write-Host "`n[6/8] Collecting Network Information..." -ForegroundColor Cyan
                
                try {
                    # Network adapters
                    Get-NetAdapter | ConvertTo-Json | Out-File (Join-Path $paths.Network "Adapters.json")
                    
                    # IP configuration
                    ipconfig /all | Out-File (Join-Path $paths.Network "ipconfig.txt")
                    
                    # Routing table
                    route print | Out-File (Join-Path $paths.Network "routes.txt")
                    
                    # ARP cache
                    arp -a | Out-File (Join-Path $paths.Network "arp.txt")
                    
                    # DNS cache
                    ipconfig /displaydns | Out-File (Join-Path $paths.Network "dns_cache.txt")
                    
                    # Active connections
                    Get-NetTCPConnection | ConvertTo-Json | Out-File (Join-Path $paths.Network "tcp_connections.json")
                    
                    # Listening ports
                    netstat -ano | Out-File (Join-Path $paths.Network "netstat.txt")
                    
                    # Network shares
                    net share | Out-File (Join-Path $paths.Network "shares.txt")
                    
                    Write-Host "  Network information collected" -ForegroundColor Green
                    $results.ArtifactsCollected += "Network Information"
                }
                catch {
                    Write-Warning "Error collecting network info: $_"
                    $results.Summary.Errors++
                }
            }
            
            # 7. COLLECT EXECUTION ARTIFACTS
            if ($IncludeExecutionArtifacts) {
                Write-Host "`n[7/8] Collecting Execution Artifacts..." -ForegroundColor Cyan
                
                try {
                    # Running processes
                    Get-Process | Select-Object Name, Id, Path, StartTime, @{N='WorkingSetMB';E={[Math]::Round($_.WorkingSet/1MB,2)}} |
                        ConvertTo-Json | Out-File (Join-Path $paths.Execution "Processes.json")
                    
                    # Services
                    Get-Service | Select-Object Name, DisplayName, Status, StartType |
                        ConvertTo-Json | Out-File (Join-Path $paths.Execution "Services.json")
                    
                    # Scheduled tasks
                    Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{N='LastRunTime';E={$_.LastRunTime}} |
                        ConvertTo-Json | Out-File (Join-Path $paths.Execution "ScheduledTasks.json")
                    
                    # Startup programs
                    Get-CimInstance Win32_StartupCommand |
                        Select-Object Name, Command, Location, User |
                        ConvertTo-Json | Out-File (Join-Path $paths.Execution "StartupPrograms.json")
                    
                    Write-Host "  Execution artifacts collected" -ForegroundColor Green
                    $results.ArtifactsCollected += "Execution Artifacts"
                }
                catch {
                    Write-Warning "Error collecting execution artifacts: $_"
                    $results.Summary.Errors++
                }
            }
            
            # 8. COLLECT USER INFORMATION
            Write-Host "`n[8/8] Collecting User Information..." -ForegroundColor Cyan
            
            try {
                # Local users
                Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet |
                    ConvertTo-Json | Out-File (Join-Path $paths.Users "LocalUsers.json")
                
                # Local groups
                Get-LocalGroup | ConvertTo-Json | Out-File (Join-Path $paths.Users "LocalGroups.json")
                
                # Logged on users
                quser 2>&1 | Out-File (Join-Path $paths.Users "LoggedOnUsers.txt")
                
                # User profiles
                Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Select-Object Name, CreationTime, LastWriteTime |
                    ConvertTo-Json | Out-File (Join-Path $paths.Users "UserProfiles.json")
                
                Write-Host "  User information collected" -ForegroundColor Green
                $results.ArtifactsCollected += "User Information"
            }
            catch {
                Write-Warning "Error collecting user info: $_"
                $results.Summary.Errors++
            }
            
            # CALCULATE COLLECTION SIZE
            Write-Host "`n[*] Calculating collection statistics..." -ForegroundColor Cyan
            
            $collectedFiles = Get-ChildItem -Path $collectionRoot -Recurse -File -ErrorAction SilentlyContinue
            $results.Summary.TotalFiles = $collectedFiles.Count
            $results.Summary.TotalSize = ($collectedFiles | Measure-Object -Property Length -Sum).Sum
            
            $totalSizeMB = [Math]::Round($results.Summary.TotalSize / 1MB, 2)
            Write-Host "  Total Files: $($results.Summary.TotalFiles)" -ForegroundColor Green
            Write-Host "  Total Size: $totalSizeMB MB" -ForegroundColor Green
            
            # CREATE COLLECTION MANIFEST
            $manifest = @{
                CollectionDate = $results.CollectionDate
                ComputerName = $results.ComputerName
                Profile = $results.Profile
                Collector = $env:USERNAME
                ArtifactsCollected = $results.ArtifactsCollected
                TotalFiles = $results.Summary.TotalFiles
                TotalSizeMB = $totalSizeMB
                Errors = $results.Summary.Errors
            }
            
            $manifest | ConvertTo-Json -Depth 5 | Out-File (Join-Path $collectionRoot "MANIFEST.json")
            Write-Host "`nCollection manifest created" -ForegroundColor Green
            
            # COMPRESS OUTPUT
            if ($CompressOutput) {
                Write-Host "`n[*] Compressing collection..." -ForegroundColor Cyan
                
                try {
                    $zipPath = "$collectionRoot.zip"
                    
                    Compress-Archive -Path $collectionRoot -DestinationPath $zipPath -CompressionLevel Optimal
                    
                    if (Test-Path $zipPath) {
                        $zipFile = Get-Item $zipPath
                        $zipSizeMB = [Math]::Round($zipFile.Length / 1MB, 2)
                        $compressionRatio = [Math]::Round((1 - ($zipFile.Length / $results.Summary.TotalSize)) * 100, 1)
                        
                        Write-Host "  Archive created: $zipPath" -ForegroundColor Green
                        Write-Host "  Compressed Size: $zipSizeMB MB" -ForegroundColor Cyan
                        Write-Host "  Compression Ratio: $compressionRatio%" -ForegroundColor Cyan
                        
                        $results.CompressedArchive = $zipPath
                        
                        # Remove source if requested
                        if ($RemoveSource) {
                            Remove-Item $collectionRoot -Recurse -Force
                            Write-Host "  Original collection removed" -ForegroundColor Gray
                        }
                    }
                }
                catch {
                    Write-Warning "Compression failed: $_"
                }
            }
            
        }
        catch {
            Write-Error "Error during artifact collection: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "  FORENSIC COLLECTION COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        
        Write-Host "`nCollection Summary:" -ForegroundColor Cyan
        Write-Host "  Computer: $($results.ComputerName)" -ForegroundColor White
        Write-Host "  Profile: $($results.Profile)" -ForegroundColor White
        Write-Host "  Output Path: $($results.OutputPath)" -ForegroundColor White
        Write-Host "  Total Files: $($results.Summary.TotalFiles)" -ForegroundColor White
        Write-Host "  Total Size: $([Math]::Round($results.Summary.TotalSize/1MB,2)) MB" -ForegroundColor White
        Write-Host "  Errors: $($results.Summary.Errors)" -ForegroundColor $(if($results.Summary.Errors -gt 0){'Yellow'}else{'White'})
        
        if ($results.CompressedArchive) {
            Write-Host "  Archive: $($results.CompressedArchive)" -ForegroundColor Green
        }
        
        Write-Host "`nArtifacts Collected:" -ForegroundColor Cyan
        foreach ($artifact in $results.ArtifactsCollected) {
            Write-Host "  - $artifact" -ForegroundColor Green
        }
        
        Write-Host "`nNext Steps:" -ForegroundColor Yellow
        Write-Host "  1. Review MANIFEST.json for collection details" -ForegroundColor Gray
        Write-Host "  2. Analyze collected artifacts with forensic tools" -ForegroundColor Gray
        Write-Host "  3. Store evidence securely with chain of custody" -ForegroundColor Gray
        Write-Host "  4. Calculate file hash for integrity verification" -ForegroundColor Gray
        
        return $results
    }
}