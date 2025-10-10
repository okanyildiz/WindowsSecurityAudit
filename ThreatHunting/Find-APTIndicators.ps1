function Find-APTIndicators {
    <#
    .SYNOPSIS
        Detects Advanced Persistent Threat (APT) indicators on the system
    .DESCRIPTION
        Hunts for APT indicators including suspicious services, scheduled tasks,
        registry modifications, file system artifacts, and network connections.
        Uses whitelisting to minimize false positives.
    .PARAMETER CheckServices
        Check for suspicious services
    .PARAMETER CheckScheduledTasks
        Check for suspicious scheduled tasks
    .PARAMETER CheckRegistry
        Check for registry-based persistence
    .PARAMETER CheckNetworkConnections
        Check for suspicious network connections
    .PARAMETER DeepScan
        Enable comprehensive scanning (slower but more thorough)
    .EXAMPLE
        Find-APTIndicators -CheckServices -CheckScheduledTasks -CheckRegistry
        Find-APTIndicators -DeepScan
    .OUTPUTS
        PSCustomObject with APT indicators
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckServices,
        
        [Parameter()]
        [switch]$CheckScheduledTasks,
        
        [Parameter()]
        [switch]$CheckRegistry,
        
        [Parameter()]
        [switch]$CheckNetworkConnections,
        
        [Parameter()]
        [switch]$DeepScan
    )
    
    begin {
        Write-Host "=== APT INDICATOR HUNTING ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        if ($DeepScan) {
            $CheckServices = $true
            $CheckScheduledTasks = $true
            $CheckRegistry = $true
            $CheckNetworkConnections = $true
            Write-Host "Deep Scan Mode: Enabled" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Indicators = @{
                SuspiciousServices = @()
                SuspiciousScheduledTasks = @()
                RegistryPersistence = @()
                NetworkConnections = @()
            }
            ThreatScore = 0
            RiskLevel = 'Unknown'
            Summary = @{
                TotalIndicators = 0
                CriticalIndicators = 0
                HighIndicators = 0
                MediumIndicators = 0
            }
            Recommendations = @()
        }
        
        # Known malicious patterns (actual threats only)
        $knownMaliciousNames = @(
            'mimikatz', 'rubeus', 'sharphound', 'bloodhound', 'covenant',
            'empire', 'meterpreter', 'cobalt', 'beacon', 'lazagne',
            'procdump', 'paexec', 'wmiexec', 'smbexec', 'psexesvc',
            'invoke-obfuscation', 'powersploit', 'nishang'
        )
        
        # WHITELIST - Known legitimate software/services
        $legitimateServices = @(
            'WinDefend', 'WdNisSvc', 'Sense', 'WdBoot', 'WdFilter', 'WdNisDrv', 
            'MDCoreSvc', 'MsSecCore', 'SecurityHealthService',
            'MpsSvc', 'Spooler', 'BITS', 'wuauserv', 'CryptSvc',
            'OneSyncSvc', 'AdobeARMservice', 'AdobeUpdateService',
            'GoogleUpdate', 'gupdate', 'gupdatem', 'TeamViewer', 'LogMeIn',
            'Dropbox', 'DropboxUpdate', 'Box', 'ZoomCptService', 'CiscoSpark',
            'ClickToRunSvc', 'InstallService', 'SgrmBroker'
        )
        
        $legitimateTaskPatterns = @(
            'Microsoft', 'Windows', 'Adobe', 'Google', 'OneDrive',
            'Dropbox', 'Zoom', 'Cisco', 'Teams', 'Slack', 'Skype',
            'Driver', 'Update', 'Cleanup', 'Maintenance', 'Office',
            'OfficeClickToRun', 'OfficeSvc', 'Chrome', 'Firefox', 'Edge'
        )
        
        $legitimateRegistryValues = @(
            'OneDrive', 'Slack', 'Teams', 'Zoom', 'Cisco',
            'Discord', 'Spotify', 'Steam', 'Epic', 'Origin',
            'Chrome', 'Firefox', 'Edge', 'Brave', 'Opera',
            'Visual Studio', 'VSCode', 'Notepad', 'Sublime',
            'Office', 'Word', 'Excel', 'PowerPoint', 'Outlook'
        )
        
        # Windows system folders (legitimate)
        $legitimateRegistryKeys = @(
            'Common Administrative Tools', 'Common AppData', 'Common Desktop',
            'Common Documents', 'Common Programs', 'Common Start Menu',
            'Common Startup', 'Common Templates', 'CommonMusic',
            'CommonPictures', 'CommonVideo', 'OEM Links'
        )
        
        # Suspicious locations - using single quotes for $Recycle to avoid variable expansion
        $suspiciousLocations = @(
            "$env:TEMP",
            "$env:APPDATA\Local\Temp",
            "C:\Users\Public",
            "C:\Windows\Temp",
            "C:\Temp",
            'C:\$Recycle.Bin'
        )
    }
    
    process {
        try {
            # 1. Check Suspicious Services
            if ($CheckServices) {
                Write-Host "`n[1/4] Hunting for suspicious services..." -ForegroundColor Cyan
                
                try {
                    $services = Get-CimInstance Win32_Service | Where-Object { 
                        $_.StartMode -eq 'Auto' -or $_.State -eq 'Running' 
                    }
                    
                    foreach ($service in $services) {
                        # Skip whitelisted services
                        $isWhitelisted = $false
                        foreach ($legit in $legitimateServices) {
                            if ($service.Name -like "*$legit*" -or $service.DisplayName -like "*$legit*") {
                                $isWhitelisted = $true
                                break
                            }
                        }
                        
                        if ($isWhitelisted) {
                            continue
                        }
                        
                        $suspiciousScore = 0
                        $reasons = @()
                        
                        # Check for actual malicious names
                        foreach ($malName in $knownMaliciousNames) {
                            if ($service.Name -match $malName -or $service.DisplayName -match $malName) {
                                $suspiciousScore += 70
                                $reasons += "CRITICAL: Name matches known malware: $malName"
                            }
                        }
                        
                        # Check PathName
                        if ($service.PathName) {
                            # Check for suspicious locations (exclude Program Files)
                            if ($service.PathName -notmatch "Program Files") {
                                foreach ($suspiciousLoc in $suspiciousLocations) {
                                    if ($service.PathName -match [regex]::Escape($suspiciousLoc)) {
                                        $suspiciousScore += 40
                                        $reasons += "Runs from suspicious temp/public location"
                                        break
                                    }
                                }
                            }
                            
                            # Check for long encoded commands (100+ chars of base64)
                            if ($service.PathName -match "powershell.*-enc\s+[A-Za-z0-9+/=]{100,}") {
                                $suspiciousScore += 60
                                $reasons += "CRITICAL: Contains long encoded PowerShell command"
                            }
                            
                            # Check for multiple evasion techniques
                            if ($service.PathName -match "-nop.*-w\s+hidden.*-exec\s+bypass") {
                                $suspiciousScore += 50
                                $reasons += "Uses multiple evasion techniques"
                            }
                            
                            # Check for download cradles
                            if ($service.PathName -match "IEX.*\(.*WebClient.*DownloadString|Invoke-WebRequest.*IEX") {
                                $suspiciousScore += 65
                                $reasons += "CRITICAL: Downloads and executes remote code"
                            }
                        }
                        
                        # Only flag if score is significant (40+ threshold)
                        if ($suspiciousScore -ge 40) {
                            $severity = if ($suspiciousScore -ge 60) { 'Critical' }
                                       elseif ($suspiciousScore -ge 45) { 'High' }
                                       else { 'Medium' }
                            
                            $results.Indicators.SuspiciousServices += [PSCustomObject]@{
                                Severity = $severity
                                Name = $service.Name
                                DisplayName = $service.DisplayName
                                PathName = $service.PathName
                                StartMode = $service.StartMode
                                State = $service.State
                                StartName = $service.StartName
                                SuspiciousScore = $suspiciousScore
                                Reasons = $reasons -join '; '
                            }
                            
                            $results.ThreatScore += $suspiciousScore
                            
                            if ($severity -eq 'Critical') { $results.Summary.CriticalIndicators++ }
                            elseif ($severity -eq 'High') { $results.Summary.HighIndicators++ }
                            else { $results.Summary.MediumIndicators++ }
                            
                            Write-Host "  [!] Suspicious Service: $($service.Name) [Score: $suspiciousScore]" -ForegroundColor Red
                        }
                    }
                    
                    if ($results.Indicators.SuspiciousServices.Count -eq 0) {
                        Write-Host "  No suspicious services found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking services: $_"
                }
            }
            
            # 2. Check Suspicious Scheduled Tasks
            if ($CheckScheduledTasks) {
                Write-Host "`n[2/4] Hunting for suspicious scheduled tasks..." -ForegroundColor Cyan
                
                try {
                    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
                    
                    foreach ($task in $tasks) {
                        # Skip whitelisted tasks
                        $isWhitelisted = $false
                        foreach ($pattern in $legitimateTaskPatterns) {
                            if ($task.TaskName -like "*$pattern*" -or $task.TaskPath -like "*$pattern*") {
                                $isWhitelisted = $true
                                break
                            }
                        }
                        
                        if ($isWhitelisted) {
                            continue
                        }
                        
                        $suspiciousScore = 0
                        $reasons = @()
                        
                        # Check for actual malicious names
                        foreach ($malName in $knownMaliciousNames) {
                            if ($task.TaskName -match $malName) {
                                $suspiciousScore += 70
                                $reasons += "CRITICAL: Name matches known malware: $malName"
                            }
                        }
                        
                        # Check actions - with proper error handling
                        $actionDetails = @()
                        foreach ($action in $task.Actions) {
                            # Check if Execute property exists
                            if ($action.PSObject.Properties.Name -contains 'Execute' -and $action.Execute) {
                                $actionDetails += "$($action.Execute) $($action.Arguments)"
                                
                                # Check for long encoded commands
                                if ($action.Arguments -match "-enc\s+[A-Za-z0-9+/=]{100,}") {
                                    $suspiciousScore += 60
                                    $reasons += "CRITICAL: Contains long encoded command"
                                }
                                
                                # Check for download cradles
                                if ($action.Arguments -match "IEX.*DownloadString|Invoke-WebRequest.*IEX|Net\.WebClient.*DownloadString") {
                                    $suspiciousScore += 65
                                    $reasons += "CRITICAL: Downloads and executes remote code"
                                }
                                
                                # Check for suspicious locations (exclude Program Files)
                                if ($action.Execute -notmatch "Program Files") {
                                    foreach ($suspiciousLoc in $suspiciousLocations) {
                                        if ($action.Execute -match [regex]::Escape($suspiciousLoc)) {
                                            $suspiciousScore += 35
                                            $reasons += "Executes from suspicious temp location"
                                            break
                                        }
                                    }
                                }
                            }
                            elseif ($action.PSObject.Properties.Name -contains 'Id') {
                                # ComHandler or other action type
                                $actionDetails += "Action: $($action.Id)"
                            }
                        }
                        
                        # Only flag if score is significant (35+ threshold)
                        if ($suspiciousScore -ge 35) {
                            $severity = if ($suspiciousScore -ge 60) { 'Critical' }
                                       elseif ($suspiciousScore -ge 45) { 'High' }
                                       else { 'Medium' }
                            
                            $results.Indicators.SuspiciousScheduledTasks += [PSCustomObject]@{
                                Severity = $severity
                                TaskName = $task.TaskName
                                TaskPath = $task.TaskPath
                                State = $task.State
                                Actions = ($actionDetails -join '; ')
                                RunAs = $task.Principal.UserId
                                SuspiciousScore = $suspiciousScore
                                Reasons = $reasons -join '; '
                            }
                            
                            $results.ThreatScore += $suspiciousScore
                            
                            if ($severity -eq 'Critical') { $results.Summary.CriticalIndicators++ }
                            elseif ($severity -eq 'High') { $results.Summary.HighIndicators++ }
                            else { $results.Summary.MediumIndicators++ }
                            
                            Write-Host "  [!] Suspicious Task: $($task.TaskName) [Score: $suspiciousScore]" -ForegroundColor Red
                        }
                    }
                    
                    if ($results.Indicators.SuspiciousScheduledTasks.Count -eq 0) {
                        Write-Host "  No suspicious scheduled tasks found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking scheduled tasks: $_"
                }
            }
            
            # 3. Check Registry Persistence
            if ($CheckRegistry) {
                Write-Host "`n[3/4] Hunting for registry-based persistence..." -ForegroundColor Cyan
                
                try {
                    # Common persistence registry locations
                    $persistenceKeys = @(
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                    )
                    
                    foreach ($keyPath in $persistenceKeys) {
                        if (Test-Path $keyPath) {
                            $values = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                            
                            foreach ($property in $values.PSObject.Properties) {
                                # Skip PowerShell default properties
                                if ($property.Name -match "^PS") {
                                    continue
                                }
                                
                                # Skip whitelisted registry values - using -like for pattern matching
                                $isWhitelisted = $false
                                foreach ($legit in $legitimateRegistryValues) {
                                    if ($property.Name -like "*$legit*") {
                                        $isWhitelisted = $true
                                        break
                                    }
                                }
                                
                                # Skip Windows system registry keys
                                foreach ($sysKey in $legitimateRegistryKeys) {
                                    if ($property.Name -eq $sysKey) {
                                        $isWhitelisted = $true
                                        break
                                    }
                                }
                                
                                if ($isWhitelisted) {
                                    continue
                                }
                                
                                $value = $property.Value
                                if (-not $value) {
                                    continue
                                }
                                
                                $suspiciousScore = 0
                                $reasons = @()
                                
                                # Check for actual malicious patterns
                                foreach ($malName in $knownMaliciousNames) {
                                    if ($value -match $malName) {
                                        $suspiciousScore += 70
                                        $reasons += "CRITICAL: Matches known malware: $malName"
                                    }
                                }
                                
                                # Check for long encoded commands (100+ chars)
                                if ($value -match "-enc\s+[A-Za-z0-9+/=]{100,}") {
                                    $suspiciousScore += 60
                                    $reasons += "CRITICAL: Contains long encoded command"
                                }
                                
                                # Check for download cradles
                                if ($value -match "IEX.*DownloadString|Invoke-WebRequest.*IEX|Net\.WebClient.*DownloadString") {
                                    $suspiciousScore += 65
                                    $reasons += "CRITICAL: Downloads and executes remote code"
                                }
                                
                                # Check for suspicious locations (exclude Program Files)
                                if ($value -notmatch "Program Files") {
                                    foreach ($suspiciousLoc in $suspiciousLocations) {
                                        if ($value -match [regex]::Escape($suspiciousLoc)) {
                                            $suspiciousScore += 35
                                            $reasons += "Points to suspicious temp location"
                                            break
                                        }
                                    }
                                }
                                
                                # Check for heavy obfuscation (10+ obfuscation chars)
                                if ($value -match "(\^|`){10,}|(%[a-zA-Z0-9]){10,}") {
                                    $suspiciousScore += 40
                                    $reasons += "Heavily obfuscated"
                                }
                                
                                # Only flag if score is significant (35+ threshold)
                                if ($suspiciousScore -ge 35) {
                                    $severity = if ($suspiciousScore -ge 60) { 'Critical' }
                                               elseif ($suspiciousScore -ge 45) { 'High' }
                                               else { 'Medium' }
                                    
                                    $results.Indicators.RegistryPersistence += [PSCustomObject]@{
                                        Severity = $severity
                                        RegistryKey = $keyPath
                                        ValueName = $property.Name
                                        ValueData = if ($value.Length -gt 200) { $value.Substring(0, 200) + "..." } else { $value }
                                        SuspiciousScore = $suspiciousScore
                                        Reasons = $reasons -join '; '
                                    }
                                    
                                    $results.ThreatScore += $suspiciousScore
                                    
                                    if ($severity -eq 'Critical') { $results.Summary.CriticalIndicators++ }
                                    elseif ($severity -eq 'High') { $results.Summary.HighIndicators++ }
                                    else { $results.Summary.MediumIndicators++ }
                                    
                                    Write-Host "  [!] Suspicious Registry: $($property.Name) [Score: $suspiciousScore]" -ForegroundColor Red
                                }
                            }
                        }
                    }
                    
                    if ($results.Indicators.RegistryPersistence.Count -eq 0) {
                        Write-Host "  No suspicious registry persistence found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking registry: $_"
                }
            }
            
            # 4. Check Network Connections
            if ($CheckNetworkConnections) {
                Write-Host "`n[4/4] Hunting for suspicious network connections..." -ForegroundColor Cyan
                
                try {
                    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                    
                    foreach ($conn in $connections) {
                        $suspiciousScore = 0
                        $reasons = @()
                        
                        # Get process info
                        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                        
                        if ($process) {
                            # Check for actual malicious process names
                            foreach ($malName in $knownMaliciousNames) {
                                if ($process.Name -match $malName) {
                                    $suspiciousScore += 70
                                    $reasons += "CRITICAL: Process matches known malware"
                                }
                            }
                            
                            # Check for high-risk ports (not common web traffic)
                            $highRiskPorts = @(4444, 5555, 1337, 31337, 6666, 7777)
                            if ($conn.RemotePort -in $highRiskPorts) {
                                $suspiciousScore += 50
                                $reasons += "Uses high-risk port: $($conn.RemotePort)"
                            }
                            
                            # Scripting processes with external connections (exclude localhost and known IPs)
                            if ($process.Name -match "powershell|cmd|wscript|cscript|mshta" -and
                                $conn.RemoteAddress -notmatch "127\.0\.0\.1|::1|0\.0\.0\.0") {
                                $suspiciousScore += 40
                                $reasons += "Scripting process with external network connection"
                            }
                        }
                        
                        # Only flag if score is significant (40+ threshold)
                        if ($suspiciousScore -ge 40) {
                            $severity = if ($suspiciousScore -ge 60) { 'Critical' }
                                       elseif ($suspiciousScore -ge 45) { 'High' }
                                       else { 'Medium' }
                            
                            $results.Indicators.NetworkConnections += [PSCustomObject]@{
                                Severity = $severity
                                ProcessName = $process.Name
                                ProcessId = $conn.OwningProcess
                                ProcessPath = $process.Path
                                LocalAddress = "$($conn.LocalAddress):$($conn.LocalPort)"
                                RemoteAddress = "$($conn.RemoteAddress):$($conn.RemotePort)"
                                State = $conn.State
                                SuspiciousScore = $suspiciousScore
                                Reasons = $reasons -join '; '
                            }
                            
                            $results.ThreatScore += $suspiciousScore
                            
                            if ($severity -eq 'Critical') { $results.Summary.CriticalIndicators++ }
                            elseif ($severity -eq 'High') { $results.Summary.HighIndicators++ }
                            else { $results.Summary.MediumIndicators++ }
                            
                            Write-Host "  [!] Suspicious Connection: $($process.Name) -> $($conn.RemoteAddress):$($conn.RemotePort) [Score: $suspiciousScore]" -ForegroundColor Red
                        }
                    }
                    
                    if ($results.Indicators.NetworkConnections.Count -eq 0) {
                        Write-Host "  No suspicious network connections found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking network connections: $_"
                }
            }
            
            # Calculate total indicators and risk level
            $results.Summary.TotalIndicators = 
                $results.Indicators.SuspiciousServices.Count +
                $results.Indicators.SuspiciousScheduledTasks.Count +
                $results.Indicators.RegistryPersistence.Count +
                $results.Indicators.NetworkConnections.Count
            
            # Determine risk level based on threat score and critical indicators
            if ($results.Summary.CriticalIndicators -gt 0 -or $results.ThreatScore -ge 200) {
                $results.RiskLevel = 'Critical'
            } elseif ($results.Summary.HighIndicators -gt 2 -or $results.ThreatScore -ge 100) {
                $results.RiskLevel = 'High'
            } elseif ($results.Summary.TotalIndicators -gt 0) {
                $results.RiskLevel = 'Medium'
            } else {
                $results.RiskLevel = 'Low'
            }
            
            # Generate recommendations
            if ($results.Summary.CriticalIndicators -gt 0) {
                $results.Recommendations += "IMMEDIATE ACTION: Investigate and contain critical indicators"
                $results.Recommendations += "Isolate affected systems from network"
                $results.Recommendations += "Collect forensic evidence before remediation"
            }
            
            if ($results.Indicators.SuspiciousServices.Count -gt 0) {
                $results.Recommendations += "Review and disable suspicious services"
            }
            
            if ($results.Indicators.SuspiciousScheduledTasks.Count -gt 0) {
                $results.Recommendations += "Remove suspicious scheduled tasks"
            }
            
            if ($results.Indicators.RegistryPersistence.Count -gt 0) {
                $results.Recommendations += "Clean registry persistence mechanisms"
            }
            
            if ($results.Summary.TotalIndicators -gt 0) {
                $results.Recommendations += "Enable enhanced logging and monitoring"
                $results.Recommendations += "Conduct full forensic analysis"
            }
            
        }
        catch {
            Write-Error "Error during APT hunting: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== HUNT COMPLETE ===" -ForegroundColor $(
            if ($results.RiskLevel -in @('Critical', 'High')) { 'Red' }
            elseif ($results.RiskLevel -eq 'Medium') { 'Yellow' }
            else { 'Green' }
        )
        
        Write-Host "`nThreat Assessment:" -ForegroundColor Cyan
        Write-Host "  Risk Level: " -NoNewline
        Write-Host $results.RiskLevel -ForegroundColor $(
            switch ($results.RiskLevel) {
                'Critical' { 'Red' }
                'High' { 'Red' }
                'Medium' { 'Yellow' }
                'Low' { 'Green' }
            }
        )
        Write-Host "  Threat Score: $($results.ThreatScore)" -ForegroundColor White
        Write-Host "  Total Indicators: $($results.Summary.TotalIndicators)" -ForegroundColor White
        
        if ($results.Summary.TotalIndicators -gt 0) {
            Write-Host "`nIndicator Breakdown:" -ForegroundColor Cyan
            Write-Host "  Critical: $($results.Summary.CriticalIndicators)" -ForegroundColor Red
            Write-Host "  High: $($results.Summary.HighIndicators)" -ForegroundColor Yellow
            Write-Host "  Medium: $($results.Summary.MediumIndicators)" -ForegroundColor Yellow
            
            if ($results.Indicators.SuspiciousServices.Count -gt 0) {
                Write-Host "`n  Suspicious Services: $($results.Indicators.SuspiciousServices.Count)" -ForegroundColor Red
            }
            if ($results.Indicators.SuspiciousScheduledTasks.Count -gt 0) {
                Write-Host "  Suspicious Tasks: $($results.Indicators.SuspiciousScheduledTasks.Count)" -ForegroundColor Red
            }
            if ($results.Indicators.RegistryPersistence.Count -gt 0) {
                Write-Host "  Registry Persistence: $($results.Indicators.RegistryPersistence.Count)" -ForegroundColor Red
            }
            if ($results.Indicators.NetworkConnections.Count -gt 0) {
                Write-Host "  Network Connections: $($results.Indicators.NetworkConnections.Count)" -ForegroundColor Red
            }
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        if ($results.RiskLevel -in @('Critical', 'High')) {
            Write-Host "`n[!!!] APT INDICATORS DETECTED - INCIDENT RESPONSE REQUIRED [!!!]" -ForegroundColor Red -BackgroundColor Black
        } elseif ($results.RiskLevel -eq 'Low' -and $results.Summary.TotalIndicators -eq 0) {
            Write-Host "`n[OK] No APT indicators detected - System appears clean" -ForegroundColor Green
        }
        
        return $results
    }
}