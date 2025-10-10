function Get-MITREAttackMapping {
    <#
    .SYNOPSIS
        Maps detected activities to MITRE ATT&CK framework techniques
    .DESCRIPTION
        Analyzes system activities and maps them to MITRE ATT&CK tactics and techniques.
        Provides detailed technique information with detection methods and recommendations.
    .PARAMETER CheckProcesses
        Analyze running processes for MITRE techniques
    .PARAMETER CheckRegistry
        Analyze registry for persistence techniques
    .PARAMETER CheckNetworkActivity
        Analyze network activity for C2 techniques
    .PARAMETER CheckEventLogs
        Analyze security event logs for technique indicators
    .PARAMETER FullAnalysis
        Run all checks
    .EXAMPLE
        Get-MITREAttackMapping -CheckProcesses -CheckRegistry
        Get-MITREAttackMapping -FullAnalysis
    .OUTPUTS
        PSCustomObject with MITRE ATT&CK technique mappings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckProcesses,
        
        [Parameter()]
        [switch]$CheckRegistry,
        
        [Parameter()]
        [switch]$CheckNetworkActivity,
        
        [Parameter()]
        [switch]$CheckEventLogs,
        
        [Parameter()]
        [switch]$FullAnalysis
    )
    
    begin {
        Write-Host "=== MITRE ATT&CK TECHNIQUE MAPPING ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        if ($FullAnalysis) {
            $CheckProcesses = $true
            $CheckRegistry = $true
            $CheckNetworkActivity = $true
            $CheckEventLogs = $true
            Write-Host "Full Analysis Mode: Enabled" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            DetectedTechniques = @()
            TacticBreakdown = @{
                InitialAccess = @()
                Execution = @()
                Persistence = @()
                PrivilegeEscalation = @()
                DefenseEvasion = @()
                CredentialAccess = @()
                Discovery = @()
                LateralMovement = @()
                Collection = @()
                CommandAndControl = @()
                Exfiltration = @()
                Impact = @()
            }
            Summary = @{
                TotalTechniques = 0
                TacticsCovered = 0
                RiskScore = 0
            }
            Recommendations = @()
        }
        
        # Legitimate process whitelist
        $legitimateProcesses = @(
            'svchost', 'explorer', 'dwm', 'lsass', 'csrss', 'smss', 'winlogon',
            'services', 'spoolsv', 'taskhost', 'taskhostw', 'RuntimeBroker',
            'SearchIndexer', 'Microsoft.Photos', 'SystemSettings', 'ShellExperienceHost',
            'sihost', 'fontdrvhost', 'conhost', 'dllhost', 'SearchApp',
            'StartMenuExperienceHost', 'TextInputHost', 'MoUsoCoreWorker',
            'SgrmBroker', 'AutoBootInstallService', 'erlsrv', 'gamingservices',
            'Xbox', 'Windows', 'Microsoft'
        )
        
        # MITRE ATT&CK Technique Database - IMPROVED with context-aware detection
        $mitreDB = @{
            'T1059.001' = @{
                Name = 'Command and Scripting Interpreter: PowerShell'
                Tactic = 'Execution'
                Description = 'Adversaries abuse PowerShell to execute commands'
                ProcessName = 'powershell.exe|pwsh.exe'
                SuspiciousArgs = @('-enc', '-encodedcommand', '-w hidden', '-windowstyle hidden', '-nop', '-noprofile', '-exec bypass', '-executionpolicy bypass')
                RequiresCommandLine = $true
                Severity = 'High'
            }
            'T1059.003' = @{
                Name = 'Command and Scripting Interpreter: Windows Command Shell'
                Tactic = 'Execution'
                Description = 'Adversaries abuse cmd.exe to execute commands'
                ProcessName = 'cmd.exe'
                SuspiciousArgs = @('/c whoami', '/c net user', '/c net localgroup', '/c tasklist', '/c ipconfig /all')
                RequiresCommandLine = $true
                Severity = 'Medium'
            }
            'T1547.001' = @{
                Name = 'Boot or Logon Autostart Execution: Registry Run Keys'
                Tactic = 'Persistence'
                Description = 'Adversaries achieve persistence via registry run keys'
                DetectionType = 'Registry'
                RegistryPaths = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
                )
                Severity = 'High'
            }
            'T1053.005' = @{
                Name = 'Scheduled Task/Job: Scheduled Task'
                Tactic = 'Persistence'
                Description = 'Adversaries schedule tasks for persistence'
                ProcessName = 'schtasks.exe'
                SuspiciousArgs = @('/create', 'Register-ScheduledTask', 'New-ScheduledTask')
                RequiresCommandLine = $true
                Severity = 'High'
            }
            'T1543.003' = @{
                Name = 'Create or Modify System Process: Windows Service'
                Tactic = 'Persistence'
                Description = 'Adversaries create/modify services for persistence'
                ProcessName = 'sc.exe'
                SuspiciousArgs = @('create', 'config', 'New-Service')
                RequiresCommandLine = $true
                Severity = 'High'
            }
            'T1055' = @{
                Name = 'Process Injection'
                Tactic = 'DefenseEvasion'
                Description = 'Adversaries inject code into processes'
                SuspiciousArgs = @('VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'QueueUserAPC')
                RequiresCommandLine = $true
                Severity = 'Critical'
            }
            'T1027' = @{
                Name = 'Obfuscated Files or Information'
                Tactic = 'DefenseEvasion'
                Description = 'Adversaries obfuscate files or information'
                SuspiciousArgs = @('-enc [A-Za-z0-9+/=]{50,}', 'FromBase64String', '[Convert]::FromBase64')
                RequiresCommandLine = $true
                Severity = 'High'
            }
            'T1070.001' = @{
                Name = 'Indicator Removal: Clear Windows Event Logs'
                Tactic = 'DefenseEvasion'
                Description = 'Adversaries clear event logs to hide activity'
                ProcessName = 'wevtutil.exe'
                SuspiciousArgs = @('clear-log', 'cl', 'Clear-EventLog')
                RequiresCommandLine = $true
                Severity = 'High'
            }
            'T1003.001' = @{
                Name = 'OS Credential Dumping: LSASS Memory'
                Tactic = 'CredentialAccess'
                Description = 'Adversaries dump credentials from LSASS'
                ProcessName = 'procdump|procdump64|mimikatz'
                SuspiciousArgs = @('lsass', 'sekurlsa', 'logonpasswords')
                RequiresCommandLine = $false
                Severity = 'Critical'
            }
            'T1003.002' = @{
                Name = 'OS Credential Dumping: Security Account Manager'
                Tactic = 'CredentialAccess'
                Description = 'Adversaries access SAM database for credentials'
                ProcessName = 'reg.exe'
                SuspiciousArgs = @('save.*HKLM\\SAM', 'save.*HKLM\\SYSTEM', 'save.*HKLM\\SECURITY')
                RequiresCommandLine = $true
                Severity = 'Critical'
            }
            'T1087.001' = @{
                Name = 'Account Discovery: Local Account'
                Tactic = 'Discovery'
                Description = 'Adversaries enumerate local accounts'
                ProcessName = 'net.exe|net1.exe'
                SuspiciousArgs = @('user', 'localgroup', 'accounts')
                RequiresCommandLine = $true
                Severity = 'Medium'
            }
            'T1087.002' = @{
                Name = 'Account Discovery: Domain Account'
                Tactic = 'Discovery'
                Description = 'Adversaries enumerate domain accounts'
                ProcessName = 'net.exe|dsquery.exe'
                SuspiciousArgs = @('user /domain', 'group /domain', 'Get-ADUser')
                RequiresCommandLine = $true
                Severity = 'Medium'
            }
            'T1082' = @{
                Name = 'System Information Discovery'
                Tactic = 'Discovery'
                Description = 'Adversaries gather system information'
                ProcessName = 'systeminfo.exe|wmic.exe'
                SuspiciousArgs = @('computersystem', 'os', 'qfe')
                RequiresCommandLine = $true
                Severity = 'Low'
            }
            'T1071.001' = @{
                Name = 'Application Layer Protocol: Web Protocols'
                Tactic = 'CommandAndControl'
                Description = 'Adversaries use HTTP/HTTPS for C2'
                ProcessName = 'powershell.exe|pwsh.exe'
                SuspiciousArgs = @('Invoke-WebRequest.*IEX', 'WebClient.*DownloadString', 'Net.WebClient.*DownloadFile')
                RequiresCommandLine = $true
                Severity = 'High'
            }
            'T1571' = @{
                Name = 'Non-Standard Port'
                Tactic = 'CommandAndControl'
                Description = 'Adversaries use non-standard ports for C2'
                DetectionType = 'Network'
                Severity = 'Medium'
            }
            'T1486' = @{
                Name = 'Data Encrypted for Impact'
                Tactic = 'Impact'
                Description = 'Adversaries encrypt data (ransomware)'
                SuspiciousArgs = @('\.encrypted', '\.locked', '\.crypt', 'ransom', 'YOUR_FILES')
                RequiresCommandLine = $true
                Severity = 'Critical'
            }
        }
    }
    
    process {
        try {
            # 1. Check Processes for Technique Indicators
            if ($CheckProcesses) {
                Write-Host "`n[1/4] Analyzing running processes..." -ForegroundColor Cyan
                
                try {
                    # Get processes with command line using WMI
                    $processes = Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ExecutablePath, CommandLine
                    
                    foreach ($process in $processes) {
                        # Skip whitelisted legitimate processes
                        $isLegitimate = $false
                        foreach ($legitProc in $legitimateProcesses) {
                            if ($process.Name -like "*$legitProc*") {
                                $isLegitimate = $true
                                break
                            }
                        }
                        
                        if ($isLegitimate) {
                            continue
                        }
                        
                        foreach ($techId in $mitreDB.Keys) {
                            $technique = $mitreDB[$techId]
                            
                            # Skip registry/network-only techniques
                           if ($technique.ContainsKey('DetectionType') -and $technique.DetectionType -in @('Registry', 'Network')) {
    continue
}
                            
                            # Skip if no process name defined
                            if (-not $technique.ContainsKey('ProcessName')) {
                                continue
                            }
                            
                            $matched = $false
                            $matchedIndicator = ""
                            
                            # Check if process name matches
                            if ($process.Name -match $technique.ProcessName) {
                                # If technique requires command line analysis
                                if ($technique.RequiresCommandLine) {
                                    if ($process.CommandLine) {
                                        foreach ($arg in $technique.SuspiciousArgs) {
                                            if ($process.CommandLine -match $arg) {
                                                $matched = $true
                                                $matchedIndicator = $arg
                                                break
                                            }
                                        }
                                    }
                                }
                                else {
                                    # Process name alone is suspicious (e.g., mimikatz)
                                    $matched = $true
                                    $matchedIndicator = "Suspicious process name"
                                }
                            }
                            
                            if ($matched) {
                                $detection = [PSCustomObject]@{
                                    TechniqueID = $techId
                                    TechniqueName = $technique.Name
                                    Tactic = $technique.Tactic
                                    Severity = $technique.Severity
                                    DetectionSource = 'Process'
                                    Evidence = "Process: $($process.Name) (PID: $($process.ProcessId)) - Indicator: $matchedIndicator"
                                    CommandLine = if ($process.CommandLine) { $process.CommandLine.Substring(0, [Math]::Min(200, $process.CommandLine.Length)) } else { "N/A" }
                                    Description = $technique.Description
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.DetectedTechniques += $detection
                                $results.TacticBreakdown[$technique.Tactic] += $detection
                                
                                Write-Host "  [!] Detected: $techId - $($technique.Name)" -ForegroundColor Yellow
                                Write-Host "      Evidence: $matchedIndicator" -ForegroundColor Gray
                            }
                        }
                    }
                    
                    if ($results.DetectedTechniques.Count -eq 0) {
                        Write-Host "  No suspicious process activity detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error analyzing processes: $_"
                }
            }
            
            # 2. Check Registry for Persistence Techniques
            if ($CheckRegistry) {
                Write-Host "`n[2/4] Analyzing registry keys..." -ForegroundColor Cyan
                
                try {
                    $runKeys = @(
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
                    )
                    
                    $suspiciousEntries = @()
                    
                    foreach ($key in $runKeys) {
                        if (Test-Path $key) {
                            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                            
                            if ($values) {
                                # Count non-PS properties
                                $entryCount = 0
                                foreach ($prop in $values.PSObject.Properties) {
                                    if ($prop.Name -notmatch "^PS") {
                                        $entryCount++
                                        
                                        # Check for suspicious patterns
                                        $value = $prop.Value
                                        if ($value -match "temp|appdata\\local\\temp|public|programdata|script|\.vbs|\.js|\.bat|http|download") {
                                            $suspiciousEntries += "  - $($prop.Name): $value"
                                        }
                                    }
                                }
                                
                                if ($entryCount -gt 0) {
                                    # T1547.001 - Registry Run Keys detected
                                    $detection = [PSCustomObject]@{
                                        TechniqueID = 'T1547.001'
                                        TechniqueName = $mitreDB['T1547.001'].Name
                                        Tactic = 'Persistence'
                                        Severity = 'Medium'  # Medium unless suspicious
                                        DetectionSource = 'Registry'
                                        Evidence = "Registry Run Key found: $key ($entryCount entries)"
                                        CommandLine = "N/A"
                                        Description = $mitreDB['T1547.001'].Description
                                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                    }
                                    
                                    # Check if already detected for this key
                                    $alreadyDetected = $results.DetectedTechniques | Where-Object { 
                                        $_.TechniqueID -eq 'T1547.001' -and $_.Evidence -match [regex]::Escape($key)
                                    }
                                    
                                    if (-not $alreadyDetected) {
                                        $results.DetectedTechniques += $detection
                                        $results.TacticBreakdown.Persistence += $detection
                                        Write-Host "  [!] Detected: T1547.001 - Registry Run Keys ($entryCount entries in $key)" -ForegroundColor Yellow
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($suspiciousEntries.Count -gt 0) {
                        Write-Host "      Suspicious entries found:" -ForegroundColor Red
                        $suspiciousEntries | Select-Object -First 3 | ForEach-Object {
                            Write-Host $_ -ForegroundColor Red
                        }
                    }
                }
                catch {
                    Write-Warning "Error analyzing registry: $_"
                }
            }
            
            # 3. Check Network Activity for C2 Techniques
            if ($CheckNetworkActivity) {
                Write-Host "`n[3/4] Analyzing network activity..." -ForegroundColor Cyan
                
                try {
                    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                    
                    $suspiciousConnections = 0
                    
                    foreach ($conn in $connections) {
                        # Check for non-standard ports (T1571)
                        $nonStandardPorts = @(4444, 5555, 31337, 1337, 6666, 7777)
                        
                        if ($conn.RemotePort -in $nonStandardPorts) {
                            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                            
                            # Skip if it's a known legitimate process
                            $isLegitimate = $false
                            foreach ($legitProc in $legitimateProcesses) {
                                if ($process.Name -like "*$legitProc*") {
                                    $isLegitimate = $true
                                    break
                                }
                            }
                            
                            if (-not $isLegitimate) {
                                $detection = [PSCustomObject]@{
                                    TechniqueID = 'T1571'
                                    TechniqueName = $mitreDB['T1571'].Name
                                    Tactic = 'CommandAndControl'
                                    Severity = 'High'
                                    DetectionSource = 'Network'
                                    Evidence = "Non-standard port $($conn.RemotePort) used by $($process.Name) -> $($conn.RemoteAddress)"
                                    CommandLine = "N/A"
                                    Description = $mitreDB['T1571'].Description
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.DetectedTechniques += $detection
                                $results.TacticBreakdown.CommandAndControl += $detection
                                $suspiciousConnections++
                                
                                Write-Host "  [!] Detected: T1571 - Non-Standard Port ($($conn.RemotePort))" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    if ($suspiciousConnections -eq 0) {
                        Write-Host "  No suspicious network activity detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error analyzing network activity: $_"
                }
            }
            
            # 4. Check Event Logs for Technique Indicators
            if ($CheckEventLogs) {
                Write-Host "`n[4/4] Analyzing security event logs..." -ForegroundColor Cyan
                
                try {
                    # Check for log clearing (T1070.001) - High severity event
                    $logCleared = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 1102
                    } -MaxEvents 10 -ErrorAction SilentlyContinue
                    
                    if ($logCleared) {
                        foreach ($event in $logCleared) {
                            $detection = [PSCustomObject]@{
                                TechniqueID = 'T1070.001'
                                TechniqueName = $mitreDB['T1070.001'].Name
                                Tactic = 'DefenseEvasion'
                                Severity = 'High'
                                DetectionSource = 'EventLog'
                                Evidence = "Security log cleared at $($event.TimeCreated)"
                                CommandLine = "N/A"
                                Description = $mitreDB['T1070.001'].Description
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            
                            $results.DetectedTechniques += $detection
                            $results.TacticBreakdown.DefenseEvasion += $detection
                        }
                        
                        Write-Host "  [!] Detected: T1070.001 - Event Log Clearing ($($logCleared.Count) events)" -ForegroundColor Red
                    }
                    else {
                        Write-Host "  No suspicious event log activity detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error analyzing event logs: $_"
                }
            }
            
            # Calculate summary statistics
            $uniqueTechniques = @($results.DetectedTechniques | Select-Object -Unique -Property TechniqueID)
            $results.Summary.TotalTechniques = $uniqueTechniques.Count
            
            # Count tactics with detections
            $tacticCount = 0
            foreach ($tactic in $results.TacticBreakdown.Keys) {
                if ($results.TacticBreakdown[$tactic].Count -gt 0) {
                    $tacticCount++
                }
            }
            $results.Summary.TacticsCovered = $tacticCount
            
            # Calculate risk score
            foreach ($technique in $results.DetectedTechniques) {
                $riskScore = switch ($technique.Severity) {
                    'Critical' { 10 }
                    'High' { 7 }
                    'Medium' { 4 }
                    'Low' { 2 }
                    default { 1 }
                }
                $results.Summary.RiskScore += $riskScore
            }
            
            # Generate recommendations
            if ($results.Summary.TotalTechniques -gt 0) {
                $results.Recommendations += "Review detected MITRE ATT&CK techniques immediately"
                $results.Recommendations += "Investigate command lines and process chains"
                $results.Recommendations += "Enable advanced audit logging for covered tactics"
                
                # Severity-based recommendations
                $criticalCount = @($results.DetectedTechniques | Where-Object { $_.Severity -eq 'Critical' }).Count
                if ($criticalCount -gt 0) {
                    $results.Recommendations += "CRITICAL: $criticalCount critical techniques detected - immediate response required"
                }
            }
            
            # Tactic-specific recommendations
            if ($results.TacticBreakdown.Persistence.Count -gt 0) {
                $results.Recommendations += "Review and harden persistence mechanisms"
            }
            
            if ($results.TacticBreakdown.CredentialAccess.Count -gt 0) {
                $results.Recommendations += "CRITICAL: Investigate credential access attempts immediately"
            }
            
            if ($results.TacticBreakdown.DefenseEvasion.Count -gt 0) {
                $results.Recommendations += "Strengthen security controls and monitoring"
            }
            
        }
        catch {
            Write-Error "Error during MITRE ATT&CK mapping: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nMITRE ATT&CK Coverage:" -ForegroundColor Cyan
        Write-Host "  Unique Techniques Detected: $($results.Summary.TotalTechniques)" -ForegroundColor White
        Write-Host "  Tactics Covered: $($results.Summary.TacticsCovered)/12" -ForegroundColor White
        Write-Host "  Risk Score: $($results.Summary.RiskScore)" -ForegroundColor $(
            if ($results.Summary.RiskScore -ge 50) { 'Red' }
            elseif ($results.Summary.RiskScore -ge 20) { 'Yellow' }
            else { 'Green' }
        )
        
        if ($results.Summary.TotalTechniques -gt 0) {
            Write-Host "`nDetected Techniques by Tactic:" -ForegroundColor Cyan
            
            foreach ($tactic in $results.TacticBreakdown.Keys | Sort-Object) {
                $count = $results.TacticBreakdown[$tactic].Count
                if ($count -gt 0) {
                    Write-Host "  $tactic : $count technique(s)" -ForegroundColor Yellow
                }
            }
            
            Write-Host "`nTop Detected Techniques:" -ForegroundColor Cyan
            $results.DetectedTechniques | 
                Group-Object TechniqueID | 
                Sort-Object Count -Descending | 
                Select-Object -First 5 | 
                ForEach-Object {
                    $tech = $_.Group[0]
                    Write-Host "  $($tech.TechniqueID) - $($tech.TechniqueName) [$($tech.Severity)]" -ForegroundColor White
                }
        }
        else {
            Write-Host "`nNo suspicious MITRE ATT&CK techniques detected" -ForegroundColor Green
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | Select-Object -Unique | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nMITRE ATT&CK Navigator:" -ForegroundColor Cyan
        Write-Host "  https://mitre-attack.github.io/attack-navigator/" -ForegroundColor Gray
        
        return $results
    }
}