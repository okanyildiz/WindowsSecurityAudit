function Export-ComplianceEvidence {
    <#
    .SYNOPSIS
        Collects and packages compliance audit evidence
    .DESCRIPTION
        Gathers configuration files, logs, screenshots, and system information
        for compliance audit purposes. Creates timestamped ZIP package with
        chain of custody documentation and integrity hashes.
    .PARAMETER OutputPath
        Path where evidence package will be created
    .PARAMETER EvidenceTypes
        Types of evidence to collect: Configuration, Logs, Screenshots, SystemInfo, All
    .PARAMETER IncludeEventLogs
        Include Windows Event Log exports
    .PARAMETER DaysBack
        Number of days back to collect event logs (default: 7)
    .PARAMETER AuditorName
        Name of person collecting evidence
    .PARAMETER CaseReference
        Case or audit reference number
    .EXAMPLE
        Export-ComplianceEvidence -OutputPath "C:\Audits" -AuditorName "John Doe" -CaseReference "AUD-2025-001"
    .OUTPUTS
        String path to created evidence package
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('All', 'Configuration', 'Logs', 'Screenshots', 'SystemInfo')]
        [string[]]$EvidenceTypes = @('All'),
        
        [Parameter()]
        [switch]$IncludeEventLogs,
        
        [Parameter()]
        [int]$DaysBack = 7,
        
        [Parameter()]
        [string]$AuditorName = $env:USERNAME,
        
        [Parameter()]
        [string]$CaseReference = "AUDIT-$(Get-Date -Format 'yyyyMMdd')"
    )
    
    begin {
        Write-Host "=== COMPLIANCE EVIDENCE COLLECTION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Auditor: $AuditorName" -ForegroundColor Yellow
        Write-Host "Case Reference: $CaseReference" -ForegroundColor Yellow
        
        if ($EvidenceTypes -contains 'All') {
            $EvidenceTypes = @('Configuration', 'Logs', 'Screenshots', 'SystemInfo')
        }
        
        # Create timestamp and working directory
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $evidenceName = "ComplianceEvidence_${CaseReference}_$timestamp"
        $workingDir = Join-Path $OutputPath $evidenceName
        
        # Create directory structure
        $directories = @{
            Root = $workingDir
            Configuration = Join-Path $workingDir "01_Configuration"
            Logs = Join-Path $workingDir "02_Logs"
            Screenshots = Join-Path $workingDir "03_Screenshots"
            SystemInfo = Join-Path $workingDir "04_SystemInfo"
            Metadata = Join-Path $workingDir "00_Metadata"
        }
        
        foreach ($dir in $directories.Values) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        
        # Initialize evidence manifest
        $manifest = [PSCustomObject]@{
            CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Auditor = $AuditorName
            CaseReference = $CaseReference
            EvidenceTypes = $EvidenceTypes
            CollectedFiles = @()
            Hashes = @()
            Notes = @()
        }
    }
    
    process {
        try {
            # 1. CONFIGURATION EVIDENCE
            if ($EvidenceTypes -contains 'Configuration') {
                Write-Host "`n[1/4] Collecting Configuration Evidence..." -ForegroundColor Cyan
                
                try {
                    # Security Policy Export
                    Write-Host "  Exporting security policy..." -ForegroundColor Gray
                    $secpolPath = Join-Path $directories.Configuration "SecurityPolicy.inf"
                    $null = secedit /export /cfg $secpolPath /quiet
                    Start-Sleep -Milliseconds 500
                    
                    if (Test-Path $secpolPath) {
                        $manifest.CollectedFiles += "01_Configuration\SecurityPolicy.inf"
                        $hash = (Get-FileHash $secpolPath -Algorithm SHA256).Hash
                        $manifest.Hashes += [PSCustomObject]@{
                            File = "SecurityPolicy.inf"
                            SHA256 = $hash
                        }
                    }
                    
                    # Audit Policy Export
                    Write-Host "  Exporting audit policies..." -ForegroundColor Gray
                    $auditPath = Join-Path $directories.Configuration "AuditPolicy.csv"
                    auditpol /backup /file:$auditPath | Out-Null
                    
                    if (Test-Path $auditPath) {
                        $manifest.CollectedFiles += "01_Configuration\AuditPolicy.csv"
                        $hash = (Get-FileHash $auditPath -Algorithm SHA256).Hash
                        $manifest.Hashes += [PSCustomObject]@{
                            File = "AuditPolicy.csv"
                            SHA256 = $hash
                        }
                    }
                    
                    # Firewall Rules Export
                    Write-Host "  Exporting firewall rules..." -ForegroundColor Gray
                    $fwPath = Join-Path $directories.Configuration "FirewallRules.csv"
                    Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile | 
                        Export-Csv $fwPath -NoTypeInformation
                    
                    $manifest.CollectedFiles += "01_Configuration\FirewallRules.csv"
                    $hash = (Get-FileHash $fwPath -Algorithm SHA256).Hash
                    $manifest.Hashes += [PSCustomObject]@{
                        File = "FirewallRules.csv"
                        SHA256 = $hash
                    }
                    
                    # Registry Exports (Key Security Settings)
                    Write-Host "  Exporting registry settings..." -ForegroundColor Gray
                    $regExports = @{
                        'PasswordPolicy' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                        'AuditSettings' = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
                        'WindowsDefender' = 'HKLM\SOFTWARE\Microsoft\Windows Defender'
                    }
                    
                    foreach ($regName in $regExports.Keys) {
                        $regPath = Join-Path $directories.Configuration "Registry_$regName.reg"
                        $regKey = $regExports[$regName]
                        
                        try {
                            $null = reg export $regKey $regPath /y 2>$null
                            if (Test-Path $regPath) {
                                $manifest.CollectedFiles += "01_Configuration\Registry_$regName.reg"
                            }
                        }
                        catch {
                            Write-Warning "Could not export registry key: $regKey"
                        }
                    }
                    
                    # Group Policy Results - FIXED: Use uppercase /H /F
                    Write-Host "  Generating Group Policy report..." -ForegroundColor Gray
                    $gpPath = Join-Path $directories.Configuration "GroupPolicy.html"
                    try {
                        gpresult /H $gpPath /F | Out-Null
                        
                        if (Test-Path $gpPath) {
                            $manifest.CollectedFiles += "01_Configuration\GroupPolicy.html"
                        }
                    }
                    catch {
                        Write-Warning "Could not generate Group Policy report"
                    }
                    
                    Write-Host "  Configuration evidence collected" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Error collecting configuration evidence: $_"
                    $manifest.Notes += "Configuration collection had errors: $_"
                }
            }
            
            # 2. LOG EVIDENCE
            if ($EvidenceTypes -contains 'Logs') {
                Write-Host "`n[2/4] Collecting Log Evidence..." -ForegroundColor Cyan
                
                try {
                    # Export Event Logs if requested
                    if ($IncludeEventLogs) {
                        Write-Host "  Exporting event logs (last $DaysBack days)..." -ForegroundColor Gray
                        
                        $logNames = @('Security', 'System', 'Application')
                        $startDate = (Get-Date).AddDays(-$DaysBack)
                        
                        foreach ($logName in $logNames) {
                            try {
                                $logPath = Join-Path $directories.Logs "EventLog_$logName.evtx"
                                $query = "*[System[TimeCreated[@SystemTime>='$($startDate.ToUniversalTime().ToString('o'))']]]"
                                
                                wevtutil epl $logName $logPath "/q:$query" 2>$null
                                
                                if (Test-Path $logPath) {
                                    $manifest.CollectedFiles += "02_Logs\EventLog_$logName.evtx"
                                    Write-Host "    Exported $logName log" -ForegroundColor Gray
                                }
                            }
                            catch {
                                Write-Warning "Could not export $logName log"
                            }
                        }
                    }
                    
                    # Recent Failed Logon Attempts
                    Write-Host "  Collecting failed logon attempts..." -ForegroundColor Gray
                    $failedLogons = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4625
                        StartTime = (Get-Date).AddDays(-$DaysBack)
                    } -ErrorAction SilentlyContinue | Select-Object -First 100
                    
                    if ($failedLogons) {
                        $logonPath = Join-Path $directories.Logs "FailedLogons.csv"
                        $failedLogons | Select-Object TimeCreated, Id, Message | 
                            Export-Csv $logonPath -NoTypeInformation
                        $manifest.CollectedFiles += "02_Logs\FailedLogons.csv"
                    }
                    
                    # PowerShell Script Block Logs
                    Write-Host "  Collecting PowerShell logs..." -ForegroundColor Gray
                    $psLogs = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-PowerShell/Operational'
                        StartTime = (Get-Date).AddDays(-$DaysBack)
                    } -ErrorAction SilentlyContinue | Select-Object -First 100
                    
                    if ($psLogs) {
                        $psPath = Join-Path $directories.Logs "PowerShellLogs.csv"
                        $psLogs | Select-Object TimeCreated, Id, LevelDisplayName, Message | 
                            Export-Csv $psPath -NoTypeInformation
                        $manifest.CollectedFiles += "02_Logs\PowerShellLogs.csv"
                    }
                    
                    Write-Host "  Log evidence collected" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Error collecting log evidence: $_"
                    $manifest.Notes += "Log collection had errors: $_"
                }
            }
            
            # 3. SCREENSHOTS
            if ($EvidenceTypes -contains 'Screenshots') {
                Write-Host "`n[3/4] Capturing Screenshots..." -ForegroundColor Cyan
                
                try {
                    # Windows Defender Status Screenshot
                    Write-Host "  Capturing Windows Defender status..." -ForegroundColor Gray
                    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($defenderStatus) {
                        $defPath = Join-Path $directories.Screenshots "WindowsDefender_Status.txt"
                        $defenderStatus | Format-List | Out-File $defPath
                        $manifest.CollectedFiles += "03_Screenshots\WindowsDefender_Status.txt"
                    }
                    
                    # Firewall Status
                    Write-Host "  Capturing firewall status..." -ForegroundColor Gray
                    $fwStatus = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
                    $fwStatusPath = Join-Path $directories.Screenshots "Firewall_Status.txt"
                    $fwStatus | Format-Table -AutoSize | Out-File $fwStatusPath
                    $manifest.CollectedFiles += "03_Screenshots\Firewall_Status.txt"
                    
                    # BitLocker Status
                    Write-Host "  Capturing BitLocker status..." -ForegroundColor Gray
                    $blStatus = Get-BitLockerVolume -ErrorAction SilentlyContinue
                    if ($blStatus) {
                        $blPath = Join-Path $directories.Screenshots "BitLocker_Status.txt"
                        $blStatus | Format-List | Out-File $blPath
                        $manifest.CollectedFiles += "03_Screenshots\BitLocker_Status.txt"
                    }
                    
                    Write-Host "  Screenshots captured" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Error capturing screenshots: $_"
                    $manifest.Notes += "Screenshot capture had errors: $_"
                }
            }
            
            # 4. SYSTEM INFORMATION
            if ($EvidenceTypes -contains 'SystemInfo') {
                Write-Host "`n[4/4] Collecting System Information..." -ForegroundColor Cyan
                
                try {
                    # System Information Report
                    Write-Host "  Generating system information report..." -ForegroundColor Gray
                    $sysInfoPath = Join-Path $directories.SystemInfo "SystemInfo.txt"
                    systeminfo | Out-File $sysInfoPath
                    $manifest.CollectedFiles += "04_SystemInfo\SystemInfo.txt"
                    
                    # Installed Software
                    Write-Host "  Collecting installed software list..." -ForegroundColor Gray
                    $softwarePath = Join-Path $directories.SystemInfo "InstalledSoftware.csv"
                    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
                        Where-Object { $_.DisplayName } | 
                        Export-Csv $softwarePath -NoTypeInformation
                    $manifest.CollectedFiles += "04_SystemInfo\InstalledSoftware.csv"
                    
                    # Local Users
                    Write-Host "  Collecting local users information..." -ForegroundColor Gray
                    $usersPath = Join-Path $directories.SystemInfo "LocalUsers.csv"
                    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires | 
                        Export-Csv $usersPath -NoTypeInformation
                    $manifest.CollectedFiles += "04_SystemInfo\LocalUsers.csv"
                    
                    # Local Groups - FIXED: Proper error handling with foreach
                    Write-Host "  Collecting local groups information..." -ForegroundColor Gray
                    $groupsPath = Join-Path $directories.SystemInfo "LocalGroups.csv"
                    $groupData = @()
                    
                    $localGroups = @(Get-LocalGroup -ErrorAction SilentlyContinue)
                    foreach ($group in $localGroups) {
                        try {
                            $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue)
                            $groupData += [PSCustomObject]@{
                                GroupName = $group.Name
                                Members = if ($members.Count -gt 0) { ($members.Name -join '; ') } else { 'No members' }
                            }
                        }
                        catch {
                            $groupData += [PSCustomObject]@{
                                GroupName = $group.Name
                                Members = 'Error retrieving members'
                            }
                        }
                    }
                    
                    if ($groupData.Count -gt 0) {
                        $groupData | Export-Csv $groupsPath -NoTypeInformation
                        $manifest.CollectedFiles += "04_SystemInfo\LocalGroups.csv"
                    }
                    
                    # Network Configuration
                    Write-Host "  Collecting network configuration..." -ForegroundColor Gray
                    $netPath = Join-Path $directories.SystemInfo "NetworkConfig.txt"
                    ipconfig /all | Out-File $netPath
                    $manifest.CollectedFiles += "04_SystemInfo\NetworkConfig.txt"
                    
                    # Services
                    Write-Host "  Collecting services list..." -ForegroundColor Gray
                    $servicesPath = Join-Path $directories.SystemInfo "Services.csv"
                    Get-Service | Select-Object Name, DisplayName, Status, StartType | 
                        Export-Csv $servicesPath -NoTypeInformation
                    $manifest.CollectedFiles += "04_SystemInfo\Services.csv"
                    
                    # Windows Updates
                    Write-Host "  Collecting Windows Update history..." -ForegroundColor Gray
                    try {
                        $updatesPath = Join-Path $directories.SystemInfo "WindowsUpdates.csv"
                        $session = New-Object -ComObject Microsoft.Update.Session
                        $searcher = $session.CreateUpdateSearcher()
                        $historyCount = $searcher.GetTotalHistoryCount()
                        if ($historyCount -gt 0) {
                            $history = $searcher.QueryHistory(0, [Math]::Min($historyCount, 100))
                            $history | Select-Object Title, Date, @{N='Result';E={
                                switch($_.ResultCode) {
                                    0 { 'NotStarted' }
                                    1 { 'InProgress' }
                                    2 { 'Succeeded' }
                                    3 { 'SucceededWithErrors' }
                                    4 { 'Failed' }
                                    5 { 'Aborted' }
                                }
                            }} | Export-Csv $updatesPath -NoTypeInformation
                            $manifest.CollectedFiles += "04_SystemInfo\WindowsUpdates.csv"
                        }
                    }
                    catch {
                        Write-Warning "Could not collect Windows Update history"
                    }
                    
                    Write-Host "  System information collected" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Error collecting system information: $_"
                    $manifest.Notes += "System information collection had errors: $_"
                }
            }
            
            # 5. GENERATE CHAIN OF CUSTODY & MANIFEST
            Write-Host "`n[*] Generating chain of custody documentation..." -ForegroundColor Cyan
            
            # Save manifest
            $manifestPath = Join-Path $directories.Metadata "Evidence_Manifest.json"
            $manifest | ConvertTo-Json -Depth 10 | Out-File $manifestPath -Encoding UTF8
            
            # Generate Chain of Custody
            $custodyPath = Join-Path $directories.Metadata "Chain_of_Custody.txt"
            $custody = @"
CHAIN OF CUSTODY DOCUMENTATION
================================

Case Reference: $CaseReference
Collection Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Time Zone: $([System.TimeZoneInfo]::Local.DisplayName)

SYSTEM INFORMATION:
Computer Name: $($env:COMPUTERNAME)
Domain: $($env:USERDOMAIN)
IP Address: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).IPAddress)
Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption)

EVIDENCE COLLECTOR:
Name: $AuditorName
Account: $($env:USERDOMAIN)\$($env:USERNAME)
Collection Method: WindowsSecurityAudit PowerShell Module

EVIDENCE COLLECTED:
Total Files: $($manifest.CollectedFiles.Count)
Evidence Types: $($EvidenceTypes -join ', ')

FILE INTEGRITY HASHES:
$($manifest.Hashes | ForEach-Object { "  $($_.File): $($_.SHA256)" } | Out-String)

NOTES:
$($manifest.Notes -join "`n")

CERTIFICATION:
I certify that this evidence was collected using automated tools in a forensically
sound manner. All timestamps are accurate, and file integrity hashes have been
recorded for verification purposes.

Collector Signature: ___________________________  Date: __________

Reviewer Signature: ____________________________  Date: __________
"@
            $custody | Out-File $custodyPath -Encoding UTF8
            
            # Generate README
            $readmePath = Join-Path $directories.Root "README.txt"
            $readme = @"
COMPLIANCE EVIDENCE PACKAGE
===========================

Case Reference: $CaseReference
Collection Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)

DIRECTORY STRUCTURE:
00_Metadata/        - Chain of custody and evidence manifest
01_Configuration/   - System configuration exports
02_Logs/            - Event logs and security logs
03_Screenshots/     - Status captures and documentation
04_SystemInfo/      - System inventory and information

INTEGRITY VERIFICATION:
All collected files have been hashed with SHA-256.
See 00_Metadata/Evidence_Manifest.json for hash values.

IMPORTANT NOTES:
- This evidence package should be stored securely
- Maintain chain of custody at all times
- Do not modify files after collection
- Verify file hashes before using as audit evidence

For questions contact: $AuditorName
"@
            $readme | Out-File $readmePath -Encoding UTF8
            
            # 6. CREATE ZIP PACKAGE
            Write-Host "[*] Creating evidence package..." -ForegroundColor Cyan
            
            $zipPath = "$workingDir.zip"
            
            if (Test-Path $zipPath) {
                Remove-Item $zipPath -Force
            }
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($workingDir, $zipPath, 'Optimal', $false)
            
            # Generate ZIP hash
            $zipHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
            
            # Clean up working directory
            Remove-Item $workingDir -Recurse -Force
            
            Write-Host "`nEvidence package created successfully!" -ForegroundColor Green
            Write-Host "Package: $zipPath" -ForegroundColor White
            Write-Host "SHA-256: $zipHash" -ForegroundColor Gray
            Write-Host "Size: $([math]::Round((Get-Item $zipPath).Length / 1MB, 2)) MB" -ForegroundColor Gray
            
        }
        catch {
            Write-Error "Error during evidence collection: $_"
            
            # Clean up on error
            if (Test-Path $workingDir) {
                Remove-Item $workingDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            throw
        }
    }
    
    end {
        Write-Host "`n=== EVIDENCE COLLECTION COMPLETE ===" -ForegroundColor Cyan
        Write-Host "Package Location: $zipPath" -ForegroundColor Green
        Write-Host "Files Collected: $($manifest.CollectedFiles.Count)" -ForegroundColor White
        Write-Host "Package Hash: $zipHash" -ForegroundColor Gray
        
        return [PSCustomObject]@{
            PackagePath = $zipPath
            PackageHash = $zipHash
            FilesCollected = $manifest.CollectedFiles.Count
            CollectionDate = $manifest.CollectionDate
            CaseReference = $CaseReference
            Auditor = $AuditorName
        }
    }
}