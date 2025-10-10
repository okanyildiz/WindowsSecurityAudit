function Get-SecurityBaseline {
    <#
    .SYNOPSIS
        Gets the current security baseline status of the Windows system
    .DESCRIPTION
        Retrieves comprehensive security configuration including Windows Defender, 
        Firewall, UAC, BitLocker, and Windows Update status
    .PARAMETER ComputerName
        Name of the computer to check (default: local computer)
    .PARAMETER ExportPath
        Path to export the results as JSON
    .EXAMPLE
        Get-SecurityBaseline
        Get-SecurityBaseline -ComputerName "SERVER01" -ExportPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with security baseline information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Position = 1)]
        [string]$ExportPath
    )
    
    begin {
        Write-Verbose "Starting security baseline check for $ComputerName"
        $results = [PSCustomObject]@{
            ComputerName = $ComputerName
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            WindowsDefender = $null
            Firewall = $null
            UAC = $null
            BitLocker = $null
            WindowsUpdate = $null
            SecurityScore = 0
        }
    }
    
    process {
        try {
            # Check Windows Defender Status
            Write-Verbose "Checking Windows Defender status..."
            try {
                $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
                $results.WindowsDefender = [PSCustomObject]@{
                    AntivirusEnabled = $defenderStatus.AntivirusEnabled
                    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                    BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                    IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                    SignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                    SignatureVersion = $defenderStatus.AntivirusSignatureVersion
                }
                if ($defenderStatus.RealTimeProtectionEnabled) { $results.SecurityScore += 20 }
            }
            catch {
                Write-Warning "Could not retrieve Windows Defender status: $_"
                $results.WindowsDefender = "Not available or not installed"
            }
            
            # Check Firewall Status
            Write-Verbose "Checking Windows Firewall status..."
            try {
                $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
                $results.Firewall = @()
                foreach ($profile in $firewallProfiles) {
                    $results.Firewall += [PSCustomObject]@{
                        Profile = $profile.Name
                        Enabled = $profile.Enabled
                        DefaultInboundAction = $profile.DefaultInboundAction.ToString()
                        DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
                    }
                    if ($profile.Enabled) { $results.SecurityScore += 10 }
                }
            }
            catch {
                Write-Warning "Could not retrieve Firewall status: $_"
                $results.Firewall = "Error retrieving firewall status"
            }
            
            # Check UAC Settings
            Write-Verbose "Checking UAC settings..."
            try {
                $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $uacSettings = Get-ItemProperty -Path $uacKey -ErrorAction Stop
                $results.UAC = [PSCustomObject]@{
                    EnableLUA = $uacSettings.EnableLUA
                    ConsentPromptBehaviorAdmin = $uacSettings.ConsentPromptBehaviorAdmin
                    ConsentPromptBehaviorUser = $uacSettings.ConsentPromptBehaviorUser
                    EnableSecureUIAPaths = $uacSettings.EnableSecureUIAPaths
                    EnableVirtualization = $uacSettings.EnableVirtualization
                }
                if ($uacSettings.EnableLUA -eq 1) { $results.SecurityScore += 15 }
            }
            catch {
                Write-Warning "Could not retrieve UAC settings: $_"
                $results.UAC = "Error retrieving UAC settings"
            }
            
            # Check BitLocker Status
            Write-Verbose "Checking BitLocker status..."
            try {
                $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop
                $results.BitLocker = @()
                foreach ($volume in $bitlockerVolumes) {
                    $results.BitLocker += [PSCustomObject]@{
                        MountPoint = $volume.MountPoint
                        VolumeStatus = $volume.VolumeStatus.ToString()
                        ProtectionStatus = $volume.ProtectionStatus.ToString()
                        EncryptionPercentage = $volume.EncryptionPercentage
                        EncryptionMethod = if ($volume.EncryptionMethod) { $volume.EncryptionMethod.ToString() } else { "None" }
                    }
                    if ($volume.ProtectionStatus -eq "On") { $results.SecurityScore += 10 }
                }
            }
            catch {
                Write-Warning "Could not retrieve BitLocker status: $_"
                $results.BitLocker = "BitLocker not available or access denied"
            }
            
            # Check Windows Update Status
            Write-Verbose "Checking Windows Update status..."
            try {
                # Try to get pending updates count
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $searchResult = $updateSearcher.Search("IsInstalled=0")
                $pendingCount = $searchResult.Updates.Count
                
                # Try to get last update check date
                $lastCheck = $null
                try {
                    $auKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect"
                    if (Test-Path $auKey) {
                        $lastCheckProp = Get-ItemProperty -Path $auKey -Name "LastSuccessTime" -ErrorAction SilentlyContinue
                        if ($lastCheckProp -and $lastCheckProp.LastSuccessTime) {
                            $lastCheck = $lastCheckProp.LastSuccessTime
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve last update check time"
                }
                
                # Check if auto updates are enabled
                $autoUpdateEnabled = $true
                try {
                    $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                    if (Test-Path $wuKey) {
                        $auSettings = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
                        if ($auSettings -and $auSettings.NoAutoUpdate -eq 1) {
                            $autoUpdateEnabled = $false
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not determine auto update settings"
                }
                
                $results.WindowsUpdate = [PSCustomObject]@{
                    PendingUpdates = $pendingCount
                    LastUpdateCheck = $lastCheck
                    AutoUpdateEnabled = $autoUpdateEnabled
                }
                
                if ($pendingCount -eq 0) { $results.SecurityScore += 15 }
            }
            catch {
                Write-Warning "Could not retrieve Windows Update status: $_"
                $results.WindowsUpdate = [PSCustomObject]@{
                    PendingUpdates = "Unable to determine"
                    LastUpdateCheck = "Unknown"
                    AutoUpdateEnabled = "Unknown"
                }
            }
            
            # Calculate final security score
            $results.SecurityScore = [Math]::Min($results.SecurityScore, 100)
            
        }
        catch {
            Write-Error "Error during security baseline check: $_"
            throw
        }
    }
    
    end {
        # Export results if path specified
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "SecurityBaseline_$ComputerName_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Verbose "Results exported to: $exportFile"
        }
        
        # Return results
        return $results
    }
}