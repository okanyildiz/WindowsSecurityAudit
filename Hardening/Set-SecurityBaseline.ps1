function Set-SecurityBaseline {
    <#
    .SYNOPSIS
        Applies Windows security baseline configuration
    .DESCRIPTION
        Configures Windows security settings based on industry best practices and hardening guides
        (CIS benchmarks, Microsoft Security Baselines)
    .PARAMETER BaselineLevel
        Security baseline level: Basic, Recommended, or Strict
    .PARAMETER EnableBitLocker
        Enable BitLocker encryption on system drive
    .PARAMETER DisableSMBv1
        Disable SMBv1 protocol
    .PARAMETER ConfigureFirewall
        Configure Windows Firewall with recommended settings
    .EXAMPLE
        Set-SecurityBaseline -BaselineLevel Recommended
        Set-SecurityBaseline -BaselineLevel Strict -EnableBitLocker -DisableSMBv1
    .OUTPUTS
        PSCustomObject with baseline configuration results
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateSet('Basic', 'Recommended', 'Strict')]
        [string]$BaselineLevel = 'Recommended',
        
        [Parameter()]
        [switch]$EnableBitLocker,
        
        [Parameter()]
        [switch]$DisableSMBv1,
        
        [Parameter()]
        [switch]$ConfigureFirewall
    )
    
    begin {
        Write-Host "=== WINDOWS SECURITY BASELINE CONFIGURATION ===" -ForegroundColor Cyan
        Write-Host "Baseline Level: $BaselineLevel" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges!"
        }
        
        $results = [PSCustomObject]@{
            ConfigurationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            BaselineLevel = $BaselineLevel
            Changes = @()
            Errors = @()
            RequiresReboot = $false
            Categories = @{
                UAC = @{}
                Firewall = @{}
                WindowsDefender = @{}
                NetworkSecurity = @{}
                AccountSecurity = @{}
                SystemSecurity = @{}
                BitLocker = @{}
            }
        }
    }
    
    process {
        try {
            # Category 1: UAC Configuration
            Write-Host "`n[1/7] Configuring User Account Control (UAC)..." -ForegroundColor Cyan
            
            $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            
            try {
                # Enable UAC
                Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -Force
                $results.Changes += "UAC enabled"
                
                # Prompt for admin credentials
                Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
                
                # Elevate signed executables
                if ($BaselineLevel -in @('Recommended', 'Strict')) {
                    Set-ItemProperty -Path $uacPath -Name "ValidateAdminCodeSignatures" -Value 1 -Type DWord -Force
                    $results.Changes += "UAC: Require signed executables"
                }
                
                # Secure desktop for elevation prompts
                if ($BaselineLevel -eq 'Strict') {
                    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
                    $results.Changes += "UAC: Secure desktop for prompts"
                }
                
                $results.Categories.UAC = @{
                    Enabled = $true
                    Status = 'Configured'
                }
                
                Write-Host "  UAC: Configured" -ForegroundColor Green
            }
            catch {
                $results.Errors += "UAC configuration failed: $_"
                Write-Warning "  UAC configuration failed: $_"
            }
            
            # Category 2: Windows Firewall
            Write-Host "`n[2/7] Configuring Windows Firewall..." -ForegroundColor Cyan
            
            if ($ConfigureFirewall -or $BaselineLevel -in @('Recommended', 'Strict')) {
                try {
                    # Enable firewall for all profiles
                    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                    $results.Changes += "Windows Firewall enabled for all profiles"
                    
                    # Configure default actions
                    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow
                    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow
                    Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
                    $results.Changes += "Firewall: Block inbound by default"
                    
                    # Disable firewall notifications for Public profile
                    Set-NetFirewallProfile -Profile Public -NotifyOnListen False
                    
                    if ($BaselineLevel -eq 'Strict') {
                        # Enable logging
                        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384
                        $results.Changes += "Firewall: Logging enabled"
                    }
                    
                    $results.Categories.Firewall = @{
                        Enabled = $true
                        Status = 'Configured'
                        Profiles = 'All profiles enabled'
                    }
                    
                    Write-Host "  Firewall: Configured" -ForegroundColor Green
                }
                catch {
                    $results.Errors += "Firewall configuration failed: $_"
                    Write-Warning "  Firewall configuration failed: $_"
                }
            }
            else {
                Write-Host "  Firewall: Skipped" -ForegroundColor Yellow
            }
            
            # Category 3: Windows Defender
            Write-Host "`n[3/7] Configuring Windows Defender..." -ForegroundColor Cyan
            
            try {
                # Enable Real-Time Protection
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                $results.Changes += "Windows Defender: Real-time protection enabled"
                
                # Enable Cloud Protection
                Set-MpPreference -MAPSReporting Advanced
                Set-MpPreference -SubmitSamplesConsent SendAllSamples
                $results.Changes += "Windows Defender: Cloud protection enabled"
                
                # Enable PUA (Potentially Unwanted Applications) protection
                Set-MpPreference -PUAProtection Enabled
                $results.Changes += "Windows Defender: PUA protection enabled"
                
                if ($BaselineLevel -in @('Recommended', 'Strict')) {
                    # Enable Network Protection
                    Set-MpPreference -EnableNetworkProtection Enabled
                    $results.Changes += "Windows Defender: Network protection enabled"
                    
                    # Enable Controlled Folder Access
                    Set-MpPreference -EnableControlledFolderAccess Enabled
                    $results.Changes += "Windows Defender: Controlled folder access enabled"
                }
                
                # Update definitions
                Update-MpSignature -ErrorAction SilentlyContinue
                $results.Changes += "Windows Defender: Signatures updated"
                
                $results.Categories.WindowsDefender = @{
                    RealTimeProtection = $true
                    CloudProtection = $true
                    Status = 'Configured'
                }
                
                Write-Host "  Windows Defender: Configured" -ForegroundColor Green
            }
            catch {
                $results.Errors += "Windows Defender configuration failed: $_"
                Write-Warning "  Windows Defender configuration failed: $_"
            }
            
            # Category 4: Network Security
            Write-Host "`n[4/7] Configuring Network Security..." -ForegroundColor Cyan
            
            try {
                # Disable SMBv1
                if ($DisableSMBv1 -or $BaselineLevel -in @('Recommended', 'Strict')) {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                    $results.Changes += "SMBv1 protocol disabled"
                    $results.RequiresReboot = $true
                    Write-Host "  SMBv1: Disabled (reboot required)" -ForegroundColor Green
                }
                
                # Configure SMBv2/v3 encryption
                if ($BaselineLevel -eq 'Strict') {
                    Set-SmbServerConfiguration -EncryptData $true -Force
                    $results.Changes += "SMB encryption enabled"
                }
                
                # Disable NetBIOS over TCP/IP
                if ($BaselineLevel -eq 'Strict') {
                    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
                    foreach ($adapter in $adapters) {
                        $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
                    }
                    $results.Changes += "NetBIOS over TCP/IP disabled"
                }
                
                # Disable LLMNR
                if ($BaselineLevel -eq 'Strict') {
                    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                    if (-not (Test-Path $llmnrPath)) {
                        New-Item -Path $llmnrPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
                    $results.Changes += "LLMNR disabled"
                }
                
                $results.Categories.NetworkSecurity = @{
                    SMBv1Disabled = $true
                    Status = 'Configured'
                }
                
                Write-Host "  Network Security: Configured" -ForegroundColor Green
            }
            catch {
                $results.Errors += "Network security configuration failed: $_"
                Write-Warning "  Network security configuration failed: $_"
            }
            
            # Category 5: Account Security
            Write-Host "`n[5/7] Configuring Account Security..." -ForegroundColor Cyan
            
            try {
                # Disable Guest account
                Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                $results.Changes += "Guest account disabled"
                
                # Rename Administrator account (if desired in Strict mode)
                if ($BaselineLevel -eq 'Strict') {
                    # Note: This is commented out as renaming admin is risky
                    # Rename-LocalUser -Name "Administrator" -NewName "Admin_SecureAccount"
                    # $results.Changes += "Administrator account renamed"
                }
                
                # Configure account lockout policy
                net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
                $results.Changes += "Account lockout policy configured (5 attempts, 30 min lockout)"
                
                # Password policy
                if ($BaselineLevel -in @('Recommended', 'Strict')) {
                    net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null
                    $results.Changes += "Password policy: 12 char minimum, 90 day max age"
                }
                
                $results.Categories.AccountSecurity = @{
                    GuestDisabled = $true
                    LockoutPolicy = 'Configured'
                    Status = 'Configured'
                }
                
                Write-Host "  Account Security: Configured" -ForegroundColor Green
            }
            catch {
                $results.Errors += "Account security configuration failed: $_"
                Write-Warning "  Account security configuration failed: $_"
            }
            
            # Category 6: System Security
            Write-Host "`n[6/7] Configuring System Security..." -ForegroundColor Cyan
            
            try {
                # Disable AutoRun/AutoPlay
                $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                if (-not (Test-Path $autorunPath)) {
                    New-Item -Path $autorunPath -Force | Out-Null
                }
                Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
                $results.Changes += "AutoRun/AutoPlay disabled"
                
                # Disable Remote Assistance
                $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
                Set-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
                $results.Changes += "Remote Assistance disabled"
                
                # Enable DEP (Data Execution Prevention)
                bcdedit /set nx AlwaysOn | Out-Null
                $results.Changes += "DEP enabled"
                
                # Disable unnecessary services
                if ($BaselineLevel -eq 'Strict') {
                    $servicesToDisable = @(
                        'RemoteRegistry',
                        'RemoteAccess',
                        'Telephony',
                        'SharedAccess'  # Internet Connection Sharing
                    )
                    
                    foreach ($service in $servicesToDisable) {
                        try {
                            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                            $results.Changes += "Service disabled: $service"
                        }
                        catch {
                            # Service might not exist
                        }
                    }
                }
                
                # Enable Windows Update automatic updates
                $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                if (-not (Test-Path $wuPath)) {
                    New-Item -Path $wuPath -Force | Out-Null
                }
                Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 4 -Type DWord -Force  # Auto download and install
                $results.Changes += "Windows Update: Automatic updates enabled"
                
                $results.Categories.SystemSecurity = @{
                    AutoRunDisabled = $true
                    RemoteAssistanceDisabled = $true
                    DEPEnabled = $true
                    Status = 'Configured'
                }
                
                Write-Host "  System Security: Configured" -ForegroundColor Green
            }
            catch {
                $results.Errors += "System security configuration failed: $_"
                Write-Warning "  System security configuration failed: $_"
            }
            
            # Category 7: BitLocker Encryption
            Write-Host "`n[7/7] Configuring BitLocker..." -ForegroundColor Cyan
            
            if ($EnableBitLocker) {
                try {
                    $volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
                    
                    if ($volume.ProtectionStatus -ne 'On') {
                        Write-Host "  Enabling BitLocker on C:..." -ForegroundColor Yellow
                        Write-Warning "  This may take several minutes..."
                        
                        # Enable BitLocker with TPM
                        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -ErrorAction Stop
                        $results.Changes += "BitLocker enabled on system drive"
                        $results.RequiresReboot = $true
                        
                        Write-Host "  BitLocker: Enabled (encryption in progress)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  BitLocker: Already enabled" -ForegroundColor Yellow
                    }
                    
                    $results.Categories.BitLocker = @{
                        Enabled = $true
                        Status = 'Enabled'
                    }
                }
                catch {
                    $results.Errors += "BitLocker configuration failed: $_"
                    Write-Warning "  BitLocker failed: $_"
                    Write-Warning "  Note: TPM may be required, or device may not support BitLocker"
                }
            }
            else {
                Write-Host "  BitLocker: Skipped" -ForegroundColor Yellow
                $results.Categories.BitLocker = @{
                    Enabled = $false
                    Status = 'Not Configured'
                }
            }
            
        }
        catch {
            Write-Error "Error during security baseline configuration: $_"
            throw
        }
    }
    
end {
        Write-Host "`n=== BASELINE CONFIGURATION COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nChanges Applied: $($results.Changes.Count)" -ForegroundColor Cyan
        if ($results.Changes.Count -gt 0) {
            $results.Changes | ForEach-Object {
                Write-Host "  + $_" -ForegroundColor White
            }
        }
        
        if ($results.Errors.Count -gt 0) {
            Write-Host "`nErrors Encountered: $($results.Errors.Count)" -ForegroundColor Red
            $results.Errors | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Red
            }
        }
        
        if ($results.RequiresReboot) {
            Write-Host "`n[!] SYSTEM REBOOT REQUIRED" -ForegroundColor Yellow -BackgroundColor Red
            Write-Host "Some changes require a system restart to take effect" -ForegroundColor Yellow
        }
        
        Write-Host "`nSecurity Baseline Status:" -ForegroundColor Cyan
        Write-Host "  Level: $($results.BaselineLevel)" -ForegroundColor White
        Write-Host "  UAC: $($results.Categories.UAC.Status)" -ForegroundColor White
        Write-Host "  Firewall: $($results.Categories.Firewall.Status)" -ForegroundColor White
        Write-Host "  Windows Defender: $($results.Categories.WindowsDefender.Status)" -ForegroundColor White
        Write-Host "  Network Security: $($results.Categories.NetworkSecurity.Status)" -ForegroundColor White
        Write-Host "  Account Security: $($results.Categories.AccountSecurity.Status)" -ForegroundColor White
        Write-Host "  System Security: $($results.Categories.SystemSecurity.Status)" -ForegroundColor White
        Write-Host "  BitLocker: $($results.Categories.BitLocker.Status)" -ForegroundColor White
        
        Write-Host "`nRecommendations:" -ForegroundColor Cyan
        Write-Host "  1. Review all changes and test system functionality" -ForegroundColor White
        Write-Host "  2. Document the baseline configuration" -ForegroundColor White
        Write-Host "  3. Schedule regular security audits" -ForegroundColor White
        Write-Host "  4. Keep Windows and Defender signatures updated" -ForegroundColor White
        Write-Host "  5. Monitor security logs regularly" -ForegroundColor White
        
        return $results
    }
}