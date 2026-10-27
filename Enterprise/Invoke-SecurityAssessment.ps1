function Invoke-SecurityAssessment {
    <#
    .SYNOPSIS
        Performs comprehensive security assessment and generates detailed report
    .DESCRIPTION
        Conducts thorough security evaluation including baseline checks, vulnerability assessment,
        compliance validation, and provides actionable recommendations
    .PARAMETER AssessmentType
        Type of assessment: Basic, Standard, or Advanced
    .PARAMETER IncludeCompliance
        Include compliance checks (CIS, NIST, etc.)
    .PARAMETER OutputPath
        Path to save assessment report
    .EXAMPLE
        Invoke-SecurityAssessment -AssessmentType Standard
        Invoke-SecurityAssessment -AssessmentType Advanced -IncludeCompliance -OutputPath "C:\Assessments"
    .OUTPUTS
        PSCustomObject with assessment results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Basic', 'Standard', 'Advanced')]
        [string]$AssessmentType = 'Standard',
        
        [Parameter()]
        [switch]$IncludeCompliance,
        
        [Parameter()]
        [string]$OutputPath = "C:\SecurityAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    begin {
        Write-Host "=== SECURITY ASSESSMENT ===" -ForegroundColor Cyan
        Write-Host "Assessment Type: $AssessmentType" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        if ($AssessmentType -ne 'Standard') {
            Write-Warning "AssessmentType '$AssessmentType' is accepted, but Basic, Standard, and Advanced currently all run the same set of checks."
        }
        
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $assessment = [PSCustomObject]@{
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            AssessmentType = $AssessmentType
            ComputerName = $env:COMPUTERNAME
            OverallScore = 0
            RiskLevel = 'Unknown'
            Categories = @{
                SystemSecurity = $null
                NetworkSecurity = $null
                AccountSecurity = $null
                ApplicationSecurity = $null
                DataProtection = $null
            }
            Findings = @()
            Recommendations = @()
            ComplianceChecks = @()
        }
    }
    
    process {
        try {
            # Category 1: System Security
            Write-Host "`n[1/5] Assessing System Security..." -ForegroundColor Cyan
            
            $systemSecurity = [PSCustomObject]@{
                CategoryScore = 0
                MaxScore = 100
                Checks = @()
            }
            
            # Windows Defender (cmdlet absent on hosts without the Defender feature - guard the lookup)
            $defender = $null
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
            }
            if ($defender) {
                if ($defender.RealTimeProtectionEnabled) {
                    $systemSecurity.CategoryScore += 20
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Windows Defender Real-Time Protection'
                        Status = 'Pass'
                        Score = 20
                        Details = 'Enabled'
                    }
                } else {
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Windows Defender Real-Time Protection'
                        Status = 'Fail'
                        Score = 0
                        Details = 'Disabled - Critical risk'
                    }
                    $assessment.Findings += [PSCustomObject]@{
                        Severity = 'Critical'
                        Category = 'System Security'
                        Finding = 'Windows Defender real-time protection is disabled'
                        Impact = 'System vulnerable to malware and viruses'
                        Recommendation = 'Enable Windows Defender real-time protection immediately'
                    }
                }
                
                # Signature updates
                if ($null -ne $defender.AntivirusSignatureLastUpdated) {
                    $signatureAge = (Get-Date) - [datetime]$defender.AntivirusSignatureLastUpdated
                    if ($signatureAge.Days -le 2) {
                        $systemSecurity.CategoryScore += 10
                        $systemSecurity.Checks += [PSCustomObject]@{
                            Check = 'Antivirus Signatures'
                            Status = 'Pass'
                            Score = 10
                            Details = "Updated $($signatureAge.Days) days ago"
                        }
                    } else {
                        $systemSecurity.Checks += [PSCustomObject]@{
                            Check = 'Antivirus Signatures'
                            Status = 'Fail'
                            Score = 0
                            Details = "Outdated ($($signatureAge.Days) days old)"
                        }
                        $assessment.Findings += [PSCustomObject]@{
                            Severity = 'High'
                            Category = 'System Security'
                            Finding = 'Antivirus signatures are outdated'
                            Impact = 'Cannot detect latest threats'
                            Recommendation = 'Update Windows Defender definitions'
                        }
                    }
                } else {
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Antivirus Signatures'
                        Status = 'Unknown'
                        Score = 0
                        Details = 'Signature update time not available'
                    }
                }
            }
            
            # Firewall (cmdlet absent on hosts without the NetSecurity module - guard the lookup)
            $firewallProfiles = @()
            $firewallQuerySucceeded = $false
            $firewallQueryError = $null
            if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                try {
                    $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
                    $firewallQuerySucceeded = $true
                } catch {
                    $firewallQueryError = ($_.Exception.Message -split "\r?\n")[0]
                }
            } else {
                $firewallQueryError = 'Get-NetFirewallProfile cmdlet not available'
            }
            $enabledProfiles = @($firewallProfiles | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Enabled'] -and $_.Enabled -eq $true }).Count
            if (-not $firewallQuerySucceeded) {
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Firewall'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $firewallQueryError"
                }
            } elseif ($enabledProfiles -eq 3) {
                $systemSecurity.CategoryScore += 20
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Firewall'
                    Status = 'Pass'
                    Score = 20
                    Details = 'All profiles enabled'
                }
            } else {
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Firewall'
                    Status = 'Fail'
                    Score = 0
                    Details = "Only $enabledProfiles profiles enabled"
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'System Security'
                    Finding = "Only $enabledProfiles firewall profiles are enabled"
                    Impact = 'Network-based attacks may succeed'
                    Recommendation = 'Enable all firewall profiles'
                }
            }
            
            # UAC
            $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $uacProps = Get-ItemProperty -Path $uacKey -ErrorAction SilentlyContinue
            $uacEnabled = if ($null -ne $uacProps -and $uacProps.PSObject.Properties['EnableLUA']) { $uacProps.EnableLUA } else { $null }
            if ($uacEnabled -eq 1) {
                $systemSecurity.CategoryScore += 15
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'User Account Control (UAC)'
                    Status = 'Pass'
                    Score = 15
                    Details = 'Enabled'
                }
            } else {
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'User Account Control (UAC)'
                    Status = 'Fail'
                    Score = 0
                    Details = 'Disabled'
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'System Security'
                    Finding = 'User Account Control is disabled'
                    Impact = 'Malware can gain elevated privileges easily'
                    Recommendation = 'Enable UAC'
                }
            }
            
            # BitLocker (module absent on hosts without the BitLocker feature - guard the lookup)
            $bitlocker = $null
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            }
            if ($bitlocker -and $bitlocker.ProtectionStatus -eq 'On') {
                $systemSecurity.CategoryScore += 15
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'BitLocker Encryption'
                    Status = 'Pass'
                    Score = 15
                    Details = 'System drive encrypted'
                }
            } else {
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'BitLocker Encryption'
                    Status = 'Fail'
                    Score = 0
                    Details = 'System drive not encrypted'
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Data Protection'
                    Finding = 'System drive is not encrypted'
                    Impact = 'Data vulnerable if device is lost or stolen'
                    Recommendation = 'Enable BitLocker encryption'
                }
            }
            
            # Secure Boot
            try {
                $secureBoot = Confirm-SecureBootUEFI
                if ($secureBoot) {
                    $systemSecurity.CategoryScore += 10
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Secure Boot'
                        Status = 'Pass'
                        Score = 10
                        Details = 'Enabled'
                    }
                } else {
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Secure Boot'
                        Status = 'Fail'
                        Score = 0
                        Details = 'Disabled'
                    }
                }
            } catch {
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'Secure Boot'
                    Status = 'Unknown'
                    Score = 0
                    Details = 'Cannot determine status'
                }
            }
            
            # Windows Updates
            try {
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates.Count
                
                if ($pendingUpdates -eq 0) {
                    $systemSecurity.CategoryScore += 10
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Windows Updates'
                        Status = 'Pass'
                        Score = 10
                        Details = 'No pending updates'
                    }
                } else {
                    $systemSecurity.Checks += [PSCustomObject]@{
                        Check = 'Windows Updates'
                        Status = 'Fail'
                        Score = 0
                        Details = "$pendingUpdates pending updates"
                    }
                    $assessment.Findings += [PSCustomObject]@{
                        Severity = 'Medium'
                        Category = 'System Security'
                        Finding = "$pendingUpdates Windows updates pending"
                        Impact = 'Known vulnerabilities not patched'
                        Recommendation = 'Install pending Windows updates'
                    }
                }
            } catch {
                $systemSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Updates'
                    Status = 'Unknown'
                    Score = 0
                    Details = 'Cannot check update status'
                }
            }
            
            $assessment.Categories.SystemSecurity = $systemSecurity
            
            # Category 2: Network Security
            Write-Host "[2/5] Assessing Network Security..." -ForegroundColor Cyan
            
            $networkSecurity = [PSCustomObject]@{
                CategoryScore = 0
                MaxScore = 100
                Checks = @()
            }
            
            # Check for dangerous open ports
            $dangerousPorts = @(23, 135, 139, 445, 1433, 3389, 5985, 5986)
            $listeningPorts = @()
            $portQuerySucceeded = $false
            $portQueryError = $null
            try {
                $listeningPorts = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
                $portQuerySucceeded = $true
            } catch {
                $portQueryError = ($_.Exception.Message -split "\r?\n")[0]
            }
            $exposedPorts = @($listeningPorts | Where-Object { $null -ne $_ -and $_.PSObject.Properties['LocalPort'] -and $dangerousPorts -contains $_.LocalPort })
            
            if (-not $portQuerySucceeded) {
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'Dangerous Ports'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $portQueryError"
                }
            } elseif ($exposedPorts.Count -eq 0) {
                $networkSecurity.CategoryScore += 30
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'Dangerous Ports'
                    Status = 'Pass'
                    Score = 30
                    Details = 'No commonly exploited ports exposed'
                }
            } else {
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'Dangerous Ports'
                    Status = 'Fail'
                    Score = 0
                    Details = "$($exposedPorts.Count) dangerous ports listening"
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'Network Security'
                    Finding = "Dangerous ports exposed: $(($exposedPorts.LocalPort | Select-Object -Unique) -join ', ')"
                    Impact = 'Network attack surface increased'
                    Recommendation = 'Close unnecessary ports or restrict access'
                }
            }
            
            # Network shares
            $shares = @()
            $shareQuerySucceeded = $false
            $shareQueryError = $null
            if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
                try {
                    $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Name'] -and $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$)$' })
                    $shareQuerySucceeded = $true
                } catch {
                    $shareQueryError = ($_.Exception.Message -split "\r?\n")[0]
                }
            } else {
                $shareQueryError = 'Get-SmbShare cmdlet not available'
            }
            if (-not $shareQuerySucceeded) {
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'Network Shares'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $shareQueryError"
                }
            } elseif ($shares.Count -eq 0) {
                $networkSecurity.CategoryScore += 20
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'Network Shares'
                    Status = 'Pass'
                    Score = 20
                    Details = 'No user shares configured'
                }
            } else {
                $networkSecurity.CategoryScore += 10
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'Network Shares'
                    Status = 'Warning'
                    Score = 10
                    Details = "$($shares.Count) shares configured"
                }
            }
            
            # SMB version (cmdlet absent without the SmbShare module - guard the lookup)
            $smbConfig = $null
            if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
                $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            }
            if ($null -ne $smbConfig -and $smbConfig.EnableSMB1Protocol -eq $false) {
                $networkSecurity.CategoryScore += 25
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'SMBv1 Protocol'
                    Status = 'Pass'
                    Score = 25
                    Details = 'Disabled (secure)'
                }
            } else {
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'SMBv1 Protocol'
                    Status = 'Fail'
                    Score = 0
                    Details = 'Enabled (insecure)'
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'Network Security'
                    Finding = 'SMBv1 protocol is enabled'
                    Impact = 'Vulnerable to WannaCry-style attacks'
                    Recommendation = 'Disable SMBv1 protocol'
                }
            }
            
            # WiFi security (if applicable)
            $wifiProfiles = @(Get-WlanProfileList)
            if ($wifiProfiles.Count -gt 0) {
                $networkSecurity.CategoryScore += 10
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'WiFi Profiles'
                    Status = 'Info'
                    Score = 10
                    Details = "$($wifiProfiles.Count) WiFi profiles configured"
                }
            }
            
            # Network Level Authentication for RDP
            $rdpNLAProps = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
            $rdpNLA = if ($null -ne $rdpNLAProps -and $rdpNLAProps.PSObject.Properties['UserAuthentication']) { $rdpNLAProps.UserAuthentication } else { $null }
            if ($rdpNLA -eq 1) {
                $networkSecurity.CategoryScore += 15
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'RDP Network Level Authentication'
                    Status = 'Pass'
                    Score = 15
                    Details = 'Enabled'
                }
            } else {
                $networkSecurity.Checks += [PSCustomObject]@{
                    Check = 'RDP Network Level Authentication'
                    Status = 'Fail'
                    Score = 0
                    Details = 'Disabled'
                }
            }
            
            $assessment.Categories.NetworkSecurity = $networkSecurity
            
            # Category 3: Account Security
            Write-Host "[3/5] Assessing Account Security..." -ForegroundColor Cyan
            
            $accountSecurity = [PSCustomObject]@{
                CategoryScore = 0
                MaxScore = 100
                Checks = @()
            }
            
            # Local accounts
            $localUsers = @()
            $localUserQuerySucceeded = $false
            $localUserQueryError = $null
            try {
                $localUsers = @(Get-LocalUser -ErrorAction Stop | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Enabled'] -and $_.Enabled -eq $true })
                $localUserQuerySucceeded = $true
            } catch {
                $localUserQueryError = ($_.Exception.Message -split "\r?\n")[0]
            }
            if ($localUserQuerySucceeded) {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Local User Accounts'
                    Status = 'Info'
                    Score = 0
                    Details = "$($localUsers.Count) enabled accounts"
                }
            } else {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Local User Accounts'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $localUserQueryError"
                }
            }
            
            # Administrator account status (well-known SID RID 500 - culture-invariant)
            $adminAccount = $null
            $adminQuerySucceeded = $false
            $adminQueryError = $null
            try {
                $adminAccount = @(Get-LocalUser -ErrorAction Stop | Where-Object { $null -ne $_ -and $_.PSObject.Properties['SID'] -and $null -ne $_.SID -and $_.SID.Value -match '-500$' }) | Select-Object -First 1
                $adminQuerySucceeded = $true
            } catch {
                $adminQueryError = ($_.Exception.Message -split "\r?\n")[0]
            }
            if (-not $adminQuerySucceeded) {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Built-in Administrator Account'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $adminQueryError"
                }
            } elseif ($adminAccount -and $adminAccount.Enabled -eq $false) {
                $accountSecurity.CategoryScore += 20
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Built-in Administrator Account'
                    Status = 'Pass'
                    Score = 20
                    Details = 'Disabled'
                }
            } else {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Built-in Administrator Account'
                    Status = 'Fail'
                    Score = 0
                    Details = 'Enabled'
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Account Security'
                    Finding = 'Built-in Administrator account is enabled'
                    Impact = 'Well-known account is attack target'
                    Recommendation = 'Disable built-in Administrator account'
                }
            }
            
            # Guest account (well-known SID RID 501 - culture-invariant)
            $guestAccount = $null
            $guestQuerySucceeded = $false
            $guestQueryError = $null
            try {
                $guestAccount = @(Get-LocalUser -ErrorAction Stop | Where-Object { $null -ne $_ -and $_.PSObject.Properties['SID'] -and $null -ne $_.SID -and $_.SID.Value -match '-501$' }) | Select-Object -First 1
                $guestQuerySucceeded = $true
            } catch {
                $guestQueryError = ($_.Exception.Message -split "\r?\n")[0]
            }
            if (-not $guestQuerySucceeded) {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Guest Account'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $guestQueryError"
                }
            } elseif ($guestAccount -and $guestAccount.Enabled -eq $false) {
                $accountSecurity.CategoryScore += 15
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Guest Account'
                    Status = 'Pass'
                    Score = 15
                    Details = 'Disabled'
                }
            } else {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Guest Account'
                    Status = 'Fail'
                    Score = 0
                    Details = 'Enabled'
                }
            }
            
            # Password policy
            $passwordPolicy = Get-LocalPasswordPolicy
            if ($null -ne $passwordPolicy -and $passwordPolicy.Source -ne 'Unavailable') {
                $minLengthText = if ($null -eq $passwordPolicy.MinPasswordLength) { 'unknown' } else { "$($passwordPolicy.MinPasswordLength)" }
                $maxAgeText = if ($null -eq $passwordPolicy.MaxPasswordAgeDays) { 'unknown' } elseif ($passwordPolicy.MaxPasswordAgeDays -lt 0) { 'never' } else { "$($passwordPolicy.MaxPasswordAgeDays) days" }
                $accountSecurity.CategoryScore += 20
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Password Policy'
                    Status = 'Info'
                    Score = 20
                    Details = "Min length: $minLengthText, Max age: $maxAgeText"
                }
            } else {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Password Policy'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Unable to determine password policy'
                }
            }
            
            # Accounts without passwords
            $noPasswordAccounts = @($localUsers | Where-Object { $_.PasswordRequired -eq $false })
            if (-not $localUserQuerySucceeded) {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Password Required'
                    Status = 'Warning'
                    Score = 0
                    Details = "Unable to evaluate - $localUserQueryError"
                }
            } elseif ($noPasswordAccounts.Count -eq 0) {
                $accountSecurity.CategoryScore += 25
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Password Required'
                    Status = 'Pass'
                    Score = 25
                    Details = 'All accounts require passwords'
                }
            } else {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Password Required'
                    Status = 'Fail'
                    Score = 0
                    Details = "$($noPasswordAccounts.Count) accounts without passwords"
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Category = 'Account Security'
                    Finding = "$($noPasswordAccounts.Count) accounts do not require passwords"
                    Impact = 'Unauthorized access possible'
                    Recommendation = 'Require passwords for all accounts'
                }
            }
            
            # Administrator group members
            $admins = @(Get-AdminGroupMembers)
            if ($script:AdminGroupLookupSucceeded -ne $true) {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Administrator Group Size'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Unable to enumerate administrators'
                }
            } elseif ($admins.Count -le 2) {
                $accountSecurity.CategoryScore += 20
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Administrator Group Size'
                    Status = 'Pass'
                    Score = 20
                    Details = "$($admins.Count) members (appropriate)"
                }
            } else {
                $accountSecurity.Checks += [PSCustomObject]@{
                    Check = 'Administrator Group Size'
                    Status = 'Warning'
                    Score = 10
                    Details = "$($admins.Count) members (excessive)"
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Account Security'
                    Finding = "$($admins.Count) users in Administrators group"
                    Impact = 'Excessive privileged access'
                    Recommendation = 'Limit administrator access to necessary personnel'
                }
            }
            
            $assessment.Categories.AccountSecurity = $accountSecurity
            
            # Category 4: Application Security
            Write-Host "[4/5] Assessing Application Security..." -ForegroundColor Cyan
            
            $applicationSecurity = [PSCustomObject]@{
                CategoryScore = 0
                MaxScore = 100
                Checks = @()
            }
            
            # PowerShell execution policy
            $executionPolicy = Get-ExecutionPolicy -Scope LocalMachine
            if ($executionPolicy -in @('AllSigned', 'RemoteSigned', 'Restricted')) {
                $applicationSecurity.CategoryScore += 25
                $applicationSecurity.Checks += [PSCustomObject]@{
                    Check = 'PowerShell Execution Policy'
                    Status = 'Pass'
                    Score = 25
                    Details = $executionPolicy
                }
            } else {
                $applicationSecurity.Checks += [PSCustomObject]@{
                    Check = 'PowerShell Execution Policy'
                    Status = 'Fail'
                    Score = 0
                    Details = "$executionPolicy (insecure)"
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Application Security'
                    Finding = "PowerShell execution policy is $executionPolicy"
                    Impact = 'Malicious scripts can execute without restriction'
                    Recommendation = 'Set execution policy to RemoteSigned or AllSigned'
                }
            }
            
            # PowerShell logging
          # PowerShell logging
$psLogging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if ($psLogging -and $psLogging.EnableScriptBlockLogging -eq 1) {
    $applicationSecurity.CategoryScore += 20
    $applicationSecurity.Checks += [PSCustomObject]@{
        Check = 'PowerShell Script Block Logging'
        Status = 'Pass'
        Score = 20
        Details = 'Enabled'
    }
} else {
    $applicationSecurity.Checks += [PSCustomObject]@{
        Check = 'PowerShell Script Block Logging'
        Status = 'Fail'
        Score = 0
        Details = 'Disabled'
    }
}
            
            # AppLocker
          # AppLocker
try {
    $appLockerPolicies = Get-AppLockerPolicy -Effective -ErrorAction Stop
    if ($appLockerPolicies) {
        $applicationSecurity.CategoryScore += 25
        $applicationSecurity.Checks += [PSCustomObject]@{
            Check = 'AppLocker'
            Status = 'Pass'
            Score = 25
            Details = 'Configured'
        }
    } else {
        $applicationSecurity.Checks += [PSCustomObject]@{
            Check = 'AppLocker'
            Status = 'Fail'
            Score = 0
            Details = 'Not configured'
        }
    }
} catch {
    $applicationSecurity.Checks += [PSCustomObject]@{
        Check = 'AppLocker'
        Status = 'N/A'
        Score = 0
        Details = 'Not available (Windows Pro/Enterprise feature)'
    }
}
            
            # Windows Defender Application Control
            # Win32_DeviceGuard.CodeIntegrityPolicyEnforcementStatus: 1 = Audit mode, 2 = Enforced
            $wdacStatus = $null
            if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                $wdacStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
            }
            $wdacEnforcement = if ($null -ne $wdacStatus -and $wdacStatus.PSObject.Properties['CodeIntegrityPolicyEnforcementStatus']) { $wdacStatus.CodeIntegrityPolicyEnforcementStatus } else { $null }
            if ($null -eq $wdacEnforcement) {
                $applicationSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Defender Application Control'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Unable to determine'
                }
            } elseif ($wdacEnforcement -eq 2) {
                $applicationSecurity.CategoryScore += 30
                $applicationSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Defender Application Control'
                    Status = 'Pass'
                    Score = 30
                    Details = 'Enforced'
                }
            } elseif ($wdacEnforcement -eq 1) {
                $applicationSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Defender Application Control'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Audit mode only (not enforcing)'
                }
            } else {
                $applicationSecurity.Checks += [PSCustomObject]@{
                    Check = 'Windows Defender Application Control'
                    Status = 'Info'
                    Score = 0
                    Details = 'Not enforced'
                }
            }
            
            $assessment.Categories.ApplicationSecurity = $applicationSecurity
            
            # Category 5: Data Protection
            Write-Host "[5/5] Assessing Data Protection..." -ForegroundColor Cyan
            
            $dataProtection = [PSCustomObject]@{
                CategoryScore = 0
                MaxScore = 100
                Checks = @()
            }
            
            # BitLocker (already checked, summarize)
            if ($bitlocker -and $bitlocker.ProtectionStatus -eq 'On') {
                $dataProtection.CategoryScore += 40
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'System Drive Encryption'
                    Status = 'Pass'
                    Score = 40
                    Details = 'BitLocker enabled'
                }
            } else {
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'System Drive Encryption'
                    Status = 'Fail'
                    Score = 0
                    Details = 'Not encrypted'
                }
            }
            
            # Backup status (Get-WmiObject exists only in Windows PowerShell 5.1 - guard the lookup)
            $backupStatus = $null
            if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
                $backupStatus = Get-WmiObject -Namespace root\Microsoft\Windows\Backup -Class MSFT_WBBackupSet -ErrorAction SilentlyContinue
            }
            if ($backupStatus) {
                $dataProtection.CategoryScore += 30
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'Windows Backup'
                    Status = 'Pass'
                    Score = 30
                    Details = 'Configured'
                }
            } else {
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'Windows Backup'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Not configured'
                }
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Category = 'Data Protection'
                    Finding = 'Windows Backup is not configured'
                    Impact = 'Data loss risk in case of failure'
                    Recommendation = 'Configure regular backups'
                }
            }
            
            # System Restore (cmdlet absent on Server Core / non-Windows - guard the lookup)
            $systemRestore = $null
            if (Get-Command Get-ComputerRestorePoint -ErrorAction SilentlyContinue) {
                $systemRestore = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
            }
            if ($systemRestore) {
                $dataProtection.CategoryScore += 15
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'System Restore Points'
                    Status = 'Pass'
                    Score = 15
                    Details = "$($systemRestore.Count) restore points available"
                }
            } else {
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'System Restore Points'
                    Status = 'Warning'
                    Score = 0
                    Details = 'No restore points'
                }
            }
            
            # Audit logging
            $auditTable = Get-AuditPolicyTable
            $auditEntries = if ($null -ne $auditTable) { @($auditTable.Values) } else { @() }
            $auditedCount = @($auditEntries | Where-Object { $_.Success -or $_.Failure }).Count
            $knownCount = @($auditEntries | Where-Object { $null -ne $_.Value }).Count
            if ($auditedCount -gt 0) {
                $dataProtection.CategoryScore += 15
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'Audit Logging'
                    Status = 'Pass'
                    Score = 15
                    Details = 'Configured'
                }
            } elseif ($knownCount -eq 0) {
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'Audit Logging'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Unable to determine'
                }
            } else {
                $dataProtection.Checks += [PSCustomObject]@{
                    Check = 'Audit Logging'
                    Status = 'Warning'
                    Score = 0
                    Details = 'Limited auditing'
                }
            }
            
            $assessment.Categories.DataProtection = $dataProtection
            
            # Compliance checks (optional)
            if ($IncludeCompliance) {
                Write-Host "`n[Compliance] Running Compliance Checks..." -ForegroundColor Cyan
                
                # CIS Benchmark (Level 1)
                try {
                    Write-Host "  Running CIS Benchmark (Level 1)..." -ForegroundColor Yellow
                    $cisResult = Test-CISBenchmark -Level 1
                    if ($null -ne $cisResult) {
                        $cisPercentage = $null
                        if ($cisResult.PSObject.Properties['Summary'] -and $null -ne $cisResult.Summary) {
                            if ($cisResult.Summary -is [hashtable] -and $cisResult.Summary.ContainsKey('CompliancePercentage')) {
                                $cisPercentage = $cisResult.Summary['CompliancePercentage']
                            }
                        }
                        $assessment.ComplianceChecks += [PSCustomObject]@{
                            Framework = 'CIS Benchmark'
                            Version = 'Level 1'
                            Status = 'Completed'
                            CompliancePercentage = $cisPercentage
                            Result = $cisResult
                        }
                    } else {
                        Write-Warning "CIS Benchmark check returned no results"
                        $assessment.ComplianceChecks += [PSCustomObject]@{
                            Framework = 'CIS Benchmark'
                            Version = 'Level 1'
                            Status = 'NoResults'
                            CompliancePercentage = $null
                            Result = $null
                        }
                    }
                } catch {
                    Write-Warning "CIS Benchmark compliance check failed: $_"
                    $assessment.ComplianceChecks += [PSCustomObject]@{
                        Framework = 'CIS Benchmark'
                        Version = 'Level 1'
                        Status = 'Error'
                        CompliancePercentage = $null
                        Result = $null
                    }
                }
                
                # NIST 800-53 Compliance
                try {
                    Write-Host "  Running NIST 800-53 Compliance..." -ForegroundColor Yellow
                    $nistResult = Test-NISTCompliance
                    if ($null -ne $nistResult) {
                        $nistPercentage = $null
                        if ($nistResult.PSObject.Properties['Summary'] -and $null -ne $nistResult.Summary) {
                            if ($nistResult.Summary -is [hashtable] -and $nistResult.Summary.ContainsKey('CompliancePercentage')) {
                                $nistPercentage = $nistResult.Summary['CompliancePercentage']
                            }
                        }
                        $assessment.ComplianceChecks += [PSCustomObject]@{
                            Framework = 'NIST 800-53'
                            Version = 'Rev 5'
                            Status = 'Completed'
                            CompliancePercentage = $nistPercentage
                            Result = $nistResult
                        }
                    } else {
                        Write-Warning "NIST 800-53 check returned no results"
                        $assessment.ComplianceChecks += [PSCustomObject]@{
                            Framework = 'NIST 800-53'
                            Version = 'Rev 5'
                            Status = 'NoResults'
                            CompliancePercentage = $null
                            Result = $null
                        }
                    }
                } catch {
                    Write-Warning "NIST 800-53 compliance check failed: $_"
                    $assessment.ComplianceChecks += [PSCustomObject]@{
                        Framework = 'NIST 800-53'
                        Version = 'Rev 5'
                        Status = 'Error'
                        CompliancePercentage = $null
                        Result = $null
                    }
                }
                
                # PCI-DSS Compliance (v4.0)
                try {
                    Write-Host "  Running PCI-DSS Compliance (v4.0)..." -ForegroundColor Yellow
                    $pciResult = Test-PCI-DSS -Version '4.0'
                    if ($null -ne $pciResult) {
                        $pciPercentage = $null
                        if ($pciResult.PSObject.Properties['Summary'] -and $null -ne $pciResult.Summary) {
                            if ($pciResult.Summary -is [hashtable] -and $pciResult.Summary.ContainsKey('CompliancePercentage')) {
                                $pciPercentage = $pciResult.Summary['CompliancePercentage']
                            }
                        }
                        $assessment.ComplianceChecks += [PSCustomObject]@{
                            Framework = 'PCI-DSS'
                            Version = '4.0'
                            Status = 'Completed'
                            CompliancePercentage = $pciPercentage
                            Result = $pciResult
                        }
                    } else {
                        Write-Warning "PCI-DSS check returned no results"
                        $assessment.ComplianceChecks += [PSCustomObject]@{
                            Framework = 'PCI-DSS'
                            Version = '4.0'
                            Status = 'NoResults'
                            CompliancePercentage = $null
                            Result = $null
                        }
                    }
                } catch {
                    Write-Warning "PCI-DSS compliance check failed: $_"
                    $assessment.ComplianceChecks += [PSCustomObject]@{
                        Framework = 'PCI-DSS'
                        Version = '4.0'
                        Status = 'Error'
                        CompliancePercentage = $null
                        Result = $null
                    }
                }
            }
            
            # Calculate overall score
           # Calculate overall score
$totalScore = 0
$maxScore = 0
try {
    foreach ($categoryName in $assessment.Categories.Keys) {
        $category = $assessment.Categories[$categoryName]
        if ($category) {
            try {
                if ($category.PSObject.Properties.Name -contains 'CategoryScore') {
                    $totalScore += [int]$category.CategoryScore
                    $maxScore += [int]$category.MaxScore
                }
            } catch {
                Write-Verbose "Could not calculate score for category: $categoryName"
            }
        }
    }
    
    # Prevent division by zero
    if ($maxScore -gt 0) {
        $assessment.OverallScore = [math]::Round(($totalScore / $maxScore) * 100, 2)
    } else {
        $assessment.OverallScore = 0
    }
} catch {
    Write-Warning "Could not calculate overall score: $_"
    $assessment.OverallScore = 0
}

# Determine risk level
if ($assessment.OverallScore -ge 80) {
    $assessment.RiskLevel = 'Low'
} elseif ($assessment.OverallScore -ge 60) {
    $assessment.RiskLevel = 'Medium'
} elseif ($assessment.OverallScore -ge 40) {
    $assessment.RiskLevel = 'High'
} else {
    $assessment.RiskLevel = 'Critical'
}
            
            # Generate recommendations
            $assessment.Recommendations = @(
                "Overall Security Score: $($assessment.OverallScore)/100 - Risk Level: $($assessment.RiskLevel)",
                "Address all Critical severity findings immediately",
                "Implement a regular patch management schedule",
                "Enable all recommended security features",
                "Conduct security assessments quarterly",
                "Review and update security policies regularly"
            )
            
        }
        catch {
            Write-Error "Error during security assessment: $_"
            throw
        }
    }
    
    end {
        # Display summary
        Write-Host "`n=== ASSESSMENT COMPLETE ===" -ForegroundColor Green
        Write-Host "Overall Security Score: $($assessment.OverallScore)/100" -ForegroundColor $(
            if ($assessment.OverallScore -ge 80) { 'Green' }
            elseif ($assessment.OverallScore -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        Write-Host "Risk Level: $($assessment.RiskLevel)" -ForegroundColor $(
            switch ($assessment.RiskLevel) {
                'Low' { 'Green' }
                'Medium' { 'Yellow' }
                'High' { 'Red' }
                'Critical' { 'Red' }
            }
        )
        
     Write-Host "`nCategory Scores:" -ForegroundColor Cyan
foreach ($categoryName in $assessment.Categories.Keys) {
    $category = $assessment.Categories[$categoryName]
    if ($category -and $category -is [PSCustomObject]) {
        try {
            if ($category.PSObject.Properties.Name -contains 'CategoryScore' -and 
                $category.PSObject.Properties.Name -contains 'MaxScore') {
                $catScore = [int]$category.CategoryScore
                $catMax = [int]$category.MaxScore
                if ($catMax -gt 0) {
                    $percentage = [math]::Round(($catScore / $catMax) * 100, 0)
                    Write-Host "  $($categoryName): $percentage%" -ForegroundColor White
                }
            }
        } catch {
            Write-Verbose "Could not display score for: $categoryName"
        }
    }
}
        
        Write-Host "`nFindings: $($assessment.Findings.Count)" -ForegroundColor Cyan
        $criticalCount = @($assessment.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highCount = @($assessment.Findings | Where-Object { $_.Severity -eq 'High' }).Count
        $mediumCount = @($assessment.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        
        Write-Host "  Critical: $criticalCount" -ForegroundColor Red
        Write-Host "  High: $highCount" -ForegroundColor Yellow
        Write-Host "  Medium: $mediumCount" -ForegroundColor Yellow
        
        # Compliance summary (when -IncludeCompliance was used)
        if (@($assessment.ComplianceChecks).Count -gt 0) {
            Write-Host "`nCompliance Summary:" -ForegroundColor Cyan
            foreach ($complianceCheck in $assessment.ComplianceChecks) {
                if ($null -ne $complianceCheck -and $complianceCheck.PSObject.Properties['Status']) {
                    $frameworkName = ''
                    if ($complianceCheck.PSObject.Properties['Framework']) {
                        $frameworkName = $complianceCheck.Framework
                    }
                    $frameworkVersion = ''
                    if ($complianceCheck.PSObject.Properties['Version']) {
                        $frameworkVersion = $complianceCheck.Version
                    }
                    if ($complianceCheck.Status -eq 'Completed') {
                        $percentageText = 'N/A'
                        if ($complianceCheck.PSObject.Properties['CompliancePercentage'] -and $null -ne $complianceCheck.CompliancePercentage) {
                            $percentageText = "$($complianceCheck.CompliancePercentage)%"
                        }
                        Write-Host "  $frameworkName ($frameworkVersion): $percentageText compliant" -ForegroundColor White
                    } else {
                        Write-Host "  $frameworkName ($frameworkVersion): $($complianceCheck.Status)" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Save results
        $assessment | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputPath "SecurityAssessment.json") -Encoding UTF8
        
        # Export findings
        if ($assessment.Findings.Count -gt 0) {
            $assessment.Findings | Export-Csv (Join-Path $OutputPath "SecurityFindings.csv") -NoTypeInformation
        }
        
        # Export recommendations
        $assessment.Recommendations | Out-File (Join-Path $OutputPath "Recommendations.txt")
        
        Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
        
        return $assessment
    }
}