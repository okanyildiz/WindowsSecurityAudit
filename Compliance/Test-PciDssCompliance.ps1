function Test-PciDssCompliance {
    <#
    .SYNOPSIS
        Tests system compliance against PCI-DSS requirements
    .DESCRIPTION
        Evaluates Windows system against Payment Card Industry Data Security Standard (PCI-DSS)
        requirements for systems that store, process, or transmit cardholder data
    .PARAMETER Version
        PCI-DSS version: 3.2.1 or 4.0 (default: 4.0)
    .PARAMETER RequirementFilter
        Specific requirement to test: All, Network, Data, AccessControl, Monitoring, Testing
    .EXAMPLE
        Test-PciDssCompliance
        Test-PciDssCompliance -Version '4.0' -RequirementFilter Network
    .OUTPUTS
        PSCustomObject with PCI-DSS compliance results
    .NOTES
        Test-PCI-DSS is kept as a backward-compatible alias.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('3.2.1', '4.0')]
        [string]$Version = '4.0',
        
        [Parameter()]
        [ValidateSet('All', 'Network', 'Data', 'AccessControl', 'Monitoring', 'Testing')]
        [string]$RequirementFilter = 'All'
    )
    
    begin {
        if ($Version -ne '4.0') {
            Write-Warning "Version $Version requested; only 4.0 checks are currently implemented"
            $Version = '4.0'
        }
        Write-Host "=== PCI-DSS COMPLIANCE TEST ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "PCI-DSS Version: $Version" -ForegroundColor Yellow
        Write-Host "Requirement: $RequirementFilter" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            PCIDSSVersion = $Version
            RequirementFilter = $RequirementFilter
            Requirements = @()
            Summary = @{
                TotalRequirements = 0
                InPlace = 0
                NotInPlace = 0
                NotApplicable = 0
                CompliancePercentage = 0
            }
            Recommendations = @()
        }
        
        # Helper function to test registry value
        function Test-RegistryValue {
            param(
                [string]$Path,
                [string]$Name,
                [object]$ExpectedValue
            )
            
            try {
                if (Test-Path $Path) {
                    $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | 
                             Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
                    
                    return @{
                        Compliant = ($value -eq $ExpectedValue)
                        ActualValue = $value
                        ExpectedValue = $ExpectedValue
                    }
                }
                return @{
                    Compliant = $false
                    ActualValue = "Path not found"
                    ExpectedValue = $ExpectedValue
                }
            }
            catch {
                return @{
                    Compliant = $false
                    ActualValue = "Error"
                    ExpectedValue = $ExpectedValue
                }
            }
        }
    }
    
    process {
        try {
            # 1. REQUIREMENT 1: Install and maintain network security controls
            if ($RequirementFilter -in @('All', 'Network')) {
                Write-Host "`n[1/6] Testing Requirement 1: Network Security Controls..." -ForegroundColor Cyan
                
                try {
                    # Req 1.2: Network security controls (firewalls)
                    # Gate on Get-Command: CommandNotFoundException ignores
                    # -ErrorAction SilentlyContinue and would drop all network
                    # requirements via the catch block below.
                    $firewallCmdletAvailable = $null -ne (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)
                    $firewallProfiles = $null
                    if ($firewallCmdletAvailable) {
                        try { $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop } catch { $firewallProfiles = $null }
                    }
                    $allFirewallsEnabled = ($null -ne $firewallProfiles) -and (@($firewallProfiles | Where-Object { $null -ne $_ -and -not $_.Enabled }).Count -eq 0)
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '1.2.1'
                        RequirementName = 'Firewall Configuration'
                        Category = 'Network'
                        Description = 'Firewalls must be enabled and properly configured'
                        Expected = 'All firewall profiles enabled'
                        Actual = if (-not $firewallCmdletAvailable) { 'Unable to evaluate — Get-NetFirewallProfile unavailable' }
                                 elseif ($null -eq $firewallProfiles) { "Unable to retrieve firewall profiles" }
                                 elseif ($allFirewallsEnabled) { "All enabled" } else { "Some disabled" }
                        Status = if (-not $firewallCmdletAvailable) { 'NotApplicable' }
                                 elseif ($allFirewallsEnabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Enable all Windows Firewall profiles (Domain, Private, Public)'
                    }
                    $results.Requirements += $req
                    
                    # Req 1.3: Inbound traffic restrictions
                    $defaultInboundBlock = @($firewallProfiles | Where-Object { $null -ne $_ -and $_.DefaultInboundAction -ne 'Block' })
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '1.3.1'
                        RequirementName = 'Inbound Traffic Restriction'
                        Category = 'Network'
                        Description = 'Inbound traffic should be denied by default'
                        Expected = 'Default action: Block'
                        Actual = if (-not $firewallCmdletAvailable) { 'Unable to evaluate — Get-NetFirewallProfile unavailable' }
                                 elseif ($null -eq $firewallProfiles) { "Unable to retrieve firewall profiles" }
                                 elseif ($defaultInboundBlock.Count -eq 0) { "All blocked" } else { "$($defaultInboundBlock.Count) profiles allow" }
                        Status = if (-not $firewallCmdletAvailable) { 'NotApplicable' }
                                 elseif (($null -ne $firewallProfiles) -and $defaultInboundBlock.Count -eq 0) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Set default inbound action to Block for all profiles'
                    }
                    $results.Requirements += $req
                    
                    # Req 1.4: Restrict connections between untrusted networks
                    $publicProfile = $firewallProfiles | Where-Object { $null -ne $_ -and $_.Name -eq 'Public' }
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '1.4.1'
                        RequirementName = 'Public Network Protection'
                        Category = 'Network'
                        Description = 'Public network profile must be restrictive'
                        Expected = 'Public profile enabled and blocking inbound'
                        Actual = if (-not $firewallCmdletAvailable) { 'Unable to evaluate — Get-NetFirewallProfile unavailable' }
                                 elseif ($publicProfile) { "Enabled: $($publicProfile.Enabled), Inbound: $($publicProfile.DefaultInboundAction)" } else { "Public profile not found" }
                        Status = if (-not $firewallCmdletAvailable) { 'NotApplicable' }
                                 elseif ($publicProfile -and $publicProfile.Enabled -and $publicProfile.DefaultInboundAction -eq 'Block') { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Enable Public profile with default inbound block'
                    }
                    $results.Requirements += $req
                }
                catch {
                    Write-Warning "Error testing Network requirements: $_"
                }
            }
            
            # 2. REQUIREMENT 3: Protect stored account data
            if ($RequirementFilter -in @('All', 'Data')) {
                Write-Host "`n[2/6] Testing Requirement 3: Protect Stored Data..." -ForegroundColor Cyan
                
                try {
                    # Req 3.3: Sensitive authentication data not retained
                    $req = [PSCustomObject]@{
                        RequirementID = '3.3.1'
                        RequirementName = 'Sensitive Data Retention'
                        Category = 'Data'
                        Description = 'Sensitive authentication data must not be stored'
                        Expected = 'No card data stored (manual verification)'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Priority = 'Critical'
                        Remediation = 'Ensure no full track data, CVV2, or PIN blocks are stored'
                    }
                    $results.Requirements += $req
                    
                    # Req 3.5: Primary account number (PAN) protection
                    # Gate on Get-Command: CommandNotFoundException ignores
                    # -ErrorAction SilentlyContinue and would drop this requirement.
                    $bitlockerAvailable = $null -ne (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
                    $bitlockerStatus = $null
                    if ($bitlockerAvailable) {
                        try { $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop } catch { $bitlockerStatus = $null }
                    }
                    $bitlockerEnabled = ($null -ne $bitlockerStatus) -and ($bitlockerStatus.ProtectionStatus -eq 'On')
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '3.5.1'
                        RequirementName = 'Data at Rest Encryption'
                        Category = 'Data'
                        Description = 'PAN must be rendered unreadable (encryption)'
                        Expected = 'Disk encryption enabled (BitLocker)'
                        Actual = if (-not $bitlockerAvailable) { 'Unable to evaluate — Get-BitLockerVolume unavailable' }
                                 elseif ($bitlockerEnabled) { "Enabled" } else { "Disabled" }
                        Status = if (-not $bitlockerAvailable) { 'NotApplicable' }
                                 elseif ($bitlockerEnabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Enable BitLocker or third-party disk encryption'
                    }
                    $results.Requirements += $req
                    
                    # Req 3.6: Cryptographic key management
                    $req = [PSCustomObject]@{
                        RequirementID = '3.6.1'
                        RequirementName = 'Key Management'
                        Category = 'Data'
                        Description = 'Cryptographic keys must be managed securely'
                        Expected = 'Key management procedures documented'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Priority = 'High'
                        Remediation = 'Document and implement key management procedures'
                    }
                    $results.Requirements += $req
                }
                catch {
                    Write-Warning "Error testing Data Protection requirements: $_"
                }
            }
            
            # 3. REQUIREMENT 7 & 8: Access Control
            if ($RequirementFilter -in @('All', 'AccessControl')) {
                Write-Host "`n[3/6] Testing Requirements 7 & 8: Access Control..." -ForegroundColor Cyan
                
                try {
                    # Req 7.1: Limit access to system components
                    $guestUser = Get-LocalUserByRid -Rid 501 -ErrorAction SilentlyContinue
                    $guestKnown = ($null -ne $guestUser) -and ($null -ne $guestUser.Enabled)
                    $guestDisabled = $guestKnown -and ($guestUser.Enabled -eq $false)

                    $req = [PSCustomObject]@{
                        RequirementID = '7.1.1'
                        RequirementName = 'Access Limitations'
                        Category = 'AccessControl'
                        Description = 'Unnecessary accounts must be disabled'
                        Expected = 'Guest account disabled'
                        Actual = if (-not $guestKnown) { 'Unable to determine (insufficient privileges or unsupported platform)' }
                                 elseif ($guestDisabled) { "Disabled" } else { "Enabled" }
                        Status = if (-not $guestKnown) { 'NotApplicable' }
                                 elseif ($guestDisabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Disable Guest and other unnecessary accounts'
                    }
                    $results.Requirements += $req
                    
                    # Req 8.2: User identification and authentication
                    $passwordPolicy = Get-LocalPasswordPolicy
                    $minPasswordLength = $passwordPolicy.MinPasswordLength

                    $req = [PSCustomObject]@{
                        RequirementID = '8.2.3'
                        RequirementName = 'Password Complexity'
                        Category = 'AccessControl'
                        Description = 'Passwords must meet minimum complexity'
                        Expected = 'Minimum 12 characters (or 8 if MFA)'
                        Actual = if ($null -eq $minPasswordLength) { 'Unable to determine (insufficient privileges or unsupported platform)' }
                                 else { "$minPasswordLength characters" }
                        Status = if ($null -eq $minPasswordLength) { 'NotApplicable' }
                                 elseif ($minPasswordLength -ge 12) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Set minimum password length to 12 characters'
                    }
                    $results.Requirements += $req

                    # Req 8.2.4: Change passwords every 90 days
                    $maxAgeDays = $passwordPolicy.MaxPasswordAgeDays

                    $req = [PSCustomObject]@{
                        RequirementID = '8.2.4'
                        RequirementName = 'Password Change Frequency'
                        Category = 'AccessControl'
                        Description = 'Passwords must be changed periodically'
                        Expected = '90 days or less'
                        Actual = if ($null -eq $maxAgeDays) { 'Unable to determine (insufficient privileges or unsupported platform)' }
                                 elseif ($maxAgeDays -eq -1) { 'Never expires' } else { "$maxAgeDays days" }
                        Status = if ($null -eq $maxAgeDays) { 'NotApplicable' }
                                 elseif ($maxAgeDays -gt 0 -and $maxAgeDays -le 90) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Set maximum password age to 90 days'
                    }
                    $results.Requirements += $req
                    
                    # Req 8.3: Multi-factor authentication
                    $req = [PSCustomObject]@{
                        RequirementID = '8.3.1'
                        RequirementName = 'Multi-Factor Authentication'
                        Category = 'AccessControl'
                        Description = 'MFA required for all access to CDE'
                        Expected = 'MFA enabled for administrators'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Priority = 'Critical'
                        Remediation = 'Implement MFA (Windows Hello, Smart Card, or third-party)'
                    }
                    $results.Requirements += $req
                }
                catch {
                    Write-Warning "Error testing Access Control requirements: $_"
                }
            }
            
            # 4. REQUIREMENT 10: Log and monitor all access
            if ($RequirementFilter -in @('All', 'Monitoring')) {
                Write-Host "`n[4/6] Testing Requirement 10: Logging and Monitoring..." -ForegroundColor Cyan
                
                try {
                    # Req 10.2: Audit logs for all users
                    $logonGuid = Get-AuditSubcategoryGuid -Name 'Logon'
                    $logonAuditValue = $null
                    if ($null -ne $logonGuid) {
                        $logonTable = Get-AuditPolicyTable -Subcategory 'Logon'
                        $logonKey = ($logonGuid -replace '[{}]', '').ToLowerInvariant()
                        if ($logonTable.ContainsKey($logonKey)) { $logonAuditValue = $logonTable[$logonKey].Value }
                    }

                    $req = [PSCustomObject]@{
                        RequirementID = '10.2.1'
                        RequirementName = 'User Access Logging'
                        Category = 'Monitoring'
                        Description = 'All access to system components must be logged'
                        Expected = 'Logon auditing: Success and Failure'
                        Actual = if ($null -eq $logonAuditValue) { 'Unable to determine (insufficient privileges or unsupported platform)' }
                                 elseif ($logonAuditValue -eq 3) { "Enabled" } else { "Not configured" }
                        Status = if ($null -eq $logonAuditValue) { 'NotApplicable' }
                                 elseif ($logonAuditValue -eq 3) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Enable audit policy for Logon events'
                    }
                    $results.Requirements += $req

                    # Req 10.3: Audit trail content
                    $fileSystemGuid = Get-AuditSubcategoryGuid -Name 'File System'
                    $objectAuditValue = $null
                    if ($null -ne $fileSystemGuid) {
                        $fileSystemTable = Get-AuditPolicyTable -Subcategory 'File System'
                        $fileSystemKey = ($fileSystemGuid -replace '[{}]', '').ToLowerInvariant()
                        if ($fileSystemTable.ContainsKey($fileSystemKey)) { $objectAuditValue = $fileSystemTable[$fileSystemKey].Value }
                    }

                    $req = [PSCustomObject]@{
                        RequirementID = '10.3.1'
                        RequirementName = 'Audit Trail Details'
                        Category = 'Monitoring'
                        Description = 'Logs must contain sufficient detail'
                        Expected = 'File system auditing enabled'
                        Actual = if ($null -eq $objectAuditValue) { 'Unable to determine (insufficient privileges or unsupported platform)' }
                                 elseif ($objectAuditValue -ge 1 -and $objectAuditValue -le 3) { "Enabled" } else { "Not configured" }
                        Status = if ($null -eq $objectAuditValue) { 'NotApplicable' }
                                 elseif ($objectAuditValue -ge 1 -and $objectAuditValue -le 3) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Enable file system object access auditing'
                    }
                    $results.Requirements += $req
                    
                    # Req 10.5: Protect audit trails
                    $winEventAvailable = $null -ne (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)
                    $securityLog = $null
                    if ($winEventAvailable) {
                        try { $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop } catch { $securityLog = $null }
                    }
                    $eventLogSize = if ($securityLog) { $securityLog.MaximumSizeInBytes } else { 0 }
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '10.5.1'
                        RequirementName = 'Audit Trail Protection'
                        Category = 'Monitoring'
                        Description = 'Audit trails must be secured and retained'
                        Expected = 'Security log >= 100MB'
                        Actual = if (-not $winEventAvailable) { 'Unable to evaluate — Get-WinEvent unavailable' }
                                 else { "$([math]::Round($eventLogSize/1MB)) MB" }
                        Status = if (-not $winEventAvailable) { 'NotApplicable' }
                                 elseif ($eventLogSize -ge 100MB) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Increase Security log size to at least 100MB'
                    }
                    $results.Requirements += $req
                    
                    # Req 10.7: Time synchronization
                    # Get-Service is Windows/Linux-only; gate on Get-Command so a
                    # missing cmdlet cannot drop this requirement via the catch below.
                    $serviceCmdletAvailable = $null -ne (Get-Command Get-Service -ErrorAction SilentlyContinue)
                    $w32timeService = $null
                    if ($serviceCmdletAvailable) {
                        try { $w32timeService = Get-Service -Name W32Time -ErrorAction Stop } catch { $w32timeService = $null }
                    }
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '10.7.1'
                        RequirementName = 'Time Synchronization'
                        Category = 'Monitoring'
                        Description = 'System clocks must be synchronized'
                        Expected = 'Windows Time service running'
                        Actual = if (-not $serviceCmdletAvailable) { 'Unable to evaluate — Get-Service unavailable' }
                                 elseif ($w32timeService) { $w32timeService.Status } else { "Not found" }
                        Status = if (-not $serviceCmdletAvailable) { 'NotApplicable' }
                                 elseif ($w32timeService -and $w32timeService.Status -eq 'Running') { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Medium'
                        Remediation = 'Ensure Windows Time service is running and configured'
                    }
                    $results.Requirements += $req
                }
                catch {
                    Write-Warning "Error testing Monitoring requirements: $_"
                }
            }
            
            # 5. REQUIREMENT 11: Test security systems regularly
            if ($RequirementFilter -in @('All', 'Testing')) {
                Write-Host "`n[5/6] Testing Requirement 11: Security Testing..." -ForegroundColor Cyan
                
                try {
                    # Req 11.3: Vulnerability scanning
                    # Gate on Get-Command: CommandNotFoundException ignores
                    # -ErrorAction SilentlyContinue and would drop this requirement.
                    $mpStatusAvailable = $null -ne (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
                    $defenderStatus = $null
                    if ($mpStatusAvailable) {
                        try { $defenderStatus = Get-MpComputerStatus -ErrorAction Stop } catch { $defenderStatus = $null }
                    }
                    $defenderEnabled = ($null -ne $defenderStatus) -and $defenderStatus.AntivirusEnabled
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '11.3.1'
                        RequirementName = 'Vulnerability Management'
                        Category = 'Testing'
                        Description = 'Vulnerability scans must be performed'
                        Expected = 'Antivirus enabled'
                        Actual = if (-not $mpStatusAvailable) { 'Unable to evaluate — Get-MpComputerStatus unavailable' }
                                 elseif ($defenderEnabled) { "Windows Defender enabled" } else { "Disabled" }
                        Status = if (-not $mpStatusAvailable) { 'NotApplicable' }
                                 elseif ($defenderEnabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Enable Windows Defender or approved antivirus'
                    }
                    $results.Requirements += $req
                    
                    # Req 11.5: Change detection
                    $req = [PSCustomObject]@{
                        RequirementID = '11.5.1'
                        RequirementName = 'File Integrity Monitoring'
                        Category = 'Testing'
                        Description = 'Implement file integrity monitoring'
                        Expected = 'FIM solution deployed'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Priority = 'High'
                        Remediation = 'Implement file integrity monitoring (FIM) solution'
                    }
                    $results.Requirements += $req
                }
                catch {
                    Write-Warning "Error testing Security Testing requirements: $_"
                }
            }
            
            # 6. REQUIREMENT 12: Support information security with organizational policies
            if ($RequirementFilter -in @('All')) {
                Write-Host "`n[6/6] Testing Requirement 12: Security Policies..." -ForegroundColor Cyan
                
                try {
                    # Req 12.1: Security policy
                    $req = [PSCustomObject]@{
                        RequirementID = '12.1.1'
                        RequirementName = 'Information Security Policy'
                        Category = 'Policy'
                        Description = 'Establish security policy'
                        Expected = 'Security policy documented and reviewed annually'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Priority = 'High'
                        Remediation = 'Document and maintain information security policy'
                    }
                    $results.Requirements += $req
                    
                    # Req 12.10: Incident response plan
                    $req = [PSCustomObject]@{
                        RequirementID = '12.10.1'
                        RequirementName = 'Incident Response Plan'
                        Category = 'Policy'
                        Description = 'Implement incident response plan'
                        Expected = 'Incident response plan documented and tested'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Priority = 'Critical'
                        Remediation = 'Create and test incident response procedures'
                    }
                    $results.Requirements += $req
                }
                catch {
                    Write-Warning "Error testing Policy requirements: $_"
                }
            }
            
            # Calculate summary
            $results.Summary.TotalRequirements = $results.Requirements.Count
            $results.Summary.InPlace = @($results.Requirements | Where-Object { $_.Status -eq 'InPlace' }).Count
            $results.Summary.NotInPlace = @($results.Requirements | Where-Object { $_.Status -eq 'NotInPlace' }).Count
            $results.Summary.NotApplicable = @($results.Requirements | Where-Object { $_.Status -eq 'NotApplicable' }).Count
            
            $testableRequirements = $results.Summary.TotalRequirements - $results.Summary.NotApplicable
            if ($testableRequirements -gt 0) {
                $results.Summary.CompliancePercentage = [math]::Round(
                    ($results.Summary.InPlace / $testableRequirements) * 100, 2
                )
            }
            
            # Generate recommendations
            $criticalNotInPlace = @($results.Requirements | Where-Object { $_.Status -eq 'NotInPlace' -and $_.Priority -eq 'Critical' })
            $highNotInPlace = @($results.Requirements | Where-Object { $_.Status -eq 'NotInPlace' -and $_.Priority -eq 'High' })
            
            if ($criticalNotInPlace.Count -gt 0) {
                $results.Recommendations += "CRITICAL: $($criticalNotInPlace.Count) critical requirement(s) not in place"
                $results.Recommendations += "Address critical gaps immediately to achieve compliance"
            }
            
            if ($highNotInPlace.Count -gt 0) {
                $results.Recommendations += "HIGH: $($highNotInPlace.Count) high-priority requirement(s) not in place"
            }
            
            if ($results.Summary.CompliancePercentage -lt 100) {
                $results.Recommendations += "Full PCI-DSS compliance requires all requirements to be in place"
            }
            
            $results.Recommendations += "Engage a Qualified Security Assessor (QSA) for formal validation"
            $results.Recommendations += "Review PCI-DSS Self-Assessment Questionnaire (SAQ) for your merchant level"
            
        }
        catch {
            Write-Error "Error during PCI-DSS compliance testing: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== COMPLIANCE TEST COMPLETE ===" -ForegroundColor $(
            if ($results.Summary.CompliancePercentage -eq 100) { 'Green' }
            elseif ($results.Summary.CompliancePercentage -ge 80) { 'Yellow' }
            else { 'Red' }
        )
        
        Write-Host "`nCompliance Summary:" -ForegroundColor Cyan
        Write-Host "  Total Requirements Tested: $($results.Summary.TotalRequirements)" -ForegroundColor White
        Write-Host "  In Place: $($results.Summary.InPlace)" -ForegroundColor Green
        Write-Host "  Not In Place: $($results.Summary.NotInPlace)" -ForegroundColor Red
        Write-Host "  Not Applicable: $($results.Summary.NotApplicable)" -ForegroundColor Gray
        Write-Host "  Compliance: $($results.Summary.CompliancePercentage)%" -ForegroundColor $(
            if ($results.Summary.CompliancePercentage -eq 100) { 'Green' }
            elseif ($results.Summary.CompliancePercentage -ge 80) { 'Yellow' }
            else { 'Red' }
        )
        
        if ($results.Requirements.Count -gt 0) {
            $notInPlace = @($results.Requirements | Where-Object { $_.Status -eq 'NotInPlace' })
            if ($notInPlace.Count -gt 0) {
                Write-Host "`nGaps by Priority:" -ForegroundColor Cyan
                $gapsByPriority = $notInPlace | Group-Object Priority
                foreach ($group in $gapsByPriority | Sort-Object Name) {
                    Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor $(
                        switch ($group.Name) {
                            'Critical' { 'Red' }
                            'High' { 'Red' }
                            'Medium' { 'Yellow' }
                            default { 'White' }
                        }
                    )
                }
            }
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nPCI Security Standards: https://www.pcisecuritystandards.org/" -ForegroundColor Gray
        Write-Host "Note: This is a preliminary assessment. Formal PCI-DSS compliance requires QSA validation." -ForegroundColor Yellow
        
        return $results
    }
}