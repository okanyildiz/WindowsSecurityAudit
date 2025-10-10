function Test-NISTCompliance {
    <#
    .SYNOPSIS
        Tests system compliance against NIST 800-53 security controls
    .DESCRIPTION
        Evaluates Windows system against NIST (National Institute of Standards and Technology)
        SP 800-53 security and privacy controls for federal information systems
    .PARAMETER ControlFamily
        Specific control family to test: All, AccessControl, AuditAccountability, 
        IdentificationAuthentication, SystemProtection, ConfigurationManagement
    .PARAMETER Revision
        NIST 800-53 revision: 4 or 5 (default: 5)
    .EXAMPLE
        Test-NISTCompliance
        Test-NISTCompliance -ControlFamily AccessControl -Revision 5
    .OUTPUTS
        PSCustomObject with NIST compliance results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('All', 'AccessControl', 'AuditAccountability', 'IdentificationAuthentication', 
                     'SystemProtection', 'ConfigurationManagement')]
        [string]$ControlFamily = 'All',
        
        [Parameter()]
        [ValidateSet(4, 5)]
        [int]$Revision = 5
    )
    
    begin {
        Write-Host "=== NIST 800-53 COMPLIANCE TEST ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Revision: NIST 800-53 Rev $Revision" -ForegroundColor Yellow
        Write-Host "Control Family: $ControlFamily" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            NISTRevision = $Revision
            ControlFamily = $ControlFamily
            Controls = @()
            Summary = @{
                TotalControls = 0
                Compliant = 0
                NonCompliant = 0
                PartiallyCompliant = 0
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
            # 1. ACCESS CONTROL (AC) FAMILY
            if ($ControlFamily -in @('All', 'AccessControl')) {
                Write-Host "`n[1/5] Testing Access Control (AC) Controls..." -ForegroundColor Cyan
                
                try {
                    # AC-2: Account Management
                    $guestDisabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled -eq $false
                    $adminDisabled = (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled -eq $false
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AC-2'
                        ControlName = 'Account Management'
                        ControlFamily = 'AccessControl'
                        Description = 'Guest and default Administrator accounts should be disabled'
                        Expected = 'Guest and Administrator accounts disabled'
                        Actual = "Guest: $(if($guestDisabled){'Disabled'}else{'Enabled'}), Admin: $(if($adminDisabled){'Disabled'}else{'Enabled'})"
                        Status = if ($guestDisabled -and $adminDisabled) { 'Compliant' } 
                                 elseif ($guestDisabled -or $adminDisabled) { 'PartiallyCompliant' }
                                 else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Disable built-in Guest and Administrator accounts'
                    }
                    $results.Controls += $control
                    
                    # AC-7: Unsuccessful Logon Attempts
                    $regTest = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                        -Name 'MaxDevicePasswordFailedAttempts' -ExpectedValue 5
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AC-7'
                        ControlName = 'Unsuccessful Logon Attempts'
                        ControlFamily = 'AccessControl'
                        Description = 'System should lock after failed login attempts'
                        Expected = '5 or fewer attempts'
                        Actual = if ($regTest.ActualValue) { "$($regTest.ActualValue) attempts" } else { "Not configured" }
                        Status = if ($regTest.Compliant) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Configure account lockout after 5 failed attempts'
                    }
                    $results.Controls += $control
                    
                    # AC-11: Session Lock
                    $regTest = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                        -Name 'InactivityTimeoutSecs' -ExpectedValue 900
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AC-11'
                        ControlName = 'Session Lock'
                        ControlFamily = 'AccessControl'
                        Description = 'Automatic screen lock after inactivity'
                        Expected = '15 minutes (900 seconds) or less'
                        Actual = if ($regTest.ActualValue) { "$([math]::Round($regTest.ActualValue/60)) minutes" } else { "Not configured" }
                        Status = if ($regTest.Compliant -or $regTest.ActualValue -le 900) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Medium'
                        Remediation = 'Configure screen lock timeout to 15 minutes or less'
                    }
                    $results.Controls += $control
                    
                    # AC-17: Remote Access
                    $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AC-17'
                        ControlName = 'Remote Access'
                        ControlFamily = 'AccessControl'
                        Description = 'Remote access should be controlled and monitored'
                        Expected = 'RDP disabled or properly secured'
                        Actual = if ($rdpEnabled -eq 1) { "Disabled" } else { "Enabled" }
                        Status = if ($rdpEnabled -eq 1) { 'Compliant' } else { 'PartiallyCompliant' }
                        Impact = 'High'
                        Remediation = 'Disable RDP if not needed, or ensure NLA and firewall rules'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing Access Control: $_"
                }
            }
            
            # 2. AUDIT AND ACCOUNTABILITY (AU) FAMILY
            if ($ControlFamily -in @('All', 'AuditAccountability')) {
                Write-Host "`n[2/5] Testing Audit and Accountability (AU) Controls..." -ForegroundColor Cyan
                
                try {
                    # AU-2: Audit Events
                    $auditLogons = auditpol /get /subcategory:"Logon" 2>$null
                    $auditConfigured = $auditLogons -match "Success and Failure|Success|Failure"
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AU-2'
                        ControlName = 'Audit Events'
                        ControlFamily = 'AuditAccountability'
                        Description = 'System must audit significant security events'
                        Expected = 'Audit policies configured'
                        Actual = if ($auditConfigured) { "Configured" } else { "Not configured" }
                        Status = if ($auditConfigured) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Enable audit policies for security events'
                    }
                    $results.Controls += $control
                    
                    # AU-3: Content of Audit Records
                    $eventLogSize = (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AU-3'
                        ControlName = 'Content of Audit Records'
                        ControlFamily = 'AuditAccountability'
                        Description = 'Audit records must contain sufficient detail'
                        Expected = 'Security log size >= 100MB'
                        Actual = "$([math]::Round($eventLogSize/1MB)) MB"
                        Status = if ($eventLogSize -ge 100MB) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Medium'
                        Remediation = 'Increase Security event log size to at least 100MB'
                    }
                    $results.Controls += $control
                    
                    # AU-9: Protection of Audit Information
                    $logPath = "C:\Windows\System32\winevt\Logs\Security.evtx"
                    if (Test-Path $logPath) {
                        $acl = Get-Acl $logPath -ErrorAction SilentlyContinue
                        $protected = @($acl.Access | Where-Object { $_.IdentityReference -match "Users" -and $_.FileSystemRights -match "FullControl|Modify|Write" })
                        
                        $control = [PSCustomObject]@{
                            ControlID = 'AU-9'
                            ControlName = 'Protection of Audit Information'
                            ControlFamily = 'AuditAccountability'
                            Description = 'Audit logs must be protected from unauthorized access'
                            Expected = 'Security log protected from normal users'
                            Actual = if ($protected.Count -gt 0) { "Weak permissions detected" } else { "Properly protected" }
                            Status = if ($protected.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }
                            Impact = 'High'
                            Remediation = 'Restrict Security event log access to administrators only'
                        }
                        $results.Controls += $control
                    }
                    
                    # AU-12: Audit Generation
                    $auditProcessCreation = auditpol /get /subcategory:"Process Creation" 2>$null
                    $processAuditConfigured = $auditProcessCreation -match "Success"
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'AU-12'
                        ControlName = 'Audit Generation'
                        ControlFamily = 'AuditAccountability'
                        Description = 'System must generate audit records for defined events'
                        Expected = 'Process creation auditing enabled'
                        Actual = if ($processAuditConfigured) { "Enabled" } else { "Disabled" }
                        Status = if ($processAuditConfigured) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Medium'
                        Remediation = 'Enable process creation auditing'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing Audit and Accountability: $_"
                }
            }
            
            # 3. IDENTIFICATION AND AUTHENTICATION (IA) FAMILY
            if ($ControlFamily -in @('All', 'IdentificationAuthentication')) {
                Write-Host "`n[3/5] Testing Identification and Authentication (IA) Controls..." -ForegroundColor Cyan
                
                try {
                    # IA-2: Identification and Authentication
                    $passwordPolicy = net accounts 2>$null
                    $minPasswordLength = ($passwordPolicy | Select-String "Minimum password length").ToString().Split(':')[1].Trim()
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'IA-2'
                        ControlName = 'Identification and Authentication'
                        ControlFamily = 'IdentificationAuthentication'
                        Description = 'System must uniquely identify and authenticate users'
                        Expected = 'Minimum password length >= 14 characters'
                        Actual = "$minPasswordLength characters"
                        Status = if ([int]$minPasswordLength -ge 14) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Set minimum password length to 14 characters'
                    }
                    $results.Controls += $control
                    
                    # IA-5: Authenticator Management
                    $maxPasswordAge = ($passwordPolicy | Select-String "Maximum password age").ToString().Split(':')[1].Trim().Split(' ')[0]
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'IA-5'
                        ControlName = 'Authenticator Management'
                        ControlFamily = 'IdentificationAuthentication'
                        Description = 'Authenticators must be managed securely'
                        Expected = 'Maximum password age <= 60 days'
                        Actual = "$maxPasswordAge days"
                        Status = if ([int]$maxPasswordAge -le 60 -and [int]$maxPasswordAge -gt 0) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Set maximum password age to 60 days or less'
                    }
                    $results.Controls += $control
                    
                    # IA-8: Identification and Authentication (Non-Organizational Users)
                    $regTest = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                        -Name 'LimitBlankPasswordUse' -ExpectedValue 1
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'IA-8'
                        ControlName = 'Non-Organizational User Authentication'
                        ControlFamily = 'IdentificationAuthentication'
                        Description = 'Blank passwords should not be allowed'
                        Expected = 'Blank passwords disabled'
                        Actual = if ($regTest.Compliant) { "Disabled" } else { "Allowed" }
                        Status = if ($regTest.Compliant) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Critical'
                        Remediation = 'Disable blank password usage'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing Identification and Authentication: $_"
                }
            }
            
            # 4. SYSTEM AND COMMUNICATIONS PROTECTION (SC) FAMILY
            if ($ControlFamily -in @('All', 'SystemProtection')) {
                Write-Host "`n[4/5] Testing System and Communications Protection (SC) Controls..." -ForegroundColor Cyan
                
                try {
                    # SC-7: Boundary Protection - FIX: Wrap in @()
                    $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                    $disabledFirewalls = @($firewallProfiles | Where-Object { -not $_.Enabled })
                    $allFirewallsEnabled = $disabledFirewalls.Count -eq 0
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'SC-7'
                        ControlName = 'Boundary Protection'
                        ControlFamily = 'SystemProtection'
                        Description = 'Firewall must protect system boundaries'
                        Expected = 'All firewall profiles enabled'
                        Actual = if ($allFirewallsEnabled) { "All enabled" } else { "Some disabled" }
                        Status = if ($allFirewallsEnabled) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Critical'
                        Remediation = 'Enable Windows Firewall for all profiles'
                    }
                    $results.Controls += $control
                    
                    # SC-8: Transmission Confidentiality and Integrity
                    $regTest = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                        -Name 'NoLMHash' -ExpectedValue 1
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'SC-8'
                        ControlName = 'Transmission Confidentiality'
                        ControlFamily = 'SystemProtection'
                        Description = 'Weak LAN Manager hashes should not be stored'
                        Expected = 'LM hash storage disabled'
                        Actual = if ($regTest.Compliant) { "Disabled" } else { "Enabled" }
                        Status = if ($regTest.Compliant) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Disable LAN Manager hash storage'
                    }
                    $results.Controls += $control
                    
                    # SC-28: Protection of Information at Rest
                    $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                    $bitlockerEnabled = $bitlockerStatus.ProtectionStatus -eq 'On'
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'SC-28'
                        ControlName = 'Protection of Information at Rest'
                        ControlFamily = 'SystemProtection'
                        Description = 'Data at rest should be encrypted'
                        Expected = 'BitLocker enabled'
                        Actual = if ($bitlockerEnabled) { "Enabled" } else { "Disabled" }
                        Status = if ($bitlockerEnabled) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'High'
                        Remediation = 'Enable BitLocker encryption'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing System Protection: $_"
                }
            }
            
            # 5. CONFIGURATION MANAGEMENT (CM) FAMILY
            if ($ControlFamily -in @('All', 'ConfigurationManagement')) {
                Write-Host "`n[5/5] Testing Configuration Management (CM) Controls..." -ForegroundColor Cyan
                
                try {
                    # CM-6: Configuration Settings
                    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    $defenderEnabled = $defenderStatus.AntivirusEnabled
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'CM-6'
                        ControlName = 'Configuration Settings'
                        ControlFamily = 'ConfigurationManagement'
                        Description = 'Security configuration settings must be established'
                        Expected = 'Windows Defender enabled'
                        Actual = if ($defenderEnabled) { "Enabled" } else { "Disabled" }
                        Status = if ($defenderEnabled) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Critical'
                        Remediation = 'Enable Windows Defender antivirus'
                    }
                    $results.Controls += $control
                    
                    # CM-7: Least Functionality - FIX: Wrap in @()
                    $allServices = Get-Service -ErrorAction SilentlyContinue
                    $unnecessaryServices = @($allServices | Where-Object { 
                        $_.Name -in @('TlntSvr', 'SNMP', 'SSDPSRV') -and $_.Status -eq 'Running'
                    })
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'CM-7'
                        ControlName = 'Least Functionality'
                        ControlFamily = 'ConfigurationManagement'
                        Description = 'Unnecessary services should be disabled'
                        Expected = 'No unnecessary services running'
                        Actual = if ($unnecessaryServices.Count -eq 0) { "Clean" } else { "$($unnecessaryServices.Count) unnecessary services" }
                        Status = if ($unnecessaryServices.Count -eq 0) { 'Compliant' } else { 'NonCompliant' }
                        Impact = 'Medium'
                        Remediation = 'Disable unnecessary services (Telnet, SNMP, SSDP)'
                    }
                    $results.Controls += $control
                    
                    # CM-8: Information System Component Inventory
                    $control = [PSCustomObject]@{
                        ControlID = 'CM-8'
                        ControlName = 'System Component Inventory'
                        ControlFamily = 'ConfigurationManagement'
                        Description = 'Maintain accurate inventory of system components'
                        Expected = 'Inventory maintained'
                        Actual = 'Manual verification required'
                        Status = 'NotApplicable'
                        Impact = 'Low'
                        Remediation = 'Implement automated inventory management'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing Configuration Management: $_"
                }
            }
            
            # Calculate summary - FIX: All wrapped in @()
            $results.Summary.TotalControls = $results.Controls.Count
            $results.Summary.Compliant = @($results.Controls | Where-Object { $_.Status -eq 'Compliant' }).Count
            $results.Summary.NonCompliant = @($results.Controls | Where-Object { $_.Status -eq 'NonCompliant' }).Count
            $results.Summary.PartiallyCompliant = @($results.Controls | Where-Object { $_.Status -eq 'PartiallyCompliant' }).Count
            $results.Summary.NotApplicable = @($results.Controls | Where-Object { $_.Status -eq 'NotApplicable' }).Count
            
            $testableControls = $results.Summary.TotalControls - $results.Summary.NotApplicable
            if ($testableControls -gt 0) {
                $compliantCount = $results.Summary.Compliant + ($results.Summary.PartiallyCompliant * 0.5)
                $results.Summary.CompliancePercentage = [math]::Round(($compliantCount / $testableControls) * 100, 2)
            }
            
            # Generate recommendations - FIX: All wrapped in @()
            $criticalFailed = @($results.Controls | Where-Object { $_.Status -eq 'NonCompliant' -and $_.Impact -eq 'Critical' })
            $highFailed = @($results.Controls | Where-Object { $_.Status -eq 'NonCompliant' -and $_.Impact -eq 'High' })
            
            if ($criticalFailed.Count -gt 0) {
                $results.Recommendations += "CRITICAL: $($criticalFailed.Count) critical control(s) non-compliant"
                $results.Recommendations += "Address critical controls immediately"
            }
            
            if ($highFailed.Count -gt 0) {
                $results.Recommendations += "HIGH: $($highFailed.Count) high-impact control(s) non-compliant"
            }
            
            if ($results.Summary.CompliancePercentage -lt 80) {
                $results.Recommendations += "Compliance below 80% - implement remediation plan"
            }
            
            $results.Recommendations += "Review all non-compliant controls"
            $results.Recommendations += "Document compensating controls where applicable"
            
        }
        catch {
            Write-Error "Error during NIST compliance testing: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== COMPLIANCE TEST COMPLETE ===" -ForegroundColor $(
            if ($results.Summary.CompliancePercentage -ge 80) { 'Green' }
            elseif ($results.Summary.CompliancePercentage -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        
        Write-Host "`nCompliance Summary:" -ForegroundColor Cyan
        Write-Host "  Total Controls Tested: $($results.Summary.TotalControls)" -ForegroundColor White
        Write-Host "  Compliant: $($results.Summary.Compliant)" -ForegroundColor Green
        Write-Host "  Non-Compliant: $($results.Summary.NonCompliant)" -ForegroundColor Red
        Write-Host "  Partially Compliant: $($results.Summary.PartiallyCompliant)" -ForegroundColor Yellow
        Write-Host "  Not Applicable: $($results.Summary.NotApplicable)" -ForegroundColor Gray
        Write-Host "  Compliance: $($results.Summary.CompliancePercentage)%" -ForegroundColor $(
            if ($results.Summary.CompliancePercentage -ge 80) { 'Green' }
            elseif ($results.Summary.CompliancePercentage -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        
        if ($results.Controls.Count -gt 0) {
            $nonCompliant = @($results.Controls | Where-Object { $_.Status -eq 'NonCompliant' })
            if ($nonCompliant.Count -gt 0) {
                Write-Host "`nNon-Compliant Controls by Impact:" -ForegroundColor Cyan
                $failedByImpact = $nonCompliant | Group-Object Impact
                foreach ($group in $failedByImpact | Sort-Object Name) {
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
        
        Write-Host "`nNIST SP 800-53: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" -ForegroundColor Gray
        
        return $results
    }
}