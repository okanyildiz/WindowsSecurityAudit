function Test-PCI-DSS {
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
        Test-PCI-DSS
        Test-PCI-DSS -Version 4.0 -RequirementFilter Network
    .OUTPUTS
        PSCustomObject with PCI-DSS compliance results
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
                    $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                    $allFirewallsEnabled = @($firewallProfiles | Where-Object { -not $_.Enabled }).Count -eq 0
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '1.2.1'
                        RequirementName = 'Firewall Configuration'
                        Category = 'Network'
                        Description = 'Firewalls must be enabled and properly configured'
                        Expected = 'All firewall profiles enabled'
                        Actual = if ($allFirewallsEnabled) { "All enabled" } else { "Some disabled" }
                        Status = if ($allFirewallsEnabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Enable all Windows Firewall profiles (Domain, Private, Public)'
                    }
                    $results.Requirements += $req
                    
                    # Req 1.3: Inbound traffic restrictions
                    $defaultInboundBlock = @($firewallProfiles | Where-Object { $_.DefaultInboundAction -ne 'Block' })
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '1.3.1'
                        RequirementName = 'Inbound Traffic Restriction'
                        Category = 'Network'
                        Description = 'Inbound traffic should be denied by default'
                        Expected = 'Default action: Block'
                        Actual = if ($defaultInboundBlock.Count -eq 0) { "All blocked" } else { "$($defaultInboundBlock.Count) profiles allow" }
                        Status = if ($defaultInboundBlock.Count -eq 0) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Set default inbound action to Block for all profiles'
                    }
                    $results.Requirements += $req
                    
                    # Req 1.4: Restrict connections between untrusted networks
                    $publicProfile = $firewallProfiles | Where-Object { $_.Name -eq 'Public' }
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '1.4.1'
                        RequirementName = 'Public Network Protection'
                        Category = 'Network'
                        Description = 'Public network profile must be restrictive'
                        Expected = 'Public profile enabled and blocking inbound'
                        Actual = "Enabled: $($publicProfile.Enabled), Inbound: $($publicProfile.DefaultInboundAction)"
                        Status = if ($publicProfile.Enabled -and $publicProfile.DefaultInboundAction -eq 'Block') { 'InPlace' } else { 'NotInPlace' }
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
                    $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                    $bitlockerEnabled = $bitlockerStatus.ProtectionStatus -eq 'On'
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '3.5.1'
                        RequirementName = 'Data at Rest Encryption'
                        Category = 'Data'
                        Description = 'PAN must be rendered unreadable (encryption)'
                        Expected = 'Disk encryption enabled (BitLocker)'
                        Actual = if ($bitlockerEnabled) { "Enabled" } else { "Disabled" }
                        Status = if ($bitlockerEnabled) { 'InPlace' } else { 'NotInPlace' }
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
                    $guestDisabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled -eq $false
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '7.1.1'
                        RequirementName = 'Access Limitations'
                        Category = 'AccessControl'
                        Description = 'Unnecessary accounts must be disabled'
                        Expected = 'Guest account disabled'
                        Actual = if ($guestDisabled) { "Disabled" } else { "Enabled" }
                        Status = if ($guestDisabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Disable Guest and other unnecessary accounts'
                    }
                    $results.Requirements += $req
                    
                    # Req 8.2: User identification and authentication
                    $passwordPolicy = net accounts 2>$null
                    $minPasswordLength = ($passwordPolicy | Select-String "Minimum password length").ToString().Split(':')[1].Trim()
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '8.2.3'
                        RequirementName = 'Password Complexity'
                        Category = 'AccessControl'
                        Description = 'Passwords must meet minimum complexity'
                        Expected = 'Minimum 12 characters (or 8 if MFA)'
                        Actual = "$minPasswordLength characters"
                        Status = if ([int]$minPasswordLength -ge 12) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Set minimum password length to 12 characters'
                    }
                    $results.Requirements += $req
                    
                    # Req 8.2.4: Change passwords every 90 days
                    $maxPasswordAge = ($passwordPolicy | Select-String "Maximum password age").ToString().Split(':')[1].Trim().Split(' ')[0]
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '8.2.4'
                        RequirementName = 'Password Change Frequency'
                        Category = 'AccessControl'
                        Description = 'Passwords must be changed periodically'
                        Expected = '90 days or less'
                        Actual = "$maxPasswordAge days"
                        Status = if ([int]$maxPasswordAge -le 90 -and [int]$maxPasswordAge -gt 0) { 'InPlace' } else { 'NotInPlace' }
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
                    $auditLogons = auditpol /get /subcategory:"Logon" 2>$null
                    $logonAuditEnabled = $auditLogons -match "Success and Failure"
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '10.2.1'
                        RequirementName = 'User Access Logging'
                        Category = 'Monitoring'
                        Description = 'All access to system components must be logged'
                        Expected = 'Logon auditing: Success and Failure'
                        Actual = if ($logonAuditEnabled) { "Enabled" } else { "Not configured" }
                        Status = if ($logonAuditEnabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'Critical'
                        Remediation = 'Enable audit policy for Logon events'
                    }
                    $results.Requirements += $req
                    
                    # Req 10.3: Audit trail content
                    $auditObjectAccess = auditpol /get /subcategory:"File System" 2>$null
                    $objectAuditEnabled = $auditObjectAccess -match "Success|Failure"
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '10.3.1'
                        RequirementName = 'Audit Trail Details'
                        Category = 'Monitoring'
                        Description = 'Logs must contain sufficient detail'
                        Expected = 'File system auditing enabled'
                        Actual = if ($objectAuditEnabled) { "Enabled" } else { "Not configured" }
                        Status = if ($objectAuditEnabled) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Enable file system object access auditing'
                    }
                    $results.Requirements += $req
                    
                    # Req 10.5: Protect audit trails
                    $eventLogSize = (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '10.5.1'
                        RequirementName = 'Audit Trail Protection'
                        Category = 'Monitoring'
                        Description = 'Audit trails must be secured and retained'
                        Expected = 'Security log >= 100MB'
                        Actual = "$([math]::Round($eventLogSize/1MB)) MB"
                        Status = if ($eventLogSize -ge 100MB) { 'InPlace' } else { 'NotInPlace' }
                        Priority = 'High'
                        Remediation = 'Increase Security log size to at least 100MB'
                    }
                    $results.Requirements += $req
                    
                    # Req 10.7: Time synchronization
                    $w32timeService = Get-Service -Name W32Time -ErrorAction SilentlyContinue
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '10.7.1'
                        RequirementName = 'Time Synchronization'
                        Category = 'Monitoring'
                        Description = 'System clocks must be synchronized'
                        Expected = 'Windows Time service running'
                        Actual = if ($w32timeService) { $w32timeService.Status } else { "Not found" }
                        Status = if ($w32timeService.Status -eq 'Running') { 'InPlace' } else { 'NotInPlace' }
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
                    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    $defenderEnabled = $defenderStatus.AntivirusEnabled
                    
                    $req = [PSCustomObject]@{
                        RequirementID = '11.3.1'
                        RequirementName = 'Vulnerability Management'
                        Category = 'Testing'
                        Description = 'Vulnerability scans must be performed'
                        Expected = 'Antivirus enabled'
                        Actual = if ($defenderEnabled) { "Windows Defender enabled" } else { "Disabled" }
                        Status = if ($defenderEnabled) { 'InPlace' } else { 'NotInPlace' }
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