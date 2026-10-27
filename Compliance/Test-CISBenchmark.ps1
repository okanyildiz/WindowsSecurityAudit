function Test-CISBenchmark {
    <#
    .SYNOPSIS
        Tests system compliance against CIS Benchmark controls
    .DESCRIPTION
        Evaluates Windows system against CIS (Center for Internet Security) Benchmark
        recommendations for security configuration
    .PARAMETER Level
        CIS Benchmark Level: 1 (basic) or 2 (high security)
    .PARAMETER Category
        Specific category to test: All, PasswordPolicy, AuditPolicy, SecurityOptions, WindowsFirewall
    .EXAMPLE
        Test-CISBenchmark -Level 1
        Test-CISBenchmark -Level 2 -Category PasswordPolicy
    .OUTPUTS
        PSCustomObject with CIS compliance results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet(1, 2)]
        [int]$Level = 1,
        
        [Parameter()]
        [ValidateSet('All', 'PasswordPolicy', 'AuditPolicy', 'SecurityOptions', 'WindowsFirewall', 'UserRights')]
        [string]$Category = 'All'
    )
    
    begin {
        if ($Level -ne 1) {
            Write-Warning "Level $Level requested; only Level 1 checks are currently implemented"
            $Level = 1
        }
        Write-Host "=== CIS BENCHMARK COMPLIANCE TEST ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "CIS Level: $Level" -ForegroundColor Yellow
        Write-Host "Category: $Category" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            CISLevel = $Level
            Category = $Category
            Controls = @()
            Summary = @{
                TotalControls = 0
                Passed = 0
                Failed = 0
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
                [object]$ExpectedValue,
                [string]$Comparison = 'Equal'
            )
            
            try {
                if (Test-Path $Path) {
                    $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name
                    
                    $result = switch ($Comparison) {
                        'Equal' { $value -eq $ExpectedValue }
                        'GreaterOrEqual' { $value -ge $ExpectedValue }
                        'LessOrEqual' { $value -le $ExpectedValue }
                        'NotEqual' { $value -ne $ExpectedValue }
                        default { $false }
                    }
                    
                    return @{
                        Compliant = $result
                        ActualValue = $value
                        ExpectedValue = $ExpectedValue
                    }
                }
                else {
                    return @{
                        Compliant = $false
                        ActualValue = "Path not found"
                        ExpectedValue = $ExpectedValue
                    }
                }
            }
            catch {
                return @{
                    Compliant = $false
                    ActualValue = "Error: $_"
                    ExpectedValue = $ExpectedValue
                }
            }
        }
        
        # Helper function to safely parse secedit value
     # Helper function to safely parse secedit value - FIXED
        function Get-SecEditValue {
            param(
                [string]$Content,
                [string]$Setting
            )
            
            try {
                # Split content into lines and search - FIX: regex match on lines
                $lines = $Content -split "`r?`n"
                $matchedLine = $lines | Where-Object { $_ -match "^\s*$Setting\s*=" } | Select-Object -First 1
                
                if ($matchedLine) {
                    # Split on = and take second part, trim whitespace
                    $value = ($matchedLine -split '=', 2)[1].Trim()
                    return $value
                }
                return $null
            }
            catch {
                return $null
            }
        }
    }
    
    process {
        try {
            # 1. PASSWORD POLICY CONTROLS
            if ($Category -in @('All', 'PasswordPolicy')) {
                Write-Host "`n[1/5] Testing Password Policy Controls..." -ForegroundColor Cyan
                
                try {
                    # Export security policy. secedit is Windows-only; when it is
                    # missing or the export fails, emit the controls as Manual instead
                    # of silently dropping them (the per-setting 'if ($value)' guards
                    # below used to skip controls with no warning).
                    $seceditCmd = Get-Command 'secedit.exe' -ErrorAction SilentlyContinue
                    if ($null -eq $seceditCmd) { $seceditCmd = Get-Command 'secedit' -ErrorAction SilentlyContinue }

                    $secpolContent = $null
                    if ($null -ne $seceditCmd) {
                        $tempFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "secpol_$(Get-Random).cfg"
                        try {
                            $null = & $seceditCmd.Source /export /cfg $tempFile /quiet 2>&1
                            Start-Sleep -Milliseconds 500
                            if (Test-Path $tempFile) {
                                $secpolContent = Get-Content $tempFile -Raw
                            }
                        }
                        catch {
                            Write-Warning "Could not export security policy: $_"
                        }
                        finally {
                            if (Test-Path $tempFile -ErrorAction SilentlyContinue) {
                                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }

                    if ($null -eq $secpolContent) {
                        Write-Warning "Could not export security policy; password policy controls require manual review"
                        $manualSpecs = @(
                            @{ ControlID = 'CIS-1.1.1'; ControlName = 'Enforce password history'; Expected = '24 or more passwords'; Severity = 'High'; Remediation = 'Set to 24 or more passwords remembered' }
                            @{ ControlID = 'CIS-1.1.2'; ControlName = 'Maximum password age'; Expected = '365 or fewer days (but not 0)'; Severity = 'High'; Remediation = 'Set to 365 or fewer days' }
                            @{ ControlID = 'CIS-1.1.3'; ControlName = 'Minimum password age'; Expected = '1 or more days'; Severity = 'Medium'; Remediation = 'Set to 1 or more days' }
                            @{ ControlID = 'CIS-1.1.4'; ControlName = 'Minimum password length'; Expected = '14 or more characters'; Severity = 'High'; Remediation = 'Set to 14 or more characters' }
                            @{ ControlID = 'CIS-1.1.5'; ControlName = 'Password must meet complexity requirements'; Expected = 'Enabled'; Severity = 'Critical'; Remediation = 'Enable password complexity requirements' }
                        )
                        foreach ($spec in $manualSpecs) {
                            $control = [PSCustomObject]@{
                                ControlID = $spec.ControlID
                                ControlName = $spec.ControlName
                                Category = 'PasswordPolicy'
                                Expected = $spec.Expected
                                Actual = 'Unable to evaluate — secedit export unavailable'
                                Status = 'Manual'
                                Severity = $spec.Severity
                                Remediation = $spec.Remediation
                            }
                            $results.Controls += $control
                        }
                    }
                    else {
                        # CIS 1.1.1 - Password History
                        $passwordHistory = Get-SecEditValue -Content $secpolContent -Setting "PasswordHistorySize"
                        $control = [PSCustomObject]@{
                            ControlID = 'CIS-1.1.1'
                            ControlName = 'Enforce password history'
                            Category = 'PasswordPolicy'
                            Expected = '24 or more passwords'
                            Actual = if ($null -ne $passwordHistory) { "$passwordHistory passwords" } else { 'Unable to evaluate — setting missing from secedit export' }
                            Status = if ($null -eq $passwordHistory) { 'Manual' } elseif ([int]$passwordHistory -ge 24) { 'Pass' } else { 'Fail' }
                            Severity = 'High'
                            Remediation = 'Set to 24 or more passwords remembered'
                        }
                        $results.Controls += $control

                        # CIS 1.1.2 - Maximum password age
                        $maxPasswordAge = Get-SecEditValue -Content $secpolContent -Setting "MaximumPasswordAge"
                        $control = [PSCustomObject]@{
                            ControlID = 'CIS-1.1.2'
                            ControlName = 'Maximum password age'
                            Category = 'PasswordPolicy'
                            Expected = '365 or fewer days (but not 0)'
                            Actual = if ($null -ne $maxPasswordAge) { "$maxPasswordAge days" } else { 'Unable to evaluate — setting missing from secedit export' }
                            Status = if ($null -eq $maxPasswordAge) { 'Manual' } elseif ([int]$maxPasswordAge -le 365 -and [int]$maxPasswordAge -gt 0) { 'Pass' } else { 'Fail' }
                            Severity = 'High'
                            Remediation = 'Set to 365 or fewer days'
                        }
                        $results.Controls += $control

                        # CIS 1.1.3 - Minimum password age
                        $minPasswordAge = Get-SecEditValue -Content $secpolContent -Setting "MinimumPasswordAge"
                        $control = [PSCustomObject]@{
                            ControlID = 'CIS-1.1.3'
                            ControlName = 'Minimum password age'
                            Category = 'PasswordPolicy'
                            Expected = '1 or more days'
                            Actual = if ($null -ne $minPasswordAge) { "$minPasswordAge days" } else { 'Unable to evaluate — setting missing from secedit export' }
                            Status = if ($null -eq $minPasswordAge) { 'Manual' } elseif ([int]$minPasswordAge -ge 1) { 'Pass' } else { 'Fail' }
                            Severity = 'Medium'
                            Remediation = 'Set to 1 or more days'
                        }
                        $results.Controls += $control

                        # CIS 1.1.4 - Minimum password length
                        $minPasswordLength = Get-SecEditValue -Content $secpolContent -Setting "MinimumPasswordLength"
                        $control = [PSCustomObject]@{
                            ControlID = 'CIS-1.1.4'
                            ControlName = 'Minimum password length'
                            Category = 'PasswordPolicy'
                            Expected = '14 or more characters'
                            Actual = if ($null -ne $minPasswordLength) { "$minPasswordLength characters" } else { 'Unable to evaluate — setting missing from secedit export' }
                            Status = if ($null -eq $minPasswordLength) { 'Manual' } elseif ([int]$minPasswordLength -ge 14) { 'Pass' } else { 'Fail' }
                            Severity = 'High'
                            Remediation = 'Set to 14 or more characters'
                        }
                        $results.Controls += $control

                        # CIS 1.1.5 - Password complexity
                        $passwordComplexity = Get-SecEditValue -Content $secpolContent -Setting "PasswordComplexity"
                        $control = [PSCustomObject]@{
                            ControlID = 'CIS-1.1.5'
                            ControlName = 'Password must meet complexity requirements'
                            Category = 'PasswordPolicy'
                            Expected = 'Enabled'
                            Actual = if ($null -eq $passwordComplexity) { 'Unable to evaluate — setting missing from secedit export' }
                                     elseif ($passwordComplexity -eq '1') { 'Enabled' } else { 'Disabled' }
                            Status = if ($null -eq $passwordComplexity) { 'Manual' } elseif ($passwordComplexity -eq '1') { 'Pass' } else { 'Fail' }
                            Severity = 'Critical'
                            Remediation = 'Enable password complexity requirements'
                        }
                        $results.Controls += $control
                    }
                }
                catch {
                    Write-Warning "Error testing password policy: $_"
                }
            }
            
            # 2. AUDIT POLICY CONTROLS
            if ($Category -in @('All', 'AuditPolicy')) {
                Write-Host "`n[2/5] Testing Audit Policy Controls..." -ForegroundColor Cyan
                
                try {
                    # CIS 17.1.1 - Audit Credential Validation
                    $auditTable = Get-AuditPolicyTable -Subcategory 'Credential Validation', 'Application Group Management', 'Account Lockout'
                    $credentialValidationGuid = Get-AuditSubcategoryGuid -Name 'Credential Validation'
                    $credentialValidation = $null
                    if ($null -ne $credentialValidationGuid) {
                        $credentialValidationKey = ($credentialValidationGuid -replace '[{}]', '').ToLowerInvariant()
                        $credentialValidation = $auditTable[$credentialValidationKey]
                    }

                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-17.1.1'
                        ControlName = 'Audit Credential Validation'
                        Category = 'AuditPolicy'
                        Expected = 'Success and Failure'
                        Actual = if ($null -eq $credentialValidation -or $null -eq $credentialValidation.Value) { 'Unable to determine' }
                                 elseif ($credentialValidation.Success -and $credentialValidation.Failure) { 'Success and Failure' }
                                 elseif ($credentialValidation.Success) { 'Success' }
                                 elseif ($credentialValidation.Failure) { 'Failure' } else { 'No Auditing' }
                        Status = if ($null -eq $credentialValidation -or $null -eq $credentialValidation.Value) { 'Manual' }
                                 elseif ($credentialValidation.Value -eq 3) { 'Pass' } else { 'Fail' }
                        Severity = 'High'
                        Remediation = 'Configure to audit Success and Failure'
                    }
                    $results.Controls += $control

                    # CIS 17.2.1 - Audit Application Group Management
                    $appGroupGuid = Get-AuditSubcategoryGuid -Name 'Application Group Management'
                    $appGroupManagement = $null
                    if ($null -ne $appGroupGuid) {
                        $appGroupKey = ($appGroupGuid -replace '[{}]', '').ToLowerInvariant()
                        $appGroupManagement = $auditTable[$appGroupKey]
                    }

                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-17.2.1'
                        ControlName = 'Audit Application Group Management'
                        Category = 'AuditPolicy'
                        Expected = 'Success and Failure'
                        Actual = if ($null -eq $appGroupManagement -or $null -eq $appGroupManagement.Value) { 'Unable to determine' }
                                 elseif ($appGroupManagement.Success -and $appGroupManagement.Failure) { 'Success and Failure' }
                                 elseif ($appGroupManagement.Success) { 'Success' }
                                 elseif ($appGroupManagement.Failure) { 'Failure' } else { 'No Auditing' }
                        Status = if ($null -eq $appGroupManagement -or $null -eq $appGroupManagement.Value) { 'Manual' }
                                 elseif ($appGroupManagement.Value -eq 3) { 'Pass' } else { 'Fail' }
                        Severity = 'Medium'
                        Remediation = 'Configure to audit Success and Failure'
                    }
                    $results.Controls += $control

                    # CIS 17.5.1 - Audit Account Lockout
                    $accountLockoutGuid = Get-AuditSubcategoryGuid -Name 'Account Lockout'
                    $accountLockout = $null
                    if ($null -ne $accountLockoutGuid) {
                        $accountLockoutKey = ($accountLockoutGuid -replace '[{}]', '').ToLowerInvariant()
                        $accountLockout = $auditTable[$accountLockoutKey]
                    }

                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-17.5.1'
                        ControlName = 'Audit Account Lockout'
                        Category = 'AuditPolicy'
                        Expected = 'Success'
                        Actual = if ($null -eq $accountLockout -or $null -eq $accountLockout.Value) { 'Unable to determine' }
                                 elseif ($accountLockout.Value -ge 1 -and $accountLockout.Value -le 3) { 'Configured' } else { 'Not Configured' }
                        Status = if ($null -eq $accountLockout -or $null -eq $accountLockout.Value) { 'Manual' }
                                 elseif ($accountLockout.Value -ge 1 -and $accountLockout.Value -le 3) { 'Pass' } else { 'Fail' }
                        Severity = 'Medium'
                        Remediation = 'Configure to audit Success'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing audit policy: $_"
                }
            }
            
            # 3. SECURITY OPTIONS
            if ($Category -in @('All', 'SecurityOptions')) {
                Write-Host "`n[3/5] Testing Security Options..." -ForegroundColor Cyan
                
                try {
                    # CIS 2.3.1.1 - Accounts: Administrator account status
                    $adminUser = Get-LocalUserByRid -Rid 500 -ErrorAction SilentlyContinue
                    $adminKnown = ($null -ne $adminUser) -and ($null -ne $adminUser.Enabled)
                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-2.3.1.1'
                        ControlName = 'Accounts: Administrator account status'
                        Category = 'SecurityOptions'
                        Expected = 'Disabled'
                        Actual = if (-not $adminKnown) { 'Unable to determine' }
                                 elseif ($adminUser.Enabled) { 'Enabled' } else { 'Disabled' }
                        Status = if (-not $adminKnown) { 'Manual' }
                                 elseif ($adminUser.Enabled) { 'Fail' } else { 'Pass' }
                        Severity = 'High'
                        Remediation = 'Disable the built-in Administrator account'
                    }
                    $results.Controls += $control

                    # CIS 2.3.1.5 - Accounts: Guest account status
                    $guestUser = Get-LocalUserByRid -Rid 501 -ErrorAction SilentlyContinue
                    $guestKnown = ($null -ne $guestUser) -and ($null -ne $guestUser.Enabled)
                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-2.3.1.5'
                        ControlName = 'Accounts: Guest account status'
                        Category = 'SecurityOptions'
                        Expected = 'Disabled'
                        Actual = if (-not $guestKnown) { 'Unable to determine' }
                                 elseif ($guestUser.Enabled) { 'Enabled' } else { 'Disabled' }
                        Status = if (-not $guestKnown) { 'Manual' }
                                 elseif ($guestUser.Enabled) { 'Fail' } else { 'Pass' }
                        Severity = 'High'
                        Remediation = 'Disable the Guest account'
                    }
                    $results.Controls += $control
                    
                    # CIS 2.3.7.1 - Interactive logon: Do not display last user name
                    $regTest = Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                        -Name 'DontDisplayLastUserName' -ExpectedValue 1
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-2.3.7.1'
                        ControlName = 'Interactive logon: Do not display last user name'
                        Category = 'SecurityOptions'
                        Expected = 'Enabled'
                        Actual = if ($regTest.ActualValue -eq 1) { 'Enabled' } else { 'Disabled' }
                        Status = if ($regTest.Compliant) { 'Pass' } else { 'Fail' }
                        Severity = 'Medium'
                        Remediation = 'Enable to hide last logged on user'
                    }
                    $results.Controls += $control
                    
                    # CIS 2.3.11.1 - Network security: Do not store LAN Manager hash
                    $regTest = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                        -Name 'NoLMHash' -ExpectedValue 1
                    
                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-2.3.11.1'
                        ControlName = 'Network security: Do not store LAN Manager hash'
                        Category = 'SecurityOptions'
                        Expected = 'Enabled'
                        Actual = if ($regTest.ActualValue -eq 1) { 'Enabled' } else { 'Disabled' }
                        Status = if ($regTest.Compliant) { 'Pass' } else { 'Fail' }
                        Severity = 'High'
                        Remediation = 'Enable to prevent storing weak LM hashes'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing security options: $_"
                }
            }
            
            # 4. WINDOWS FIREWALL
            if ($Category -in @('All', 'WindowsFirewall')) {
                Write-Host "`n[4/5] Testing Windows Firewall..." -ForegroundColor Cyan
                
                try {
                    # Gate on Get-Command: CommandNotFoundException ignores
                    # -ErrorAction SilentlyContinue; an empty result must not silently
                    # produce zero CIS-9.x controls.
                    $firewallCmdletAvailable = $null -ne (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)
                    $firewallProfiles = $null
                    if ($firewallCmdletAvailable) {
                        try { $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop) } catch { $firewallProfiles = $null }
                    }

                    if (-not $firewallCmdletAvailable -or @($firewallProfiles).Count -eq 0) {
                        Write-Warning "Unable to retrieve firewall profiles; firewall controls require manual review"
                        $control = [PSCustomObject]@{
                            ControlID = 'CIS-9.1.1'
                            ControlName = 'Windows Firewall: Firewall state'
                            Category = 'WindowsFirewall'
                            Expected = 'On'
                            Actual = 'Unable to evaluate — Get-NetFirewallProfile unavailable or returned no profiles'
                            Status = 'Manual'
                            Severity = 'Critical'
                            Remediation = 'Verify Windows Firewall is enabled for all profiles'
                        }
                        $results.Controls += $control
                    }
                    else {
                        foreach ($profile in $firewallProfiles) {
                        # CIS 9.1.1 - Domain Profile Firewall State
                        $control = [PSCustomObject]@{
                            ControlID = "CIS-9.$($profile.Name).1"
                            ControlName = "Windows Firewall: $($profile.Name): Firewall state"
                            Category = 'WindowsFirewall'
                            Expected = 'On'
                            Actual = if ($profile.Enabled) { 'On' } else { 'Off' }
                            Status = if ($profile.Enabled) { 'Pass' } else { 'Fail' }
                            Severity = 'Critical'
                            Remediation = "Enable Windows Firewall for $($profile.Name) profile"
                        }
                        $results.Controls += $control
                        
                        # CIS 9.1.2 - Inbound connections
                        $control = [PSCustomObject]@{
                            ControlID = "CIS-9.$($profile.Name).2"
                            ControlName = "Windows Firewall: $($profile.Name): Inbound connections"
                            Category = 'WindowsFirewall'
                            Expected = 'Block (default)'
                            Actual = $profile.DefaultInboundAction
                            Status = if ($profile.DefaultInboundAction -eq 'Block') { 'Pass' } else { 'Fail' }
                            Severity = 'High'
                            Remediation = "Set inbound connections to Block for $($profile.Name)"
                        }
                        $results.Controls += $control
                        }
                    }
                }
                catch {
                    Write-Warning "Error testing Windows Firewall: $_"
                }
            }
            
            # 5. USER RIGHTS ASSIGNMENT
            if ($Category -in @('All', 'UserRights')) {
                Write-Host "`n[5/5] Testing User Rights Assignment..." -ForegroundColor Cyan
                
                try {
                    # CIS 2.2.1 - Access this computer from the network
                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-2.2.1'
                        ControlName = 'Access this computer from the network'
                        Category = 'UserRights'
                        Expected = 'Administrators, Remote Desktop Users (for workstations)'
                        Actual = 'Manual verification required'
                        Status = 'Manual'
                        Severity = 'Medium'
                        Remediation = 'Limit to Administrators and Remote Desktop Users only'
                    }
                    $results.Controls += $control
                    
                    # CIS 2.2.3 - Allow log on locally
                    $control = [PSCustomObject]@{
                        ControlID = 'CIS-2.2.3'
                        ControlName = 'Allow log on locally'
                        Category = 'UserRights'
                        Expected = 'Administrators, Users'
                        Actual = 'Manual verification required'
                        Status = 'Manual'
                        Severity = 'Medium'
                        Remediation = 'Review and restrict local logon rights'
                    }
                    $results.Controls += $control
                }
                catch {
                    Write-Warning "Error testing user rights: $_"
                }
            }
            
            # Calculate summary - FIX: Use @() to ensure array
            $results.Summary.TotalControls = $results.Controls.Count
            $results.Summary.Passed = @($results.Controls | Where-Object { $_.Status -eq 'Pass' }).Count
            $results.Summary.Failed = @($results.Controls | Where-Object { $_.Status -eq 'Fail' }).Count
            $results.Summary.NotApplicable = @($results.Controls | Where-Object { $_.Status -eq 'Manual' }).Count
            
            if ($results.Summary.TotalControls -gt 0) {
                $testableControls = $results.Summary.TotalControls - $results.Summary.NotApplicable
                if ($testableControls -gt 0) {
                    $results.Summary.CompliancePercentage = [math]::Round(
                        ($results.Summary.Passed / $testableControls) * 100, 2
                    )
                }
            }
            
            # Generate recommendations - FIX: Use @() to ensure array
            $failedCritical = @($results.Controls | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' })
            $failedHigh = @($results.Controls | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'High' })
            
            if ($failedCritical.Count -gt 0) {
                $results.Recommendations += "CRITICAL: $($failedCritical.Count) critical control(s) failed"
                $results.Recommendations += "Address critical failures immediately to reduce security risk"
            }
            
            if ($failedHigh.Count -gt 0) {
                $results.Recommendations += "HIGH: $($failedHigh.Count) high-severity control(s) failed"
            }
            
            if ($results.Summary.CompliancePercentage -lt 70) {
                $results.Recommendations += "Compliance below 70% - comprehensive security review required"
            }
            
            $results.Recommendations += "Review failed controls and implement remediation steps"
            $results.Recommendations += "Document exceptions for controls that cannot be implemented"
            
        }
        catch {
            Write-Error "Error during CIS benchmark testing: $_"
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
        Write-Host "  Passed: $($results.Summary.Passed)" -ForegroundColor Green
        Write-Host "  Failed: $($results.Summary.Failed)" -ForegroundColor Red
        Write-Host "  Manual Review: $($results.Summary.NotApplicable)" -ForegroundColor Yellow
        Write-Host "  Compliance: $($results.Summary.CompliancePercentage)%" -ForegroundColor $(
            if ($results.Summary.CompliancePercentage -ge 80) { 'Green' }
            elseif ($results.Summary.CompliancePercentage -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        
        if ($results.Controls.Count -gt 0) {
            $failedControls = @($results.Controls | Where-Object { $_.Status -eq 'Fail' })
            if ($failedControls.Count -gt 0) {
                Write-Host "`nFailed Controls by Severity:" -ForegroundColor Cyan
                $failedBySeverity = $failedControls | Group-Object Severity
                foreach ($group in $failedBySeverity | Sort-Object Name) {
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
        
        Write-Host "`nCIS Benchmarks: https://www.cisecurity.org/cis-benchmarks" -ForegroundColor Gray
        
        return $results
    }
}