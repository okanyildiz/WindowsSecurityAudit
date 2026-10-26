function Enable-AuditPolicies {
    <#
    .SYNOPSIS
        Configures Windows audit policies for security monitoring
    .DESCRIPTION
        Enables comprehensive audit policies for tracking security events including logon,
        account management, object access, policy changes, and privilege use
    .PARAMETER AuditLevel
        Audit level: Basic, Standard, or Comprehensive
    .PARAMETER IncludeFileAuditing
        Enable file and folder access auditing
    .PARAMETER IncludeRegistryAuditing
        Enable registry access auditing
    .EXAMPLE
        Enable-AuditPolicies -AuditLevel Standard
        Enable-AuditPolicies -AuditLevel Comprehensive -IncludeFileAuditing -IncludeRegistryAuditing
    .OUTPUTS
        PSCustomObject with audit configuration results
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateSet('Basic', 'Standard', 'Comprehensive')]
        [string]$AuditLevel = 'Standard',
        
        [Parameter()]
        [switch]$IncludeFileAuditing,
        
        [Parameter()]
        [switch]$IncludeRegistryAuditing
    )
    
    begin {
        Write-Host "=== WINDOWS AUDIT POLICIES CONFIGURATION ===" -ForegroundColor Cyan
        Write-Host "Audit Level: $AuditLevel" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges!"
        }
        
        $results = [PSCustomObject]@{
            ConfigurationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            AuditLevel = $AuditLevel
            PoliciesConfigured = @()
            Errors = @()
            AuditCategories = @{
                AccountLogon = @{}
                AccountManagement = @{}
                DetailedTracking = @{}
                LogonLogoff = @{}
                ObjectAccess = @{}
                PolicyChange = @{}
                PrivilegeUse = @{}
                System = @{}
            }
        }
        
        # Audit policy settings based on level
        $auditSettings = @{
            Basic = @{
                'Account Logon' = @('Credential Validation')
                'Account Management' = @('User Account Management', 'Security Group Management')
                'Logon/Logoff' = @('Logon', 'Logoff', 'Account Lockout')
                'Policy Change' = @('Audit Policy Change', 'Authentication Policy Change')
                'System' = @('Security State Change', 'Security System Extension')
            }
            Standard = @{
                'Account Logon' = @('Credential Validation', 'Kerberos Authentication Service')
                'Account Management' = @('User Account Management', 'Security Group Management', 'Computer Account Management')
                'Detailed Tracking' = @('Process Creation', 'Process Termination')
                'Logon/Logoff' = @('Logon', 'Logoff', 'Account Lockout', 'Special Logon')
                'Object Access' = @('File System', 'Registry', 'Handle Manipulation')
                'Policy Change' = @('Audit Policy Change', 'Authentication Policy Change', 'Authorization Policy Change')
                'Privilege Use' = @('Sensitive Privilege Use')
                'System' = @('Security State Change', 'Security System Extension', 'System Integrity')
            }
            Comprehensive = @{
                'Account Logon' = @('Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations')
                'Account Management' = @('User Account Management', 'Security Group Management', 'Computer Account Management', 'Distribution Group Management', 'Application Group Management')
                'Detailed Tracking' = @('Process Creation', 'Process Termination', 'DPAPI Activity', 'RPC Events', 'Plug and Play Events')
                'Logon/Logoff' = @('Logon', 'Logoff', 'Account Lockout', 'Special Logon', 'Other Logon/Logoff Events', 'Network Policy Server')
                'Object Access' = @('File System', 'Registry', 'Kernel Object', 'SAM', 'Handle Manipulation', 'File Share', 'Filtering Platform Packet Drop', 'Filtering Platform Connection')
                'Policy Change' = @('Audit Policy Change', 'Authentication Policy Change', 'Authorization Policy Change', 'MPSSVC Rule-Level Policy Change', 'Filtering Platform Policy Change')
                'Privilege Use' = @('Sensitive Privilege Use', 'Non Sensitive Privilege Use')
                'System' = @('Security State Change', 'Security System Extension', 'System Integrity', 'IPsec Driver', 'Other System Events')
            }
        }

        foreach ($level in @($auditSettings.Keys)) {
            foreach ($category in @($auditSettings[$level].Keys)) {
                $auditSettings[$level][$category] = @($auditSettings[$level][$category] | ForEach-Object {
                    @{ Name = $_; Guid = Get-AuditSubcategoryGuid -Name $_ }
                })
            }
        }
    }
    
    process {
        try {
            $selectedSettings = $auditSettings[$AuditLevel]
            $totalCategories = ($selectedSettings.Keys | Measure-Object).Count
            $currentCategory = 0
            
            foreach ($category in $selectedSettings.Keys) {
                $currentCategory++
                Write-Host "`n[$currentCategory/$totalCategories] Configuring: $category" -ForegroundColor Cyan
                
                foreach ($subcategory in $selectedSettings[$category]) {
                    try {
                        if ($null -eq $subcategory.Guid) {
                            Write-Warning "  - Skipped: $($subcategory.Name) (no GUID in subcategory map)"
                            continue
                        }
                        # Enable both Success and Failure auditing
                        if ($PSCmdlet.ShouldProcess($subcategory.Name, "Enable audit policy")) {
                            $result = & auditpol /set /subcategory:"$($subcategory.Guid)" /success:enable /failure:enable 2>&1
                            
                            if ($LASTEXITCODE -eq 0) {
                                $results.PoliciesConfigured += $subcategory.Name
                                Write-Host "  + $($subcategory.Name)" -ForegroundColor Green
                            }
                            else {
                                $results.Errors += "Failed to configure: $($subcategory.Name) - $result"
                                Write-Warning "  - Failed: $($subcategory.Name)"
                            }
                        }
                    }
                    catch {
                        $results.Errors += "Error configuring $($subcategory.Name) : $_"
                        Write-Warning "  - Error: $($subcategory.Name)"
                    }
                }
                
                # Store category status
                $categoryKey = $category -replace '[/ ]', ''
                if ($results.AuditCategories.ContainsKey($categoryKey)) {
                    $results.AuditCategories[$categoryKey] = @{
                        Configured = $true
                        Subcategories = @($selectedSettings[$category] | ForEach-Object { $_.Name })
                    }
                }
            }
            
            # Configure Advanced Audit Policies
            Write-Host "`n[ADVANCED] Configuring advanced audit settings..." -ForegroundColor Cyan
            
            # Force audit policy subcategory settings
            try {
                $regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
                if ($PSCmdlet.ShouldProcess($regPath, "Enable advanced audit policy mode (SCENoApplyLegacyAuditPolicy)")) {
                    Set-ItemProperty -Path $regPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force
                    Write-Host "  + Advanced audit policy mode enabled" -ForegroundColor Green
                    $results.PoliciesConfigured += "Advanced Audit Policy Mode"
                }
            }
            catch {
                $results.Errors += "Failed to enable advanced audit mode: $_"
                Write-Warning "  - Failed to enable advanced audit mode"
            }
            
            # Increase Security event log size
            try {
                $logName = 'Security'
                if ($PSCmdlet.ShouldProcess($logName, "Set Security event log maximum size to 1GB")) {
                    $log = Get-WinEvent -ListLog $logName
                    
                    # Set to 1GB
                    $log.MaximumSizeInBytes = 1GB
                    $log.SaveChanges()
                    
                    Write-Host "  + Security log size increased to 1GB" -ForegroundColor Green
                    $results.PoliciesConfigured += "Security Log Size: 1GB"
                }
            }
            catch {
                $results.Errors += "Failed to increase log size: $_"
                Write-Warning "  - Failed to increase log size"
            }
            
            # Enable log retention
            try {
                if ($PSCmdlet.ShouldProcess("Security", "Configure Security log retention (archive full log, no overwrite)")) {
                    wevtutil sl Security /rt:false /ab:true
                    Write-Host "  + Security log retention enabled" -ForegroundColor Green
                    $results.PoliciesConfigured += "Security Log Retention"
                }
            }
            catch {
                $results.Errors += "Failed to configure log retention: $_"
            }
            
            # Configure Command Line Process Auditing
            if ($AuditLevel -in @('Standard', 'Comprehensive')) {
                Write-Host "`n[PROCESS] Enabling command line process auditing..." -ForegroundColor Cyan
                try {
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
                    if ($PSCmdlet.ShouldProcess($regPath, "Enable command line process auditing")) {
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force | Out-Null
                        }
                        Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
                        Write-Host "  + Command line auditing enabled" -ForegroundColor Green
                        $results.PoliciesConfigured += "Command Line Process Auditing"
                    }
                }
                catch {
                    $results.Errors += "Failed to enable command line auditing: $_"
                    Write-Warning "  - Failed to enable command line auditing"
                }
            }
            
            # File System Auditing
            if ($IncludeFileAuditing -or $AuditLevel -eq 'Comprehensive') {
                Write-Host "`n[FILE SYSTEM] Configuring file system auditing..." -ForegroundColor Cyan
                
                $pathsToAudit = @(
                    "$env:SystemRoot\System32",
                    "$env:ProgramFiles",
                    "$env:USERPROFILE\Documents"
                )
                
                $fileAuditApplied = $false
                foreach ($path in $pathsToAudit) {
                    if (Test-Path $path) {
                        try {
                            if ($PSCmdlet.ShouldProcess($path, "Add file system audit rule (Everyone: Delete/ChangePermissions/TakeOwnership)")) {
                                # Get current ACL
                                $acl = Get-Acl $path
                                
                                # Create audit rule for Everyone - Track both Success and Failure
                                $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                                    (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),
                                    "Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership",
                                    "ContainerInherit,ObjectInherit",
                                    "None",
                                    "Success,Failure"
                                )
                                
                                # Add audit rule
                                $acl.AddAuditRule($auditRule)
                                Set-Acl -Path $path -AclObject $acl
                                
                                Write-Host "  + Auditing enabled on: $path" -ForegroundColor Green
                                $fileAuditApplied = $true
                            }
                        }
                        catch {
                            Write-Warning "  - Failed to audit: $path"
                        }
                    }
                }
                if ($fileAuditApplied) {
                    $results.PoliciesConfigured += "File System Auditing"
                }
            }
            
            # Registry Auditing
            if ($IncludeRegistryAuditing -or $AuditLevel -eq 'Comprehensive') {
                Write-Host "`n[REGISTRY] Configuring registry auditing..." -ForegroundColor Cyan
                
                $regKeysToAudit = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    "HKLM:\SYSTEM\CurrentControlSet\Services"
                )
                
                $registryAuditApplied = $false
                foreach ($regKey in $regKeysToAudit) {
                    if (Test-Path $regKey) {
                        try {
                            if ($PSCmdlet.ShouldProcess($regKey, "Add registry audit rule (Everyone: SetValue/CreateSubKey/Delete)")) {
                                $acl = Get-Acl $regKey
                                
                                $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
                                    (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),
                                    "SetValue,CreateSubKey,Delete",
                                    "ContainerInherit",
                                    "None",
                                    "Success,Failure"
                                )
                                
                                $acl.AddAuditRule($auditRule)
                                Set-Acl -Path $regKey -AclObject $acl
                                
                                Write-Host "  + Auditing enabled on: $regKey" -ForegroundColor Green
                                $registryAuditApplied = $true
                            }
                        }
                        catch {
                            Write-Warning "  - Failed to audit: $regKey"
                        }
                    }
                }
                if ($registryAuditApplied) {
                    $results.PoliciesConfigured += "Registry Auditing"
                }
            }
            
        }
        catch {
            Write-Error "Error during audit policy configuration: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== AUDIT CONFIGURATION COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nPolicies Configured: $($results.PoliciesConfigured.Count)" -ForegroundColor Cyan
        
        if ($results.Errors.Count -gt 0) {
            Write-Host "`nErrors: $($results.Errors.Count)" -ForegroundColor Red
            $results.Errors | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Red
            }
        }
        
        Write-Host "`nAudit Summary:" -ForegroundColor Cyan
        Write-Host "  Level: $($results.AuditLevel)" -ForegroundColor White
        Write-Host "  Policies Enabled: $($results.PoliciesConfigured.Count)" -ForegroundColor White
        Write-Host "  Security Log: 1GB" -ForegroundColor White
        
        # Verify current audit policy
        Write-Host "`nVerifying configuration..." -ForegroundColor Cyan
        $auditTable = Get-AuditPolicyTable -Force
        $verifiedPolicies = 0
        $unverifiedPolicies = @()
        foreach ($category in $selectedSettings.Keys) {
            foreach ($subcategory in $selectedSettings[$category]) {
                if ($null -eq $subcategory.Guid) { continue }
                $guidKey = ($subcategory.Guid -replace '[{}]', '').ToLowerInvariant()
                if ($auditTable.ContainsKey($guidKey) -and $null -ne $auditTable[$guidKey].Value -and
                    $auditTable[$guidKey].Value -ge 1 -and $auditTable[$guidKey].Value -le 3) {
                    $verifiedPolicies++
                }
                else {
                    $unverifiedPolicies += $subcategory.Name
                }
            }
        }
        Write-Host "  Verified: $verifiedPolicies subcategories with auditing enabled" -ForegroundColor White
        if ($unverifiedPolicies.Count -gt 0) {
            Write-Host "  Unverified: $($unverifiedPolicies.Count)" -ForegroundColor Yellow
            foreach ($name in $unverifiedPolicies) {
                Write-Host "    - $name" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nRecommendations:" -ForegroundColor Cyan
        Write-Host "  1. Monitor Security event log regularly" -ForegroundColor White
        Write-Host "  2. Set up log forwarding to SIEM if available" -ForegroundColor White
        Write-Host "  3. Review audit events daily for suspicious activity" -ForegroundColor White
        Write-Host "  4. Implement log retention policy" -ForegroundColor White
        Write-Host "  5. Test audit logging with known actions" -ForegroundColor White
        
        Write-Host "`nImportant Event IDs to monitor:" -ForegroundColor Yellow
        Write-Host "  4624 - Successful logon" -ForegroundColor White
        Write-Host "  4625 - Failed logon" -ForegroundColor White
        Write-Host "  4672 - Special privileges assigned" -ForegroundColor White
        Write-Host "  4720 - User account created" -ForegroundColor White
        Write-Host "  4740 - User account locked out" -ForegroundColor White
        Write-Host "  4688 - Process created" -ForegroundColor White
        
        return $results
    }
}