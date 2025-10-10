function Find-ADVulnerabilities {
    <#
    .SYNOPSIS
        Detects common Active Directory vulnerabilities and misconfigurations
    .DESCRIPTION
        Scans for AD vulnerabilities including Kerberoasting, AS-REP Roasting, 
        weak permissions, and dangerous configurations
    .PARAMETER CheckKerberoasting
        Check for Kerberoastable accounts
    .PARAMETER CheckASREPRoasting
        Check for AS-REP Roastable accounts
    .PARAMETER CheckWeakPermissions
        Check for weak ACL permissions
    .PARAMETER Domain
        Target domain (default: current domain)
    .EXAMPLE
        Find-ADVulnerabilities -CheckKerberoasting -CheckASREPRoasting
        Find-ADVulnerabilities -CheckWeakPermissions -Domain "contoso.com"
    .OUTPUTS
        PSCustomObject with vulnerability findings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckKerberoasting,
        
        [Parameter()]
        [switch]$CheckASREPRoasting,
        
        [Parameter()]
        [switch]$CheckWeakPermissions,
        
        [Parameter()]
        [string]$Domain
    )
    
    begin {
        Write-Host "=== ACTIVE DIRECTORY VULNERABILITY SCAN ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check if ActiveDirectory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory module not found. Install RSAT tools."
            Write-Host "To install: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Yellow
            throw "ActiveDirectory module required"
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # If no domain specified, use current
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        Write-Host "Target Domain: $Domain" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            Vulnerabilities = @{
                Kerberoasting = @()
                ASREPRoasting = @()
                WeakPermissions = @()
                DangerousConfigurations = @()
            }
            Summary = @{
                TotalVulnerabilities = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
            }
            Recommendations = @()
        }
    }
    
    process {
        try {
            # 1. Check for Kerberoastable accounts
            if ($CheckKerberoasting) {
                Write-Host "`n[1/3] Checking for Kerberoastable accounts..." -ForegroundColor Cyan
                
                try {
                    # Find accounts with SPN set
                    $kerberoastableUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, Enabled, AdminCount -Server $Domain
                    
                    foreach ($user in $kerberoastableUsers) {
                        $severity = 'Medium'
                        
                        # Elevated severity for privileged accounts
                        if ($user.AdminCount -eq 1) {
                            $severity = 'Critical'
                            $results.Summary.CriticalFindings++
                        } else {
                            $results.Summary.MediumFindings++
                        }
                        
                        # Check password age
                        $passwordAge = if ($user.PasswordLastSet) {
                            (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
                        } else {
                            "Never changed"
                        }
                        
                        $results.Vulnerabilities.Kerberoasting += [PSCustomObject]@{
                            Severity = $severity
                            Username = $user.SamAccountName
                            DisplayName = $user.Name
                            Enabled = $user.Enabled
                            IsPrivileged = ($user.AdminCount -eq 1)
                            SPNs = $user.ServicePrincipalName -join ', '
                            PasswordAge = $passwordAge
                            Description = "Account has SPN set and is vulnerable to Kerberoasting attack"
                        }
                        
                        Write-Host "  Found: $($user.SamAccountName) - Severity: $severity" -ForegroundColor $(
                            if ($severity -eq 'Critical') { 'Red' } else { 'Yellow' }
                        )
                    }
                    
                    if ($kerberoastableUsers.Count -eq 0) {
                        Write-Host "  No Kerberoastable accounts found" -ForegroundColor Green
                    } else {
                        $results.Recommendations += "Review and remove unnecessary SPNs from accounts"
                        $results.Recommendations += "Use long, complex passwords for accounts with SPNs"
                        $results.Recommendations += "Consider using Group Managed Service Accounts (gMSA)"
                    }
                }
                catch {
                    Write-Warning "Error checking Kerberoasting: $_"
                }
            }
            
            # 2. Check for AS-REP Roastable accounts
            if ($CheckASREPRoasting) {
                Write-Host "`n[2/3] Checking for AS-REP Roastable accounts..." -ForegroundColor Cyan
                
                try {
                    # Find accounts with "Do not require Kerberos preauthentication"
                    $asrepUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, PasswordLastSet, Enabled, AdminCount -Server $Domain
                    
                    foreach ($user in $asrepUsers) {
                        $severity = 'High'
                        
                        if ($user.AdminCount -eq 1) {
                            $severity = 'Critical'
                            $results.Summary.CriticalFindings++
                        } else {
                            $results.Summary.HighFindings++
                        }
                        
                        $passwordAge = if ($user.PasswordLastSet) {
                            (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
                        } else {
                            "Never changed"
                        }
                        
                        $results.Vulnerabilities.ASREPRoasting += [PSCustomObject]@{
                            Severity = $severity
                            Username = $user.SamAccountName
                            DisplayName = $user.Name
                            Enabled = $user.Enabled
                            IsPrivileged = ($user.AdminCount -eq 1)
                            PasswordAge = $passwordAge
                            Description = "Account does not require Kerberos pre-authentication (AS-REP Roasting)"
                        }
                        
                        Write-Host "  Found: $($user.SamAccountName) - Severity: $severity" -ForegroundColor $(
                            if ($severity -eq 'Critical') { 'Red' } else { 'Yellow' }
                        )
                    }
                    
                    if ($asrepUsers.Count -eq 0) {
                        Write-Host "  No AS-REP Roastable accounts found" -ForegroundColor Green
                    } else {
                        $results.Recommendations += "Enable Kerberos pre-authentication for all accounts"
                        $results.Recommendations += "Review accounts with DoesNotRequirePreAuth enabled"
                    }
                }
                catch {
                    Write-Warning "Error checking AS-REP Roasting: $_"
                }
            }
            
            # 3. Check for weak permissions and dangerous configurations
            if ($CheckWeakPermissions) {
                Write-Host "`n[3/3] Checking for weak permissions..." -ForegroundColor Cyan
                
                try {
                    # Check for users with "Password Never Expires"
                    Write-Host "  Checking password policies..." -ForegroundColor Yellow
                    $neverExpireUsers = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires, AdminCount -Server $Domain
                    
                    foreach ($user in $neverExpireUsers) {
                        $severity = if ($user.AdminCount -eq 1) { 'High' } else { 'Medium' }
                        
                        if ($severity -eq 'High') {
                            $results.Summary.HighFindings++
                        } else {
                            $results.Summary.MediumFindings++
                        }
                        
                        $results.Vulnerabilities.WeakPermissions += [PSCustomObject]@{
                            Severity = $severity
                            Type = 'Password Policy'
                            Object = $user.SamAccountName
                            Issue = 'Password Never Expires'
                            IsPrivileged = ($user.AdminCount -eq 1)
                            Description = "Account password is set to never expire"
                        }
                    }
                    
                    Write-Host "    Found $($neverExpireUsers.Count) accounts with non-expiring passwords" -ForegroundColor $(
                        if ($neverExpireUsers.Count -gt 0) { 'Yellow' } else { 'Green' }
                    )
                    
                    # Check for disabled password complexity
                    Write-Host "  Checking domain password policy..." -ForegroundColor Yellow
                    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Domain
                    
                    if ($domainPolicy.ComplexityEnabled -eq $false) {
                        $results.Vulnerabilities.DangerousConfigurations += [PSCustomObject]@{
                            Severity = 'Critical'
                            Type = 'Password Policy'
                            Issue = 'Password Complexity Disabled'
                            Description = 'Domain password policy does not require complex passwords'
                        }
                        $results.Summary.CriticalFindings++
                        Write-Host "    [!] Password complexity is DISABLED" -ForegroundColor Red
                    }
                    
                    if ($domainPolicy.MinPasswordLength -lt 12) {
                        $results.Vulnerabilities.DangerousConfigurations += [PSCustomObject]@{
                            Severity = 'High'
                            Type = 'Password Policy'
                            Issue = "Minimum Password Length: $($domainPolicy.MinPasswordLength)"
                            Description = 'Minimum password length is less than 12 characters'
                        }
                        $results.Summary.HighFindings++
                        Write-Host "    [!] Minimum password length is only $($domainPolicy.MinPasswordLength) characters" -ForegroundColor Yellow
                    }
                    
                    # Check for accounts with reversible encryption
                    Write-Host "  Checking for reversible encryption..." -ForegroundColor Yellow
                    $reversibleUsers = Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption -Server $Domain
                    
                    foreach ($user in $reversibleUsers) {
                        $results.Vulnerabilities.DangerousConfigurations += [PSCustomObject]@{
                            Severity = 'Critical'
                            Type = 'Password Storage'
                            Object = $user.SamAccountName
                            Issue = 'Reversible Encryption Enabled'
                            Description = 'Password stored with reversible encryption (plaintext equivalent)'
                        }
                        $results.Summary.CriticalFindings++
                        Write-Host "    [!] $($user.SamAccountName) has reversible encryption enabled" -ForegroundColor Red
                    }
                    
                    if (-not $results.Recommendations -contains "Enforce strong password policies") {
                        $results.Recommendations += "Enforce strong password policies (min 12 chars, complexity enabled)"
                        $results.Recommendations += "Regular password rotation for privileged accounts"
                        $results.Recommendations += "Disable reversible encryption for all accounts"
                    }
                }
                catch {
                    Write-Warning "Error checking weak permissions: $_"
                }
            }
            
            # Calculate total vulnerabilities
            $results.Summary.TotalVulnerabilities = $results.Summary.CriticalFindings + 
                                                   $results.Summary.HighFindings + 
                                                   $results.Summary.MediumFindings
            
        }
        catch {
            Write-Error "Error during AD vulnerability scan: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nVulnerability Summary:" -ForegroundColor Cyan
        Write-Host "  Total Vulnerabilities: $($results.Summary.TotalVulnerabilities)" -ForegroundColor White
        Write-Host "  Critical: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumFindings)" -ForegroundColor Yellow
        
        if ($results.Vulnerabilities.Kerberoasting.Count -gt 0) {
            Write-Host "`nKerberoastable Accounts: $($results.Vulnerabilities.Kerberoasting.Count)" -ForegroundColor Yellow
            $results.Vulnerabilities.Kerberoasting | Select-Object -First 5 | ForEach-Object {
                Write-Host "  - $($_.Username) [$($_.Severity)]" -ForegroundColor $(
                    if ($_.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
                )
            }
        }
        
        if ($results.Vulnerabilities.ASREPRoasting.Count -gt 0) {
            Write-Host "`nAS-REP Roastable Accounts: $($results.Vulnerabilities.ASREPRoasting.Count)" -ForegroundColor Yellow
            $results.Vulnerabilities.ASREPRoasting | Select-Object -First 5 | ForEach-Object {
                Write-Host "  - $($_.Username) [$($_.Severity)]" -ForegroundColor $(
                    if ($_.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
                )
            }
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | Select-Object -Unique | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nNote: This scan requires domain connectivity and RSAT tools" -ForegroundColor Gray
        
        return $results
    }
}