function Find-ADBackdoors {
    <#
    .SYNOPSIS
        Detects potential backdoors and persistence mechanisms in Active Directory
    .DESCRIPTION
        Scans for AD backdoors including AdminSDHolder abuse, DCSync permissions,
        SIDHistory manipulation, and other persistence mechanisms
    .PARAMETER CheckAdminSDHolder
        Check for AdminSDHolder tampering
    .PARAMETER CheckDCSync
        Check for DCSync permissions
    .PARAMETER CheckSIDHistory
        Check for SIDHistory abuse
    .PARAMETER CheckDelegation
        Check for dangerous delegations
    .PARAMETER Domain
        Target domain
    .EXAMPLE
        Find-ADBackdoors -CheckAdminSDHolder -CheckDCSync -CheckSIDHistory
        Find-ADBackdoors -CheckDelegation -Domain "contoso.com"
    .OUTPUTS
        PSCustomObject with backdoor findings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckAdminSDHolder,
        
        [Parameter()]
        [switch]$CheckDCSync,
        
        [Parameter()]
        [switch]$CheckSIDHistory,
        
        [Parameter()]
        [switch]$CheckDelegation,
        
        [Parameter()]
        [string]$Domain
    )
    
    begin {
        Write-Host "=== AD BACKDOOR DETECTION ===" -ForegroundColor Cyan
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module required"
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        Write-Host "Domain: $Domain" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            Backdoors = @{
                AdminSDHolder = @()
                DCSync = @()
                SIDHistory = @()
                DangerousDelegations = @()
            }
            Summary = @{
                TotalBackdoors = 0
                CriticalFindings = 0
                HighFindings = 0
            }
            Recommendations = @()
        }
    }
    
    process {
        try {
            # 1. Check AdminSDHolder
            if ($CheckAdminSDHolder) {
                Write-Host "`n[1/4] Checking AdminSDHolder..." -ForegroundColor Cyan
                
                try {
                    # Get AdminSDHolder object
                    $adminSDHolder = Get-ADObject -Filter {Name -eq "AdminSDHolder"} -SearchBase "CN=System,$((Get-ADDomain -Server $Domain).DistinguishedName)" -Properties ntSecurityDescriptor -Server $Domain
                    
                    if ($adminSDHolder) {
                        # Check users with AdminCount=1 who shouldn't have it
                        $adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf -Server $Domain
                        
                        # Get actual privileged group members
                        $privilegedGroups = @(
                            'Domain Admins',
                            'Enterprise Admins',
                            'Schema Admins',
                            'Administrators',
                            'Account Operators',
                            'Backup Operators',
                            'Server Operators',
                            'Print Operators'
                        )
                        
                        $legitimatePrivilegedUsers = @()
                        foreach ($groupName in $privilegedGroups) {
                            try {
                                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $Domain -ErrorAction SilentlyContinue
                                if ($group) {
                                    $members = Get-ADGroupMember -Identity $group -Recursive -Server $Domain -ErrorAction SilentlyContinue
                                    $legitimatePrivilegedUsers += $members.SamAccountName
                                }
                            }
                            catch {
                                Write-Verbose "Could not check group: $groupName"
                            }
                        }
                        
                        # Find suspicious AdminCount users
                        foreach ($user in $adminCountUsers) {
                            if ($user.SamAccountName -notin $legitimatePrivilegedUsers) {
                                $results.Backdoors.AdminSDHolder += [PSCustomObject]@{
                                    Severity = 'Critical'
                                    Username = $user.SamAccountName
                                    DisplayName = $user.Name
                                    Issue = 'AdminCount=1 but not in privileged groups'
                                    Description = 'Possible AdminSDHolder abuse for persistence'
                                }
                                
                                $results.Summary.CriticalFindings++
                                Write-Host "  [!] Suspicious: $($user.SamAccountName)" -ForegroundColor Red
                            }
                        }
                        
                        if ($results.Backdoors.AdminSDHolder.Count -eq 0) {
                            Write-Host "  No AdminSDHolder abuse detected" -ForegroundColor Green
                        }
                    }
                }
                catch {
                    Write-Warning "Error checking AdminSDHolder: $_"
                }
            }
            
            # 2. Check DCSync Permissions
            if ($CheckDCSync) {
                Write-Host "`n[2/4] Checking DCSync permissions..." -ForegroundColor Cyan
                
                try {
                    # Get domain root
                    $domainDN = (Get-ADDomain -Server $Domain).DistinguishedName
                    $domainObject = Get-ADObject -Identity $domainDN -Properties ntSecurityDescriptor -Server $Domain
                    
                    # DCSync requires these rights:
                    # - DS-Replication-Get-Changes (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
                    # - DS-Replication-Get-Changes-All (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
                    
                    $acl = $domainObject.ntSecurityDescriptor
                    
                    $dcsyncRights = @(
                        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes
                        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
                    )
                    
                    foreach ($ace in $acl.Access) {
                        if ($ace.ObjectType -in $dcsyncRights) {
                            # Resolve SID to account
                            try {
                                $account = Get-ADObject -Filter "objectSid -eq '$($ace.IdentityReference)'" -Server $Domain -ErrorAction SilentlyContinue
                                
                                if ($account) {
                                    # Check if it's a legitimate DC or admin account
                                    $isLegitimate = $account.Name -match "Domain Controllers|Enterprise Admins|Administrators"
                                    
                                    if (-not $isLegitimate) {
                                        $results.Backdoors.DCSync += [PSCustomObject]@{
                                            Severity = 'Critical'
                                            Account = $account.Name
                                            AccountType = $account.ObjectClass
                                            Permission = 'DCSync'
                                            Issue = 'Non-standard account has DCSync permissions'
                                            Description = 'Can replicate password hashes from domain'
                                        }
                                        
                                        $results.Summary.CriticalFindings++
                                        Write-Host "  [!] DCSync: $($account.Name)" -ForegroundColor Red
                                    }
                                }
                            }
                            catch {
                                Write-Verbose "Could not resolve SID: $($ace.IdentityReference)"
                            }
                        }
                    }
                    
                    if ($results.Backdoors.DCSync.Count -eq 0) {
                        Write-Host "  No suspicious DCSync permissions found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking DCSync permissions: $_"
                }
            }
            
            # 3. Check SIDHistory
            if ($CheckSIDHistory) {
                Write-Host "`n[3/4] Checking SIDHistory abuse..." -ForegroundColor Cyan
                
                try {
                    # Find users with SIDHistory
                    $usersWithSIDHistory = Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory, MemberOf -Server $Domain
                    
                    foreach ($user in $usersWithSIDHistory) {
                        # SIDHistory is legitimate in migration scenarios, but can be abused
                        $sidHistoryCount = $user.SIDHistory.Count
                        
                        # Check if any SID in history is from a privileged group
                        foreach ($sid in $user.SIDHistory) {
                            try {
                                $sidObject = Get-ADObject -Filter "objectSid -eq '$sid'" -Server $Domain -ErrorAction SilentlyContinue
                                
                                if ($sidObject) {
                                    $results.Backdoors.SIDHistory += [PSCustomObject]@{
                                        Severity = 'High'
                                        Username = $user.SamAccountName
                                        SIDHistoryObject = $sidObject.Name
                                        SIDHistoryCount = $sidHistoryCount
                                        Issue = 'User has SIDHistory attribute set'
                                        Description = 'Can be used for privilege escalation'
                                    }
                                    
                                    $results.Summary.HighFindings++
                                    Write-Host "  [!] SIDHistory: $($user.SamAccountName) -> $($sidObject.Name)" -ForegroundColor Yellow
                                }
                            }
                            catch {
                                Write-Verbose "Could not resolve SID: $sid"
                            }
                        }
                    }
                    
                    if ($results.Backdoors.SIDHistory.Count -eq 0) {
                        Write-Host "  No SIDHistory abuse detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking SIDHistory: $_"
                }
            }
            
            # 4. Check Dangerous Delegations
            if ($CheckDelegation) {
                Write-Host "`n[4/4] Checking dangerous delegations..." -ForegroundColor Cyan
                
                try {
                    # Check for unconstrained delegation
                    $unconstrainedDelegation = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -Server $Domain
                    
                    foreach ($computer in $unconstrainedDelegation) {
                        # Domain Controllers are expected to have this
                        if ($computer.Name -notmatch "DC|Domain Controller") {
                            $results.Backdoors.DangerousDelegations += [PSCustomObject]@{
                                Severity = 'High'
                                Object = $computer.Name
                                ObjectType = 'Computer'
                                DelegationType = 'Unconstrained'
                                Issue = 'Computer has unconstrained delegation enabled'
                                Description = 'Can impersonate any user to any service'
                            }
                            
                            $results.Summary.HighFindings++
                            Write-Host "  [!] Unconstrained Delegation: $($computer.Name)" -ForegroundColor Yellow
                        }
                    }
                    
                    # Check for constrained delegation with protocol transition
                    $constrainedDelegation = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation -Server $Domain
                    
                    foreach ($object in $constrainedDelegation) {
                        if ($object.TrustedToAuthForDelegation) {
                            $results.Backdoors.DangerousDelegations += [PSCustomObject]@{
                                Severity = 'Medium'
                                Object = $object.Name
                                ObjectType = $object.ObjectClass
                                DelegationType = 'Constrained with Protocol Transition'
                                DelegateTo = $object.'msDS-AllowedToDelegateTo' -join ', '
                                Issue = 'Protocol transition enabled'
                                Description = 'Can obtain service tickets without user credentials'
                            }
                            
                            Write-Host "  [!] Protocol Transition: $($object.Name)" -ForegroundColor Yellow
                        }
                    }
                    
                    if ($results.Backdoors.DangerousDelegations.Count -eq 0) {
                        Write-Host "  No dangerous delegations found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking delegations: $_"
                }
            }
            
            # Calculate total backdoors
            $results.Summary.TotalBackdoors = 
                $results.Backdoors.AdminSDHolder.Count +
                $results.Backdoors.DCSync.Count +
                $results.Backdoors.SIDHistory.Count +
                $results.Backdoors.DangerousDelegations.Count
            
            # Generate recommendations
            if ($results.Backdoors.AdminSDHolder.Count -gt 0) {
                $results.Recommendations += "Review and remove AdminCount attribute from non-privileged accounts"
                $results.Recommendations += "Investigate how AdminCount was set on these accounts"
            }
            
            if ($results.Backdoors.DCSync.Count -gt 0) {
                $results.Recommendations += "Remove DCSync permissions from non-administrative accounts immediately"
                $results.Recommendations += "Audit replication activities"
            }
            
            if ($results.Backdoors.SIDHistory.Count -gt 0) {
                $results.Recommendations += "Clear SIDHistory for accounts not in active migration"
                $results.Recommendations += "Monitor SIDHistory changes"
            }
            
            if ($results.Backdoors.DangerousDelegations.Count -gt 0) {
                $results.Recommendations += "Review and restrict delegation configurations"
                $results.Recommendations += "Use constrained delegation instead of unconstrained"
            }
            
            $results.Recommendations += "Implement regular AD security audits"
            $results.Recommendations += "Enable advanced audit policies for privilege use"
            $results.Recommendations += "Monitor for Golden Ticket indicators"
            
        }
        catch {
            Write-Error "Error during backdoor detection: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nBackdoor Summary:" -ForegroundColor Cyan
        Write-Host "  Total Backdoors Found: $($results.Summary.TotalBackdoors)" -ForegroundColor $(
            if ($results.Summary.TotalBackdoors -gt 0) { 'Red' } else { 'Green' }
        )
        Write-Host "  Critical Findings: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High Findings: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        
        if ($results.Backdoors.AdminSDHolder.Count -gt 0) {
            Write-Host "`nAdminSDHolder Abuse: $($results.Backdoors.AdminSDHolder.Count)" -ForegroundColor Red
        }
        
        if ($results.Backdoors.DCSync.Count -gt 0) {
            Write-Host "DCSync Permissions: $($results.Backdoors.DCSync.Count)" -ForegroundColor Red
        }
        
        if ($results.Backdoors.SIDHistory.Count -gt 0) {
            Write-Host "SIDHistory Abuse: $($results.Backdoors.SIDHistory.Count)" -ForegroundColor Yellow
        }
        
        if ($results.Backdoors.DangerousDelegations.Count -gt 0) {
            Write-Host "Dangerous Delegations: $($results.Backdoors.DangerousDelegations.Count)" -ForegroundColor Yellow
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        if ($results.Summary.TotalBackdoors -gt 0) {
            Write-Host "`n[!!!] BACKDOORS DETECTED - IMMEDIATE ACTION REQUIRED [!!!]" -ForegroundColor Red -BackgroundColor Black
        }
        
        return $results
    }
}