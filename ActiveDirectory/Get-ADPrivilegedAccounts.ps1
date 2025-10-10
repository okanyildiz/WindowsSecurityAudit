function Get-ADPrivilegedAccounts {
    <#
    .SYNOPSIS
        Identifies and analyzes privileged accounts in Active Directory
    .DESCRIPTION
        Discovers privileged accounts including Domain Admins, Enterprise Admins,
        and other high-privilege groups with detailed analysis
    .PARAMETER IncludeNested
        Include nested group memberships
    .PARAMETER CheckLastLogon
        Check last logon time for privileged accounts
    .PARAMETER Domain
        Target domain (default: current domain)
    .EXAMPLE
        Get-ADPrivilegedAccounts
        Get-ADPrivilegedAccounts -IncludeNested -CheckLastLogon
    .OUTPUTS
        PSCustomObject with privileged account information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeNested,
        
        [Parameter()]
        [switch]$CheckLastLogon,
        
        [Parameter()]
        [string]$Domain
    )
    
    begin {
        Write-Host "=== PRIVILEGED ACCOUNTS ANALYSIS ===" -ForegroundColor Cyan
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module required. Install RSAT tools."
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        Write-Host "Domain: $Domain" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Define privileged groups
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators',
            'DnsAdmins',
            'Group Policy Creator Owners'
        )
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            PrivilegedGroups = @()
            PrivilegedAccounts = @()
            Statistics = @{
                TotalPrivilegedAccounts = 0
                EnabledAccounts = 0
                DisabledAccounts = 0
                StaleAccounts = 0
                AccountsWithoutLogon = 0
            }
            Findings = @()
            Recommendations = @()
        }
    }
    
    process {
        try {
            Write-Host "`nAnalyzing privileged groups..." -ForegroundColor Cyan
            
            $allPrivilegedUsers = @{}
            
            foreach ($groupName in $privilegedGroups) {
                try {
                    Write-Host "`nChecking: $groupName" -ForegroundColor Yellow
                    
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $Domain -ErrorAction SilentlyContinue
                    
                    if (-not $group) {
                        Write-Verbose "Group not found: $groupName"
                        continue
                    }
                    
                    # Get group members
                    if ($IncludeNested) {
                        $members = Get-ADGroupMember -Identity $group -Recursive -Server $Domain -ErrorAction SilentlyContinue
                    } else {
                        $members = Get-ADGroupMember -Identity $group -Server $Domain -ErrorAction SilentlyContinue
                    }
                    
                    $userMembers = @($members | Where-Object { $_.objectClass -eq 'user' })
                    
                    Write-Host "  Members: $($userMembers.Count)" -ForegroundColor White
                    
                    $groupInfo = [PSCustomObject]@{
                        GroupName = $groupName
                        MemberCount = $userMembers.Count
                        Members = @()
                    }
                    
                    foreach ($member in $userMembers) {
                        # Get detailed user info
                        $user = Get-ADUser -Identity $member -Properties Enabled, PasswordLastSet, LastLogonDate, whenCreated, AdminCount -Server $Domain
                        
                        # Track unique users
                        if (-not $allPrivilegedUsers.ContainsKey($user.SamAccountName)) {
                            $allPrivilegedUsers[$user.SamAccountName] = @{
                                User = $user
                                Groups = @()
                            }
                        }
                        $allPrivilegedUsers[$user.SamAccountName].Groups += $groupName
                        
                        $memberInfo = [PSCustomObject]@{
                            Username = $user.SamAccountName
                            DisplayName = $user.Name
                            Enabled = $user.Enabled
                            Created = $user.whenCreated
                            PasswordLastSet = $user.PasswordLastSet
                            LastLogon = $user.LastLogonDate
                        }
                        
                        $groupInfo.Members += $memberInfo
                        
                        # Check for issues
                        if (-not $user.Enabled) {
                            $results.Statistics.DisabledAccounts++
                        } else {
                            $results.Statistics.EnabledAccounts++
                        }
                        
                        if ($CheckLastLogon -and $user.LastLogonDate) {
                            $daysSinceLogon = (New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).Days
                            if ($daysSinceLogon -gt 90) {
                                $results.Statistics.StaleAccounts++
                                $results.Findings += [PSCustomObject]@{
                                    Severity = 'Medium'
                                    Type = 'Stale Account'
                                    Account = $user.SamAccountName
                                    Group = $groupName
                                    Issue = "Last logon: $daysSinceLogon days ago"
                                }
                            }
                        }
                        
                        if (-not $user.LastLogonDate) {
                            $results.Statistics.AccountsWithoutLogon++
                        }
                    }
                    
                    $results.PrivilegedGroups += $groupInfo
                    
                    # Warn if group has too many members
                    if ($groupName -in @('Domain Admins', 'Enterprise Admins') -and $userMembers.Count -gt 5) {
                        $results.Findings += [PSCustomObject]@{
                            Severity = 'High'
                            Type = 'Excessive Membership'
                            Group = $groupName
                            Issue = "$($userMembers.Count) members (recommended: ≤5)"
                        }
                    }
                }
                catch {
                    Write-Warning "Error processing group $groupName : $_"
                }
            }
            
            # Process unique privileged accounts
            Write-Host "`nProcessing privileged accounts..." -ForegroundColor Cyan
            
            foreach ($username in $allPrivilegedUsers.Keys) {
                $userInfo = $allPrivilegedUsers[$username]
                $user = $userInfo.User
                
                $passwordAge = if ($user.PasswordLastSet) {
                    (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
                } else {
                    $null
                }
                
                $lastLogonAge = if ($user.LastLogonDate) {
                    (New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).Days
                } else {
                    "Never"
                }
                
                $accountInfo = [PSCustomObject]@{
                    Username = $user.SamAccountName
                    DisplayName = $user.Name
                    Enabled = $user.Enabled
                    Groups = $userInfo.Groups -join ', '
                    GroupCount = $userInfo.Groups.Count
                    PasswordAge = $passwordAge
                    LastLogon = $user.LastLogonDate
                    LastLogonAge = $lastLogonAge
                    Created = $user.whenCreated
                    AdminCount = $user.AdminCount
                }
                
                $results.PrivilegedAccounts += $accountInfo
                
                # Check for anomalies
                if ($user.Enabled -and $passwordAge -gt 180) {
                    $results.Findings += [PSCustomObject]@{
                        Severity = 'High'
                        Type = 'Old Password'
                        Account = $user.SamAccountName
                        Issue = "Password not changed in $passwordAge days"
                    }
                }
                
                if ($userInfo.Groups.Count -gt 3) {
                    $results.Findings += [PSCustomObject]@{
                        Severity = 'Medium'
                        Type = 'Excessive Privileges'
                        Account = $user.SamAccountName
                        Issue = "Member of $($userInfo.Groups.Count) privileged groups"
                    }
                }
            }
            
            $results.Statistics.TotalPrivilegedAccounts = $allPrivilegedUsers.Count
            
            # Generate recommendations
            if ($results.Statistics.DisabledAccounts -gt 0) {
                $results.Recommendations += "Remove $($results.Statistics.DisabledAccounts) disabled accounts from privileged groups"
            }
            
            if ($results.Statistics.StaleAccounts -gt 0) {
                $results.Recommendations += "Review $($results.Statistics.StaleAccounts) stale privileged accounts (90+ days inactive)"
            }
            
            if ($results.Statistics.TotalPrivilegedAccounts -gt 20) {
                $results.Recommendations += "Reduce total privileged accounts (current: $($results.Statistics.TotalPrivilegedAccounts))"
            }
            
            $results.Recommendations += "Implement privileged access workstations (PAWs)"
            $results.Recommendations += "Enable MFA for all privileged accounts"
            $results.Recommendations += "Regular privileged account audits (quarterly)"
            
        }
        catch {
            Write-Error "Error analyzing privileged accounts: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nStatistics:" -ForegroundColor Cyan
        Write-Host "  Total Privileged Accounts: $($results.Statistics.TotalPrivilegedAccounts)" -ForegroundColor White
        Write-Host "  Enabled: $($results.Statistics.EnabledAccounts)" -ForegroundColor Green
        Write-Host "  Disabled: $($results.Statistics.DisabledAccounts)" -ForegroundColor Yellow
        Write-Host "  Stale (90+ days): $($results.Statistics.StaleAccounts)" -ForegroundColor Red
        
        Write-Host "`nTop Privileged Groups:" -ForegroundColor Cyan
        $results.PrivilegedGroups | Sort-Object -Property MemberCount -Descending | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.GroupName): $($_.MemberCount) members" -ForegroundColor White
        }
        
        if ($results.Findings.Count -gt 0) {
            Write-Host "`nFindings: $($results.Findings.Count)" -ForegroundColor Yellow
            $results.Findings | Group-Object Severity | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $(
                    switch ($_.Name) {
                        'High' { 'Red' }
                        'Medium' { 'Yellow' }
                        default { 'White' }
                    }
                )
            }
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $results
    }
}