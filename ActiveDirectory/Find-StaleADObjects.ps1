function Find-StaleADObjects {
    <#
    .SYNOPSIS
        Identifies inactive and stale objects in Active Directory
    .DESCRIPTION
        Finds stale user accounts, computer accounts, and groups that haven't been 
        used within specified time periods
    .PARAMETER InactiveDays
        Number of days to consider an object stale (default: 90)
    .PARAMETER IncludeUsers
        Check for stale user accounts
    .PARAMETER IncludeComputers
        Check for stale computer accounts
    .PARAMETER IncludeGroups
        Check for empty/unused groups
    .PARAMETER Domain
        Target domain
    .EXAMPLE
        Find-StaleADObjects -InactiveDays 90 -IncludeUsers -IncludeComputers
        Find-StaleADObjects -InactiveDays 180 -IncludeUsers -IncludeComputers -IncludeGroups
    .OUTPUTS
        PSCustomObject with stale object information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$InactiveDays = 90,
        
        [Parameter()]
        [switch]$IncludeUsers,
        
        [Parameter()]
        [switch]$IncludeComputers,
        
        [Parameter()]
        [switch]$IncludeGroups,
        
        [Parameter()]
        [string]$Domain
    )
    
    begin {
        Write-Host "=== STALE AD OBJECTS SCAN ===" -ForegroundColor Cyan
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module required"
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        Write-Host "Domain: $Domain" -ForegroundColor Yellow
        Write-Host "Inactive Threshold: $InactiveDays days" -ForegroundColor Yellow
        
        $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            InactiveDays = $InactiveDays
            StaleUsers = @()
            StaleComputers = @()
            StaleGroups = @()
            Statistics = @{
                TotalStaleUsers = 0
                TotalStaleComputers = 0
                EmptyGroups = 0
                TotalObjectsToReview = 0
            }
            Recommendations = @()
        }
    }
    
    process {
        try {
            # 1. Find Stale User Accounts
            if ($IncludeUsers) {
                Write-Host "`n[1/3] Scanning for stale user accounts..." -ForegroundColor Cyan
                
                try {
                    # Get users that haven't logged on in X days
                    $staleUsers = Get-ADUser -Filter {
                        Enabled -eq $true -and 
                        LastLogonDate -lt $cutoffDate
                    } -Properties LastLogonDate, PasswordLastSet, whenCreated, Description -Server $Domain
                    
                    foreach ($user in $staleUsers) {
                        $daysSinceLogon = if ($user.LastLogonDate) {
                            (New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).Days
                        } else {
                            "Never"
                        }
                        
                        $accountAge = (New-TimeSpan -Start $user.whenCreated -End (Get-Date)).Days
                        
                        $results.StaleUsers += [PSCustomObject]@{
                            Username = $user.SamAccountName
                            DisplayName = $user.Name
                            Description = $user.Description
                            Enabled = $user.Enabled
                            LastLogon = $user.LastLogonDate
                            DaysSinceLogon = $daysSinceLogon
                            PasswordLastSet = $user.PasswordLastSet
                            Created = $user.whenCreated
                            AccountAge = $accountAge
                            DistinguishedName = $user.DistinguishedName
                        }
                    }
                    
                    $results.Statistics.TotalStaleUsers = $staleUsers.Count
                    
                    Write-Host "  Found $($staleUsers.Count) stale user accounts" -ForegroundColor $(
                        if ($staleUsers.Count -gt 0) { 'Yellow' } else { 'Green' }
                    )
                    
                    if ($staleUsers.Count -gt 0) {
                        Write-Host "  Top 5 oldest:" -ForegroundColor Yellow
                        $staleUsers | Sort-Object LastLogonDate | Select-Object -First 5 | ForEach-Object {
                            $lastLogon = if ($_.LastLogonDate) { 
                                $_.LastLogonDate.ToString("yyyy-MM-dd") 
                            } else { 
                                "Never" 
                            }
                            Write-Host "    - $($_.SamAccountName) (Last: $lastLogon)" -ForegroundColor White
                        }
                    }
                }
                catch {
                    Write-Warning "Error scanning stale users: $_"
                }
            }
            
            # 2. Find Stale Computer Accounts
            if ($IncludeComputers) {
                Write-Host "`n[2/3] Scanning for stale computer accounts..." -ForegroundColor Cyan
                
                try {
                    # Get computers that haven't connected in X days
                    $staleComputers = Get-ADComputer -Filter {
                        Enabled -eq $true -and 
                        LastLogonDate -lt $cutoffDate
                    } -Properties LastLogonDate, OperatingSystem, whenCreated, Description -Server $Domain
                    
                    foreach ($computer in $staleComputers) {
                        $daysSinceLogon = if ($computer.LastLogonDate) {
                            (New-TimeSpan -Start $computer.LastLogonDate -End (Get-Date)).Days
                        } else {
                            "Never"
                        }
                        
                        $results.StaleComputers += [PSCustomObject]@{
                            ComputerName = $computer.Name
                            Description = $computer.Description
                            OperatingSystem = $computer.OperatingSystem
                            Enabled = $computer.Enabled
                            LastLogon = $computer.LastLogonDate
                            DaysSinceLogon = $daysSinceLogon
                            Created = $computer.whenCreated
                            DistinguishedName = $computer.DistinguishedName
                        }
                    }
                    
                    $results.Statistics.TotalStaleComputers = $staleComputers.Count
                    
                    Write-Host "  Found $($staleComputers.Count) stale computer accounts" -ForegroundColor $(
                        if ($staleComputers.Count -gt 0) { 'Yellow' } else { 'Green' }
                    )
                    
                    if ($staleComputers.Count -gt 0) {
                        Write-Host "  Top 5 oldest:" -ForegroundColor Yellow
                        $staleComputers | Sort-Object LastLogonDate | Select-Object -First 5 | ForEach-Object {
                            $lastLogon = if ($_.LastLogonDate) { 
                                $_.LastLogonDate.ToString("yyyy-MM-dd") 
                            } else { 
                                "Never" 
                            }
                            Write-Host "    - $($_.Name) (Last: $lastLogon)" -ForegroundColor White
                        }
                    }
                }
                catch {
                    Write-Warning "Error scanning stale computers: $_"
                }
            }
            
            # 3. Find Empty/Unused Groups
            if ($IncludeGroups) {
                Write-Host "`n[3/3] Scanning for empty/unused groups..." -ForegroundColor Cyan
                
                try {
                    # Get all groups
                    $allGroups = Get-ADGroup -Filter * -Properties Members, whenCreated, Description -Server $Domain
                    
                    foreach ($group in $allGroups) {
                        $members = Get-ADGroupMember -Identity $group -Server $Domain -ErrorAction SilentlyContinue
                        
                        if ($members.Count -eq 0) {
                            $groupAge = (New-TimeSpan -Start $group.whenCreated -End (Get-Date)).Days
                            
                            $results.StaleGroups += [PSCustomObject]@{
                                GroupName = $group.Name
                                Description = $group.Description
                                MemberCount = 0
                                Created = $group.whenCreated
                                GroupAge = $groupAge
                                GroupScope = $group.GroupScope
                                GroupCategory = $group.GroupCategory
                                DistinguishedName = $group.DistinguishedName
                            }
                        }
                    }
                    
                    $results.Statistics.EmptyGroups = $results.StaleGroups.Count
                    
                    Write-Host "  Found $($results.StaleGroups.Count) empty groups" -ForegroundColor $(
                        if ($results.StaleGroups.Count -gt 0) { 'Yellow' } else { 'Green' }
                    )
                    
                    if ($results.StaleGroups.Count -gt 0) {
                        Write-Host "  Top 5 oldest empty groups:" -ForegroundColor Yellow
                        $results.StaleGroups | Sort-Object Created | Select-Object -First 5 | ForEach-Object {
                            Write-Host "    - $($_.GroupName) (Created: $($_.Created.ToString('yyyy-MM-dd')))" -ForegroundColor White
                        }
                    }
                }
                catch {
                    Write-Warning "Error scanning groups: $_"
                }
            }
            
            # Calculate total objects to review
            $results.Statistics.TotalObjectsToReview = 
                $results.Statistics.TotalStaleUsers + 
                $results.Statistics.TotalStaleComputers + 
                $results.Statistics.EmptyGroups
            
            # Generate recommendations
            if ($results.Statistics.TotalStaleUsers -gt 0) {
                $results.Recommendations += "Review and disable $($results.Statistics.TotalStaleUsers) stale user accounts"
                $results.Recommendations += "Move disabled accounts to separate OU after 30 days"
                $results.Recommendations += "Delete disabled accounts after 90 days (with backup)"
            }
            
            if ($results.Statistics.TotalStaleComputers -gt 0) {
                $results.Recommendations += "Remove $($results.Statistics.TotalStaleComputers) stale computer accounts"
            }
            
            if ($results.Statistics.EmptyGroups -gt 0) {
                $results.Recommendations += "Review and remove $($results.Statistics.EmptyGroups) empty groups"
            }
            
            $results.Recommendations += "Implement automated stale object cleanup policy"
            $results.Recommendations += "Schedule monthly stale object reviews"
            
        }
        catch {
            Write-Error "Error scanning for stale objects: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nStatistics:" -ForegroundColor Cyan
        Write-Host "  Stale Users: $($results.Statistics.TotalStaleUsers)" -ForegroundColor White
        Write-Host "  Stale Computers: $($results.Statistics.TotalStaleComputers)" -ForegroundColor White
        Write-Host "  Empty Groups: $($results.Statistics.EmptyGroups)" -ForegroundColor White
        Write-Host "  Total Objects to Review: $($results.Statistics.TotalObjectsToReview)" -ForegroundColor $(
            if ($results.Statistics.TotalObjectsToReview -gt 0) { 'Yellow' } else { 'Green' }
        )
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`nCleanup Impact:" -ForegroundColor Cyan
        if ($results.Statistics.TotalObjectsToReview -gt 0) {
            Write-Host "  Removing stale objects will improve AD performance" -ForegroundColor White
            Write-Host "  Reduce AD replication traffic" -ForegroundColor White
            Write-Host "  Improve security posture" -ForegroundColor White
        }
        
        return $results
    }
}