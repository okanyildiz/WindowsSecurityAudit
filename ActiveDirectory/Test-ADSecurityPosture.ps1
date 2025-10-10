function Test-ADSecurityPosture {
    <#
    .SYNOPSIS
        Performs comprehensive Active Directory security assessment
    .DESCRIPTION
        Tests AD security posture including domain policies, GPO settings,
        trust relationships, and overall security configuration
    .PARAMETER Domain
        Target domain
    .PARAMETER IncludeTrusts
        Check domain trusts
    .PARAMETER IncludeGPO
        Analyze Group Policy Objects
    .EXAMPLE
        Test-ADSecurityPosture
        Test-ADSecurityPosture -IncludeTrusts -IncludeGPO
    .OUTPUTS
        PSCustomObject with security posture assessment
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,
        
        [Parameter()]
        [switch]$IncludeTrusts,
        
        [Parameter()]
        [switch]$IncludeGPO
    )
    
    begin {
        Write-Host "=== AD SECURITY POSTURE ASSESSMENT ===" -ForegroundColor Cyan
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module required"
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        Write-Host "Domain: $Domain" -ForegroundColor Yellow
        
        $assessment = [PSCustomObject]@{
            AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            SecurityScore = 0
            MaxScore = 100
            Categories = @{
                PasswordPolicy = @{}
                AccountPolicy = @{}
                DomainControllers = @{}
                Trusts = @{}
                GPOs = @{}
            }
            Findings = @()
            Recommendations = @()
        }
    }
    
    process {
        try {
            # 1. Password Policy Assessment
            Write-Host "`n[1/5] Assessing Password Policy..." -ForegroundColor Cyan
            
            $passwordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Domain
            $score = 0
            $maxPolicyScore = 25
            
            if ($passwordPolicy.ComplexityEnabled) {
                $score += 10
                Write-Host "  + Complexity: Enabled" -ForegroundColor Green
            } else {
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Category = 'Password Policy'
                    Finding = 'Password complexity is disabled'
                }
                Write-Host "  - Complexity: Disabled" -ForegroundColor Red
            }
            
            if ($passwordPolicy.MinPasswordLength -ge 14) {
                $score += 10
                Write-Host "  + Min Length: $($passwordPolicy.MinPasswordLength) chars" -ForegroundColor Green
            } elseif ($passwordPolicy.MinPasswordLength -ge 12) {
                $score += 7
                Write-Host "  ~ Min Length: $($passwordPolicy.MinPasswordLength) chars (recommended: 14+)" -ForegroundColor Yellow
            } else {
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'Password Policy'
                    Finding = "Minimum password length is only $($passwordPolicy.MinPasswordLength) characters"
                }
                Write-Host "  - Min Length: $($passwordPolicy.MinPasswordLength) chars" -ForegroundColor Red
            }
            
            if ($passwordPolicy.MaxPasswordAge.Days -le 90 -and $passwordPolicy.MaxPasswordAge.Days -gt 0) {
                $score += 5
                Write-Host "  + Max Age: $($passwordPolicy.MaxPasswordAge.Days) days" -ForegroundColor Green
            } else {
                Write-Host "  ~ Max Age: $($passwordPolicy.MaxPasswordAge.Days) days" -ForegroundColor Yellow
            }
            
            $assessment.Categories.PasswordPolicy = @{
                Score = $score
                MaxScore = $maxPolicyScore
                ComplexityEnabled = $passwordPolicy.ComplexityEnabled
                MinPasswordLength = $passwordPolicy.MinPasswordLength
                MaxPasswordAge = $passwordPolicy.MaxPasswordAge.Days
                MinPasswordAge = $passwordPolicy.MinPasswordAge.Days
                PasswordHistoryCount = $passwordPolicy.PasswordHistoryCount
            }
            
            $assessment.SecurityScore += $score
            
            # 2. Account Lockout Policy
            Write-Host "`n[2/5] Assessing Account Lockout Policy..." -ForegroundColor Cyan
            
            $lockoutScore = 0
            $maxLockoutScore = 15
            
            if ($passwordPolicy.LockoutThreshold -gt 0) {
                if ($passwordPolicy.LockoutThreshold -le 5) {
                    $lockoutScore += 10
                    Write-Host "  + Lockout Threshold: $($passwordPolicy.LockoutThreshold) attempts" -ForegroundColor Green
                } else {
                    $lockoutScore += 5
                    Write-Host "  ~ Lockout Threshold: $($passwordPolicy.LockoutThreshold) attempts" -ForegroundColor Yellow
                }
                
                if ($passwordPolicy.LockoutDuration.TotalMinutes -ge 15) {
                    $lockoutScore += 5
                    Write-Host "  + Lockout Duration: $($passwordPolicy.LockoutDuration.TotalMinutes) minutes" -ForegroundColor Green
                }
            } else {
                $assessment.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Category = 'Account Policy'
                    Finding = 'Account lockout is disabled'
                }
                Write-Host "  - Account Lockout: Disabled" -ForegroundColor Red
            }
            
            $assessment.Categories.AccountPolicy = @{
                Score = $lockoutScore
                MaxScore = $maxLockoutScore
                LockoutThreshold = $passwordPolicy.LockoutThreshold
                LockoutDuration = $passwordPolicy.LockoutDuration.TotalMinutes
                LockoutWindow = $passwordPolicy.LockoutObservationWindow.TotalMinutes
            }
            
            $assessment.SecurityScore += $lockoutScore
            
            # 3. Domain Controllers
            Write-Host "`n[3/5] Checking Domain Controllers..." -ForegroundColor Cyan
            
            $dcs = Get-ADDomainController -Filter * -Server $Domain
            $dcScore = 0
            $maxDCScore = 20
            
            Write-Host "  Found $($dcs.Count) Domain Controllers" -ForegroundColor White
            
            foreach ($dc in $dcs) {
                if ($dc.IsReadOnly) {
                    Write-Host "  ~ $($dc.Name) [RODC]" -ForegroundColor Yellow
                } else {
                    Write-Host "  + $($dc.Name)" -ForegroundColor Green
                }
            }
            
            if ($dcs.Count -ge 2) {
                $dcScore += 10
            }
            
            # Check for Server 2012 or older
            foreach ($dc in $dcs) {
                $os = $dc.OperatingSystem
                if ($os -match "2012|2008") {
                    $assessment.Findings += [PSCustomObject]@{
                        Severity = 'High'
                        Category = 'Domain Controllers'
                        Finding = "$($dc.Name) running unsupported OS: $os"
                    }
                }
            }
            
            $dcScore += 10
            $assessment.Categories.DomainControllers = @{
                Score = $dcScore
                MaxScore = $maxDCScore
                Count = $dcs.Count
                Controllers = $dcs.Name
            }
            
            $assessment.SecurityScore += $dcScore
            
            # 4. Domain Trusts
            if ($IncludeTrusts) {
                Write-Host "`n[4/5] Analyzing Domain Trusts..." -ForegroundColor Cyan
                
                $trusts = Get-ADTrust -Filter * -Server $Domain
                $trustScore = 0
                $maxTrustScore = 20
                
                if ($trusts) {
                    Write-Host "  Found $($trusts.Count) trust(s)" -ForegroundColor White
                    
                    foreach ($trust in $trusts) {
                        $trustType = $trust.Direction
                        $trustColor = if ($trust.Direction -eq 'Bidirectional') { 'Yellow' } else { 'Green' }
                        
                        Write-Host "  $($trust.Name) [$trustType]" -ForegroundColor $trustColor
                        
                        if ($trust.Direction -eq 'Bidirectional') {
                            $assessment.Findings += [PSCustomObject]@{
                                Severity = 'Medium'
                                Category = 'Trusts'
                                Finding = "Bidirectional trust with $($trust.Name)"
                            }
                        }
                    }
                    
                    $trustScore += 10
                } else {
                    Write-Host "  No domain trusts configured" -ForegroundColor Green
                    $trustScore += 20
                }
                
                $assessment.Categories.Trusts = @{
                    Score = $trustScore
                    MaxScore = $maxTrustScore
                    Count = $trusts.Count
                    Trusts = $trusts
                }
                
                $assessment.SecurityScore += $trustScore
            }
            
            # 5. GPO Analysis
            if ($IncludeGPO) {
                Write-Host "`n[5/5] Analyzing Group Policy Objects..." -ForegroundColor Cyan
                
                $gpos = Get-GPO -All -Domain $Domain
                $gpoScore = 0
                $maxGPOScore = 20
                
                Write-Host "  Found $($gpos.Count) GPOs" -ForegroundColor White
                
                # Check for unlinked GPOs
                $unlinkedGPOs = @($gpos | Where-Object { 
                    (Get-GPOReport -Guid $_.Id -ReportType Xml -Domain $Domain) -notmatch '<LinksTo>' 
                })
                
                if ($unlinkedGPOs.Count -gt 0) {
                    Write-Host "  ~ $($unlinkedGPOs.Count) unlinked GPOs found" -ForegroundColor Yellow
                    $assessment.Findings += [PSCustomObject]@{
                        Severity = 'Low'
                        Category = 'GPO'
                        Finding = "$($unlinkedGPOs.Count) unlinked GPOs (cleanup recommended)"
                    }
                }
                
                $gpoScore += 20
                $assessment.Categories.GPOs = @{
                    Score = $gpoScore
                    MaxScore = $maxGPOScore
                    TotalCount = $gpos.Count
                    UnlinkedCount = $unlinkedGPOs.Count
                }
                
                $assessment.SecurityScore += $gpoScore
            }
            
            # Calculate final score
            $assessment.SecurityScore = [math]::Round(($assessment.SecurityScore / $assessment.MaxScore) * 100, 0)
            
            # Generate recommendations
            if ($passwordPolicy.MinPasswordLength -lt 14) {
                $assessment.Recommendations += "Increase minimum password length to 14+ characters"
            }
            
            if ($passwordPolicy.LockoutThreshold -eq 0) {
                $assessment.Recommendations += "Enable account lockout policy (5 attempts recommended)"
            }
            
            $assessment.Recommendations += "Implement tiered administrative model"
            $assessment.Recommendations += "Enable audit policies for AD changes"
            $assessment.Recommendations += "Regular security assessments (quarterly)"
            
        }
        catch {
            Write-Error "Error during AD security assessment: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== ASSESSMENT COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nSecurity Score: $($assessment.SecurityScore)/100" -ForegroundColor $(
            if ($assessment.SecurityScore -ge 80) { 'Green' }
            elseif ($assessment.SecurityScore -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        
        Write-Host "`nCategory Scores:" -ForegroundColor Cyan
        foreach ($category in $assessment.Categories.PSObject.Properties) {
            if ($category.Value.Score -ne $null) {
                $percentage = [math]::Round(($category.Value.Score / $category.Value.MaxScore) * 100, 0)
                Write-Host "  $($category.Name): $percentage%" -ForegroundColor White
            }
        }
        
        if ($assessment.Findings.Count -gt 0) {
            Write-Host "`nFindings: $($assessment.Findings.Count)" -ForegroundColor Yellow
            $assessment.Findings | Group-Object Severity | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $(
                    switch ($_.Name) {
                        'Critical' { 'Red' }
                        'High' { 'Red' }
                        'Medium' { 'Yellow' }
                        default { 'White' }
                    }
                )
            }
        }
        
        if ($assessment.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $assessment.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $assessment
    }
}