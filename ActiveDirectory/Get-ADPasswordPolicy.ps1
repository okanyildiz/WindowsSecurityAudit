function Get-ADPasswordPolicy {
    <#
    .SYNOPSIS
        Retrieves and analyzes Active Directory password policies
    .DESCRIPTION
        Gets domain default password policy and fine-grained password policies (PSOs)
        with security analysis and recommendations
    .PARAMETER Domain
        Target domain
    .PARAMETER IncludeFineGrained
        Include Fine-Grained Password Policies (PSOs)
    .EXAMPLE
        Get-ADPasswordPolicy
        Get-ADPasswordPolicy -IncludeFineGrained -Domain "contoso.com"
    .OUTPUTS
        PSCustomObject with password policy information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,
        
        [Parameter()]
        [switch]$IncludeFineGrained
    )
    
    begin {
        Write-Host "=== AD PASSWORD POLICY ANALYSIS ===" -ForegroundColor Cyan
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module required"
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        Write-Host "Domain: $Domain" -ForegroundColor Yellow
        
        $analysis = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $Domain
            DefaultPolicy = @{}
            FineGrainedPolicies = @()
            SecurityScore = 0
            MaxScore = 100
            Findings = @()
            Recommendations = @()
        }
    }
    
    process {
        try {
            # 1. Get Default Domain Password Policy
            Write-Host "`nAnalyzing Default Password Policy..." -ForegroundColor Cyan
            
            $policy = Get-ADDefaultDomainPasswordPolicy -Server $Domain
            
            $score = 0
            
            # Complexity (20 points)
            if ($policy.ComplexityEnabled) {
                $score += 20
                Write-Host "  + Complexity Enabled: Yes" -ForegroundColor Green
            } else {
                Write-Host "  - Complexity Enabled: No" -ForegroundColor Red
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Finding = 'Password complexity is disabled'
                    Impact = 'Weak passwords can be set'
                }
            }
            
            # Min Length (25 points)
            Write-Host "  Min Password Length: $($policy.MinPasswordLength)" -ForegroundColor $(
                if ($policy.MinPasswordLength -ge 14) { 'Green' }
                elseif ($policy.MinPasswordLength -ge 12) { 'Yellow' }
                else { 'Red' }
            )
            
            if ($policy.MinPasswordLength -ge 14) {
                $score += 25
            } elseif ($policy.MinPasswordLength -ge 12) {
                $score += 20
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Finding = "Minimum password length is $($policy.MinPasswordLength) (recommended: 14+)"
                    Impact = 'Increased vulnerability to brute force'
                }
            } elseif ($policy.MinPasswordLength -ge 8) {
                $score += 10
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Finding = "Minimum password length is only $($policy.MinPasswordLength)"
                    Impact = 'Significant vulnerability to brute force'
                }
            } else {
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Finding = "Minimum password length is critically low ($($policy.MinPasswordLength))"
                    Impact = 'Extremely vulnerable to brute force'
                }
            }
            
            # Password History (10 points)
            Write-Host "  Password History: $($policy.PasswordHistoryCount)" -ForegroundColor $(
                if ($policy.PasswordHistoryCount -ge 24) { 'Green' }
                elseif ($policy.PasswordHistoryCount -ge 12) { 'Yellow' }
                else { 'Red' }
            )
            
            if ($policy.PasswordHistoryCount -ge 24) {
                $score += 10
            } elseif ($policy.PasswordHistoryCount -ge 12) {
                $score += 7
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Low'
                    Finding = "Password history count is $($policy.PasswordHistoryCount) (recommended: 24)"
                    Impact = 'Users can reuse passwords more frequently'
                }
            } else {
                $score += 3
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Finding = "Password history count is only $($policy.PasswordHistoryCount)"
                    Impact = 'Password reuse is not adequately prevented'
                }
            }
            
            # Max Password Age (15 points)
            Write-Host "  Max Password Age: $($policy.MaxPasswordAge.Days) days" -ForegroundColor $(
                if ($policy.MaxPasswordAge.Days -le 90 -and $policy.MaxPasswordAge.Days -gt 0) { 'Green' }
                elseif ($policy.MaxPasswordAge.Days -le 180) { 'Yellow' }
                else { 'Red' }
            )
            
            if ($policy.MaxPasswordAge.Days -le 90 -and $policy.MaxPasswordAge.Days -gt 0) {
                $score += 15
            } elseif ($policy.MaxPasswordAge.Days -le 180) {
                $score += 10
            } else {
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Medium'
                    Finding = "Password max age is $($policy.MaxPasswordAge.Days) days"
                    Impact = 'Passwords not rotated frequently enough'
                }
            }
            
            # Lockout Policy (20 points)
            if ($policy.LockoutThreshold -gt 0) {
                Write-Host "  Lockout Threshold: $($policy.LockoutThreshold) attempts" -ForegroundColor $(
                    if ($policy.LockoutThreshold -le 5) { 'Green' } else { 'Yellow' }
                )
                
                if ($policy.LockoutThreshold -le 5) {
                    $score += 15
                } else {
                    $score += 10
                    $analysis.Findings += [PSCustomObject]@{
                        Severity = 'Low'
                        Finding = "Lockout threshold is $($policy.LockoutThreshold) (recommended: 5 or less)"
                        Impact = 'More attempts allowed for password guessing'
                    }
                }
                
                Write-Host "  Lockout Duration: $($policy.LockoutDuration.TotalMinutes) minutes" -ForegroundColor Green
                
                if ($policy.LockoutDuration.TotalMinutes -ge 15) {
                    $score += 5
                }
            } else {
                Write-Host "  - Lockout Policy: Disabled" -ForegroundColor Red
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'High'
                    Finding = 'Account lockout policy is disabled'
                    Impact = 'No protection against brute force attacks'
                }
            }
            
            # Reversible Encryption (10 points)
            if ($policy.ReversibleEncryptionEnabled -eq $false) {
                $score += 10
                Write-Host "  + Reversible Encryption: Disabled" -ForegroundColor Green
            } else {
                Write-Host "  - Reversible Encryption: Enabled" -ForegroundColor Red
                $analysis.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Finding = 'Reversible encryption is enabled'
                    Impact = 'Passwords stored in plaintext-equivalent form'
                }
            }
            
            $analysis.SecurityScore = $score
            
            $analysis.DefaultPolicy = [PSCustomObject]@{
                ComplexityEnabled = $policy.ComplexityEnabled
                MinPasswordLength = $policy.MinPasswordLength
                PasswordHistoryCount = $policy.PasswordHistoryCount
                MaxPasswordAge = $policy.MaxPasswordAge.Days
                MinPasswordAge = $policy.MinPasswordAge.Days
                LockoutThreshold = $policy.LockoutThreshold
                LockoutDuration = $policy.LockoutDuration.TotalMinutes
                LockoutObservationWindow = $policy.LockoutObservationWindow.TotalMinutes
                ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
                DistinguishedName = $policy.DistinguishedName
            }
            
            # 2. Get Fine-Grained Password Policies
            if ($IncludeFineGrained) {
                Write-Host "`nAnalyzing Fine-Grained Password Policies (PSOs)..." -ForegroundColor Cyan
                
                try {
                    $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain
                    
                    if ($psos) {
                        Write-Host "  Found $($psos.Count) Fine-Grained Password Policies" -ForegroundColor Yellow
                        
                        foreach ($pso in $psos) {
                            $appliesTo = Get-ADFineGrainedPasswordPolicySubject -Identity $pso -Server $Domain
                            
                            $psoInfo = [PSCustomObject]@{
                                Name = $pso.Name
                                Precedence = $pso.Precedence
                                ComplexityEnabled = $pso.ComplexityEnabled
                                MinPasswordLength = $pso.MinPasswordLength
                                PasswordHistoryCount = $pso.PasswordHistoryCount
                                MaxPasswordAge = $pso.MaxPasswordAge.Days
                                LockoutThreshold = $pso.LockoutThreshold
                                AppliesTo = $appliesTo.Count
                                AppliesToObjects = $appliesTo.Name -join ', '
                            }
                            
                            $analysis.FineGrainedPolicies += $psoInfo
                            
                            Write-Host "`n  PSO: $($pso.Name)" -ForegroundColor White
                            Write-Host "    Precedence: $($pso.Precedence)" -ForegroundColor Gray
                            Write-Host "    Min Length: $($pso.MinPasswordLength)" -ForegroundColor Gray
                            Write-Host "    Applies To: $($appliesTo.Count) objects" -ForegroundColor Gray
                        }
                    } else {
                        Write-Host "  No Fine-Grained Password Policies configured" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Could not retrieve Fine-Grained Password Policies: $_"
                }
            }
            
            # Generate recommendations
            if ($policy.MinPasswordLength -lt 14) {
                $analysis.Recommendations += "Increase minimum password length to 14+ characters"
            }
            
            if (-not $policy.ComplexityEnabled) {
                $analysis.Recommendations += "Enable password complexity requirements immediately"
            }
            
            if ($policy.LockoutThreshold -eq 0) {
                $analysis.Recommendations += "Enable account lockout policy (5 attempts recommended)"
            }
            
            if ($policy.PasswordHistoryCount -lt 24) {
                $analysis.Recommendations += "Increase password history to 24 remembered passwords"
            }
            
            if ($policy.ReversibleEncryptionEnabled) {
                $analysis.Recommendations += "Disable reversible encryption immediately"
            }
            
            $analysis.Recommendations += "Consider implementing Fine-Grained Password Policies for privileged accounts"
            $analysis.Recommendations += "Regular password policy audits (quarterly)"
            
        }
        catch {
            Write-Error "Error analyzing password policies: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nPassword Policy Security Score: $($analysis.SecurityScore)/100" -ForegroundColor $(
            if ($analysis.SecurityScore -ge 80) { 'Green' }
            elseif ($analysis.SecurityScore -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        
        if ($analysis.Findings.Count -gt 0) {
            Write-Host "`nFindings: $($analysis.Findings.Count)" -ForegroundColor Yellow
            $analysis.Findings | Group-Object Severity | ForEach-Object {
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
        
        if ($analysis.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $analysis.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $analysis
    }
}