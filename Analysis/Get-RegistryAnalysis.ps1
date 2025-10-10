function Get-RegistryAnalysis {
    <#
    .SYNOPSIS
        Analyzes Windows Registry for security-relevant keys and modifications
    .DESCRIPTION
        Scans critical registry locations for suspicious entries, unauthorized modifications,
        and security misconfigurations
    .PARAMETER IncludeAutoRun
        Include AutoRun registry locations in analysis
    .PARAMETER CheckPermissions
        Check registry key permissions for anomalies
    .PARAMETER ExportPath
        Path to export detailed results
    .EXAMPLE
        Get-RegistryAnalysis
        Get-RegistryAnalysis -IncludeAutoRun -CheckPermissions -ExportPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with registry analysis results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeAutoRun,
        
        [Parameter()]
        [switch]$CheckPermissions,
        
        [Parameter()]
        [string]$ExportPath
    )
    
    begin {
        Write-Host "Analyzing Windows Registry..." -ForegroundColor Cyan
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SecuritySettings = @()
            AutoRunEntries = @()
            ServiceKeys = @()
            PolicyKeys = @()
            SuspiciousKeys = @()
            PermissionIssues = @()
            Statistics = @{
                TotalKeysScanned = 0
                SuspiciousFindings = 0
                AutoRunCount = 0
                PermissionIssues = 0
            }
        }
        
        # Critical registry paths to analyze
        $criticalPaths = @{
            # Security settings
            'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' = 'LSA Security Settings'
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = 'System Policies'
            'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' = 'SMB Settings'
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' = 'WDigest Settings'
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog' = 'Event Log Policies'
            
            # Services
            'HKLM:\SYSTEM\CurrentControlSet\Services' = 'Services'
        }
        
        # AutoRun locations
        $autoRunPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
            'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        )
    }
    
    process {
        try {
            # Analyze critical security settings
            Write-Verbose "Analyzing security settings..."
            foreach ($path in $criticalPaths.Keys) {
                if (Test-Path $path) {
                    try {
                        $key = Get-Item -Path $path -ErrorAction Stop
                        $results.Statistics.TotalKeysScanned++
                        
                        $properties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                        
                        # Analyze LSA settings
                        if ($path -match 'Lsa$') {
                            $keyObj = [PSCustomObject]@{
                                Path = $path
                                Category = $criticalPaths[$path]
                                RestrictAnonymous = $properties.RestrictAnonymous
                                LimitBlankPasswordUse = $properties.LimitBlankPasswordUse
                                NoLMHash = $properties.NoLMHash
                                DisableDomainCreds = $properties.DisableDomainCreds
                                EveryoneIncludesAnonymous = $properties.EveryoneIncludesAnonymous
                                Findings = @()
                            }
                            
                            # Check for security issues
                            if ($properties.RestrictAnonymous -ne 1) {
                                $keyObj.Findings += "RestrictAnonymous not set to secure value"
                                $results.Statistics.SuspiciousFindings++
                            }
                            if ($properties.LimitBlankPasswordUse -ne 1) {
                                $keyObj.Findings += "Blank passwords not restricted"
                                $results.Statistics.SuspiciousFindings++
                            }
                            
                            $results.SecuritySettings += $keyObj
                        }
                        
                        # Analyze WDigest settings
                        if ($path -match 'WDigest$') {
                            $useLogonCredential = $properties.UseLogonCredential
                            if ($useLogonCredential -eq 1) {
                                $results.SecuritySettings += [PSCustomObject]@{
                                    Path = $path
                                    Category = 'WDigest Credential Caching'
                                    Finding = 'WDigest credential caching is ENABLED - credentials stored in plaintext!'
                                    Severity = 'Critical'
                                    Recommendation = 'Set UseLogonCredential to 0'
                                }
                                $results.Statistics.SuspiciousFindings++
                            }
                        }
                        
                        # Analyze UAC settings
                        if ($path -match 'Policies\\System$') {
                            $keyObj = [PSCustomObject]@{
                                Path = $path
                                Category = 'User Account Control'
                                EnableLUA = $properties.EnableLUA
                                ConsentPromptBehaviorAdmin = $properties.ConsentPromptBehaviorAdmin
                                EnableInstallerDetection = $properties.EnableInstallerDetection
                                PromptOnSecureDesktop = $properties.PromptOnSecureDesktop
                                Findings = @()
                            }
                            
                            if ($properties.EnableLUA -ne 1) {
                                $keyObj.Findings += "UAC is disabled"
                                $results.Statistics.SuspiciousFindings++
                            }
                            if ($properties.PromptOnSecureDesktop -ne 1) {
                                $keyObj.Findings += "UAC not prompting on secure desktop"
                            }
                            
                            $results.SecuritySettings += $keyObj
                        }
                        
                    }
                    catch {
                        Write-Verbose "Could not analyze $path : $_"
                    }
                }
            }
            
            # Analyze AutoRun entries if requested
            if ($IncludeAutoRun) {
                Write-Verbose "Analyzing AutoRun registry locations..."
                foreach ($path in $autoRunPaths) {
                    if (Test-Path $path) {
                        try {
                            $properties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                            
                            if ($properties) {
                                $properties.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                                    $isSuspicious = $false
                                    $reasons = @()
                                    
                                    # Check for suspicious indicators
                                    if ($_.Value -match '(temp|appdata\\local\\temp|users\\public)') {
                                        $isSuspicious = $true
                                        $reasons += "Running from temporary or public location"
                                    }
                                    
                                    if ($_.Value -match '(cmd|powershell|wscript|cscript|mshta).*\.(exe|bat|vbs|js)') {
                                        $isSuspicious = $true
                                        $reasons += "Executes scripting engine"
                                    }
                                    
                                    $results.AutoRunEntries += [PSCustomObject]@{
                                        Location = $path
                                        Name = $_.Name
                                        Value = $_.Value
                                        Suspicious = $isSuspicious
                                        Reasons = if ($reasons) { $reasons -join '; ' } else { $null }
                                    }
                                    
                                    $results.Statistics.AutoRunCount++
                                    if ($isSuspicious) { $results.Statistics.SuspiciousFindings++ }
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not analyze AutoRun path $path : $_"
                        }
                    }
                }
            }
            
            # Analyze service keys
            Write-Verbose "Analyzing service registry keys..."
            $servicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services'
            if (Test-Path $servicePath) {
                $services = Get-ChildItem -Path $servicePath -ErrorAction SilentlyContinue | 
                    Select-Object -First 50  # Limit to avoid performance issues
                
                foreach ($service in $services) {
                    try {
                        $serviceProps = Get-ItemProperty -Path $service.PSPath -ErrorAction SilentlyContinue
                        
                        if ($serviceProps.ImagePath) {
                            $isSuspicious = $false
                            $reasons = @()
                            
                            # Check for suspicious service paths
                            if ($serviceProps.ImagePath -match '(temp|appdata|users\\public)') {
                                $isSuspicious = $true
                                $reasons += "Service running from suspicious location"
                            }
                            
                            # Check for services without proper quotes
                            if ($serviceProps.ImagePath -match '^[A-Z]:\\.*\s.*\.exe' -and 
                                $serviceProps.ImagePath -notmatch '^"') {
                                $isSuspicious = $true
                                $reasons += "Unquoted service path with spaces (potential privilege escalation)"
                            }
                            
                            if ($isSuspicious) {
                                $results.ServiceKeys += [PSCustomObject]@{
                                    ServiceName = $service.PSChildName
                                    ImagePath = $serviceProps.ImagePath
                                    Start = $serviceProps.Start
                                    Reasons = $reasons -join '; '
                                }
                                $results.Statistics.SuspiciousFindings++
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not analyze service $($service.PSChildName)"
                    }
                }
            }
            
            # Check registry permissions if requested
            if ($CheckPermissions) {
                Write-Verbose "Checking registry key permissions..."
                $criticalKeysToCheck = @(
                    'HKLM:\SAM',
                    'HKLM:\SECURITY',
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                )
                
                foreach ($keyPath in $criticalKeysToCheck) {
                    if (Test-Path $keyPath) {
                        try {
                            $acl = Get-Acl -Path $keyPath -ErrorAction Stop
                            
                            # Check for overly permissive access
                            foreach ($access in $acl.Access) {
                                if ($access.IdentityReference -match '(Everyone|Users|Authenticated Users)' -and
                                    $access.FileSystemRights -match '(FullControl|Write|Modify)') {
                                    
                                    $results.PermissionIssues += [PSCustomObject]@{
                                        Path = $keyPath
                                        Identity = $access.IdentityReference
                                        Rights = $access.FileSystemRights
                                        AccessControlType = $access.AccessControlType
                                        Severity = 'High'
                                    }
                                    $results.Statistics.PermissionIssues++
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not check permissions for $keyPath"
                        }
                    }
                }
            }
            
        }
        catch {
            Write-Error "Error during registry analysis: $_"
            throw
        }
    }
    
    end {
        # Display summary
        Write-Host "`nRegistry Analysis Complete!" -ForegroundColor Green
        Write-Host "`n=== Statistics ===" -ForegroundColor Cyan
        Write-Host "Keys scanned: $($results.Statistics.TotalKeysScanned)" -ForegroundColor Yellow
        Write-Host "Suspicious findings: $($results.Statistics.SuspiciousFindings)" -ForegroundColor $(if ($results.Statistics.SuspiciousFindings -gt 0) { 'Red' } else { 'Green' })
        
        if ($IncludeAutoRun) {
            Write-Host "AutoRun entries found: $($results.Statistics.AutoRunCount)" -ForegroundColor Yellow
        }
        
        if ($CheckPermissions) {
            Write-Host "Permission issues: $($results.Statistics.PermissionIssues)" -ForegroundColor $(if ($results.Statistics.PermissionIssues -gt 0) { 'Red' } else { 'Green' })
        }
        
        # Export if requested
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "RegistryAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Host "`nResults exported to: $exportFile" -ForegroundColor Cyan
        }
        
        return $results
    }
}