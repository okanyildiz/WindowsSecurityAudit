function Enable-PowerShellSecurity {
    <#
    .SYNOPSIS
        Hardens PowerShell security settings
    .DESCRIPTION
        Configures PowerShell security features including execution policy, logging,
        transcription, and constrained language mode
    .PARAMETER ExecutionPolicy
        Set execution policy (default: RemoteSigned)
    .PARAMETER EnableScriptBlockLogging
        Enable PowerShell script block logging
    .PARAMETER EnableTranscription
        Enable PowerShell transcription logging
    .PARAMETER EnableModuleLogging
        Enable PowerShell module logging
    .PARAMETER TranscriptionPath
        Path for transcription logs
    .EXAMPLE
        Enable-PowerShellSecurity -ExecutionPolicy RemoteSigned -EnableScriptBlockLogging
        Enable-PowerShellSecurity -EnableTranscription -TranscriptionPath "C:\PSLogs"
    .OUTPUTS
        PSCustomObject with configuration results
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateSet('Restricted', 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass')]
        [string]$ExecutionPolicy = 'RemoteSigned',
        
        [Parameter()]
        [switch]$EnableScriptBlockLogging,
        
        [Parameter()]
        [switch]$EnableTranscription,
        
        [Parameter()]
        [switch]$EnableModuleLogging,
        
        [Parameter()]
        [string]$TranscriptionPath = "C:\PowerShellLogs"
    )
    
    begin {
        Write-Host "=== POWERSHELL SECURITY HARDENING ===" -ForegroundColor Cyan
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges!"
        }
        
        $results = [PSCustomObject]@{
            ConfigurationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ExecutionPolicy = @{
                Before = $null
                After = $null
                Status = 'Not Changed'
            }
            ScriptBlockLogging = @{
                Enabled = $false
                Status = 'Not Configured'
            }
            Transcription = @{
                Enabled = $false
                Path = $null
                Status = 'Not Configured'
            }
            ModuleLogging = @{
                Enabled = $false
                Status = 'Not Configured'
            }
            Changes = @()
        }
    }
    
    process {
        try {
            # 1. Configure Execution Policy
            Write-Host "`n[1/4] Configuring Execution Policy..." -ForegroundColor Cyan
            
            $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
            $results.ExecutionPolicy.Before = $currentPolicy
            
            if ($currentPolicy -ne $ExecutionPolicy) {
                if ($PSCmdlet.ShouldProcess("LocalMachine", "Set Execution Policy to $ExecutionPolicy")) {
                    Set-ExecutionPolicy -ExecutionPolicy $ExecutionPolicy -Scope LocalMachine -Force
                    $results.ExecutionPolicy.After = $ExecutionPolicy
                    $results.ExecutionPolicy.Status = 'Changed'
                    $results.Changes += "Execution Policy changed from $currentPolicy to $ExecutionPolicy"
                    Write-Host "  Execution Policy set to: $ExecutionPolicy" -ForegroundColor Green
                }
            } else {
                $results.ExecutionPolicy.After = $currentPolicy
                $results.ExecutionPolicy.Status = 'Already Configured'
                Write-Host "  Execution Policy already set to: $ExecutionPolicy" -ForegroundColor Yellow
            }
            
            # 2. Configure Script Block Logging
            Write-Host "`n[2/4] Configuring Script Block Logging..." -ForegroundColor Cyan
            
            if ($EnableScriptBlockLogging) {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                
                if ($PSCmdlet.ShouldProcess("Registry", "Enable PowerShell Script Block Logging")) {
                    # Create registry path if it doesn't exist
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    
                    # Enable script block logging
                    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
                    
                    # Enable logging of invocation start/stop
                    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
                    
                    $results.ScriptBlockLogging.Enabled = $true
                    $results.ScriptBlockLogging.Status = 'Enabled'
                    $results.Changes += "Script Block Logging enabled"
                    
                    Write-Host "  Script Block Logging: Enabled" -ForegroundColor Green
                }
            } else {
                Write-Host "  Script Block Logging: Skipped" -ForegroundColor Yellow
            }
            
            # 3. Configure PowerShell Transcription
            Write-Host "`n[3/4] Configuring PowerShell Transcription..." -ForegroundColor Cyan
            
            if ($EnableTranscription) {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
                
                if ($PSCmdlet.ShouldProcess("Registry", "Enable PowerShell Transcription")) {
                    # Create transcription directory
                    if (-not (Test-Path $TranscriptionPath)) {
                        New-Item -Path $TranscriptionPath -ItemType Directory -Force | Out-Null
                    }
                    
                    # Create registry path if it doesn't exist
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    
                    # Enable transcription
                    Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value $TranscriptionPath -Type String -Force
                    Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
                    
                    $results.Transcription.Enabled = $true
                    $results.Transcription.Path = $TranscriptionPath
                    $results.Transcription.Status = 'Enabled'
                    $results.Changes += "PowerShell Transcription enabled at: $TranscriptionPath"
                    
                    Write-Host "  Transcription: Enabled" -ForegroundColor Green
                    Write-Host "  Transcription Path: $TranscriptionPath" -ForegroundColor White
                }
            } else {
                Write-Host "  Transcription: Skipped" -ForegroundColor Yellow
            }
            
            # 4. Configure Module Logging
            Write-Host "`n[4/4] Configuring Module Logging..." -ForegroundColor Cyan
            
            if ($EnableModuleLogging) {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                $moduleNamesPath = "$regPath\ModuleNames"
                
                if ($PSCmdlet.ShouldProcess("Registry", "Enable PowerShell Module Logging")) {
                    # Create registry paths
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    if (-not (Test-Path $moduleNamesPath)) {
                        New-Item -Path $moduleNamesPath -Force | Out-Null
                    }
                    
                    # Enable module logging
                    Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
                    
                    # Log all modules
                    Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String -Force
                    
                    $results.ModuleLogging.Enabled = $true
                    $results.ModuleLogging.Status = 'Enabled'
                    $results.Changes += "Module Logging enabled for all modules"
                    
                    Write-Host "  Module Logging: Enabled" -ForegroundColor Green
                }
            } else {
                Write-Host "  Module Logging: Skipped" -ForegroundColor Yellow
            }
            
            # Additional PowerShell Security Settings
            Write-Host "`n[ADDITIONAL] Applying Additional Security Settings..." -ForegroundColor Cyan
            
            # Disable PowerShell v2 (if exists)
            $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
            if ($psv2Feature -and $psv2Feature.State -eq 'Enabled') {
                if ($PSCmdlet.ShouldProcess("Windows Feature", "Disable PowerShell v2")) {
                    try {
                        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction Stop | Out-Null
                        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
                        $results.Changes += "PowerShell v2 disabled (requires restart)"
                        Write-Host "  PowerShell v2: Disabled (restart required)" -ForegroundColor Green
                    } catch {
                        Write-Warning "  Could not disable PowerShell v2: $_"
                    }
                }
            } else {
                Write-Host "  PowerShell v2: Already disabled or not installed" -ForegroundColor Yellow
            }
            
            # Configure WSMAN (Windows Remote Management) security
            Write-Host "`n[WSMAN] Configuring Windows Remote Management Security..." -ForegroundColor Cyan
            
            try {
                # Disable Basic Authentication
                Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false -Force
                $results.Changes += "WSMAN Basic Authentication disabled"
                Write-Host "  WSMAN Basic Auth: Disabled" -ForegroundColor Green
                
                # Enable Kerberos
                Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force
                Write-Host "  WSMAN Kerberos: Enabled" -ForegroundColor Green
                
            } catch {
                Write-Warning "  Could not configure WSMAN: $_"
            }
            
        }
        catch {
            Write-Error "Error during PowerShell security hardening: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== CONFIGURATION COMPLETE ===" -ForegroundColor Green
        Write-Host "`nChanges Applied:" -ForegroundColor Cyan
        
        if ($results.Changes.Count -gt 0) {
            $results.Changes | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor White
            }
        } else {
            Write-Host "  No changes were made" -ForegroundColor Yellow
        }
        
        Write-Host "`nCurrent Configuration:" -ForegroundColor Cyan
        Write-Host "  Execution Policy: $($results.ExecutionPolicy.After)" -ForegroundColor White
        Write-Host "  Script Block Logging: $($results.ScriptBlockLogging.Status)" -ForegroundColor White
        Write-Host "  Transcription: $($results.Transcription.Status)" -ForegroundColor White
        Write-Host "  Module Logging: $($results.ModuleLogging.Status)" -ForegroundColor White
        
        if ($results.Changes -match 'restart') {
            Write-Host "`n⚠ RESTART REQUIRED for some changes to take effect" -ForegroundColor Yellow
        }
        
        Write-Host "`nRecommendations:" -ForegroundColor Cyan
        Write-Host "  1. Test scripts after changing execution policy" -ForegroundColor White
        Write-Host "  2. Monitor PowerShell logs regularly" -ForegroundColor White
        Write-Host "  3. Rotate transcription logs to prevent disk space issues" -ForegroundColor White
        Write-Host "  4. Consider implementing JEA (Just Enough Administration)" -ForegroundColor White
        
        return $results
    }
}