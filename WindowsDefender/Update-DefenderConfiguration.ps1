function Update-DefenderConfiguration {
    <#
    .SYNOPSIS
        Updates Windows Defender configuration settings
    .DESCRIPTION
        Modifies Windows Defender settings including real-time protection, cloud protection,
        automatic sample submission, PUA protection, and exclusions
    .PARAMETER EnableRealTimeProtection
        Enable or disable real-time protection
    .PARAMETER EnableCloudProtection
        Enable cloud-delivered protection
    .PARAMETER EnableAutoSampleSubmission
        Enable automatic sample submission
    .PARAMETER PUAProtection
        Configure Potentially Unwanted Application protection (Disabled, Enabled, AuditMode)
    .PARAMETER AddExclusionPath
        Add path exclusion(s)
    .PARAMETER RemoveExclusionPath
        Remove path exclusion(s)
    .PARAMETER AddExclusionExtension
        Add file extension exclusion(s)
    .PARAMETER ScheduleScan
        Configure scheduled scan (Day and Time required)
    .PARAMETER ScanDay
        Day for scheduled scan (0-7, where 0=Everyday, 1=Sunday, 7=Saturday)
    .PARAMETER ScanTime
        Time for scheduled scan (HH:MM format)
    .EXAMPLE
        Update-DefenderConfiguration -EnableRealTimeProtection $true -EnableCloudProtection
        Update-DefenderConfiguration -PUAProtection Enabled -ScheduleScan -ScanDay 0 -ScanTime "02:00"
        Update-DefenderConfiguration -AddExclusionPath "C:\TrustedApp"
    .OUTPUTS
        PSCustomObject with configuration update results
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [ValidateNotNull()]
        [bool]$EnableRealTimeProtection,
        
        [Parameter()]
        [switch]$EnableCloudProtection,
        
        [Parameter()]
        [switch]$EnableAutoSampleSubmission,
        
        [Parameter()]
        [ValidateSet('Disabled', 'Enabled', 'AuditMode')]
        [string]$PUAProtection,
        
        [Parameter()]
        [string[]]$AddExclusionPath,
        
        [Parameter()]
        [string[]]$RemoveExclusionPath,
        
        [Parameter()]
        [string[]]$AddExclusionExtension,
        
        [Parameter()]
        [switch]$ScheduleScan,
        
        [Parameter()]
        [ValidateRange(0, 7)]
        [int]$ScanDay,
        
        [Parameter()]
        [string]$ScanTime
    )
    
    begin {
        Write-Host "=== WINDOWS DEFENDER CONFIGURATION UPDATE ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges!"
        }
        
        # Validate scheduled scan parameters
        if ($ScheduleScan -and (-not $PSBoundParameters.ContainsKey('ScanDay') -or -not $ScanTime)) {
            throw "ScheduleScan requires both ScanDay and ScanTime parameters!"
        }
        
        if ($ScanTime) {
            try {
                $null = [datetime]::ParseExact($ScanTime, "HH:mm", $null)
            }
            catch {
                throw "ScanTime must be in HH:MM format (e.g., '02:00' or '14:30')"
            }
        }
        
        $results = [PSCustomObject]@{
            ConfigurationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Changes = @()
            Errors = @()
            BeforeConfiguration = @{}
            AfterConfiguration = @{}
        }
        
        # Get current configuration
        try {
            $currentPrefs = Get-MpPreference
            $currentStatus = Get-MpComputerStatus
            
            $results.BeforeConfiguration = [PSCustomObject]@{
                RealTimeProtectionEnabled = $currentStatus.RealTimeProtectionEnabled
                CloudProtection = $currentPrefs.MAPSReporting
                SampleSubmission = $currentPrefs.SubmitSamplesConsent
                PUAProtection = $currentPrefs.PUAProtection
                ScanScheduleDay = $currentPrefs.ScanScheduleDay
                ScanScheduleTime = $currentPrefs.ScanScheduleTime
                ExclusionPaths = $currentPrefs.ExclusionPath
                ExclusionExtensions = $currentPrefs.ExclusionExtension
            }
        }
        catch {
            Write-Warning "Could not retrieve current configuration: $_"
        }
    }
    
    process {
        try {
            # 1. Real-Time Protection
            if ($PSBoundParameters.ContainsKey('EnableRealTimeProtection')) {
                Write-Host "`n[1] Configuring Real-Time Protection..." -ForegroundColor Cyan
                
                try {
                    if ($PSCmdlet.ShouldProcess("Real-Time Protection", "Set to $EnableRealTimeProtection")) {
                        Set-MpPreference -DisableRealtimeMonitoring (-not $EnableRealTimeProtection)
                        $results.Changes += "Real-Time Protection: $EnableRealTimeProtection"
                        Write-Host "  Real-Time Protection: " -NoNewline
                        Write-Host $EnableRealTimeProtection -ForegroundColor $(if ($EnableRealTimeProtection) { 'Green' } else { 'Red' })
                    }
                }
                catch {
                    $results.Errors += "Failed to configure Real-Time Protection: $_"
                    Write-Warning "  Failed to configure Real-Time Protection: $_"
                }
            }
            
            # 2. Cloud Protection
            if ($EnableCloudProtection) {
                Write-Host "`n[2] Configuring Cloud Protection..." -ForegroundColor Cyan
                
                try {
                    if ($PSCmdlet.ShouldProcess("Cloud Protection", "Enable")) {
                        # Advanced = 2, Basic = 1, Disabled = 0
                        Set-MpPreference -MAPSReporting Advanced
                        $results.Changes += "Cloud Protection: Enabled (Advanced)"
                        Write-Host "  Cloud Protection: Enabled (Advanced)" -ForegroundColor Green
                    }
                }
                catch {
                    $results.Errors += "Failed to configure Cloud Protection: $_"
                    Write-Warning "  Failed to configure Cloud Protection: $_"
                }
            }
            
            # 3. Automatic Sample Submission
            if ($EnableAutoSampleSubmission) {
                Write-Host "`n[3] Configuring Automatic Sample Submission..." -ForegroundColor Cyan
                
                try {
                    if ($PSCmdlet.ShouldProcess("Sample Submission", "Enable")) {
                        # SendAllSamples = 3
                        Set-MpPreference -SubmitSamplesConsent SendAllSamples
                        $results.Changes += "Automatic Sample Submission: Enabled"
                        Write-Host "  Automatic Sample Submission: Enabled" -ForegroundColor Green
                    }
                }
                catch {
                    $results.Errors += "Failed to configure Sample Submission: $_"
                    Write-Warning "  Failed to configure Sample Submission: $_"
                }
            }
            
            # 4. PUA Protection
            if ($PUAProtection) {
                Write-Host "`n[4] Configuring PUA Protection..." -ForegroundColor Cyan
                
                try {
                    $puaValue = switch ($PUAProtection) {
                        'Disabled' { 0 }
                        'Enabled' { 1 }
                        'AuditMode' { 2 }
                    }
                    
                    if ($PSCmdlet.ShouldProcess("PUA Protection", "Set to $PUAProtection")) {
                        Set-MpPreference -PUAProtection $puaValue
                        $results.Changes += "PUA Protection: $PUAProtection"
                        Write-Host "  PUA Protection: $PUAProtection" -ForegroundColor Green
                    }
                }
                catch {
                    $results.Errors += "Failed to configure PUA Protection: $_"
                    Write-Warning "  Failed to configure PUA Protection: $_"
                }
            }
            
            # 5. Add Path Exclusions
            if ($AddExclusionPath) {
                Write-Host "`n[5] Adding Path Exclusions..." -ForegroundColor Cyan
                
                foreach ($path in $AddExclusionPath) {
                    try {
                        if ($PSCmdlet.ShouldProcess($path, "Add exclusion")) {
                            Add-MpPreference -ExclusionPath $path
                            $results.Changes += "Added path exclusion: $path"
                            Write-Host "  + $path" -ForegroundColor Green
                        }
                    }
                    catch {
                        $results.Errors += "Failed to add path exclusion '$path': $_"
                        Write-Warning "  Failed to add: $path"
                    }
                }
            }
            
            # 6. Remove Path Exclusions
            if ($RemoveExclusionPath) {
                Write-Host "`n[6] Removing Path Exclusions..." -ForegroundColor Cyan
                
                foreach ($path in $RemoveExclusionPath) {
                    try {
                        if ($PSCmdlet.ShouldProcess($path, "Remove exclusion")) {
                            Remove-MpPreference -ExclusionPath $path
                            $results.Changes += "Removed path exclusion: $path"
                            Write-Host "  - $path" -ForegroundColor Yellow
                        }
                    }
                    catch {
                        $results.Errors += "Failed to remove path exclusion '$path': $_"
                        Write-Warning "  Failed to remove: $path"
                    }
                }
            }
            
            # 7. Add Extension Exclusions
            if ($AddExclusionExtension) {
                Write-Host "`n[7] Adding Extension Exclusions..." -ForegroundColor Cyan
                
                foreach ($ext in $AddExclusionExtension) {
                    try {
                        # Ensure extension starts with dot
                        $extension = if ($ext.StartsWith('.')) { $ext } else { ".$ext" }
                        
                        if ($PSCmdlet.ShouldProcess($extension, "Add exclusion")) {
                            Add-MpPreference -ExclusionExtension $extension
                            $results.Changes += "Added extension exclusion: $extension"
                            Write-Host "  + $extension" -ForegroundColor Green
                        }
                    }
                    catch {
                        $results.Errors += "Failed to add extension exclusion '$ext': $_"
                        Write-Warning "  Failed to add: $ext"
                    }
                }
            }
            
            # 8. Schedule Scan
            if ($ScheduleScan) {
                Write-Host "`n[8] Configuring Scheduled Scan..." -ForegroundColor Cyan
                
                try {
                    if ($PSCmdlet.ShouldProcess("Scheduled Scan", "Configure")) {
                        # Configure scan day
                        Set-MpPreference -ScanScheduleDay $ScanDay
                        
                        # Parse and set time
                        $timeSpan = [TimeSpan]::Parse($ScanTime)
                        Set-MpPreference -ScanScheduleTime $timeSpan
                        
                        # Enable scheduled scan
                        Set-MpPreference -DisableScheduledScan $false
                        
                        $dayName = switch ($ScanDay) {
                            0 { 'Everyday' }
                            1 { 'Sunday' }
                            2 { 'Monday' }
                            3 { 'Tuesday' }
                            4 { 'Wednesday' }
                            5 { 'Thursday' }
                            6 { 'Friday' }
                            7 { 'Saturday' }
                        }
                        
                        $results.Changes += "Scheduled Scan: $dayName at $ScanTime"
                        Write-Host "  Scheduled Scan: $dayName at $ScanTime" -ForegroundColor Green
                    }
                }
                catch {
                    $results.Errors += "Failed to configure scheduled scan: $_"
                    Write-Warning "  Failed to configure scheduled scan: $_"
                }
            }
            
            # Additional recommended settings
            Write-Host "`n[ADDITIONAL] Applying recommended settings..." -ForegroundColor Cyan
            
            try {
                # Enable behavior monitoring
                Set-MpPreference -DisableBehaviorMonitoring $false
                Write-Host "  + Behavior Monitoring enabled" -ForegroundColor Green
                
                # Enable IOAV protection
                Set-MpPreference -DisableIOAVProtection $false
                Write-Host "  + IOAV Protection enabled" -ForegroundColor Green
                
                # Enable script scanning
                Set-MpPreference -DisableScriptScanning $false
                Write-Host "  + Script Scanning enabled" -ForegroundColor Green
                
                # Check for signatures before scan
                Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
                Write-Host "  + Check signatures before scan enabled" -ForegroundColor Green
                
                $results.Changes += "Additional protections enabled"
            }
            catch {
                Write-Verbose "Some additional settings could not be configured: $_"
            }
            
        }
        catch {
            Write-Error "Error during configuration update: $_"
            throw
        }
    }
    
    end {
        # Get updated configuration
        try {
            $updatedPrefs = Get-MpPreference
            $updatedStatus = Get-MpComputerStatus
            
            $results.AfterConfiguration = [PSCustomObject]@{
                RealTimeProtectionEnabled = $updatedStatus.RealTimeProtectionEnabled
                CloudProtection = $updatedPrefs.MAPSReporting
                SampleSubmission = $updatedPrefs.SubmitSamplesConsent
                PUAProtection = $updatedPrefs.PUAProtection
                ScanScheduleDay = $updatedPrefs.ScanScheduleDay
                ScanScheduleTime = $updatedPrefs.ScanScheduleTime
                ExclusionPaths = $updatedPrefs.ExclusionPath
                ExclusionExtensions = $updatedPrefs.ExclusionExtension
            }
        }
        catch {
            Write-Warning "Could not retrieve updated configuration: $_"
        }
        
        # Display summary
        Write-Host "`n=== CONFIGURATION UPDATE COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nChanges Applied: $($results.Changes.Count)" -ForegroundColor Cyan
        if ($results.Changes.Count -gt 0) {
            $results.Changes | ForEach-Object {
                Write-Host "  + $_" -ForegroundColor White
            }
        }
        else {
            Write-Host "  No changes were made" -ForegroundColor Yellow
        }
        
        if ($results.Errors.Count -gt 0) {
            Write-Host "`nErrors: $($results.Errors.Count)" -ForegroundColor Red
            $results.Errors | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Red
            }
        }
        
        Write-Host "`nCurrent Protection Status:" -ForegroundColor Cyan
        Write-Host "  Real-Time Protection: " -NoNewline
        Write-Host $results.AfterConfiguration.RealTimeProtectionEnabled -ForegroundColor $(
            if ($results.AfterConfiguration.RealTimeProtectionEnabled) { 'Green' } else { 'Red' }
        )
        
        $cloudStatus = switch ($results.AfterConfiguration.CloudProtection) {
            0 { 'Disabled' }
            1 { 'Basic' }
            2 { 'Advanced' }
            default { 'Unknown' }
        }
        Write-Host "  Cloud Protection: $cloudStatus" -ForegroundColor White
        
        $sampleStatus = switch ($results.AfterConfiguration.SampleSubmission) {
            0 { 'Always Prompt' }
            1 { 'Send Safe Samples' }
            2 { 'Never Send' }
            3 { 'Send All Samples' }
            default { 'Unknown' }
        }
        Write-Host "  Sample Submission: $sampleStatus" -ForegroundColor White
        
        $puaStatus = switch ($results.AfterConfiguration.PUAProtection) {
            0 { 'Disabled' }
            1 { 'Enabled' }
            2 { 'Audit Mode' }
            default { 'Unknown' }
        }
        Write-Host "  PUA Protection: $puaStatus" -ForegroundColor White
        
        if ($results.AfterConfiguration.ExclusionPaths) {
            Write-Host "`nExclusions:" -ForegroundColor Yellow
            Write-Host "  Paths: $($results.AfterConfiguration.ExclusionPaths.Count)" -ForegroundColor White
            if ($results.AfterConfiguration.ExclusionExtensions) {
                Write-Host "  Extensions: $($results.AfterConfiguration.ExclusionExtensions.Count)" -ForegroundColor White
            }
        }
        
        Write-Host "`nRecommendations:" -ForegroundColor Cyan
        Write-Host "  1. Verify protection settings in Windows Security" -ForegroundColor White
        Write-Host "  2. Run a Quick Scan to test configuration" -ForegroundColor White
        Write-Host "  3. Review exclusions regularly" -ForegroundColor White
        Write-Host "  4. Keep automatic updates enabled" -ForegroundColor White
        Write-Host "  5. Monitor Windows Security notifications" -ForegroundColor White
        
        return $results
    }
}