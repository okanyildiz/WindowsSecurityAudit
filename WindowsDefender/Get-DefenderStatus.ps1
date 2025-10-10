function Get-DefenderStatus {
    <#
    .SYNOPSIS
        Retrieves comprehensive Windows Defender status and configuration
    .DESCRIPTION
        Collects detailed information about Windows Defender including protection status,
        signature versions, scan history, threat detections, and exclusions
    .PARAMETER IncludeThreatHistory
        Include detected threat history
    .PARAMETER IncludeExclusions
        Include configured exclusions
    .EXAMPLE
        Get-DefenderStatus
        Get-DefenderStatus -IncludeThreatHistory -IncludeExclusions
    .OUTPUTS
        PSCustomObject with Defender status information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeThreatHistory,
        
        [Parameter()]
        [switch]$IncludeExclusions
    )
    
    begin {
        Write-Host "=== WINDOWS DEFENDER STATUS ===" -ForegroundColor Cyan
        
        $status = [PSCustomObject]@{
            CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            ProtectionStatus = @{}
            SignatureStatus = @{}
            ScanHistory = @{}
            Configuration = @{}
            ThreatHistory = @()
            Exclusions = @{}
            HealthStatus = 'Unknown'
            Recommendations = @()
        }
    }
    
    process {
        try {
            # Get main Defender status
            Write-Host "Collecting Defender status..." -ForegroundColor Yellow
            
            $mpStatus = Get-MpComputerStatus
            
            # Protection Status
            $status.ProtectionStatus = [PSCustomObject]@{
                AntivirusEnabled = $mpStatus.AntivirusEnabled
                AntispywareEnabled = $mpStatus.AntispywareEnabled
                RealTimeProtectionEnabled = $mpStatus.RealTimeProtectionEnabled
                OnAccessProtectionEnabled = $mpStatus.OnAccessProtectionEnabled
                BehaviorMonitorEnabled = $mpStatus.BehaviorMonitorEnabled
                IoavProtectionEnabled = $mpStatus.IoavProtectionEnabled
                NISEnabled = $mpStatus.NISEnabled
                IsTamperProtected = $mpStatus.IsTamperProtected
            }
            
            # Signature Status
            $status.SignatureStatus = [PSCustomObject]@{
                AntivirusSignatureVersion = $mpStatus.AntivirusSignatureVersion
                AntispywareSignatureVersion = $mpStatus.AntispywareSignatureVersion
                NISSignatureVersion = $mpStatus.NISSignatureVersion
                AntivirusSignatureLastUpdated = $mpStatus.AntivirusSignatureLastUpdated
                AntispywareSignatureLastUpdated = $mpStatus.AntispywareSignatureLastUpdated
                NISSignatureLastUpdated = $mpStatus.NISSignatureLastUpdated
                SignatureAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
            }
            
            # Scan History
            $status.ScanHistory = [PSCustomObject]@{
                QuickScanStartTime = $mpStatus.QuickScanStartTime
                QuickScanEndTime = $mpStatus.QuickScanEndTime
                QuickScanAge = if ($mpStatus.QuickScanAge) { $mpStatus.QuickScanAge } else { "Never" }
                FullScanStartTime = $mpStatus.FullScanStartTime
                FullScanEndTime = $mpStatus.FullScanEndTime
                FullScanAge = if ($mpStatus.FullScanAge) { $mpStatus.FullScanAge } else { "Never" }
            }
            
            # Get Defender preferences/configuration
            $mpPreferences = Get-MpPreference
            
            $status.Configuration = [PSCustomObject]@{
                DisableAutoExclusions = $mpPreferences.DisableAutoExclusions
                DisableRealtimeMonitoring = $mpPreferences.DisableRealtimeMonitoring
                DisableBehaviorMonitoring = $mpPreferences.DisableBehaviorMonitoring
                DisableIOAVProtection = $mpPreferences.DisableIOAVProtection
                DisableScriptScanning = $mpPreferences.DisableScriptScanning
                MAPSReporting = $mpPreferences.MAPSReporting
                SubmitSamplesConsent = $mpPreferences.SubmitSamplesConsent
                PUAProtection = $mpPreferences.PUAProtection
                ScanAvgCPULoadFactor = $mpPreferences.ScanAvgCPULoadFactor
                CheckForSignaturesBeforeRunningScan = $mpPreferences.CheckForSignaturesBeforeRunningScan
                ScanParameters = $mpPreferences.ScanParameters
                ScanScheduleDay = $mpPreferences.ScanScheduleDay
                ScanScheduleTime = $mpPreferences.ScanScheduleTime
            }
            
            # Threat History
            if ($IncludeThreatHistory) {
                Write-Host "Collecting threat history..." -ForegroundColor Yellow
                
                try {
                    $threats = Get-MpThreatDetection
                    foreach ($threat in $threats) {
                        $status.ThreatHistory += [PSCustomObject]@{
                            ThreatName = $threat.ThreatName
                            SeverityID = $threat.SeverityID
                            InitialDetectionTime = $threat.InitialDetectionTime
                            LastThreatStatusChangeTime = $threat.LastThreatStatusChangeTime
                            ActionSuccess = $threat.ActionSuccess
                            Resources = $threat.Resources
                        }
                    }
                }
                catch {
                    Write-Verbose "No threat history available or access denied"
                }
            }
            
            # Exclusions
            if ($IncludeExclusions) {
                Write-Host "Collecting exclusions..." -ForegroundColor Yellow
                
                $status.Exclusions = [PSCustomObject]@{
                    ExclusionPath = $mpPreferences.ExclusionPath
                    ExclusionExtension = $mpPreferences.ExclusionExtension
                    ExclusionProcess = $mpPreferences.ExclusionProcess
                    ExclusionIpAddress = $mpPreferences.ExclusionIpAddress
                }
            }
            
            # Determine overall health status
            $healthScore = 0
            $maxScore = 100
            
            # Check critical protections (60 points)
            if ($status.ProtectionStatus.RealTimeProtectionEnabled) { $healthScore += 20 } else { $status.Recommendations += "Enable Real-Time Protection" }
            if ($status.ProtectionStatus.BehaviorMonitorEnabled) { $healthScore += 15 } else { $status.Recommendations += "Enable Behavior Monitoring" }
            if ($status.ProtectionStatus.IoavProtectionEnabled) { $healthScore += 10 } else { $status.Recommendations += "Enable IOAV Protection" }
            if ($status.ProtectionStatus.NISEnabled) { $healthScore += 15 } else { $status.Recommendations += "Enable Network Inspection System" }
            
            # Check signature age (20 points)
            $signatureAge = $status.SignatureStatus.SignatureAge.Days
            if ($signatureAge -le 1) {
                $healthScore += 20
            } elseif ($signatureAge -le 3) {
                $healthScore += 15
                $status.Recommendations += "Update virus definitions (current age: $signatureAge days)"
            } elseif ($signatureAge -le 7) {
                $healthScore += 10
                $status.Recommendations += "Update virus definitions urgently (current age: $signatureAge days)"
            } else {
                $status.Recommendations += "Update virus definitions immediately (current age: $signatureAge days)"
            }
            
            # Check scan history (20 points)
            if ($status.ScanHistory.QuickScanAge -ne "Never") {
                if ($status.ScanHistory.QuickScanAge -le 7) {
                    $healthScore += 10
                } elseif ($status.ScanHistory.QuickScanAge -le 14) {
                    $healthScore += 5
                    $status.Recommendations += "Run a Quick Scan (last scan: $($status.ScanHistory.QuickScanAge) days ago)"
                } else {
                    $status.Recommendations += "Run a Quick Scan urgently (last scan: $($status.ScanHistory.QuickScanAge) days ago)"
                }
            } else {
                $status.Recommendations += "Run a Quick Scan (never performed)"
            }
            
            if ($status.ScanHistory.FullScanAge -ne "Never") {
                if ($status.ScanHistory.FullScanAge -le 30) {
                    $healthScore += 10
                } elseif ($status.ScanHistory.FullScanAge -le 60) {
                    $healthScore += 5
                    $status.Recommendations += "Run a Full Scan (last scan: $($status.ScanHistory.FullScanAge) days ago)"
                } else {
                    $status.Recommendations += "Run a Full Scan urgently (last scan: $($status.ScanHistory.FullScanAge) days ago)"
                }
            } else {
                $status.Recommendations += "Run a Full Scan (never performed)"
            }
            
            # Determine health status
            if ($healthScore -ge 90) {
                $status.HealthStatus = 'Excellent'
            } elseif ($healthScore -ge 75) {
                $status.HealthStatus = 'Good'
            } elseif ($healthScore -ge 60) {
                $status.HealthStatus = 'Fair'
            } elseif ($healthScore -ge 40) {
                $status.HealthStatus = 'Poor'
            } else {
                $status.HealthStatus = 'Critical'
            }
            
        }
        catch {
            Write-Error "Error collecting Defender status: $_"
            throw
        }
    }
    
    end {
        # Display summary
        Write-Host "`n=== DEFENDER STATUS SUMMARY ===" -ForegroundColor Cyan
        
        Write-Host "`nHealth Status: " -NoNewline
        $color = switch ($status.HealthStatus) {
            'Excellent' { 'Green' }
            'Good' { 'Green' }
            'Fair' { 'Yellow' }
            'Poor' { 'Red' }
            'Critical' { 'Red' }
            default { 'White' }
        }
        Write-Host $status.HealthStatus -ForegroundColor $color
        
        Write-Host "`nProtection Status:" -ForegroundColor Cyan
        Write-Host "  Real-Time Protection: " -NoNewline
        Write-Host $status.ProtectionStatus.RealTimeProtectionEnabled -ForegroundColor $(if ($status.ProtectionStatus.RealTimeProtectionEnabled) { 'Green' } else { 'Red' })
        Write-Host "  Behavior Monitor: " -NoNewline
        Write-Host $status.ProtectionStatus.BehaviorMonitorEnabled -ForegroundColor $(if ($status.ProtectionStatus.BehaviorMonitorEnabled) { 'Green' } else { 'Red' })
        Write-Host "  Network Inspection: " -NoNewline
        Write-Host $status.ProtectionStatus.NISEnabled -ForegroundColor $(if ($status.ProtectionStatus.NISEnabled) { 'Green' } else { 'Red' })
        Write-Host "  Tamper Protection: " -NoNewline
        Write-Host $status.ProtectionStatus.IsTamperProtected -ForegroundColor $(if ($status.ProtectionStatus.IsTamperProtected) { 'Green' } else { 'Yellow' })
        
        Write-Host "`nSignatures:" -ForegroundColor Cyan
        Write-Host "  Version: $($status.SignatureStatus.AntivirusSignatureVersion)"
        Write-Host "  Last Updated: $($status.SignatureStatus.AntivirusSignatureLastUpdated)"
        Write-Host "  Age: $($status.SignatureStatus.SignatureAge.Days) days" -ForegroundColor $(
            if ($status.SignatureStatus.SignatureAge.Days -le 1) { 'Green' }
            elseif ($status.SignatureStatus.SignatureAge.Days -le 3) { 'Yellow' }
            else { 'Red' }
        )
        
        Write-Host "`nLast Scans:" -ForegroundColor Cyan
        Write-Host "  Quick Scan: " -NoNewline
        if ($status.ScanHistory.QuickScanAge -ne "Never") {
            Write-Host "$($status.ScanHistory.QuickScanAge) days ago"
        } else {
            Write-Host "Never" -ForegroundColor Red
        }
        Write-Host "  Full Scan: " -NoNewline
        if ($status.ScanHistory.FullScanAge -ne "Never") {
            Write-Host "$($status.ScanHistory.FullScanAge) days ago"
        } else {
            Write-Host "Never" -ForegroundColor Red
        }
        
        if ($IncludeThreatHistory -and $status.ThreatHistory.Count -gt 0) {
            Write-Host "`nThreat Detections: $($status.ThreatHistory.Count)" -ForegroundColor Red
            $status.ThreatHistory | Select-Object -First 5 | ForEach-Object {
                Write-Host "  - $($_.ThreatName) [$($_.InitialDetectionTime)]" -ForegroundColor Red
            }
        }
        
        if ($status.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Yellow
            $status.Recommendations | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $status
    }
}