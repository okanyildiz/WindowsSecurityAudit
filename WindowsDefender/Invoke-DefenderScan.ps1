function Invoke-DefenderScan {
    <#
    .SYNOPSIS
        Initiates Windows Defender scans with various options
    .DESCRIPTION
        Starts Windows Defender antivirus scans including Quick Scan, Full Scan, Custom Scan,
        and Offline Scan with progress tracking and result reporting
    .PARAMETER ScanType
        Type of scan: Quick, Full, Custom, or Offline
    .PARAMETER ScanPath
        Path to scan (required for Custom scan)
    .PARAMETER UpdateSignatures
        Update virus definitions before scanning
    .PARAMETER Priority
        Scan priority: Low or Normal
    .EXAMPLE
        Invoke-DefenderScan -ScanType Quick
        Invoke-DefenderScan -ScanType Full -UpdateSignatures
        Invoke-DefenderScan -ScanType Custom -ScanPath "C:\Users"
    .OUTPUTS
        PSCustomObject with scan results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Quick', 'Full', 'Custom', 'Offline')]
        [string]$ScanType,
        
        [Parameter()]
        [string]$ScanPath,
        
        [Parameter()]
        [switch]$UpdateSignatures,
        
        [Parameter()]
        [ValidateSet('Low', 'Normal')]
        [string]$Priority = 'Normal'
    )
    
    begin {
        Write-Host "=== WINDOWS DEFENDER SCAN ===" -ForegroundColor Cyan
        Write-Host "Scan Type: $ScanType" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges!"
        }
        
        # Validate custom scan path
        if ($ScanType -eq 'Custom' -and -not $ScanPath) {
            throw "ScanPath is required for Custom scan type!"
        }
        
        if ($ScanType -eq 'Custom' -and -not (Test-Path $ScanPath)) {
            throw "ScanPath does not exist: $ScanPath"
        }
        
        $results = [PSCustomObject]@{
            ScanType = $ScanType
            StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            EndTime = $null
            Duration = $null
            Status = 'Running'
            ThreatsDetected = 0
            FilesScanned = 0
            ThreatDetails = @()
            SignatureUpdate = @{
                Updated = $false
                Version = $null
                Error = $null
            }
            Errors = @()
        }
    }
    
    process {
        try {
            # Update signatures if requested
            if ($UpdateSignatures) {
                Write-Host "`nUpdating virus definitions..." -ForegroundColor Cyan
                try {
                    Update-MpSignature -ErrorAction Stop
                    $mpStatus = Get-MpComputerStatus
                    $results.SignatureUpdate.Updated = $true
                    $results.SignatureUpdate.Version = $mpStatus.AntivirusSignatureVersion
                    Write-Host "Signatures updated to version: $($mpStatus.AntivirusSignatureVersion)" -ForegroundColor Green
                }
                catch {
                    $results.SignatureUpdate.Error = $_.Exception.Message
                    Write-Warning "Failed to update signatures: $_"
                }
            }
            
            # Start the scan
            Write-Host "`nStarting $ScanType scan..." -ForegroundColor Cyan
            
            switch ($ScanType) {
                'Quick' {
                    Write-Host "This may take a few minutes..." -ForegroundColor Yellow
                    try {
                        if ($Priority -eq 'Low') {
                            Start-MpScan -ScanType QuickScan -AsJob | Out-Null
                            Write-Host "Quick scan started as background job" -ForegroundColor Green
                        }
                        else {
                            Start-MpScan -ScanType QuickScan
                            Write-Host "Quick scan completed" -ForegroundColor Green
                        }
                        $results.Status = 'Completed'
                    }
                    catch {
                        $results.Status = 'Failed'
                        $results.Errors += $_.Exception.Message
                        throw
                    }
                }
                
                'Full' {
                    Write-Host "This may take 30+ minutes depending on system size..." -ForegroundColor Yellow
                    Write-Host "Progress updates will appear in Windows Security app" -ForegroundColor Yellow
                    try {
                        if ($Priority -eq 'Low') {
                            Start-MpScan -ScanType FullScan -AsJob | Out-Null
                            Write-Host "Full scan started as background job" -ForegroundColor Green
                            Write-Host "Use Get-MpThreat to check results later" -ForegroundColor Yellow
                        }
                        else {
                            $job = Start-MpScan -ScanType FullScan -AsJob
                            Write-Host "Full scan in progress (background job)..." -ForegroundColor Yellow
                            Write-Host "Monitoring scan progress..." -ForegroundColor Cyan
                            
                            # Monitor progress
                            $startTime = Get-Date
                            while ($job.State -eq 'Running') {
                                $elapsed = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
                                Write-Host "`rElapsed time: $elapsed" -NoNewline -ForegroundColor Yellow
                                Start-Sleep -Seconds 10
                            }
                            Write-Host ""
                            
                            if ($job.State -eq 'Completed') {
                                Write-Host "Full scan completed" -ForegroundColor Green
                                $results.Status = 'Completed'
                            }
                            else {
                                Write-Warning "Scan job state: $($job.State)"
                                $results.Status = $job.State
                            }
                        }
                    }
                    catch {
                        $results.Status = 'Failed'
                        $results.Errors += $_.Exception.Message
                        throw
                    }
                }
                
                'Custom' {
                    Write-Host "Scanning path: $ScanPath" -ForegroundColor Yellow
                    try {
                        Start-MpScan -ScanType CustomScan -ScanPath $ScanPath
                        Write-Host "Custom scan completed" -ForegroundColor Green
                        $results.Status = 'Completed'
                    }
                    catch {
                        $results.Status = 'Failed'
                        $results.Errors += $_.Exception.Message
                        throw
                    }
                }
                
                'Offline' {
                    Write-Host "WARNING: Offline scan will restart your computer!" -ForegroundColor Red
                    Write-Host "Your computer will boot into Windows Defender Offline environment" -ForegroundColor Yellow
                    
                    $confirmation = Read-Host "Do you want to continue? (yes/no)"
                    if ($confirmation -eq 'yes') {
                        try {
                            Start-MpWDOScan
                            Write-Host "Offline scan initiated - system will restart" -ForegroundColor Green
                            $results.Status = 'Initiated'
                        }
                        catch {
                            $results.Status = 'Failed'
                            $results.Errors += $_.Exception.Message
                            throw
                        }
                    }
                    else {
                        Write-Host "Offline scan cancelled by user" -ForegroundColor Yellow
                        $results.Status = 'Cancelled'
                    }
                }
            }
            
            # Wait a moment for scan results to be processed
            if ($results.Status -eq 'Completed') {
                Start-Sleep -Seconds 2
            }
            
            # Get scan results and threat information
            if ($results.Status -eq 'Completed') {
                Write-Host "`nCollecting scan results..." -ForegroundColor Cyan
                
                try {
                    # Get updated Defender status
                    $mpStatus = Get-MpComputerStatus
                    
                    # Get threat detections
                    $threats = Get-MpThreat
                    $results.ThreatsDetected = $threats.Count
                    
                    foreach ($threat in $threats) {
                        $results.ThreatDetails += [PSCustomObject]@{
                            ThreatName = $threat.ThreatName
                            SeverityID = $threat.SeverityID
                            Severity = switch ($threat.SeverityID) {
                                0 { 'Unknown' }
                                1 { 'Low' }
                                2 { 'Medium' }
                                4 { 'High' }
                                5 { 'Severe' }
                                default { 'Unknown' }
                            }
                            CategoryID = $threat.CategoryID
                            InitialDetectionTime = $threat.InitialDetectionTime
                            IsActive = $threat.IsActive
                            Resources = $threat.Resources
                        }
                    }
                    
                    # Try to get scan history
                    switch ($ScanType) {
                        'Quick' {
                            $results.EndTime = $mpStatus.QuickScanEndTime
                            if ($mpStatus.QuickScanStartTime) {
                                $results.Duration = ($mpStatus.QuickScanEndTime - $mpStatus.QuickScanStartTime).ToString()
                            }
                        }
                        'Full' {
                            $results.EndTime = $mpStatus.FullScanEndTime
                            if ($mpStatus.FullScanStartTime) {
                                $results.Duration = ($mpStatus.FullScanEndTime - $mpStatus.FullScanStartTime).ToString()
                            }
                        }
                    }
                    
                }
                catch {
                    Write-Verbose "Could not retrieve detailed scan results: $_"
                }
            }
            
        }
        catch {
            Write-Error "Error during Defender scan: $_"
            $results.Status = 'Error'
            $results.Errors += $_.Exception.Message
        }
    }
    
    end {
        if ($results.Status -ne 'Initiated') {
            $results.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nScan Details:" -ForegroundColor Cyan
        Write-Host "  Type: $($results.ScanType)" -ForegroundColor White
        Write-Host "  Status: " -NoNewline
        Write-Host $results.Status -ForegroundColor $(
            switch ($results.Status) {
                'Completed' { 'Green' }
                'Running' { 'Yellow' }
                'Failed' { 'Red' }
                'Cancelled' { 'Yellow' }
                'Initiated' { 'Green' }
                default { 'White' }
            }
        )
        
        if ($results.Duration) {
            Write-Host "  Duration: $($results.Duration)" -ForegroundColor White
        }
        
        if ($results.SignatureUpdate.Updated) {
            Write-Host "`nSignature Update:" -ForegroundColor Cyan
            Write-Host "  Version: $($results.SignatureUpdate.Version)" -ForegroundColor White
        }
        
        Write-Host "`nThreats Detected: " -NoNewline
        if ($results.ThreatsDetected -gt 0) {
            Write-Host $results.ThreatsDetected -ForegroundColor Red
            
            Write-Host "`nThreat Details:" -ForegroundColor Red
            foreach ($threat in $results.ThreatDetails) {
                Write-Host "  - $($threat.ThreatName)" -ForegroundColor Red
                Write-Host "    Severity: $($threat.Severity)" -ForegroundColor Yellow
                Write-Host "    Detected: $($threat.InitialDetectionTime)" -ForegroundColor White
                if ($threat.Resources) {
                    Write-Host "    Location: $($threat.Resources)" -ForegroundColor White
                }
            }
        }
        else {
            Write-Host "0" -ForegroundColor Green
            Write-Host "  No threats detected!" -ForegroundColor Green
        }
        
        if ($results.Errors.Count -gt 0) {
            Write-Host "`nErrors:" -ForegroundColor Red
            $results.Errors | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Red
            }
        }
        
        Write-Host "`nRecommendations:" -ForegroundColor Cyan
        Write-Host "  1. Run full scans weekly" -ForegroundColor White
        Write-Host "  2. Keep definitions updated automatically" -ForegroundColor White
        Write-Host "  3. Review detected threats in Windows Security" -ForegroundColor White
        Write-Host "  4. Schedule regular scans during off-peak hours" -ForegroundColor White
        
        if ($Priority -eq 'Low' -and $results.Status -eq 'Completed') {
            Write-Host "`nNote: Background scan may still be running. Check Windows Security for status." -ForegroundColor Yellow
        }
        
        return $results
    }
}