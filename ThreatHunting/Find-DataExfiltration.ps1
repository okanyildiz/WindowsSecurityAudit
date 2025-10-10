function Find-DataExfiltration {
    <#
    .SYNOPSIS
        Detects potential data exfiltration activities
    .DESCRIPTION
        Identifies indicators of data exfiltration including large file transfers,
        uploads to cloud services, compression activities, and staging behaviors
    .PARAMETER CheckLargeTransfers
        Check for large network transfers
    .PARAMETER CheckCloudUploads
        Check for uploads to cloud services
    .PARAMETER CheckCompression
        Check for file compression activities
    .PARAMETER CheckStaging
        Check for data staging activities
    .PARAMETER ThresholdMB
        Threshold for large file transfers in MB (default: 100)
    .EXAMPLE
        Find-DataExfiltration -CheckLargeTransfers -CheckCloudUploads
        Find-DataExfiltration -CheckLargeTransfers -CheckCompression -CheckStaging -ThresholdMB 50
    .OUTPUTS
        PSCustomObject with data exfiltration indicators
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckLargeTransfers,
        
        [Parameter()]
        [switch]$CheckCloudUploads,
        
        [Parameter()]
        [switch]$CheckCompression,
        
        [Parameter()]
        [switch]$CheckStaging,
        
        [Parameter()]
        [int]$ThresholdMB = 100
    )
    
    begin {
        Write-Host "=== DATA EXFILTRATION DETECTION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Transfer Threshold: $ThresholdMB MB" -ForegroundColor Yellow
        
        if (-not ($CheckLargeTransfers -or $CheckCloudUploads -or $CheckCompression -or $CheckStaging)) {
            $CheckLargeTransfers = $true
            $CheckCloudUploads = $true
            Write-Host "No specific check selected - enabling default checks" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            ThresholdMB = $ThresholdMB
            Indicators = @{
                LargeTransfers = @()
                CloudUploads = @()
                Compression = @()
                Staging = @()
            }
            Summary = @{
                TotalIndicators = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
                TotalDataMB = 0
            }
            Recommendations = @()
        }
        
        # Known cloud services and upload endpoints
        $cloudServices = @(
            'dropbox.com',
            'drive.google.com',
            'onedrive.live.com',
            'box.com',
            'mega.nz',
            'wetransfer.com',
            'sendspace.com',
            'mediafire.com',
            'filebin.net',
            'pastebin.com',
            'transfer.sh',
            's3.amazonaws.com',
            'blob.core.windows.net'
        )
    }
    
    process {
        try {
            # 1. Check for Large Network Transfers
            if ($CheckLargeTransfers) {
                Write-Host "`n[1/4] Checking network transfers..." -ForegroundColor Cyan
                
                try {
                    # Get network interface statistics
                    $networkStats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
                    
                    if ($networkStats) {
                        foreach ($adapter in $networkStats) {
                            $sentGB = [math]::Round($adapter.SentBytes / 1GB, 2)
                            $receivedGB = [math]::Round($adapter.ReceivedBytes / 1GB, 2)
                            
                            # Check active connections with high data transfer
                            $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                                Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' }
                            
                            foreach ($conn in $connections | Select-Object -First 10) {
                                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                                
                                if ($process) {
                                    # Skip browsers and common legitimate processes
                                    if ($process.Name -match 'chrome|firefox|edge|teams|zoom|onedrive') {
                                        continue
                                    }
                                    
                                    $indicator = [PSCustomObject]@{
                                        Type = 'NetworkTransfer'
                                        Process = $process.Name
                                        ProcessId = $conn.OwningProcess
                                        RemoteAddress = $conn.RemoteAddress
                                        RemotePort = $conn.RemotePort
                                        LocalPort = $conn.LocalPort
                                        Severity = 'Medium'
                                        Description = "Active connection from $($process.Name) to $($conn.RemoteAddress)"
                                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                    }
                                    
                                    $results.Indicators.LargeTransfers += $indicator
                                    $results.Summary.MediumFindings++
                                    
                                    Write-Host "  [!] Active: $($process.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                    
                    if ($results.Indicators.LargeTransfers.Count -eq 0) {
                        Write-Host "  No suspicious large transfers detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking network transfers: $_"
                }
            }
            
            # 2. Check for Cloud Service Uploads
            if ($CheckCloudUploads) {
                Write-Host "`n[2/4] Checking cloud service uploads..." -ForegroundColor Cyan
                
                try {
                    # Check active connections to known cloud services
                    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                    
                    $foundCount = 0
                    
                    foreach ($conn in $connections) {
                        # Try to resolve hostname
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                        }
                        catch {
                            $hostname = $conn.RemoteAddress
                        }
                        
                        foreach ($cloudService in $cloudServices) {
                            if ($hostname -like "*$cloudService*") {
                                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                                
                                # Skip if it's a browser (expected behavior)
                                if ($process.Name -match 'chrome|firefox|edge|msedge') {
                                    continue
                                }
                                
                                $indicator = [PSCustomObject]@{
                                    Type = 'CloudUpload'
                                    Process = $process.Name
                                    ProcessId = $conn.OwningProcess
                                    CloudService = $cloudService
                                    RemoteAddress = $conn.RemoteAddress
                                    Hostname = $hostname
                                    Severity = 'High'
                                    Description = "Connection to $cloudService from $($process.Name)"
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.Indicators.CloudUploads += $indicator
                                $results.Summary.HighFindings++
                                $foundCount++
                                
                                Write-Host "  [!] Cloud: $cloudService via $($process.Name)" -ForegroundColor Red
                                break
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No suspicious cloud uploads detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking cloud uploads: $_"
                }
            }
            
            # 3. Check for File Compression Activities
            if ($CheckCompression) {
                Write-Host "`n[3/4] Checking compression activities..." -ForegroundColor Cyan
                
                try {
                    # Check for running compression tools
                    $compressionTools = @('7z', 'winrar', 'zip', 'rar', 'tar', 'gzip')
                    $processes = Get-Process | Select-Object Name, Id, Path, StartTime
                    
                    $foundCount = 0
                    
                    foreach ($process in $processes) {
                        foreach ($tool in $compressionTools) {
                            if ($process.Name -like "*$tool*") {
                                $indicator = [PSCustomObject]@{
                                    Type = 'Compression'
                                    Process = $process.Name
                                    ProcessId = $process.Id
                                    Path = $process.Path
                                    StartTime = if ($process.StartTime) { $process.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                                    Severity = 'Medium'
                                    Description = "Compression tool running: $($process.Name)"
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.Indicators.Compression += $indicator
                                $results.Summary.MediumFindings++
                                $foundCount++
                                
                                Write-Host "  [!] Compression: $($process.Name) (PID: $($process.Id))" -ForegroundColor Yellow
                                break
                            }
                        }
                    }
                    
                    # Check recent archive files in common locations
                    $tempPaths = @($env:TEMP, $env:USERPROFILE, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")
                    $archiveExtensions = @('*.zip', '*.rar', '*.7z', '*.tar', '*.gz')
                    
                    foreach ($path in $tempPaths) {
                        if (Test-Path $path) {
                            foreach ($ext in $archiveExtensions) {
                                $recentArchives = Get-ChildItem -Path $path -Filter $ext -File -ErrorAction SilentlyContinue |
                                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
                                    Where-Object { $_.Length -gt ($ThresholdMB * 1MB) }
                                
                                foreach ($archive in $recentArchives) {
                                    $sizeMB = [math]::Round($archive.Length / 1MB, 2)
                                    
                                    $indicator = [PSCustomObject]@{
                                        Type = 'Compression'
                                        Process = 'N/A'
                                        ProcessId = 'N/A'
                                        Path = $archive.FullName
                                        SizeMB = $sizeMB
                                        LastModified = $archive.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                        Severity = if ($sizeMB -gt 500) { 'High' } else { 'Medium' }
                                        Description = "Large archive file: $($archive.Name) ($sizeMB MB)"
                                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                    }
                                    
                                    $results.Indicators.Compression += $indicator
                                    $results.Summary.TotalDataMB += $sizeMB
                                    
                                    if ($sizeMB -gt 500) {
                                        $results.Summary.HighFindings++
                                    } else {
                                        $results.Summary.MediumFindings++
                                    }
                                    
                                    $foundCount++
                                    
                                    Write-Host "  [!] Archive: $($archive.Name) ($sizeMB MB)" -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No suspicious compression activities detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking compression: $_"
                }
            }
            
            # 4. Check for Data Staging
            if ($CheckStaging) {
                Write-Host "`n[4/4] Checking data staging..." -ForegroundColor Cyan
                
                try {
                    # Check for large files in staging locations
                    $stagingPaths = @(
                        "$env:TEMP",
                        "$env:USERPROFILE\AppData\Local\Temp",
                        "C:\Users\Public",
                        "C:\ProgramData"
                    )
                    
                    $foundCount = 0
                    
                    foreach ($path in $stagingPaths) {
                        if (Test-Path $path) {
                            # Find large files created recently
                            $recentFiles = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue -Depth 2 |
                                Where-Object { 
                                    $_.Length -gt ($ThresholdMB * 1MB) -and 
                                    $_.CreationTime -gt (Get-Date).AddHours(-24) 
                                } |
                                Sort-Object Length -Descending |
                                Select-Object -First 5
                            
                            foreach ($file in $recentFiles) {
                                $sizeMB = [math]::Round($file.Length / 1MB, 2)
                                
                                $indicator = [PSCustomObject]@{
                                    Type = 'Staging'
                                    Process = 'N/A'
                                    ProcessId = 'N/A'
                                    Path = $file.FullName
                                    FileName = $file.Name
                                    SizeMB = $sizeMB
                                    Created = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                                    Severity = if ($sizeMB -gt 500) { 'High' } else { 'Medium' }
                                    Description = "Large file in staging location: $($file.Name) ($sizeMB MB)"
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.Indicators.Staging += $indicator
                                $results.Summary.TotalDataMB += $sizeMB
                                
                                if ($sizeMB -gt 500) {
                                    $results.Summary.HighFindings++
                                } else {
                                    $results.Summary.MediumFindings++
                                }
                                
                                $foundCount++
                                
                                Write-Host "  [!] Staged: $($file.Name) ($sizeMB MB) in $path" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No suspicious data staging detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking staging: $_"
                }
            }
            
            # Calculate summary
            $results.Summary.TotalIndicators = 
                $results.Indicators.LargeTransfers.Count +
                $results.Indicators.CloudUploads.Count +
                $results.Indicators.Compression.Count +
                $results.Indicators.Staging.Count
            
            # Generate recommendations
            if ($results.Summary.TotalIndicators -gt 0) {
                if ($results.Summary.HighFindings -gt 0) {
                    $results.Recommendations += "HIGH: Investigate high-severity exfiltration indicators immediately"
                }
                
                $results.Recommendations += "Review and investigate flagged processes and files"
                $results.Recommendations += "Check network logs for data transfer volumes"
                $results.Recommendations += "Implement DLP (Data Loss Prevention) solution"
                $results.Recommendations += "Monitor cloud service access"
                $results.Recommendations += "Enable file access auditing on sensitive data"
                
                if ($results.Indicators.CloudUploads.Count -gt 0) {
                    $results.Recommendations += "Consider blocking unauthorized cloud services"
                }
                
                if ($results.Summary.TotalDataMB -gt 1000) {
                    $results.Recommendations += "CRITICAL: Large volume of data detected ($([math]::Round($results.Summary.TotalDataMB/1024, 2)) GB)"
                }
            }
            
        }
        catch {
            Write-Error "Error during data exfiltration detection: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor $(
            if ($results.Summary.HighFindings -gt 0) { 'Red' }
            elseif ($results.Summary.TotalIndicators -gt 0) { 'Yellow' }
            else { 'Green' }
        )
        
        Write-Host "`nDetection Summary:" -ForegroundColor Cyan
        Write-Host "  Total Indicators: $($results.Summary.TotalIndicators)" -ForegroundColor White
        Write-Host "  Critical: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumFindings)" -ForegroundColor Yellow
        Write-Host "  Total Data Volume: $([math]::Round($results.Summary.TotalDataMB, 2)) MB" -ForegroundColor White
        
        if ($results.Summary.TotalIndicators -gt 0) {
            Write-Host "`nIndicator Breakdown:" -ForegroundColor Cyan
            if ($results.Indicators.LargeTransfers.Count -gt 0) {
                Write-Host "  Large Transfers: $($results.Indicators.LargeTransfers.Count)" -ForegroundColor White
            }
            if ($results.Indicators.CloudUploads.Count -gt 0) {
                Write-Host "  Cloud Uploads: $($results.Indicators.CloudUploads.Count)" -ForegroundColor White
            }
            if ($results.Indicators.Compression.Count -gt 0) {
                Write-Host "  Compression: $($results.Indicators.Compression.Count)" -ForegroundColor White
            }
            if ($results.Indicators.Staging.Count -gt 0) {
                Write-Host "  Staging: $($results.Indicators.Staging.Count)" -ForegroundColor White
            }
        }
        else {
            Write-Host "`nNo data exfiltration indicators detected" -ForegroundColor Green
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | Select-Object -Unique | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        return $results
    }
}