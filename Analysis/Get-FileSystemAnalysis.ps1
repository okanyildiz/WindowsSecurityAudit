function Get-FileSystemAnalysis {
    <#
    .SYNOPSIS
        Analyzes file system for suspicious files and activities
    .DESCRIPTION
        Scans directories for malicious files, unauthorized changes, and suspicious patterns
    .PARAMETER Path
        Path to scan (default: system-critical directories)
    .PARAMETER Recursive
        Scan subdirectories recursively
    .PARAMETER CheckRecent
        Check for recently created/modified files
    .PARAMETER Hours
        Hours to look back for recent files (default: 24)
    .PARAMETER ExportPath
        Path to export detailed results
    .EXAMPLE
        Get-FileSystemAnalysis
        Get-FileSystemAnalysis -Path "C:\Windows\System32" -Recursive -CheckRecent -Hours 48
    .OUTPUTS
        PSCustomObject with file system analysis results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path,
        
        [Parameter()]
        [switch]$Recursive,
        
        [Parameter()]
        [switch]$CheckRecent,
        
        [Parameter()]
        [int]$Hours = 24,
        
        [Parameter()]
        [string]$ExportPath
    )
    
    begin {
        Write-Host "Analyzing file system..." -ForegroundColor Cyan
        
        $results = [PSCustomObject]@{
            AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SuspiciousFiles = @()
            RecentFiles = @()
            HiddenFiles = @()
            ExecutablesInTemp = @()
            AlternateDataStreams = @()
            Statistics = @{
                FilesScanned = 0
                SuspiciousFiles = 0
                RecentFiles = 0
                HiddenFiles = 0
                ADSFound = 0
            }
        }
        
        # Default critical paths to scan if none specified
        if (-not $Path) {
            $scanPaths = @(
                "$env:SystemRoot\Temp",
                "$env:TEMP",
                "$env:LOCALAPPDATA\Temp",
                "$env:PUBLIC",
                "$env:ProgramData"
            )
        }
        else {
            $scanPaths = @($Path)
        }
        
        # Suspicious file extensions
        $suspiciousExtensions = @(
            '.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.ps1',
            '.scr', '.com', '.pif', '.hta', '.msi', '.jar'
        )
        
        # Known malicious file names
        $maliciousNames = @(
            'mimikatz', 'procdump', 'psexec', 'netcat', 'nc.exe',
            'pwdump', 'fgdump', 'wce.exe', 'gsecdump', 'lsass.dmp'
        )
        
        $startTime = (Get-Date).AddHours(-$Hours)
    }
    
    process {
        try {
            foreach ($scanPath in $scanPaths) {
                if (-not (Test-Path $scanPath)) {
                    Write-Warning "Path does not exist: $scanPath"
                    continue
                }
                
                Write-Verbose "Scanning path: $scanPath"
                
                # Get files
                $getChildParams = @{
                    Path = $scanPath
                    File = $true
                    Force = $true
                    ErrorAction = 'SilentlyContinue'
                }
                
                if ($Recursive) {
                    $getChildParams.Recurse = $true
                }
                
                $files = Get-ChildItem @getChildParams
                
                foreach ($file in $files) {
                    try {
                        $results.Statistics.FilesScanned++
                        
                        $isSuspicious = $false
                        $reasons = @()
                        
                        # Check 1: Hidden files
                        if ($file.Attributes -match 'Hidden') {
                            $results.HiddenFiles += [PSCustomObject]@{
                                Path = $file.FullName
                                Name = $file.Name
                                Size = [math]::Round($file.Length / 1KB, 2)
                                Created = $file.CreationTime
                                Modified = $file.LastWriteTime
                            }
                            $results.Statistics.HiddenFiles++
                            $isSuspicious = $true
                            $reasons += "Hidden file attribute"
                        }
                        
                        # Check 2: Malicious file names
                        foreach ($malName in $maliciousNames) {
                            if ($file.Name -match $malName) {
                                $isSuspicious = $true
                                $reasons += "Matches known malicious filename: $malName"
                                break
                            }
                        }
                        
                        # Check 3: Executables in temp directories
                        if ($file.Extension -in $suspiciousExtensions -and 
                            $file.DirectoryName -match '(Temp|tmp|Temporary)') {
                            $results.ExecutablesInTemp += [PSCustomObject]@{
                                Path = $file.FullName
                                Name = $file.Name
                                Extension = $file.Extension
                                Size = [math]::Round($file.Length / 1KB, 2)
                                Created = $file.CreationTime
                            }
                            $isSuspicious = $true
                            $reasons += "Executable in temporary directory"
                        }
                        
                        # Check 4: Double extensions
                        if ($file.Name -match '\.[^.]+\.[^.]+$') {
                            $extensions = $file.Name -split '\.'
                            if ($extensions.Count -gt 2) {
                                $isSuspicious = $true
                                $reasons += "Multiple file extensions (possible masquerading)"
                            }
                        }
                        
                        # Check 5: Very recent files
                        if ($CheckRecent -and $file.CreationTime -gt $startTime) {
                            $results.RecentFiles += [PSCustomObject]@{
                                Path = $file.FullName
                                Name = $file.Name
                                Size = [math]::Round($file.Length / 1KB, 2)
                                Created = $file.CreationTime
                                Modified = $file.LastWriteTime
                            }
                            $results.Statistics.RecentFiles++
                        }
                        
                        # Check 6: Alternate Data Streams (ADS)
                        try {
                            $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue | 
                                Where-Object { $_.Stream -ne ':$DATA' }
                            
                            if ($streams) {
                                foreach ($stream in $streams) {
                                    $results.AlternateDataStreams += [PSCustomObject]@{
                                        FilePath = $file.FullName
                                        FileName = $file.Name
                                        StreamName = $stream.Stream
                                        StreamSize = $stream.Length
                                    }
                                    $results.Statistics.ADSFound++
                                    $isSuspicious = $true
                                    $reasons += "Contains alternate data stream: $($stream.Stream)"
                                }
                            }
                        }
                        catch {
                            # ADS check failed
                        }
                        
                        # Check 7: Suspicious size (very small or very large executables)
                        if ($file.Extension -in @('.exe', '.dll')) {
                            if ($file.Length -lt 10KB) {
                                $isSuspicious = $true
                                $reasons += "Unusually small executable (<10KB)"
                            }
                            elseif ($file.Length -gt 50MB) {
                                $isSuspicious = $true
                                $reasons += "Unusually large executable (>50MB)"
                            }
                        }
                        
                        # Check 8: No company/product information
                        if ($file.Extension -in @('.exe', '.dll')) {
                            try {
                                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
                                if ([string]::IsNullOrEmpty($versionInfo.CompanyName) -and 
                                    [string]::IsNullOrEmpty($versionInfo.ProductName)) {
                                    $isSuspicious = $true
                                    $reasons += "No company or product information"
                                }
                            }
                            catch {
                                # Version info check failed
                            }
                        }
                        
                        # Add to suspicious files if flagged
                        if ($isSuspicious) {
                            $results.SuspiciousFiles += [PSCustomObject]@{
                                Path = $file.FullName
                                Name = $file.Name
                                Extension = $file.Extension
                                Size = [math]::Round($file.Length / 1KB, 2)
                                Created = $file.CreationTime
                                Modified = $file.LastWriteTime
                                Attributes = $file.Attributes
                                Reasons = ($reasons -join '; ')
                            }
                            $results.Statistics.SuspiciousFiles++
                        }
                        
                    }
                    catch {
                        Write-Verbose "Error analyzing file $($file.Name): $_"
                    }
                }
            }
            
        }
        catch {
            Write-Error "Error during file system analysis: $_"
            throw
        }
    }
    
    end {
        Write-Host "`nFile System Analysis Complete!" -ForegroundColor Green
        Write-Host "`n=== Statistics ===" -ForegroundColor Cyan
        Write-Host "Files scanned: $($results.Statistics.FilesScanned)" -ForegroundColor Yellow
        Write-Host "Suspicious files: $($results.Statistics.SuspiciousFiles)" -ForegroundColor $(if ($results.Statistics.SuspiciousFiles -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Hidden files: $($results.Statistics.HiddenFiles)" -ForegroundColor Yellow
        Write-Host "Recent files: $($results.Statistics.RecentFiles)" -ForegroundColor Yellow
        Write-Host "Alternate data streams: $($results.Statistics.ADSFound)" -ForegroundColor $(if ($results.Statistics.ADSFound -gt 0) { 'Yellow' } else { 'Green' })
        
        # Export if requested
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "FileSystemAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Host "`nResults exported to: $exportFile" -ForegroundColor Cyan
        }
        
        return $results
    }
}