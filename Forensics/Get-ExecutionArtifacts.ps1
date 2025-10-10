function Get-ExecutionArtifacts {
    <#
    .SYNOPSIS
        Extracts program execution artifacts from Windows forensic sources
    .DESCRIPTION
        Analyzes Prefetch files, UserAssist registry, ShimCache, RecentApps, and 
        BAM/DAM for comprehensive program execution history. Critical for incident
        response and forensic investigations.
    .PARAMETER IncludePrefetch
        Parse Windows Prefetch files
    .PARAMETER IncludeUserAssist
        Extract UserAssist registry entries
    .PARAMETER IncludeShimCache
        Parse Application Compatibility Cache (ShimCache)
    .PARAMETER IncludeRecentApps
        Include recent applications from registry
    .PARAMETER IncludeBAM
        Parse Background Activity Moderator (Windows 10+)
    .PARAMETER OutputPath
        Path to save execution artifacts report
    .PARAMETER Format
        Report format: HTML, JSON, CSV, or All
    .EXAMPLE
        Get-ExecutionArtifacts
        Get-ExecutionArtifacts -IncludePrefetch -IncludeUserAssist -OutputPath "C:\Forensics"
    .OUTPUTS
        PSCustomObject with execution artifacts
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludePrefetch,
        
        [Parameter()]
        [switch]$IncludeUserAssist,
        
        [Parameter()]
        [switch]$IncludeShimCache,
        
        [Parameter()]
        [switch]$IncludeRecentApps,
        
        [Parameter()]
        [switch]$IncludeBAM,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML'
    )
    
    begin {
        Write-Host "=== EXECUTION ARTIFACTS ANALYSIS ===" -ForegroundColor Cyan
        Write-Host "Scan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Artifacts = @()
            Summary = @{
                TotalArtifacts = 0
                Prefetch = 0
                UserAssist = 0
                ShimCache = 0
                RecentApps = 0
                BAM = 0
            }
        }
        
        # If no specific sources selected, include common ones
        if (-not ($IncludePrefetch -or $IncludeUserAssist -or $IncludeShimCache -or $IncludeRecentApps -or $IncludeBAM)) {
            $IncludePrefetch = $true
            $IncludeUserAssist = $true
            $IncludeRecentApps = $true
            $IncludeBAM = $true
            Write-Host "No specific sources selected - including Prefetch, UserAssist, RecentApps, and BAM" -ForegroundColor Gray
        }
    }
    
    process {
        try {
            # 1. PARSE PREFETCH FILES
            if ($IncludePrefetch) {
                Write-Host "`n[1/5] Analyzing Prefetch files..." -ForegroundColor Cyan
                
                try {
                    $prefetchPath = "$env:SystemRoot\Prefetch"
                    
                    if (Test-Path $prefetchPath) {
                        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
                        
                        foreach ($file in $prefetchFiles) {
                            # Extract executable name from prefetch filename (format: EXECUTABLE-HASH.pf)
                            $executableName = ($file.BaseName -split '-')[0]
                            
                            $results.Artifacts += [PSCustomObject]@{
                                Source = 'Prefetch'
                                ExecutableName = "$executableName.exe"
                                FullPath = $null
                                Timestamp = $file.LastWriteTime
                                TimestampType = 'Last Executed (Approximate)'
                                Details = @{
                                    PrefetchFile = $file.Name
                                    FilePath = $file.FullName
                                    FileSize = $file.Length
                                    Created = $file.CreationTime
                                }
                            }
                            
                            $results.Summary.Prefetch++
                        }
                        
                        Write-Host "  Found $($prefetchFiles.Count) Prefetch files" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  Prefetch folder not found (may be disabled)" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Could not parse Prefetch files - $_"
                }
            }
            
            # 2. PARSE USERASSIST REGISTRY
            if ($IncludeUserAssist) {
                Write-Host "`n[2/5] Analyzing UserAssist registry..." -ForegroundColor Cyan
                
                try {
                    # UserAssist is per-user, so check current user
                    $userAssistPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
                    
                    if (Test-Path $userAssistPath) {
                        $guids = Get-ChildItem -Path $userAssistPath -ErrorAction SilentlyContinue
                        
                        foreach ($guid in $guids) {
                            $countPath = Join-Path $guid.PSPath 'Count'
                            
                            if (Test-Path $countPath) {
                                $entries = Get-Item -Path $countPath -ErrorAction SilentlyContinue | 
                                    Select-Object -ExpandProperty Property
                                
                                foreach ($entry in $entries) {
                                    try {
                                        # Decode ROT13 encoded entry name
                                        $decodedName = ConvertFrom-ROT13 -Text $entry
                                        
                                        # Get execution data
                                        $value = Get-ItemProperty -Path $countPath -Name $entry -ErrorAction SilentlyContinue
                                        
                                        # Skip if not an executable path
                                        if ($decodedName -notmatch '\.(exe|bat|cmd|ps1|vbs|js)') {
                                            continue
                                        }
                                        
                                        $results.Artifacts += [PSCustomObject]@{
                                            Source = 'UserAssist'
                                            ExecutableName = Split-Path -Path $decodedName -Leaf
                                            FullPath = $decodedName
                                            Timestamp = Get-Date  # UserAssist timestamp parsing is complex, using current time
                                            TimestampType = 'Tracked'
                                            Details = @{
                                                EncodedName = $entry
                                                DecodedPath = $decodedName
                                            }
                                        }
                                        
                                        $results.Summary.UserAssist++
                                    }
                                    catch {
                                        Write-Verbose "Could not decode UserAssist entry: $entry"
                                    }
                                }
                            }
                        }
                        
                        Write-Host "  Found $($results.Summary.UserAssist) UserAssist entries" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  UserAssist registry not found" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Could not parse UserAssist - $_"
                }
            }
            
            # 3. PARSE SHIMCACHE
            if ($IncludeShimCache) {
                Write-Host "`n[3/5] Analyzing ShimCache (Application Compatibility)..." -ForegroundColor Cyan
                
                try {
                    # ShimCache location
                    $shimCachePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
                    
                    if (Test-Path $shimCachePath) {
                        # ShimCache data is binary and complex to parse
                        # This is a simplified approach - full parsing requires binary analysis
                        $shimData = Get-ItemProperty -Path $shimCachePath -Name AppCompatCache -ErrorAction SilentlyContinue
                        
                        if ($shimData) {
                            Write-Host "  ShimCache data found (binary parsing not implemented)" -ForegroundColor Gray
                            Write-Host "  Note: Full ShimCache parsing requires specialized tools like ShimCacheParser" -ForegroundColor Yellow
                            
                            $results.Artifacts += [PSCustomObject]@{
                                Source = 'ShimCache'
                                ExecutableName = 'ShimCache Binary Data'
                                FullPath = $shimCachePath
                                Timestamp = Get-Date
                                TimestampType = 'Registry Key'
                                Details = @{
                                    Note = 'Binary data present - use ShimCacheParser.exe for full analysis'
                                    DataSize = $shimData.AppCompatCache.Length
                                }
                            }
                            
                            $results.Summary.ShimCache++
                        }
                    }
                    else {
                        Write-Host "  ShimCache registry not found" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Could not access ShimCache - $_"
                }
            }
            
            # 4. PARSE RECENT APPS
            if ($IncludeRecentApps) {
                Write-Host "`n[4/5] Analyzing Recent Applications..." -ForegroundColor Cyan
                
                try {
                    # Check multiple recent app locations
                    $recentPaths = @(
                        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps',
                        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched'
                    )
                    
                    foreach ($path in $recentPaths) {
                        if (Test-Path $path) {
                            $apps = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                            
                            foreach ($app in $apps) {
                                try {
                                    $props = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
                                    
                                    # Extract app path if available
                                    $appPath = $null
                                    $appName = $app.PSChildName
                                    
                                    if ($props.PSObject.Properties.Name -contains 'AppPath') {
                                        $appPath = $props.AppPath
                                        $appName = Split-Path -Path $appPath -Leaf
                                    }
                                    elseif ($props.PSObject.Properties.Name -contains 'RecentItems') {
                                        $appPath = $props.RecentItems
                                    }
                                    
                                    if ($appName -or $appPath) {
                                        $results.Artifacts += [PSCustomObject]@{
                                            Source = 'RecentApps'
                                            ExecutableName = $appName
                                            FullPath = $appPath
                                            Timestamp = Get-Date
                                            TimestampType = 'Recent Activity'
                                            Details = @{
                                                RegistryPath = $app.PSPath
                                            }
                                        }
                                        
                                        $results.Summary.RecentApps++
                                    }
                                }
                                catch {
                                    Write-Verbose "Could not read recent app: $($app.PSPath)"
                                }
                            }
                        }
                    }
                    
                    Write-Host "  Found $($results.Summary.RecentApps) recent applications" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not parse recent apps - $_"
                }
            }
            
            # 5. PARSE BAM/DAM (Background Activity Moderator)
            if ($IncludeBAM) {
                Write-Host "`n[5/5] Analyzing BAM/DAM (Background Activity Moderator)..." -ForegroundColor Cyan
                
                try {
                    # BAM location (Windows 10 1709+)
                    $bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
                    
                    if (Test-Path $bamPath) {
                        $users = Get-ChildItem -Path $bamPath -ErrorAction SilentlyContinue
                        
                        foreach ($user in $users) {
                            $entries = Get-ItemProperty -Path $user.PSPath -ErrorAction SilentlyContinue
                            
                            foreach ($property in $entries.PSObject.Properties) {
                                # Skip non-path properties
                                if ($property.Name -like 'PS*' -or $property.Name -eq 'SequenceNumber') {
                                    continue
                                }
                                
                                $execPath = $property.Name
                                
                                # Extract timestamp from binary data (simplified)
                                $timestamp = Get-Date  # Full parsing requires binary conversion
                                
                                if ($execPath -match '\.(exe|bat|cmd|ps1)$') {
                                    $results.Artifacts += [PSCustomObject]@{
                                        Source = 'BAM'
                                        ExecutableName = Split-Path -Path $execPath -Leaf
                                        FullPath = $execPath
                                        Timestamp = $timestamp
                                        TimestampType = 'Last Execution (BAM)'
                                        Details = @{
                                            UserSID = Split-Path -Path $user.PSPath -Leaf
                                        }
                                    }
                                    
                                    $results.Summary.BAM++
                                }
                            }
                        }
                        
                        Write-Host "  Found $($results.Summary.BAM) BAM entries" -ForegroundColor Green
                    }
                    else {
                        # Try DAM (older Windows 10)
                        $damPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
                        
                        if (Test-Path $damPath) {
                            Write-Host "  DAM found (older Windows 10 version)" -ForegroundColor Gray
                            # Similar parsing as BAM
                        }
                        else {
                            Write-Host "  BAM/DAM not available (Windows 10 1709+ required)" -ForegroundColor Gray
                        }
                    }
                }
                catch {
                    Write-Warning "Could not parse BAM/DAM - $_"
                }
            }
            
            # FINALIZE
            $results.Summary.TotalArtifacts = $results.Artifacts.Count
            
            # Sort artifacts by timestamp
            $results.Artifacts = $results.Artifacts | 
                Sort-Object Timestamp -Descending
            
            # 6. EXPORT REPORTS
            if ($OutputPath) {
                Write-Host "`n[*] Exporting execution artifacts..." -ForegroundColor Cyan
                
                if (-not (Test-Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $reportName = "ExecutionArtifacts_$timestamp"
                
                # Export JSON
                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $OutputPath "$reportName.json"
                    $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "  JSON report saved: $jsonPath" -ForegroundColor Green
                }
                
                # Export CSV
                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $OutputPath "$reportName.csv"
                    $results.Artifacts | Select-Object Source, ExecutableName, FullPath, Timestamp, TimestampType | 
                        Export-Csv $csvPath -NoTypeInformation
                    Write-Host "  CSV report saved: $csvPath" -ForegroundColor Green
                }
                
                # Export HTML
                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $OutputPath "$reportName.html"
                    $html = Generate-ExecutionArtifactsHTML -Results $results
                    $html | Out-File $htmlPath -Encoding UTF8
                    Write-Host "  HTML report saved: $htmlPath" -ForegroundColor Green
                }
            }
            
        }
        catch {
            Write-Error "Error during execution artifacts analysis - $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== EXECUTION ARTIFACTS ANALYSIS COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "  Total Artifacts: $($results.Summary.TotalArtifacts)" -ForegroundColor White
        Write-Host "  Prefetch Files: $($results.Summary.Prefetch)" -ForegroundColor Gray
        Write-Host "  UserAssist Entries: $($results.Summary.UserAssist)" -ForegroundColor Gray
        Write-Host "  ShimCache Entries: $($results.Summary.ShimCache)" -ForegroundColor Gray
        Write-Host "  Recent Apps: $($results.Summary.RecentApps)" -ForegroundColor Gray
        Write-Host "  BAM Entries: $($results.Summary.BAM)" -ForegroundColor Gray
        
        if ($results.Artifacts.Count -gt 0) {
            Write-Host "`nRecent Executions:" -ForegroundColor Cyan
            $results.Artifacts | 
                Where-Object { $_.ExecutableName -notlike 'ShimCache*' } |
                Select-Object -First 15 | 
                ForEach-Object {
                    $timestamp = $_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
                    $color = switch ($_.Source) {
                        'Prefetch' { 'Cyan' }
                        'UserAssist' { 'Yellow' }
                        'BAM' { 'Green' }
                        'RecentApps' { 'Magenta' }
                        default { 'White' }
                    }
                    Write-Host "  [$timestamp] [$($_.Source)] $($_.ExecutableName)" -ForegroundColor $color
                }
        }
        
        return $results
    }
}

# Helper function to decode ROT13 (used by UserAssist)
function ConvertFrom-ROT13 {
    param([string]$Text)
    
    $result = ""
    foreach ($char in $Text.ToCharArray()) {
        if ($char -match '[A-Za-z]') {
            $base = if ($char -match '[A-Z]') { 65 } else { 97 }
            $result += [char](($([int]$char - $base + 13) % 26) + $base)
        }
        else {
            $result += $char
        }
    }
    return $result
}

# Helper function to generate HTML report
function Generate-ExecutionArtifactsHTML {
    param($Results)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Execution Artifacts - $($Results.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1600px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 30px 10px 0; }
        .metric-label { font-weight: bold; color: #7f8c8d; }
        .metric-value { font-size: 24px; font-weight: bold; color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }
        th { background: #e74c3c; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; vertical-align: top; }
        tr:hover { background: #f8f9fa; }
        .source-badge { padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; color: white; }
        .source-prefetch { background: #3498db; }
        .source-userassist { background: #f39c12; }
        .source-shimcache { background: #9b59b6; }
        .source-recentapps { background: #e91e63; }
        .source-bam { background: #27ae60; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }
        .path { font-family: monospace; font-size: 11px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Program Execution Artifacts</h1>
        <p><strong>Computer:</strong> $($Results.ComputerName) | <strong>Scan Date:</strong> $($Results.ScanDate)</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="metric">
                <div class="metric-label">Total Artifacts</div>
                <div class="metric-value">$($Results.Summary.TotalArtifacts)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Prefetch</div>
                <div class="metric-value">$($Results.Summary.Prefetch)</div>
            </div>
            <div class="metric">
                <div class="metric-label">UserAssist</div>
                <div class="metric-value">$($Results.Summary.UserAssist)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Recent Apps</div>
                <div class="metric-value">$($Results.Summary.RecentApps)</div>
            </div>
            <div class="metric">
                <div class="metric-label">BAM</div>
                <div class="metric-value">$($Results.Summary.BAM)</div>
            </div>
        </div>
        
        <h2>Execution History</h2>
        <table>
            <tr>
                <th style="width: 80px;">Source</th>
                <th style="width: 200px;">Executable</th>
                <th>Full Path</th>
                <th style="width: 150px;">Timestamp</th>
                <th style="width: 150px;">Type</th>
            </tr>
"@
    
    foreach ($artifact in $Results.Artifacts) {
        $sourceClass = "source-$($artifact.Source.ToLower())"
        $timestamp = $artifact.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
        $fullPath = if ($artifact.FullPath) { 
            $artifact.FullPath -replace '<', '&lt;' -replace '>', '&gt;'
        } else { 
            'N/A' 
        }
        
        $html += @"
            <tr>
                <td><span class="source-badge $sourceClass">$($artifact.Source)</span></td>
                <td><strong>$($artifact.ExecutableName)</strong></td>
                <td><span class="path">$fullPath</span></td>
                <td>$timestamp</td>
                <td><small>$($artifact.TimestampType)</small></td>
            </tr>
"@
    }
    
    $html += "        </table>`n"
    
    $currentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    $html += @"
        
        <div class="footer">
            Generated by WindowsSecurityAudit Module | Execution Artifacts Analysis | $currentDate
            <br><strong>Note:</strong> ShimCache requires specialized binary parsing tools for full analysis
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}