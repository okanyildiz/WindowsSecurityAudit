function New-ForensicTimeline {
    <#
    .SYNOPSIS
        Creates a forensic timeline from multiple artifact sources
    .DESCRIPTION
        Builds a comprehensive timeline combining event logs, file system changes,
        registry modifications, and network connections for incident investigation.
    .PARAMETER StartTime
        Timeline start time (default: 24 hours ago)
    .PARAMETER EndTime
        Timeline end time (default: now)
    .PARAMETER IncludeEventLogs
        Include Windows event logs in timeline
    .PARAMETER IncludeFileSystem
        Include file system changes (MFT analysis)
    .PARAMETER IncludeRegistry
        Include registry modifications
    .PARAMETER IncludeNetwork
        Include network connection history
    .PARAMETER TargetPaths
        Specific paths to analyze for file system timeline
    .PARAMETER OutputPath
        Path to save timeline report
    .PARAMETER Format
        Output format: HTML, CSV, JSON, or All
    .EXAMPLE
        New-ForensicTimeline -StartTime (Get-Date).AddHours(-24)
        New-ForensicTimeline -IncludeFileSystem -TargetPaths "C:\Users\*\Downloads" -OutputPath "C:\Forensics"
    .OUTPUTS
        PSCustomObject with timeline events
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [DateTime]$StartTime = (Get-Date).AddHours(-24),
        
        [Parameter()]
        [DateTime]$EndTime = (Get-Date),
        
        [Parameter()]
        [switch]$IncludeEventLogs,
        
        [Parameter()]
        [switch]$IncludeFileSystem,
        
        [Parameter()]
        [switch]$IncludeRegistry,
        
        [Parameter()]
        [switch]$IncludeNetwork,
        
        [Parameter()]
        [string[]]$TargetPaths = @('C:\Users\*\Downloads', 'C:\Users\*\Documents', 'C:\Temp'),
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('HTML', 'CSV', 'JSON', 'All')]
        [string]$Format = 'HTML'
    )
    
    begin {
        Write-Host "=== FORENSIC TIMELINE CREATION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
        Write-Host "End Time: $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
        Write-Host "Duration: $([Math]::Round(($EndTime - $StartTime).TotalHours, 2)) hours" -ForegroundColor Yellow
        
        $timeline = [PSCustomObject]@{
            CreatedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            StartTime = $StartTime.ToString('yyyy-MM-dd HH:mm:ss')
            EndTime = $EndTime.ToString('yyyy-MM-dd HH:mm:ss')
            Events = @()
            Summary = @{
                TotalEvents = 0
                EventLogEntries = 0
                FileSystemChanges = 0
                RegistryChanges = 0
                NetworkConnections = 0
            }
        }
        
        # If no specific sources selected, include all
        if (-not ($IncludeEventLogs -or $IncludeFileSystem -or $IncludeRegistry -or $IncludeNetwork)) {
            $IncludeEventLogs = $true
            $IncludeFileSystem = $true
            $IncludeRegistry = $true
            Write-Host "No specific sources selected - including Event Logs, File System, and Registry" -ForegroundColor Gray
        }
    }
    
    process {
        try {
            # 1. COLLECT EVENT LOG ENTRIES
            if ($IncludeEventLogs) {
                Write-Host "`n[1/4] Collecting event log entries..." -ForegroundColor Cyan
                
                $eventLogs = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
                
                foreach ($logName in $eventLogs) {
                    try {
                        Write-Host "  Scanning: $logName..." -ForegroundColor Gray
                        
                        $events = Get-WinEvent -FilterHashtable @{
                            LogName = $logName
                            StartTime = $StartTime
                            EndTime = $EndTime
                        } -ErrorAction SilentlyContinue -MaxEvents 1000
                        
                        foreach ($event in $events) {
                            # FIXED: Safe message handling with null check
                            $message = if ($event.Message) {
                                $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                            } else {
                                "Event ID $($event.Id) - No message available"
                            }
                            
                            $timeline.Events += [PSCustomObject]@{
                                Timestamp = $event.TimeCreated
                                Source = 'EventLog'
                                Category = $logName
                                EventID = $event.Id
                                Level = $event.LevelDisplayName
                                Message = $message
                                Details = @{
                                    Provider = $event.ProviderName
                                    TaskDisplayName = $event.TaskDisplayName
                                    MachineName = $event.MachineName
                                }
                            }
                            
                            $timeline.Summary.EventLogEntries++
                        }
                        
                        Write-Host "    Found $($events.Count) events" -ForegroundColor Gray
                    }
                    catch {
                        Write-Warning "Could not read log $logName - $_"
                    }
                }
                
                Write-Host "  Total event log entries: $($timeline.Summary.EventLogEntries)" -ForegroundColor Green
            }
            
            # 2. COLLECT FILE SYSTEM CHANGES
            if ($IncludeFileSystem) {
                Write-Host "`n[2/4] Analyzing file system changes..." -ForegroundColor Cyan
                
                foreach ($path in $TargetPaths) {
                    if (Test-Path $path) {
                        Write-Host "  Scanning: $path..." -ForegroundColor Gray
                        
                        try {
                            # FIXED: Safe array wrapping with @()
                            $files = @(Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
                                Where-Object { 
                                    ($_.CreationTime -ge $StartTime -and $_.CreationTime -le $EndTime) -or
                                    ($_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime) -or
                                    ($_.LastAccessTime -ge $StartTime -and $_.LastAccessTime -le $EndTime)
                                } | 
                                Select-Object -First 500)
                            
                            foreach ($file in $files) {
                                # Add creation event
                                if ($file.CreationTime -ge $StartTime -and $file.CreationTime -le $EndTime) {
                                    $timeline.Events += [PSCustomObject]@{
                                        Timestamp = $file.CreationTime
                                        Source = 'FileSystem'
                                        Category = 'File Created'
                                        EventID = $null
                                        Level = 'Information'
                                        Message = "File created: $($file.FullName)"
                                        Details = @{
                                            FileName = $file.Name
                                            FilePath = $file.FullName
                                            Size = $file.Length
                                            Extension = $file.Extension
                                        }
                                    }
                                    
                                    $timeline.Summary.FileSystemChanges++
                                }
                                
                                # Add modification event
                                if ($file.LastWriteTime -ge $StartTime -and $file.LastWriteTime -le $EndTime -and
                                    $file.LastWriteTime -ne $file.CreationTime) {
                                    $timeline.Events += [PSCustomObject]@{
                                        Timestamp = $file.LastWriteTime
                                        Source = 'FileSystem'
                                        Category = 'File Modified'
                                        EventID = $null
                                        Level = 'Information'
                                        Message = "File modified: $($file.FullName)"
                                        Details = @{
                                            FileName = $file.Name
                                            FilePath = $file.FullName
                                            Size = $file.Length
                                            Extension = $file.Extension
                                        }
                                    }
                                    
                                    $timeline.Summary.FileSystemChanges++
                                }
                            }
                            
                            Write-Host "    Found $($files.Count) files" -ForegroundColor Gray
                        }
                        catch {
                            Write-Warning "Could not scan $path - $_"
                        }
                    }
                    else {
                        Write-Host "  Path not found: $path" -ForegroundColor Gray
                    }
                }
                
                Write-Host "  Total file system changes: $($timeline.Summary.FileSystemChanges)" -ForegroundColor Green
            }
            
            # 3. COLLECT REGISTRY CHANGES
            if ($IncludeRegistry) {
                Write-Host "`n[3/4] Analyzing registry modifications..." -ForegroundColor Cyan
                
                # Check recent registry activity via event logs
                try {
                    $regEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4657  # Registry value modified
                        StartTime = $StartTime
                        EndTime = $EndTime
                    } -ErrorAction SilentlyContinue -MaxEvents 500
                    
                    foreach ($event in $regEvents) {
                        # FIXED: Safe message handling
                        $message = if ($event.Message) {
                            $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                        } else {
                            "Registry value modified"
                        }
                        
                        $timeline.Events += [PSCustomObject]@{
                            Timestamp = $event.TimeCreated
                            Source = 'Registry'
                            Category = 'Registry Modified'
                            EventID = 4657
                            Level = 'Information'
                            Message = "Registry value modified"
                            Details = @{
                                EventID = $event.Id
                                Message = $message
                            }
                        }
                        
                        $timeline.Summary.RegistryChanges++
                    }
                    
                    Write-Host "  Total registry changes: $($timeline.Summary.RegistryChanges)" -ForegroundColor Green
                }
                catch {
                    Write-Host "  Registry event auditing not enabled" -ForegroundColor Gray
                }
            }
            
            # 4. COLLECT NETWORK CONNECTIONS
            if ($IncludeNetwork) {
                Write-Host "`n[4/4] Analyzing network activity..." -ForegroundColor Cyan
                
                # Current connections
                try {
                    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
                        Select-Object -First 100
                    
                    foreach ($conn in $connections) {
                        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                        
                        $timeline.Events += [PSCustomObject]@{
                            Timestamp = Get-Date  # Current snapshot
                            Source = 'Network'
                            Category = 'TCP Connection'
                            EventID = $null
                            Level = 'Information'
                            Message = "Active connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                            Details = @{
                                LocalAddress = $conn.LocalAddress
                                LocalPort = $conn.LocalPort
                                RemoteAddress = $conn.RemoteAddress
                                RemotePort = $conn.RemotePort
                                State = $conn.State
                                Process = if($process){$process.ProcessName}else{'Unknown'}
                                PID = $conn.OwningProcess
                            }
                        }
                        
                        $timeline.Summary.NetworkConnections++
                    }
                    
                    Write-Host "  Total network connections: $($timeline.Summary.NetworkConnections)" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not retrieve network connections"
                }
            }
            
            # 5. SORT AND FINALIZE TIMELINE
            Write-Host "`n[*] Sorting timeline events..." -ForegroundColor Cyan
            
            $timeline.Events = $timeline.Events | Sort-Object Timestamp -Descending
            $timeline.Summary.TotalEvents = $timeline.Events.Count
            
            Write-Host "  Total events in timeline: $($timeline.Summary.TotalEvents)" -ForegroundColor Green
            
            # 6. EXPORT REPORTS
            if ($OutputPath) {
                Write-Host "`n[*] Exporting forensic timeline..." -ForegroundColor Cyan
                
                if (-not (Test-Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $reportName = "ForensicTimeline_$timestamp"
                
                # Export JSON
                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $OutputPath "$reportName.json"
                    $timeline | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "  JSON timeline saved: $jsonPath" -ForegroundColor Green
                }
                
                # Export CSV
                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $OutputPath "$reportName.csv"
                    $timeline.Events | Select-Object Timestamp, Source, Category, Level, Message | 
                        Export-Csv $csvPath -NoTypeInformation
                    Write-Host "  CSV timeline saved: $csvPath" -ForegroundColor Green
                }
                
                # Export HTML
                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $OutputPath "$reportName.html"
                    $html = Generate-TimelineHTML -Timeline $timeline
                    $html | Out-File $htmlPath -Encoding UTF8
                    Write-Host "  HTML timeline saved: $htmlPath" -ForegroundColor Green
                }
            }
            
        }
        catch {
            Write-Error "Error during timeline creation - $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== FORENSIC TIMELINE COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "  Total Events: $($timeline.Summary.TotalEvents)" -ForegroundColor White
        Write-Host "  Event Log Entries: $($timeline.Summary.EventLogEntries)" -ForegroundColor Gray
        Write-Host "  File System Changes: $($timeline.Summary.FileSystemChanges)" -ForegroundColor Gray
        Write-Host "  Registry Changes: $($timeline.Summary.RegistryChanges)" -ForegroundColor Gray
        Write-Host "  Network Connections: $($timeline.Summary.NetworkConnections)" -ForegroundColor Gray
        
        if ($timeline.Events.Count -gt 0) {
            Write-Host "`nRecent Timeline Events:" -ForegroundColor Cyan
            $timeline.Events | 
                Select-Object -First 10 | 
                ForEach-Object {
                    $color = switch ($_.Source) {
                        'EventLog' { 'Yellow' }
                        'FileSystem' { 'Cyan' }
                        'Registry' { 'Magenta' }
                        'Network' { 'Green' }
                        default { 'White' }
                    }
                    
                    # Safe message truncation
                    $displayMessage = if ($_.Message) {
                        $_.Message.Substring(0, [Math]::Min(80, $_.Message.Length))
                    } else {
                        "No message"
                    }
                    
                    Write-Host "  [$($_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))] $($_.Source) - $($_.Category): $displayMessage" -ForegroundColor $color
                }
        }
        
        return $timeline
    }
}

# Helper function to generate HTML timeline
function Generate-TimelineHTML {
    param($Timeline)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Timeline - $($Timeline.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        .container { max-width: 1600px; margin: 0 auto; background: #2d2d2d; padding: 30px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        h1 { color: #00d4ff; border-bottom: 3px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #00b8ff; margin-top: 30px; }
        .summary { background: #3a3a3a; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #00d4ff; }
        .metric { display: inline-block; margin: 10px 30px 10px 0; }
        .metric-label { font-weight: bold; color: #888; font-size: 12px; }
        .metric-value { font-size: 28px; font-weight: bold; color: #00d4ff; }
        .timeline { margin: 30px 0; }
        .event { background: #3a3a3a; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #555; }
        .event:hover { background: #444; border-left-color: #00d4ff; }
        .event-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .event-time { color: #00d4ff; font-weight: bold; font-family: monospace; }
        .event-source { padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .source-eventlog { background: #ff6b35; color: white; }
        .source-filesystem { background: #00d4ff; color: black; }
        .source-registry { background: #a855f7; color: white; }
        .source-network { background: #10b981; color: white; }
        .event-message { color: #ccc; margin-top: 5px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #555; color: #888; font-size: 12px; }
        .filter-bar { background: #3a3a3a; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .filter-btn { background: #555; color: white; border: none; padding: 8px 15px; margin: 5px; border-radius: 3px; cursor: pointer; }
        .filter-btn:hover { background: #00d4ff; color: black; }
        .filter-btn.active { background: #00d4ff; color: black; }
    </style>
    <script>
        function filterEvents(source) {
            const events = document.querySelectorAll('.event');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            if (source === 'all') {
                events.forEach(evt => evt.style.display = 'block');
            } else {
                events.forEach(evt => {
                    if (evt.dataset.source === source) {
                        evt.style.display = 'block';
                    } else {
                        evt.style.display = 'none';
                    }
                });
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🔍 Forensic Timeline Analysis</h1>
        <p><strong>Computer:</strong> $($Timeline.ComputerName) | <strong>Generated:</strong> $($Timeline.CreatedDate)</p>
        <p><strong>Time Range:</strong> $($Timeline.StartTime) → $($Timeline.EndTime)</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="metric">
                <div class="metric-label">TOTAL EVENTS</div>
                <div class="metric-value">$($Timeline.Summary.TotalEvents)</div>
            </div>
            <div class="metric">
                <div class="metric-label">EVENT LOGS</div>
                <div class="metric-value">$($Timeline.Summary.EventLogEntries)</div>
            </div>
            <div class="metric">
                <div class="metric-label">FILE CHANGES</div>
                <div class="metric-value">$($Timeline.Summary.FileSystemChanges)</div>
            </div>
            <div class="metric">
                <div class="metric-label">REGISTRY</div>
                <div class="metric-value">$($Timeline.Summary.RegistryChanges)</div>
            </div>
            <div class="metric">
                <div class="metric-label">NETWORK</div>
                <div class="metric-value">$($Timeline.Summary.NetworkConnections)</div>
            </div>
        </div>
        
        <div class="filter-bar">
            <strong>Filter by Source:</strong>
            <button class="filter-btn active" onclick="filterEvents('all')">All</button>
            <button class="filter-btn" onclick="filterEvents('EventLog')">Event Logs</button>
            <button class="filter-btn" onclick="filterEvents('FileSystem')">File System</button>
            <button class="filter-btn" onclick="filterEvents('Registry')">Registry</button>
            <button class="filter-btn" onclick="filterEvents('Network')">Network</button>
        </div>
        
        <h2>Timeline Events</h2>
        <div class="timeline">
"@
    
    foreach ($event in $Timeline.Events) {
        $sourceClass = "source-$($event.Source.ToLower())"
        $timestamp = if ($event.Timestamp) { $event.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
        $message = if ($event.Message) { 
            $event.Message -replace '<', '&lt;' -replace '>', '&gt;'
        } else { 
            'No message available' 
        }
        
        $html += @"
            <div class="event" data-source="$($event.Source)">
                <div class="event-header">
                    <span class="event-time">$timestamp</span>
                    <span class="event-source $sourceClass">$($event.Source)</span>
                </div>
                <div><strong>$($event.Category)</strong></div>
                <div class="event-message">$message</div>
            </div>
"@
    }
    
    $currentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    $html += @"
        </div>
        
        <div class="footer">
            Generated by WindowsSecurityAudit Module | Forensic Timeline | $currentDate
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}