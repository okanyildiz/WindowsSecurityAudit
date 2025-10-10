function Get-USBHistory {
    <#
    .SYNOPSIS
        Retrieves USB device connection history from Windows artifacts
    .DESCRIPTION
        Analyzes registry, event logs, and setup logs to identify all USB devices
        that have been connected to the system, including timestamps, serial numbers,
        vendor information, and last connection times.
    .PARAMETER IncludeEventLogs
        Include event log analysis for USB connection/disconnection events
    .PARAMETER IncludeSetupAPI
        Parse SetupAPI.dev.log for detailed device installation history
    .PARAMETER DaysBack
        Number of days to look back in event logs (default: 30)
    .PARAMETER OutputPath
        Path to save USB history report
    .PARAMETER Format
        Report format: HTML, JSON, CSV, or All
    .EXAMPLE
        Get-USBHistory
        Get-USBHistory -IncludeEventLogs -IncludeSetupAPI -OutputPath "C:\Forensics"
    .OUTPUTS
        PSCustomObject with USB device history
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeEventLogs,
        
        [Parameter()]
        [switch]$IncludeSetupAPI,
        
        [Parameter()]
        [int]$DaysBack = 30,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string]$Format = 'HTML'
    )
    
    begin {
        Write-Host "=== USB DEVICE HISTORY ANALYSIS ===" -ForegroundColor Cyan
        Write-Host "Scan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Include Event Logs: $(if($IncludeEventLogs){'Yes'}else{'No'})" -ForegroundColor Yellow
        Write-Host "Include SetupAPI: $(if($IncludeSetupAPI){'Yes'}else{'No'})" -ForegroundColor Yellow
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            USBDevices = @()
            ConnectionEvents = @()
            Summary = @{
                TotalDevices = 0
                StorageDevices = 0
                OtherDevices = 0
                RecentConnections = 0
            }
        }
    }
    
    process {
        try {
            # 1. ANALYZE REGISTRY - USBSTOR (USB Storage Devices)
            Write-Host "`n[1/4] Scanning USB storage devices from registry..." -ForegroundColor Cyan
            
            try {
                $usbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
                
                if (Test-Path $usbStorPath) {
                    $vendors = Get-ChildItem -Path $usbStorPath -ErrorAction SilentlyContinue
                    
                    foreach ($vendor in $vendors) {
                        $devices = Get-ChildItem -Path $vendor.PSPath -ErrorAction SilentlyContinue
                        
                        foreach ($device in $devices) {
                            try {
                                $props = Get-ItemProperty -Path $device.PSPath -ErrorAction SilentlyContinue
                                
                                # Extract device information
                                $friendlyName = if ($props.FriendlyName) { $props.FriendlyName } else { $vendor.PSChildName }
                                $serialNumber = $device.PSChildName
                                
                                # Parse vendor string (e.g., "Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00")
                                $vendorName = if ($vendor.PSChildName -match 'Ven_([^&]+)') { $matches[1] } else { 'Unknown' }
                                $productName = if ($vendor.PSChildName -match 'Prod_([^&]+)') { $matches[1] } else { 'Unknown' }
                                $revision = if ($vendor.PSChildName -match 'Rev_([^&]+)') { $matches[1] } else { 'Unknown' }
                                
                                # FIXED: Try to get install date from registry properties
                                $installDate = $null
                                if ($props.PSObject.Properties.Name -contains 'InstallDate') {
                                    $installDate = $props.InstallDate
                                }
                                elseif ($props.PSObject.Properties.Name -contains 'FirstInstallDate') {
                                    $installDate = $props.FirstInstallDate
                                }
                                
                                $deviceInfo = [PSCustomObject]@{
                                    Type = 'Storage'
                                    FriendlyName = $friendlyName
                                    Vendor = $vendorName
                                    Product = $productName
                                    Revision = $revision
                                    SerialNumber = $serialNumber
                                    FirstInstalled = $installDate
                                    LastConnected = $installDate
                                    RegistryPath = $device.PSPath
                                }
                                
                                $results.USBDevices += $deviceInfo
                                $results.Summary.StorageDevices++
                                
                                Write-Host "  Found: $vendorName $productName (SN: $serialNumber)" -ForegroundColor Gray
                            }
                            catch {
                                Write-Verbose "Could not read device: $($device.PSPath)"
                            }
                        }
                    }
                }
                
                Write-Host "  Total USB storage devices: $($results.Summary.StorageDevices)" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not access USBSTOR registry key - $_"
            }
            
            # 2. ANALYZE REGISTRY - USB (All USB Devices)
            Write-Host "`n[2/4] Scanning all USB devices from registry..." -ForegroundColor Cyan
            
            try {
                $usbPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
                
                if (Test-Path $usbPath) {
                    $usbDevices = Get-ChildItem -Path $usbPath -ErrorAction SilentlyContinue
                    
                    foreach ($usbDevice in $usbDevices) {
                        $instances = Get-ChildItem -Path $usbDevice.PSPath -ErrorAction SilentlyContinue
                        
                        foreach ($instance in $instances) {
                            try {
                                $props = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                                
                                # Skip if already captured in USBSTOR
                                $serialNumber = $instance.PSChildName
                                $alreadyExists = $results.USBDevices | Where-Object { $_.SerialNumber -eq $serialNumber }
                                
                                if (-not $alreadyExists -and $props.FriendlyName) {
                                    # Parse VID/PID from device name (e.g., "VID_046D&PID_C52B")
                                    $vid = if ($usbDevice.PSChildName -match 'VID_([0-9A-F]+)') { $matches[1] } else { 'Unknown' }
                                    $pid = if ($usbDevice.PSChildName -match 'PID_([0-9A-F]+)') { $matches[1] } else { 'Unknown' }
                                    
                                    # FIXED: Safe timestamp retrieval from registry properties
                                    $installDate = $null
                                    try {
                                        if ($props.PSObject.Properties.Name -contains 'InstallDate') {
                                            $installDate = $props.InstallDate
                                        }
                                        elseif ($props.PSObject.Properties.Name -contains 'FirstInstallDate') {
                                            $installDate = $props.FirstInstallDate
                                        }
                                    }
                                    catch {
                                        # Timestamp not available
                                    }
                                    
                                    $deviceInfo = [PSCustomObject]@{
                                        Type = 'USB Device'
                                        FriendlyName = $props.FriendlyName
                                        Vendor = "VID_$vid"
                                        Product = "PID_$pid"
                                        Revision = 'N/A'
                                        SerialNumber = $serialNumber
                                        FirstInstalled = $installDate
                                        LastConnected = $installDate
                                        RegistryPath = $instance.PSPath
                                    }
                                    
                                    $results.USBDevices += $deviceInfo
                                    $results.Summary.OtherDevices++
                                    
                                    Write-Host "  Found: $($props.FriendlyName) (VID_$vid PID_$pid)" -ForegroundColor Gray
                                }
                            }
                            catch {
                                Write-Verbose "Could not read USB device: $($instance.PSPath)"
                            }
                        }
                    }
                }
                
                Write-Host "  Total other USB devices: $($results.Summary.OtherDevices)" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not access USB registry key - $_"
            }
            
            # 3. ANALYZE EVENT LOGS
            if ($IncludeEventLogs) {
                Write-Host "`n[3/4] Analyzing USB connection events..." -ForegroundColor Cyan
                
                try {
                    $startTime = (Get-Date).AddDays(-$DaysBack)
                    
                    # Event ID 2003 = Device connected, Event ID 20001 = First-time device installation
                    $eventLogs = @(
                        @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; ID=2003},
                        @{LogName='System'; ID=20001}
                    )
                    
                    foreach ($logConfig in $eventLogs) {
                        try {
                            $events = Get-WinEvent -FilterHashtable @{
                                LogName = $logConfig.LogName
                                ID = $logConfig.ID
                                StartTime = $startTime
                            } -ErrorAction SilentlyContinue -MaxEvents 500
                            
                            foreach ($event in $events) {
                                $message = if ($event.Message) { $event.Message } else { "USB Event $($event.Id)" }
                                
                                $results.ConnectionEvents += [PSCustomObject]@{
                                    Timestamp = $event.TimeCreated
                                    EventID = $event.Id
                                    LogName = $logConfig.LogName
                                    Message = $message.Substring(0, [Math]::Min(200, $message.Length))
                                }
                                
                                $results.Summary.RecentConnections++
                            }
                        }
                        catch {
                            Write-Verbose "Could not read log: $($logConfig.LogName)"
                        }
                    }
                    
                    Write-Host "  Total connection events: $($results.Summary.RecentConnections)" -ForegroundColor Green
                }
                catch {
                    Write-Warning "Could not analyze event logs - $_"
                }
            }
            else {
                Write-Host "`n[3/4] Skipping event log analysis (disabled)" -ForegroundColor Gray
            }
            
            # 4. PARSE SETUPAPI LOG
            if ($IncludeSetupAPI) {
                Write-Host "`n[4/4] Parsing SetupAPI device log..." -ForegroundColor Cyan
                
                try {
                    $setupApiPath = "$env:SystemRoot\inf\setupapi.dev.log"
                    
                    if (Test-Path $setupApiPath) {
                        $setupContent = Get-Content $setupApiPath -ErrorAction SilentlyContinue | 
                            Select-String -Pattern "USB|USBSTOR" -Context 0,2 | 
                            Select-Object -First 100
                        
                        $usbEntries = $setupContent.Count
                        Write-Host "  Found $usbEntries USB-related entries in SetupAPI log" -ForegroundColor Green
                        
                        # Store sample entries
                        foreach ($entry in ($setupContent | Select-Object -First 10)) {
                            $results.ConnectionEvents += [PSCustomObject]@{
                                Timestamp = $null
                                EventID = 'SetupAPI'
                                LogName = 'setupapi.dev.log'
                                Message = $entry.Line
                            }
                        }
                    }
                    else {
                        Write-Host "  SetupAPI log not found" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Could not parse SetupAPI log - $_"
                }
            }
            else {
                Write-Host "`n[4/4] Skipping SetupAPI parsing (disabled)" -ForegroundColor Gray
            }
            
            # FINALIZE
            $results.Summary.TotalDevices = $results.USBDevices.Count
            
            # Sort devices by last connection (those with dates first)
            $results.USBDevices = $results.USBDevices | 
                Sort-Object @{Expression={if($_.LastConnected){$_.LastConnected}else{[DateTime]::MinValue}}; Descending=$true}
            
            # 5. EXPORT REPORTS
            if ($OutputPath) {
                Write-Host "`n[*] Exporting USB history reports..." -ForegroundColor Cyan
                
                if (-not (Test-Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $reportName = "USBHistory_$timestamp"
                
                # Export JSON
                if ($Format -in @('JSON', 'All')) {
                    $jsonPath = Join-Path $OutputPath "$reportName.json"
                    $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
                    Write-Host "  JSON report saved: $jsonPath" -ForegroundColor Green
                }
                
                # Export CSV
                if ($Format -in @('CSV', 'All')) {
                    $csvPath = Join-Path $OutputPath "$reportName.csv"
                    $results.USBDevices | Export-Csv $csvPath -NoTypeInformation
                    Write-Host "  CSV report saved: $csvPath" -ForegroundColor Green
                }
                
                # Export HTML
                if ($Format -in @('HTML', 'All')) {
                    $htmlPath = Join-Path $OutputPath "$reportName.html"
                    $html = Generate-USBHistoryHTML -Results $results
                    $html | Out-File $htmlPath -Encoding UTF8
                    Write-Host "  HTML report saved: $htmlPath" -ForegroundColor Green
                }
            }
            
        }
        catch {
            Write-Error "Error during USB history analysis - $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== USB HISTORY ANALYSIS COMPLETE ===" -ForegroundColor Green
        
        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "  Total USB Devices: $($results.Summary.TotalDevices)" -ForegroundColor White
        Write-Host "  Storage Devices: $($results.Summary.StorageDevices)" -ForegroundColor Gray
        Write-Host "  Other USB Devices: $($results.Summary.OtherDevices)" -ForegroundColor Gray
        
        if ($IncludeEventLogs) {
            Write-Host "  Recent Connection Events: $($results.Summary.RecentConnections)" -ForegroundColor Gray
        }
        
        if ($results.USBDevices.Count -gt 0) {
            Write-Host "`nRecent USB Devices:" -ForegroundColor Cyan
            $results.USBDevices | 
                Select-Object -First 10 | 
                ForEach-Object {
                    $lastConnected = if ($_.LastConnected) { 
                        $_.LastConnected.ToString('yyyy-MM-dd HH:mm:ss') 
                    } else { 
                        'Unknown' 
                    }
                    Write-Host "  [$lastConnected] $($_.Vendor) $($_.Product) - $($_.FriendlyName)" -ForegroundColor Cyan
                }
        }
        
        return $results
    }
}

# Helper function to generate HTML report
function Generate-USBHistoryHTML {
    param($Results)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>USB Device History - $($Results.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 30px 10px 0; }
        .metric-label { font-weight: bold; color: #7f8c8d; }
        .metric-value { font-size: 24px; font-weight: bold; color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px; }
        th { background: #3498db; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top; }
        tr:hover { background: #f8f9fa; }
        .device-type { padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; color: white; }
        .type-storage { background: #27ae60; }
        .type-usb { background: #9b59b6; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px; }
        .serial { font-family: monospace; font-size: 11px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔌 USB Device History Report</h1>
        <p><strong>Computer:</strong> $($Results.ComputerName) | <strong>Scan Date:</strong> $($Results.ScanDate)</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="metric">
                <div class="metric-label">Total Devices</div>
                <div class="metric-value">$($Results.Summary.TotalDevices)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Storage Devices</div>
                <div class="metric-value">$($Results.Summary.StorageDevices)</div>
            </div>
            <div class="metric">
                <div class="metric-label">Other USB Devices</div>
                <div class="metric-value">$($Results.Summary.OtherDevices)</div>
            </div>
        </div>
        
        <h2>USB Devices</h2>
        <table>
            <tr>
                <th style="width: 80px;">Type</th>
                <th style="width: 200px;">Device Name</th>
                <th style="width: 120px;">Vendor</th>
                <th style="width: 120px;">Product</th>
                <th style="width: 200px;">Serial Number</th>
                <th style="width: 150px;">Last Connected</th>
            </tr>
"@
    
    foreach ($device in $Results.USBDevices) {
        $typeClass = if ($device.Type -eq 'Storage') { 'type-storage' } else { 'type-usb' }
        $lastConnected = if ($device.LastConnected) { 
            $device.LastConnected.ToString('yyyy-MM-dd HH:mm:ss') 
        } else { 
            'Unknown' 
        }
        $friendlyName = $device.FriendlyName -replace '<', '&lt;' -replace '>', '&gt;'
        
        $html += @"
            <tr>
                <td><span class="device-type $typeClass">$($device.Type)</span></td>
                <td><strong>$friendlyName</strong></td>
                <td>$($device.Vendor)</td>
                <td>$($device.Product)</td>
                <td><span class="serial">$($device.SerialNumber)</span></td>
                <td>$lastConnected</td>
            </tr>
"@
    }
    
    $html += "        </table>`n"
    
    # Connection Events
    if ($Results.ConnectionEvents.Count -gt 0) {
        $html += @"
        
        <h2>Recent Connection Events</h2>
        <table>
            <tr>
                <th style="width: 150px;">Timestamp</th>
                <th style="width: 100px;">Event ID</th>
                <th>Message</th>
            </tr>
"@
        
        foreach ($event in ($Results.ConnectionEvents | Select-Object -First 50)) {
            $timestamp = if ($event.Timestamp) { 
                $event.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') 
            } else { 
                'N/A' 
            }
            $message = $event.Message -replace '<', '&lt;' -replace '>', '&gt;'
            
            $html += @"
            <tr>
                <td>$timestamp</td>
                <td>$($event.EventID)</td>
                <td><small>$message</small></td>
            </tr>
"@
        }
        
        $html += "        </table>`n"
    }
    
    $currentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    $html += @"
        
        <div class="footer">
            Generated by WindowsSecurityAudit Module | USB History Analysis | $currentDate
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}