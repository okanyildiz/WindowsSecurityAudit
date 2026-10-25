function Get-ThreatIntelligence {
    <#
    .SYNOPSIS
        Matches system artifacts against threat intelligence indicators
    .DESCRIPTION
        Checks running processes, network connections, files, and registry against
        known Indicators of Compromise (IOCs) from threat intelligence feeds
    .PARAMETER CheckProcesses
        Check running processes against IOCs
    .PARAMETER CheckNetwork
        Check network connections against IOCs
    .PARAMETER CheckFiles
        Check files against IOC patterns
    .PARAMETER CheckRegistry
        Check registry against IOCs
    .PARAMETER IOCFile
        Path to custom IOC file (JSON format)
    .PARAMETER UpdateFeeds
        Download or refresh live threat intelligence feeds (URLhaus, Feodo Tracker, optional AbuseIPDB)
    .PARAMETER FeedCachePath
        Directory used to cache downloaded feed data (default: $env:LOCALAPPDATA\WindowsSecurityAudit\ThreatIntel)
    .PARAMETER FeedMaxAgeHours
        Maximum age in hours before a cached feed is downloaded again with -UpdateFeeds (default: 24)
    .PARAMETER MaxFeedEntries
        Maximum number of feed-derived indicators merged into the IOC database (default: 5000)
    .PARAMETER AbuseIPDBApiKey
        Optional AbuseIPDB API key; enables the AbuseIPDB blacklist feed (sent only as a request header)
    .EXAMPLE
        Get-ThreatIntelligence -CheckProcesses -CheckNetwork
        Get-ThreatIntelligence -CheckProcesses -CheckNetwork -CheckFiles -IOCFile "C:\iocs.json"
        Get-ThreatIntelligence -CheckNetwork -UpdateFeeds -FeedMaxAgeHours 12
    .OUTPUTS
        PSCustomObject with IOC match results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckProcesses,
        
        [Parameter()]
        [switch]$CheckNetwork,
        
        [Parameter()]
        [switch]$CheckFiles,
        
        [Parameter()]
        [switch]$CheckRegistry,
        
        [Parameter()]
        [string]$IOCFile,
        
        [Parameter()]
        [switch]$UpdateFeeds,
        
        [Parameter()]
        [string]$FeedCachePath = "$env:LOCALAPPDATA\WindowsSecurityAudit\ThreatIntel",
        
        [Parameter()]
        [int]$FeedMaxAgeHours = 24,
        
        [Parameter()]
        [int]$MaxFeedEntries = 5000,
        
        [Parameter()]
        [string]$AbuseIPDBApiKey
    )
    
    begin {
        Write-Host "=== THREAT INTELLIGENCE IOC MATCHING ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        if (-not ($CheckProcesses -or $CheckNetwork -or $CheckFiles -or $CheckRegistry)) {
            $CheckProcesses = $true
            $CheckNetwork = $true
            Write-Host "No specific check selected - enabling default checks" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Matches = @{
                ProcessIOCs = @()
                NetworkIOCs = @()
                FileIOCs = @()
                RegistryIOCs = @()
            }
            Summary = @{
                TotalMatches = 0
                CriticalMatches = 0
                HighMatches = 0
                MediumMatches = 0
                FeedStats = @()
            }
            Recommendations = @()
        }
        
        # Built-in IOC Database (Common malware/threat indicators)
        $iocDatabase = @{
            MaliciousProcesses = @{
                'mimikatz.exe' = @{ Severity = 'Critical'; Description = 'Credential dumping tool' }
                'procdump.exe' = @{ Severity = 'High'; Description = 'Memory dumping tool (can be legitimate)' }
                'rubeus.exe' = @{ Severity = 'Critical'; Description = 'Kerberos attack tool' }
                'sharphound.exe' = @{ Severity = 'High'; Description = 'AD enumeration tool (BloodHound)' }
                'covenant.exe' = @{ Severity = 'Critical'; Description = 'C2 framework' }
                'psexec.exe' = @{ Severity = 'Medium'; Description = 'Remote execution tool (can be legitimate)' }
                'paexec.exe' = @{ Severity = 'High'; Description = 'PSExec alternative' }
                'lazagne.exe' = @{ Severity = 'Critical'; Description = 'Password recovery tool' }
            }
            
            MaliciousIPs = @{
                '192.0.2.1' = @{ Severity = 'Critical'; Description = 'Known C2 server (example)' }
                '198.51.100.1' = @{ Severity = 'High'; Description = 'Known malware distribution (example)' }
            }
            
            MaliciousHashes = @{
                # Example SHA256 hashes (these are placeholders)
                '44d88612fea8a8f36de82e1278abb02f' = @{ Severity = 'Critical'; Description = 'Known malware hash' }
            }
            
            SuspiciousPatterns = @{
                ProcessCommandLine = @(
                    @{ Pattern = 'mimikatz'; Severity = 'Critical'; Description = 'Mimikatz execution detected' }
                    @{ Pattern = 'Invoke-Mimikatz'; Severity = 'Critical'; Description = 'PowerShell Mimikatz' }
                    @{ Pattern = 'sekurlsa::logonpasswords'; Severity = 'Critical'; Description = 'Credential dumping command' }
                    @{ Pattern = 'procdump.*lsass'; Severity = 'Critical'; Description = 'LSASS memory dump' }
                    @{ Pattern = 'IEX.*New-Object.*Net.WebClient.*DownloadString'; Severity = 'High'; Description = 'PowerShell download cradle' }
                    @{ Pattern = '\[Convert\]::FromBase64String'; Severity = 'Medium'; Description = 'Base64 decoding (potential obfuscation)' }
                )
                
                FilePaths = @(
                    @{ Pattern = 'C:\\Windows\\Temp\\.*\.exe'; Severity = 'High'; Description = 'Executable in Windows Temp' }
                    @{ Pattern = 'C:\\Users\\Public\\.*\.exe'; Severity = 'High'; Description = 'Executable in Public folder' }
                    @{ Pattern = 'C:\\ProgramData\\.*\.ps1'; Severity = 'Medium'; Description = 'PowerShell script in ProgramData' }
                )
                
                NetworkIndicators = @()
            }
        }
        
        # Live threat intelligence feeds
        $feedStats = @()
        
        if ($UpdateFeeds -or (Test-Path $FeedCachePath)) {
            Write-Host "`nProcessing live threat intelligence feeds..." -ForegroundColor Cyan
            
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            }
            catch {
                Write-Verbose "Could not enforce TLS 1.2: $_"
            }
            
            $feedDefinitions = @(
                @{ Name = 'Feodo Tracker'; Url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'; FileName = 'feodo_ipblocklist.txt'; Format = 'IpList'; Severity = 'Critical'; Description = 'Feodo Tracker C2' }
                @{ Name = 'URLhaus'; Url = 'https://urlhaus.abuse.ch/downloads/csv_recent.txt'; FileName = 'urlhaus_recent.csv'; Format = 'URLhausCsv'; Severity = 'High'; Description = 'URLhaus payload URL' }
            )
            
            if (-not [string]::IsNullOrWhiteSpace($AbuseIPDBApiKey)) {
                $feedDefinitions += @{ Name = 'AbuseIPDB'; Url = 'https://api.abuseipdb.com/api/v2/blacklist?plaintext'; FileName = 'abuseipdb_blacklist.txt'; Format = 'IpList'; Severity = 'High'; Description = 'AbuseIPDB blacklist' }
            }
            
            if (-not (Test-Path $FeedCachePath)) {
                try {
                    $null = New-Item -ItemType Directory -Path $FeedCachePath -Force -ErrorAction Stop
                }
                catch {
                    Write-Warning "Could not create feed cache directory '$FeedCachePath': $_"
                }
            }
            
            $feedEntryCount = 0
            $networkIndicatorKeys = @{}
            
            foreach ($feed in $feedDefinitions) {
                if ($feedEntryCount -ge $MaxFeedEntries) {
                    Write-Warning "Feed entry cap ($MaxFeedEntries) reached - skipping remaining feeds"
                    break
                }
                
                $cacheFile = Join-Path $FeedCachePath $feed.FileName
                $content = $null
                $source = 'none'
                $cacheAgeHours = $null
                $cacheExists = Test-Path $cacheFile
                
                if ($cacheExists) {
                    $cacheItem = Get-Item $cacheFile
                    $cacheAgeHours = [math]::Round(((Get-Date) - $cacheItem.LastWriteTime).TotalHours, 1)
                }
                
                $shouldDownload = $UpdateFeeds -and (-not $cacheExists -or $cacheAgeHours -ge $FeedMaxAgeHours)
                
                if ($shouldDownload) {
                    try {
                        Write-Host "  Downloading $($feed.Name) feed..." -ForegroundColor Yellow
                        $requestParams = @{
                            Uri = $feed.Url
                            OutFile = $cacheFile
                            UseBasicParsing = $true
                            TimeoutSec = 30
                            ErrorAction = 'Stop'
                        }
                        if ($feed.Name -eq 'AbuseIPDB') {
                            $requestParams['Headers'] = @{ 'Key' = $AbuseIPDBApiKey; 'Accept' = 'text/plain' }
                        }
                        Invoke-WebRequest @requestParams
                        $content = Get-Content $cacheFile -ErrorAction Stop
                        $source = 'download'
                        $cacheItem = Get-Item $cacheFile
                        $cacheAgeHours = [math]::Round(((Get-Date) - $cacheItem.LastWriteTime).TotalHours, 1)
                    }
                    catch {
                        if ($cacheExists) {
                            Write-Warning "Failed to download $($feed.Name) feed - falling back to cached copy ($cacheAgeHours hours old): $_"
                            $content = Get-Content $cacheFile -ErrorAction SilentlyContinue
                            $source = 'cache'
                        }
                        else {
                            Write-Warning "Failed to download $($feed.Name) feed and no cache available - using built-in IOCs only: $_"
                        }
                    }
                }
                elseif ($cacheExists) {
                    $content = Get-Content $cacheFile -ErrorAction SilentlyContinue
                    $source = 'cache'
                    if ($cacheAgeHours -ge $FeedMaxAgeHours) {
                        Write-Host "  $($feed.Name) cache is $cacheAgeHours hours old - run with -UpdateFeeds to refresh" -ForegroundColor Yellow
                    }
                }
                
                $entriesAdded = 0
                
                if ($null -ne $content) {
                    foreach ($line in $content) {
                        if ($feedEntryCount -ge $MaxFeedEntries) { break }
                        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
                        
                        if ($feed.Format -eq 'IpList') {
                            $ip = $line.Trim()
                            if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
                            if (-not $iocDatabase.MaliciousIPs.ContainsKey($ip)) {
                                $iocDatabase.MaliciousIPs[$ip] = @{ Severity = $feed.Severity; Description = $feed.Description }
                                $feedEntryCount++
                                $entriesAdded++
                            }
                        }
                        elseif ($feed.Format -eq 'URLhausCsv') {
                            $fields = $line -split ','
                            if ($fields.Count -lt 6) { continue }
                            $url = $fields[2].Trim().Trim('"')
                            $uri = $null
                            try { $uri = [System.Uri]$url } catch { continue }
                            if ($null -eq $uri) { continue }
                            $hostName = $uri.Host
                            if ([string]::IsNullOrWhiteSpace($hostName)) { continue }
                            
                            if ($hostName -match '^\d{1,3}(\.\d{1,3}){3}$') {
                                if (-not $iocDatabase.MaliciousIPs.ContainsKey($hostName)) {
                                    $iocDatabase.MaliciousIPs[$hostName] = @{ Severity = $feed.Severity; Description = "$($feed.Description) host" }
                                    $feedEntryCount++
                                    $entriesAdded++
                                }
                            }
                            else {
                                $pattern = [regex]::Escape($hostName)
                                if (-not $networkIndicatorKeys.ContainsKey($pattern)) {
                                    $networkIndicatorKeys[$pattern] = $true
                                    $iocDatabase.SuspiciousPatterns.NetworkIndicators += @{ Pattern = $pattern; Severity = $feed.Severity; Description = "$($feed.Description) host" }
                                    $feedEntryCount++
                                    $entriesAdded++
                                }
                            }
                        }
                    }
                }
                
                $feedStats += [PSCustomObject]@{
                    Feed = $feed.Name
                    EntryCount = $entriesAdded
                    CacheAgeHours = $cacheAgeHours
                    Source = $source
                }
            }
            
            if ($feedEntryCount -gt 0) {
                Write-Host "  Loaded $feedEntryCount indicators from live feeds" -ForegroundColor Green
            }
            else {
                Write-Host "  No live feed indicators loaded - using built-in IOCs only" -ForegroundColor Yellow
            }
        }
        
        $results.Summary.FeedStats = $feedStats
        
        # Load custom IOCs if provided
        if ($IOCFile -and (Test-Path $IOCFile)) {
            Write-Host "Loading custom IOCs from: $IOCFile" -ForegroundColor Yellow
            try {
                $customIOCs = Get-Content $IOCFile -Raw | ConvertFrom-Json
                foreach ($section in 'MaliciousProcesses', 'MaliciousIPs', 'MaliciousHashes') {
                    if ($customIOCs.PSObject.Properties[$section]) {
                        foreach ($entry in $customIOCs.$section.PSObject.Properties) {
                            $key = if ($section -eq 'MaliciousProcesses') { $entry.Name.ToLower() } else { $entry.Name }
                            $iocDatabase[$section][$key] = @{
                                Severity = if ($entry.Value.PSObject.Properties['Severity']) { $entry.Value.Severity } else { 'Medium' }
                                Description = if ($entry.Value.PSObject.Properties['Description']) { $entry.Value.Description } else { 'Custom IOC' }
                            }
                        }
                    }
                }
                if ($customIOCs.PSObject.Properties['SuspiciousPatterns']) {
                    foreach ($patternGroup in 'ProcessCommandLine', 'FilePaths') {
                        if ($customIOCs.SuspiciousPatterns.PSObject.Properties[$patternGroup]) {
                            $iocDatabase.SuspiciousPatterns[$patternGroup] += @($customIOCs.SuspiciousPatterns.$patternGroup)
                        }
                    }
                }
                Write-Host "Custom IOCs loaded successfully" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to load custom IOC file: $_"
            }
        }
    }
    
    process {
        try {
            # 1. Check Processes against IOCs
            if ($CheckProcesses) {
                Write-Host "`n[1/4] Checking processes against IOCs..." -ForegroundColor Cyan
                
                try {
                    $processes = Get-CimInstance Win32_Process | 
                        Where-Object { $null -ne $_.CommandLine } |
                        Select-Object Name, ProcessId, ExecutablePath, CommandLine
                    
                    $foundCount = 0
                    
                    foreach ($process in $processes) {
                        # Check process name against malicious process list
                        if ($iocDatabase.MaliciousProcesses.ContainsKey($process.Name.ToLower())) {
                            $ioc = $iocDatabase.MaliciousProcesses[$process.Name.ToLower()]
                            
                            $match = [PSCustomObject]@{
                                Type = 'Process'
                                IOCType = 'MaliciousProcess'
                                Indicator = $process.Name
                                ProcessId = $process.ProcessId
                                Path = $process.ExecutablePath
                                CommandLine = $process.CommandLine
                                Severity = $ioc.Severity
                                Description = $ioc.Description
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            
                            $results.Matches.ProcessIOCs += $match
                            $foundCount++
                            
                            switch ($ioc.Severity) {
                                'Critical' { $results.Summary.CriticalMatches++ }
                                'High' { $results.Summary.HighMatches++ }
                                'Medium' { $results.Summary.MediumMatches++ }
                            }
                            
                            Write-Host "  [!] MATCH: $($process.Name) [PID: $($process.ProcessId)]" -ForegroundColor Red
                            Write-Host "      Severity: $($ioc.Severity) - $($ioc.Description)" -ForegroundColor Red
                        }
                        
                        # Check command line patterns
                        if ($process.CommandLine) {
                            foreach ($pattern in $iocDatabase.SuspiciousPatterns.ProcessCommandLine) {
                                if ($process.CommandLine -match $pattern.Pattern) {
                                    $match = [PSCustomObject]@{
                                        Type = 'Process'
                                        IOCType = 'SuspiciousCommandLine'
                                        Indicator = $pattern.Pattern
                                        ProcessId = $process.ProcessId
                                        ProcessName = $process.Name
                                        CommandLine = if ($process.CommandLine.Length -gt 200) { 
                                            $process.CommandLine.Substring(0, 200) + "..." 
                                        } else { 
                                            $process.CommandLine 
                                        }
                                        Severity = $pattern.Severity
                                        Description = $pattern.Description
                                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                    }
                                    
                                    $results.Matches.ProcessIOCs += $match
                                    $foundCount++
                                    
                                    switch ($pattern.Severity) {
                                        'Critical' { $results.Summary.CriticalMatches++ }
                                        'High' { $results.Summary.HighMatches++ }
                                        'Medium' { $results.Summary.MediumMatches++ }
                                    }
                                    
                                    Write-Host "  [!] MATCH: Pattern '$($pattern.Pattern)' in $($process.Name)" -ForegroundColor Red
                                    break
                                }
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No process IOC matches found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking processes: $_"
                }
            }
            
            # 2. Check Network Connections against IOCs
            if ($CheckNetwork) {
                Write-Host "`n[2/4] Checking network connections against IOCs..." -ForegroundColor Cyan
                
                try {
                    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                    
                    $foundCount = 0
                    
                    foreach ($conn in $connections) {
                        $remoteAddress = $conn.RemoteAddress.ToString()
                        
                        # Check against malicious IPs
                        if ($iocDatabase.MaliciousIPs.ContainsKey($remoteAddress)) {
                            $ioc = $iocDatabase.MaliciousIPs[$remoteAddress]
                            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                            $processName = if ($process) { $process.Name } else { "PID $($conn.OwningProcess)" }
                            
                            $match = [PSCustomObject]@{
                                Type = 'Network'
                                IOCType = 'MaliciousIP'
                                Indicator = $conn.RemoteAddress
                                ProcessName = $processName
                                ProcessId = $conn.OwningProcess
                                LocalAddress = "$($conn.LocalAddress):$($conn.LocalPort)"
                                RemoteAddress = "$($conn.RemoteAddress):$($conn.RemotePort)"
                                Severity = $ioc.Severity
                                Description = $ioc.Description
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            
                            $results.Matches.NetworkIOCs += $match
                            $foundCount++
                            
                            switch ($ioc.Severity) {
                                'Critical' { $results.Summary.CriticalMatches++ }
                                'High' { $results.Summary.HighMatches++ }
                                'Medium' { $results.Summary.MediumMatches++ }
                            }
                            
                            Write-Host "  [!] MATCH: Malicious IP $($conn.RemoteAddress) via $processName" -ForegroundColor Red
                        }
                        
                        # Check against feed-derived network indicators
                        foreach ($pattern in $iocDatabase.SuspiciousPatterns.NetworkIndicators) {
                            if ($remoteAddress -match $pattern.Pattern) {
                                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                                $processName = if ($process) { $process.Name } else { "PID $($conn.OwningProcess)" }
                                
                                $match = [PSCustomObject]@{
                                    Type = 'Network'
                                    IOCType = 'FeedNetworkIndicator'
                                    Indicator = $pattern.Pattern
                                    ProcessName = $processName
                                    ProcessId = $conn.OwningProcess
                                    LocalAddress = "$($conn.LocalAddress):$($conn.LocalPort)"
                                    RemoteAddress = "$($conn.RemoteAddress):$($conn.RemotePort)"
                                    Severity = $pattern.Severity
                                    Description = $pattern.Description
                                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                                
                                $results.Matches.NetworkIOCs += $match
                                $foundCount++
                                
                                switch ($pattern.Severity) {
                                    'Critical' { $results.Summary.CriticalMatches++ }
                                    'High' { $results.Summary.HighMatches++ }
                                    'Medium' { $results.Summary.MediumMatches++ }
                                }
                                
                                Write-Host "  [!] MATCH: Feed indicator '$($pattern.Pattern)' via $processName" -ForegroundColor Red
                                break
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No network IOC matches found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking network: $_"
                }
            }
            
            # 3. Check Files against IOCs
            if ($CheckFiles) {
                Write-Host "`n[3/4] Checking files against IOCs..." -ForegroundColor Cyan
                
                try {
                    # Check recent files in suspicious locations
                    $suspiciousLocations = @(
                        "$env:TEMP",
                        "C:\Windows\Temp",
                        "C:\Users\Public",
                        "C:\ProgramData"
                    )
                    
                    $foundCount = 0
                    
                    foreach ($location in $suspiciousLocations) {
                        if (Test-Path $location) {
                            $recentFiles = Get-ChildItem -Path $location -File -Recurse -ErrorAction SilentlyContinue -Depth 2 |
                                Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) -and $_.Extension -match '\.(exe|dll|ps1|bat|vbs|js)$' } |
                                Select-Object -First 20
                            
                            foreach ($file in $recentFiles) {
                                # Check against file path patterns
                                foreach ($pattern in $iocDatabase.SuspiciousPatterns.FilePaths) {
                                    if ($file.FullName -match $pattern.Pattern) {
                                        $match = [PSCustomObject]@{
                                            Type = 'File'
                                            IOCType = 'SuspiciousFilePath'
                                            Indicator = $pattern.Pattern
                                            FilePath = $file.FullName
                                            FileName = $file.Name
                                            Size = $file.Length
                                            Created = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                                            Severity = $pattern.Severity
                                            Description = $pattern.Description
                                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                        }
                                        
                                        $results.Matches.FileIOCs += $match
                                        $foundCount++
                                        
                                        switch ($pattern.Severity) {
                                            'Critical' { $results.Summary.CriticalMatches++ }
                                            'High' { $results.Summary.HighMatches++ }
                                            'Medium' { $results.Summary.MediumMatches++ }
                                        }
                                        
                                        Write-Host "  [!] MATCH: $($file.Name) in suspicious location" -ForegroundColor Yellow
                                        break
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No file IOC matches found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking files: $_"
                }
            }
            
            # 4. Check Registry against IOCs
            if ($CheckRegistry) {
                Write-Host "`n[4/4] Checking registry against IOCs..." -ForegroundColor Cyan
                
                try {
                    # Check common persistence locations
                    $persistenceKeys = @(
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
                    )
                    
                    $foundCount = 0
                    
                    foreach ($key in $persistenceKeys) {
                        if (Test-Path $key) {
                            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                            
                            foreach ($prop in $values.PSObject.Properties) {
                                if ($prop.Name -match '^PS') { continue }
                                
                                $value = $prop.Value
                                
                                # Check for suspicious patterns in registry values
                                if ($value -match 'powershell.*-enc|cmd.*http|wscript.*http|mshta.*http') {
                                    $match = [PSCustomObject]@{
                                        Type = 'Registry'
                                        IOCType = 'SuspiciousRegistryValue'
                                        Indicator = 'Suspicious command pattern in registry'
                                        RegistryKey = $key
                                        ValueName = $prop.Name
                                        ValueData = if ($value.Length -gt 200) { $value.Substring(0, 200) + "..." } else { $value }
                                        Severity = 'High'
                                        Description = 'Potentially malicious command in registry autorun'
                                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                    }
                                    
                                    $results.Matches.RegistryIOCs += $match
                                    $results.Summary.HighMatches++
                                    $foundCount++
                                    
                                    Write-Host "  [!] MATCH: Suspicious pattern in $($prop.Name)" -ForegroundColor Red
                                }
                            }
                        }
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No registry IOC matches found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking registry: $_"
                }
            }
            
            # Calculate summary
            $results.Summary.TotalMatches = 
                $results.Matches.ProcessIOCs.Count +
                $results.Matches.NetworkIOCs.Count +
                $results.Matches.FileIOCs.Count +
                $results.Matches.RegistryIOCs.Count
            
            # Generate recommendations
            if ($results.Summary.TotalMatches -gt 0) {
                if ($results.Summary.CriticalMatches -gt 0) {
                    $results.Recommendations += "CRITICAL: $($results.Summary.CriticalMatches) critical IOC match(es) detected - immediate incident response required"
                    $results.Recommendations += "Isolate affected systems from network"
                    $results.Recommendations += "Collect forensic evidence before remediation"
                }
                
                if ($results.Summary.HighMatches -gt 0) {
                    $results.Recommendations += "HIGH: $($results.Summary.HighMatches) high-severity IOC match(es) require investigation"
                }
                
                $results.Recommendations += "Review all matched IOCs and their context"
                $results.Recommendations += "Check for additional indicators of compromise"
                $results.Recommendations += "Update threat intelligence feeds regularly"
                $results.Recommendations += "Consider implementing automated IOC scanning"
                
                if ($results.Matches.ProcessIOCs.Count -gt 0) {
                    $results.Recommendations += "Terminate suspicious processes and investigate their origin"
                }
                
                if ($results.Matches.NetworkIOCs.Count -gt 0) {
                    $results.Recommendations += "Block malicious IP addresses at firewall level"
                }
            }
            
        }
        catch {
            Write-Error "Error during threat intelligence matching: $_"
            throw
        }
    }
    
    end {
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor $(
            if ($results.Summary.CriticalMatches -gt 0) { 'Red' }
            elseif ($results.Summary.HighMatches -gt 0) { 'Yellow' }
            else { 'Green' }
        )
        
        Write-Host "`nIOC Match Summary:" -ForegroundColor Cyan
        Write-Host "  Total Matches: $($results.Summary.TotalMatches)" -ForegroundColor White
        Write-Host "  Critical: $($results.Summary.CriticalMatches)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighMatches)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumMatches)" -ForegroundColor Yellow
        
        if ($results.Summary.TotalMatches -gt 0) {
            Write-Host "`nMatch Breakdown:" -ForegroundColor Cyan
            if ($results.Matches.ProcessIOCs.Count -gt 0) {
                Write-Host "  Process IOCs: $($results.Matches.ProcessIOCs.Count)" -ForegroundColor White
            }
            if ($results.Matches.NetworkIOCs.Count -gt 0) {
                Write-Host "  Network IOCs: $($results.Matches.NetworkIOCs.Count)" -ForegroundColor White
            }
            if ($results.Matches.FileIOCs.Count -gt 0) {
                Write-Host "  File IOCs: $($results.Matches.FileIOCs.Count)" -ForegroundColor White
            }
            if ($results.Matches.RegistryIOCs.Count -gt 0) {
                Write-Host "  Registry IOCs: $($results.Matches.RegistryIOCs.Count)" -ForegroundColor White
            }
            
            Write-Host "`nTop Matches by Severity:" -ForegroundColor Cyan
            $allMatches = @()
            $allMatches += $results.Matches.ProcessIOCs
            $allMatches += $results.Matches.NetworkIOCs
            $allMatches += $results.Matches.FileIOCs
            $allMatches += $results.Matches.RegistryIOCs
            
            $allMatches | 
                Sort-Object { 
                    switch ($_.Severity) {
                        'Critical' { 1 }
                        'High' { 2 }
                        'Medium' { 3 }
                    }
                } |
                Select-Object -First 5 |
                ForEach-Object {
                    Write-Host "  [$($_.Severity)] $($_.IOCType): $($_.Indicator)" -ForegroundColor White
                }
        }
        else {
            Write-Host "`nNo IOC matches detected - system appears clean" -ForegroundColor Green
        }
        
        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | Select-Object -Unique | ForEach-Object {
                Write-Host "  ! $_" -ForegroundColor Yellow
            }
        }
        
        if (@($results.Summary.FeedStats).Count -gt 0) {
            Write-Host "`nThreat Intelligence Feeds:" -ForegroundColor Cyan
            foreach ($stat in $results.Summary.FeedStats) {
                $ageText = if ($null -ne $stat.CacheAgeHours) { "$($stat.CacheAgeHours)h old" } else { 'not cached' }
                Write-Host "  - $($stat.Feed): $($stat.EntryCount) entries ($($stat.Source), $ageText)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`nThreat Intelligence Sources:" -ForegroundColor Cyan
        Write-Host "  - MITRE ATT&CK: https://attack.mitre.org/" -ForegroundColor Gray
        Write-Host "  - AlienVault OTX: https://otx.alienvault.com/" -ForegroundColor Gray
        Write-Host "  - VirusTotal: https://www.virustotal.com/" -ForegroundColor Gray
        Write-Host "  - abuse.ch URLhaus/Feodo Tracker: https://urlhaus.abuse.ch/ | https://feodotracker.abuse.ch/" -ForegroundColor Gray
        Write-Host "  - AbuseIPDB: https://www.abuseipdb.com/" -ForegroundColor Gray
        
        return $results
    }
}