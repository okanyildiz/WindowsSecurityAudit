function Get-SysmonAnalytics {
    <#
    .SYNOPSIS
        Sysmon-native threat analytics across key Sysmon event types
    .DESCRIPTION
        Analyzes the Microsoft-Windows-Sysmon/Operational log for suspicious activity:
        process-creation chains and encoded/obfuscated command lines (Event ID 1),
        network connections from unexpected processes and beaconing patterns (ID 3),
        suspicious image loads into critical system processes (ID 7),
        lsass.exe process-access attempts with read-capable masks (ID 10),
        executable drops into startup/temp locations (ID 11),
        persistence-oriented registry writes (IDs 12/13), and
        anomalous DNS queries (ID 22).
        Every finding carries a MITRE ATT&CK technique ID. Behavioral checks are
        heuristics and are labeled as such - validate findings manually before
        treating them as confirmed malicious. If Sysmon is not installed, the
        function returns gracefully with Status 'NotAvailable'.
    .PARAMETER Hours
        Number of hours to look back in the Sysmon log (default: 24)
    .PARAMETER EventTypes
        Sysmon event categories to analyze. Valid values: ProcessCreation,
        NetworkConnection, ImageLoad, ProcessAccess, FileCreate, RegistryEvent,
        DnsQuery. Defaults to all categories
    .PARAMETER MaxEvents
        Maximum number of Sysmon events to load across all categories (default: 5000).
        Guards against excessive memory usage on busy systems; when the cap is hit,
        remaining categories are skipped and the cap is reported in the summary
    .EXAMPLE
        Get-SysmonAnalytics
        Get-SysmonAnalytics -Hours 48 -EventTypes ProcessCreation, NetworkConnection
    .OUTPUTS
        PSCustomObject with Findings, Summary, and Recommendations
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Hours = 24,

        [Parameter()]
        [ValidateSet('ProcessCreation', 'NetworkConnection', 'ImageLoad', 'ProcessAccess', 'FileCreate', 'RegistryEvent', 'DnsQuery')]
        [string[]]$EventTypes = @('ProcessCreation', 'NetworkConnection', 'ImageLoad', 'ProcessAccess', 'FileCreate', 'RegistryEvent', 'DnsQuery'),

        [Parameter()]
        [int]$MaxEvents = 5000
    )

    begin {
        Write-Host "Analyzing Sysmon telemetry (last $Hours hours)..." -ForegroundColor Cyan

        $sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
        $startTime = (Get-Date).AddHours(-$Hours)

        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TimeRange = "$Hours hours"
            Status = 'OK'
            Findings = @()
            Summary = [PSCustomObject]@{
                TotalFindings = 0
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                Info = 0
                SysmonPresent = $false
                EventsScanned = 0
                MaxEventsReached = $false
            }
            Recommendations = @()
        }

        $eventIdMap = @{
            ProcessCreation   = @(1)
            NetworkConnection = @(3)
            ImageLoad         = @(7)
            ProcessAccess     = @(10)
            FileCreate        = @(11)
            RegistryEvent     = @(12, 13)
            DnsQuery          = @(22)
        }

        # Null-safe EventData field extraction (Sysmon schema varies by version;
        # missing Data nodes return $null instead of throwing)
        $getEventValue = {
            param($EventData, [string]$Name)
            if ($null -eq $EventData) { return $null }
            $node = $EventData | Where-Object { $_.Name -eq $Name }
            if ($null -ne $node) { return $node.InnerText }
            return $null
        }

        $getFileName = {
            param([string]$Path)
            if ([string]::IsNullOrEmpty($Path)) { return '' }
            if ($Path -match '([^\\/]+)$') { return $Matches[1] }
            return $Path
        }

        $isPrivateIP = {
            param([string]$IP)
            if ([string]::IsNullOrEmpty($IP) -or $IP -eq '-') { return $true }
            if ($IP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.|::1$|fe80:|fc00:|fd)') { return $true }
            return $false
        }

        # Shannon entropy helper for DGA-style label detection (heuristic)
        $getEntropy = {
            param([string]$Text)
            if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
            $freq = @{}
            foreach ($char in $Text.ToCharArray()) {
                $key = [string]$char
                if ($freq.ContainsKey($key)) { $freq[$key]++ } else { $freq[$key] = 1 }
            }
            $length = $Text.Length
            $entropy = 0.0
            foreach ($k in $freq.Keys) {
                $p = $freq[$k] / $length
                $entropy -= $p * [math]::Log($p, 2)
            }
            return [math]::Round($entropy, 2)
        }

        # Granted-access mask classification aligned with Get-CredentialAccessEvents:
        # PROCESS_VM_READ (0x0010) or broad rights are suspicious for lsass handles
        $normalAccessMasks = @('0x1000', '0x1400')
        $suspiciousAccessMasks = @('0x1010', '0x101a', '0x103a', '0x143a', '0x1f0fff', '0x1fffff')

        $officeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'visio.exe', 'msaccess.exe')
        $scriptChildren = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')
        $networkAbuseProcs = @('powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe', 'bitsadmin.exe', 'cmd.exe', 'hh.exe')
        $criticalSystemProcs = @('lsass.exe', 'winlogon.exe', 'csrss.exe', 'services.exe', 'smss.exe', 'wininit.exe')
        $userWritablePathPattern = '(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Downloads\\|\\Windows\\Tasks\\)'
        $commonPorts = @(80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 445, 139, 135, 587, 465, 853)

        # Processes that legitimately issue large volumes of DNS queries (browsers,
        # system services, common collaboration tools) - used by the Event 22
        # process-mismatch heuristic
        $dnsExpectedProcs = @(
            'svchost.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'brave.exe', 'opera.exe',
            'outlook.exe', 'teams.exe', 'slack.exe', 'zoom.exe', 'onedrive.exe', 'dropbox.exe', 'code.exe',
            'wmiprvse.exe', 'dns.exe', 'lsass.exe', 'smartscreen.exe', 'searchui.exe', 'backgroundtaskhost.exe',
            'dllhost.exe', 'msmpeng.exe', 'system', 'spoolsv.exe', 'officeclicktorun.exe'
        )

        # Known-abused TLDs (heuristic signal only - many legitimate sites use these)
        $suspiciousTldPattern = '\.(top|xyz|club|online|site|buzz|tk|ml|ga|cf|gq|loan|work|click|link|pw|quest|icu|cam|rest|monster)\.?$'

        # Encoded / obfuscated command-line indicators (matching the pattern style
        # used across the module's script-block analytics)
        $encodedCommandPatterns = @(
            [PSCustomObject]@{ Name = 'Base64-encoded command argument';  Pattern = '(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}'; Severity = 'High';   Technique = 'T1027' }
            [PSCustomObject]@{ Name = 'Runtime decoding primitive';        Pattern = '(?i)frombase64string|fromcharcode|\[char\]\s*\d+'; Severity = 'High';   Technique = 'T1027' }
            [PSCustomObject]@{ Name = 'Download cradle';                   Pattern = '(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|certutil\s+.*-urlcache|bitsadmin\s+.*/transfer'; Severity = 'High'; Technique = 'T1105' }
            [PSCustomObject]@{ Name = 'Dynamic evaluation (IEX)';          Pattern = '(?i)\biex\b|invoke-expression'; Severity = 'Medium'; Technique = 'T1059.001' }
            [PSCustomObject]@{ Name = 'Hidden window execution';           Pattern = '(?i)-w(indowstyle)?\s+hidden'; Severity = 'Medium'; Technique = 'T1564.003' }
            [PSCustomObject]@{ Name = 'Execution-policy bypass';           Pattern = '(?i)-ep\s+bypass|-executionpolicy\s+bypass'; Severity = 'Medium'; Technique = 'T1059.001' }
        )

        $addFinding = {
            param(
                [Parameter(Mandatory)]$Results,
                [Parameter(Mandatory)][string]$EventType,
                [Parameter(Mandatory)][string]$Technique,
                [Parameter(Mandatory)][string]$Severity,
                [Parameter(Mandatory)]$Evidence,
                $Timestamp
            )
            $Results.Findings += [PSCustomObject]@{
                EventType = $EventType
                Technique = $Technique
                Severity = $Severity
                Evidence = $Evidence
                Timestamp = $Timestamp
            }
            switch ($Severity) {
                'Critical' { $Results.Summary.Critical++ }
                'High'     { $Results.Summary.High++ }
                'Medium'   { $Results.Summary.Medium++ }
                'Low'      { $Results.Summary.Low++ }
                default    { $Results.Summary.Info++ }
            }
        }
    }

    process {
        # Sysmon presence gate - return gracefully when the log does not exist
        try {
            $null = Get-WinEvent -ListLog $sysmonLog -ErrorAction Stop
            $results.Summary.SysmonPresent = $true
        }
        catch {
            $results.Summary.SysmonPresent = $false
            $results.Status = 'NotAvailable'
            $results.Recommendations += 'Sysmon not installed; enable for deep visibility - deploy Sysmon with a community-hardened configuration (e.g. SwiftOnSecurity/sysmon-config or Olaf Hartong''s sysmon-modular) to gain process, network, image-load, registry, and DNS telemetry'
        }

        if (-not $results.Summary.SysmonPresent) {
            return
        }

        # Load events for the selected categories, honoring the MaxEvents budget
        $eventsByType = @{}
        foreach ($eventType in $EventTypes) {
            $remaining = $MaxEvents - $results.Summary.EventsScanned
            if ($remaining -le 0) {
                $results.Summary.MaxEventsReached = $true
                Write-Warning "MaxEvents cap ($MaxEvents) reached - skipping remaining event categories: $($EventTypes | Where-Object { -not $eventsByType.ContainsKey($_) })"
                break
            }
            try {
                $categoryEvents = @(Get-WinEvent -FilterHashtable @{
                    LogName = $sysmonLog
                    ID = $eventIdMap[$eventType]
                    StartTime = $startTime
                } -MaxEvents $remaining -ErrorAction SilentlyContinue)
                $eventsByType[$eventType] = $categoryEvents
                $results.Summary.EventsScanned += @($categoryEvents).Count
            }
            catch {
                Write-Warning "Could not query Sysmon events for $eventType`: $_"
                $eventsByType[$eventType] = @()
                $results.Recommendations += "Sysmon $eventType events were not queryable - verify the Sysmon service is running and the configuration enables this event type"
            }
        }
        if ($results.Summary.EventsScanned -ge $MaxEvents) {
            $results.Summary.MaxEventsReached = $true
        }

        # 1. Process creation (Event ID 1): parent-child chains, encoded command lines,
        #    unsigned binaries in user-writable paths spawning children
        if ($eventsByType.ContainsKey('ProcessCreation')) {
            try {
                Write-Verbose "Analyzing process creation events (ID 1)..."
                $processEvents = @($eventsByType['ProcessCreation'])

                $parentImages = @{}
                foreach ($event in $processEvents) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data
                    $parentImage = & $getEventValue $eventData 'ParentImage'
                    if ($parentImage) { $parentImages[$parentImage.ToLower()] = $true }
                }

                foreach ($event in $processEvents) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $image = & $getEventValue $eventData 'Image'
                    $commandLine = & $getEventValue $eventData 'CommandLine'
                    $parentImage = & $getEventValue $eventData 'ParentImage'
                    $parentCommandLine = & $getEventValue $eventData 'ParentCommandLine'
                    $user = & $getEventValue $eventData 'User'
                    $signed = & $getEventValue $eventData 'Signed'
                    $signatureStatus = & $getEventValue $eventData 'SignatureStatus'
                    $imageName = (& $getFileName $image).ToLower()
                    $parentName = (& $getFileName $parentImage).ToLower()
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    # Office application spawning a scripting engine (T1204.002)
                    if ($officeParents -contains $parentName -and $scriptChildren -contains $imageName) {
                        & $addFinding $results 'ProcessCreation' 'T1204.002' 'High' ([PSCustomObject]@{
                            Indicator = 'Office application spawned a scripting engine'
                            ParentImage = $parentImage
                            Image = $image
                            CommandLine = $commandLine
                            User = $user
                            Note = 'Classic malicious-document execution chain - inspect the parent document'
                        }) $timestamp
                    }

                    # services.exe spawning unusual children (T1569.002)
                    if ($parentName -eq 'services.exe' -and $imageName -notin @('svchost.exe', 'msiexec.exe', 'tiworker.exe', 'trustedinstaller.exe', 'wmiprvse.exe', 'sppsvc.exe', 'sihost.exe')) {
                        & $addFinding $results 'ProcessCreation' 'T1569.002' 'Medium' ([PSCustomObject]@{
                            Indicator = 'services.exe spawned an unusual child process'
                            ParentImage = $parentImage
                            ParentCommandLine = $parentCommandLine
                            Image = $image
                            CommandLine = $commandLine
                            User = $user
                            Note = 'May indicate malicious service execution - verify the child against installed services'
                        }) $timestamp
                    }

                    # Encoded / obfuscated command lines on script-capable hosts
                    if ($commandLine -and $scriptChildren -contains $imageName) {
                        foreach ($indicator in $encodedCommandPatterns) {
                            if ($commandLine -match $indicator.Pattern) {
                                & $addFinding $results 'ProcessCreation' $indicator.Technique $indicator.Severity ([PSCustomObject]@{
                                    Indicator = $indicator.Name
                                    Image = $image
                                    ParentImage = $parentImage
                                    CommandLine = $commandLine
                                    User = $user
                                    Note = 'Obfuscation indicators are heuristics - confirm intent by decoding the command line'
                                }) $timestamp
                            }
                        }
                    }

                    # Binaries in user-writable paths that spawn children; signature
                    # fields are schema-dependent, so absence downgrades to heuristic
                    if ($image -and $image -match $userWritablePathPattern -and $parentImages.ContainsKey($image.ToLower())) {
                        $signatureNote = 'Signature fields absent from event schema - unsigned status inferred heuristically from the path'
                        $severity = 'Medium'
                        $isUnsigned = $false
                        if ($signed -and $signed -match '^(?i:false)$') { $isUnsigned = $true }
                        if ($signatureStatus -and $signatureStatus -match '^(?i:unavailable|invalid|notsigned)$') { $isUnsigned = $true }
                        if ($isUnsigned) {
                            $signatureNote = "Unsigned binary (Signed=$signed, SignatureStatus=$signatureStatus)"
                            $severity = 'High'
                        }
                        & $addFinding $results 'ProcessCreation' 'T1036' $severity ([PSCustomObject]@{
                            Indicator = 'Binary in user-writable path spawning child processes'
                            Image = $image
                            CommandLine = $commandLine
                            User = $user
                            SignatureNote = $signatureNote
                            Note = 'HEURISTIC when signature fields are absent - legitimate updaters can share this shape'
                        }) $timestamp
                    }
                }
            }
            catch {
                Write-Warning "Process creation (ID 1) analysis failed: $_"
            }
        }

        # 2. Network connections (Event ID 3): script-capable processes reaching
        #    external IPs, and rare-port beaconing (same dest ip+port > 10x in window)
        if ($eventsByType.ContainsKey('NetworkConnection')) {
            try {
                Write-Verbose "Analyzing network connection events (ID 3)..."
                $destinationCounts = @{}

                foreach ($event in @($eventsByType['NetworkConnection'])) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $image = & $getEventValue $eventData 'Image'
                    $destIP = & $getEventValue $eventData 'DestinationIp'
                    $destPort = & $getEventValue $eventData 'DestinationPort'
                    $destHost = & $getEventValue $eventData 'DestinationHostname'
                    $user = & $getEventValue $eventData 'User'
                    $imageName = (& $getFileName $image).ToLower()
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    if (-not $destIP -or $destIP -eq '-') { continue }

                    $portNumber = 0
                    if ($destPort) { try { $portNumber = [int]$destPort } catch { $portNumber = 0 } }
                    $destKey = "${destIP}:$portNumber"
                    if (-not $destinationCounts.ContainsKey($destKey)) {
                        $destinationCounts[$destKey] = [PSCustomObject]@{ Count = 0; Images = @(); LastSeen = $timestamp; Port = $portNumber; DestinationHostname = $destHost }
                    }
                    $destinationCounts[$destKey].Count++
                    if ($image -and $destinationCounts[$destKey].Images -notcontains $image) {
                        $destinationCounts[$destKey].Images += $image
                    }
                    if ($null -ne $timestamp -and ($null -eq $destinationCounts[$destKey].LastSeen -or $timestamp -gt $destinationCounts[$destKey].LastSeen)) {
                        $destinationCounts[$destKey].LastSeen = $timestamp
                    }

                    # Script-capable process connecting to a non-RFC1918 address
                    if ($networkAbuseProcs -contains $imageName -and -not (& $isPrivateIP $destIP)) {
                        $severity = 'Medium'
                        if ($imageName -in @('powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe')) { $severity = 'High' }
                        & $addFinding $results 'NetworkConnection' 'T1071' $severity ([PSCustomObject]@{
                            Indicator = 'Script-capable or proxy-execution binary made an outbound connection to an external address'
                            Image = $image
                            DestinationIp = $destIP
                            DestinationPort = $portNumber
                            DestinationHostname = $destHost
                            User = $user
                            Note = 'HEURISTIC - legitimate admin scripts also match; correlate with the process command line (Event ID 1)'
                        }) $timestamp
                    }
                }

                # Beaconing: same destination ip+port more than 10 times in the window
                foreach ($destKey in $destinationCounts.Keys) {
                    $destInfo = $destinationCounts[$destKey]
                    if ($destInfo.Count -gt 10) {
                        $technique = 'T1071.001'
                        if ($destInfo.Port -gt 0 -and $commonPorts -notcontains $destInfo.Port) { $technique = 'T1571' }
                        & $addFinding $results 'NetworkConnection' $technique 'Medium' ([PSCustomObject]@{
                            Indicator = "Beaconing pattern: $($destInfo.Count) connections to $destKey within the analysis window"
                            Destination = $destKey
                            DestinationHostname = $destInfo.DestinationHostname
                            ConnectionCount = $destInfo.Count
                            Images = ($destInfo.Images -join ', ')
                            Note = 'HEURISTIC threshold (>10 connections) - software update agents can produce similar cadence'
                        }) $destInfo.LastSeen
                    }
                }
            }
            catch {
                Write-Warning "Network connection (ID 3) analysis failed: $_"
            }
        }

        # 3. Image loads (Event ID 7): unsigned DLLs into lsass/winlogon (T1547.008 style),
        #    DLLs from temp/appdata into system processes (T1574)
        if ($eventsByType.ContainsKey('ImageLoad')) {
            try {
                Write-Verbose "Analyzing image load events (ID 7)..."

                foreach ($event in @($eventsByType['ImageLoad'])) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $image = & $getEventValue $eventData 'Image'
                    $imageLoaded = & $getEventValue $eventData 'ImageLoaded'
                    $signed = & $getEventValue $eventData 'Signed'
                    $signatureStatus = & $getEventValue $eventData 'SignatureStatus'
                    $imageName = (& $getFileName $image).ToLower()
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    if (-not $imageLoaded) { continue }

                    $isUnsigned = $false
                    if ($signed -and $signed -match '^(?i:false)$') { $isUnsigned = $true }
                    if ($signatureStatus -and $signatureStatus -match '^(?i:unavailable|invalid|notsigned)$') { $isUnsigned = $true }

                    # Unsigned module loaded into lsass.exe / winlogon.exe
                    if ($imageName -in @('lsass.exe', 'winlogon.exe') -and ($isUnsigned -or $imageLoaded -notmatch '\\Windows\\System32\\')) {
                        & $addFinding $results 'ImageLoad' 'T1547.008' 'High' ([PSCustomObject]@{
                            Indicator = 'Unsigned or non-System32 module loaded into a critical logon process'
                            Image = $image
                            ImageLoaded = $imageLoaded
                            Signed = $signed
                            SignatureStatus = $signatureStatus
                            Note = 'LSA authentication-package / SSP style load - verify the DLL against a known-good baseline'
                        }) $timestamp
                        continue
                    }

                    # DLL loaded from temp/appdata into a system process
                    if ($criticalSystemProcs -contains $imageName -and $imageLoaded -match $userWritablePathPattern) {
                        & $addFinding $results 'ImageLoad' 'T1574.002' 'High' ([PSCustomObject]@{
                            Indicator = 'DLL loaded from a user-writable directory into a system process'
                            Image = $image
                            ImageLoaded = $imageLoaded
                            Signed = $signed
                            SignatureStatus = $signatureStatus
                            Note = 'Consistent with DLL side-loading / search-order hijacking into a privileged process'
                        }) $timestamp
                    }
                }
            }
            catch {
                Write-Warning "Image load (ID 7) analysis failed: $_"
            }
        }

        # 4. Process access (Event ID 10): lsass.exe targets with VM_READ-capable masks
        #    (mask classification aligned with Get-CredentialAccessEvents)
        if ($eventsByType.ContainsKey('ProcessAccess')) {
            try {
                Write-Verbose "Analyzing process access events (ID 10)..."

                foreach ($event in @($eventsByType['ProcessAccess'])) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $targetImage = & $getEventValue $eventData 'TargetImage'
                    if (-not $targetImage -or $targetImage -notmatch 'lsass\.exe$') { continue }

                    $sourceImage = & $getEventValue $eventData 'SourceImage'
                    $sourceUser = & $getEventValue $eventData 'SourceUser'
                    $grantedAccess = & $getEventValue $eventData 'GrantedAccess'
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    $classification = 'Review'
                    $severity = 'Medium'
                    $maskValue = $null
                    if ($grantedAccess) {
                        try { $maskValue = [Convert]::ToInt64($grantedAccess, 16) } catch { $maskValue = $null }
                    }
                    if ($null -ne $maskValue) {
                        if (($maskValue -band 0x10) -ne 0 -or $suspiciousAccessMasks -contains $grantedAccess.ToLower()) {
                            $classification = 'Suspicious'
                            $severity = 'High'
                        }
                        elseif ($normalAccessMasks -contains $grantedAccess.ToLower()) {
                            $classification = 'Normal'
                            $severity = 'Info'
                        }
                    }

                    if ($classification -eq 'Normal') { continue }

                    & $addFinding $results 'ProcessAccess' 'T1003.001' $severity ([PSCustomObject]@{
                        Indicator = "Process opened lsass.exe with granted access $grantedAccess ($classification)"
                        SourceImage = $sourceImage
                        SourceUser = $sourceUser
                        TargetImage = $targetImage
                        GrantedAccess = $grantedAccess
                        Note = 'PROCESS_VM_READ (0x10) or broad rights against lsass may indicate credential dumping (T1003.001)'
                    }) $timestamp
                }
            }
            catch {
                Write-Warning "Process access (ID 10) analysis failed: $_"
            }
        }

        # 5. File create (Event ID 11): executables dropped into Startup/Prefetch/Temp
        #    by non-installer parents (T1547.001 / T1105)
        if ($eventsByType.ContainsKey('FileCreate')) {
            try {
                Write-Verbose "Analyzing file create events (ID 11)..."
                $installerParents = @('msiexec.exe', 'setup.exe', 'tiworker.exe', 'trustedinstaller.exe', 'wuauclt.exe', 'musnotification.exe', 'officeclicktorun.exe', 'msedgeupdate.exe', 'googleupdate.exe', 'svchost.exe')
                $executableExtensionPattern = '\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|hta|msi)$'

                foreach ($event in @($eventsByType['FileCreate'])) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $image = & $getEventValue $eventData 'Image'
                    $targetFilename = & $getEventValue $eventData 'TargetFilename'
                    $imageName = (& $getFileName $image).ToLower()
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    if (-not $targetFilename -or $targetFilename -notmatch $executableExtensionPattern) { continue }
                    if ($targetFilename -notmatch '(\\Start Menu\\Programs\\Startup\\|\\Prefetch\\|\\Temp\\|\\Windows\\Tasks\\)') { continue }
                    if ($installerParents -contains $imageName) { continue }

                    $technique = 'T1105'
                    if ($targetFilename -match '\\Start Menu\\Programs\\Startup\\') { $technique = 'T1547.001' }

                    & $addFinding $results 'FileCreate' $technique 'Medium' ([PSCustomObject]@{
                        Indicator = 'Executable dropped into a startup, prefetch, or temp location by a non-installer process'
                        Image = $image
                        TargetFilename = $targetFilename
                        Note = 'HEURISTIC - browsers and build tools also write executables to temp paths; verify the file hash'
                    }) $timestamp
                }
            }
            catch {
                Write-Warning "File create (ID 11) analysis failed: $_"
            }
        }

        # 6. Registry events (IDs 12/13): Run-key writes, IFEO debugger sets, LSA
        #    package changes (patterns consistent with Find-PersistenceMechanisms)
        if ($eventsByType.ContainsKey('RegistryEvent')) {
            try {
                Write-Verbose "Analyzing registry events (IDs 12/13)..."

                foreach ($event in @($eventsByType['RegistryEvent'])) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $image = & $getEventValue $eventData 'Image'
                    $targetObject = & $getEventValue $eventData 'TargetObject'
                    $details = & $getEventValue $eventData 'Details'
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    if (-not $targetObject) { continue }

                    # Run / RunOnce key writes (same key families as Find-PersistenceMechanisms)
                    if ($targetObject -match '(?i)\\(Software|SOFTWARE)\\(Microsoft\\)?Windows\\CurrentVersion\\Run(Once|Services|ServicesOnce)?(\\|$)') {
                        & $addFinding $results 'RegistryEvent' 'T1547.001' 'High' ([PSCustomObject]@{
                            Indicator = 'Write to a Run/RunOnce autostart registry key'
                            Image = $image
                            TargetObject = $targetObject
                            Details = $details
                            Note = 'New or modified autostart entry - compare with the persistence baseline from Find-PersistenceMechanisms'
                        }) $timestamp
                        continue
                    }

                    # IFEO debugger hijack
                    if ($targetObject -match '(?i)\\Image File Execution Options\\[^\\]+\\Debugger$') {
                        & $addFinding $results 'RegistryEvent' 'T1546.012' 'High' ([PSCustomObject]@{
                            Indicator = 'Image File Execution Options debugger value set'
                            Image = $image
                            TargetObject = $targetObject
                            Details = $details
                            Note = 'IFEO debuggers redirect execution of the named binary - a classic persistence / privilege-escalation primitive'
                        }) $timestamp
                        continue
                    }

                    # LSA authentication / security package changes
                    if ($targetObject -match '(?i)\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\(Authentication Packages|Security Packages|Notification Packages)$' -or
                        ($targetObject -match '(?i)\\Control\\Lsa$' -and $details -match '(?i)Authentication Packages|Security Packages|Notification Packages')) {
                        & $addFinding $results 'RegistryEvent' 'T1547.005' 'High' ([PSCustomObject]@{
                            Indicator = 'LSA authentication/security package configuration modified'
                            Image = $image
                            TargetObject = $targetObject
                            Details = $details
                            Note = 'Custom SSP/AP DLLs load into lsass at boot and can capture credentials - validate the package list against msv1_0/scecli/rassfm defaults'
                        }) $timestamp
                    }
                }
            }
            catch {
                Write-Warning "Registry event (ID 12/13) analysis failed: $_"
            }
        }

        # 7. DNS queries (Event ID 22): DGA-ish high-entropy labels, known-abused TLDs,
        #    queries issued by unexpected processes (all heuristics)
        if ($eventsByType.ContainsKey('DnsQuery')) {
            try {
                Write-Verbose "Analyzing DNS query events (ID 22)..."

                foreach ($event in @($eventsByType['DnsQuery'])) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $image = & $getEventValue $eventData 'Image'
                    $queryName = & $getEventValue $eventData 'QueryName'
                    $queryResults = & $getEventValue $eventData 'QueryResults'
                    $imageName = (& $getFileName $image).ToLower()
                    $timestamp = $null
                    if ($null -ne $event -and $null -ne ($event.PSObject.Properties['TimeCreated']) -and $null -ne $event.TimeCreated) {
                        $timestamp = $event.TimeCreated
                    }

                    if (-not $queryName) { continue }

                    # DGA-style label: long label with high Shannon entropy (heuristic)
                    $labels = $queryName.TrimEnd('.') -split '\.'
                    foreach ($label in $labels) {
                        if ($label.Length -ge 20) {
                            $entropy = & $getEntropy $label
                            if ($entropy -gt 3.8 -or $label.Length -ge 30) {
                                & $addFinding $results 'DnsQuery' 'T1568.002' 'Medium' ([PSCustomObject]@{
                                    Indicator = "High-entropy DNS label (length $($label.Length), entropy $entropy) - DGA-style heuristic"
                                    Image = $image
                                    QueryName = $queryName
                                    QueryResults = $queryResults
                                    Note = 'HEURISTIC - CDN and telemetry domains can also produce long high-entropy labels'
                                }) $timestamp
                            }
                            break
                        }
                    }

                    # Known-abused TLD (heuristic)
                    if ($queryName -match $suspiciousTldPattern) {
                        & $addFinding $results 'DnsQuery' 'T1071.004' 'Low' ([PSCustomObject]@{
                            Indicator = 'Query for a domain on a frequently abused TLD'
                            Image = $image
                            QueryName = $queryName
                            QueryResults = $queryResults
                            Note = 'HEURISTIC - these TLDs also host legitimate services; combine with other signals before blocking'
                        }) $timestamp
                    }

                    # Query issued by a process that does not normally resolve DNS
                    if ($imageName -and $dnsExpectedProcs -notcontains $imageName -and $image -notmatch '(?i)\\Windows\\System32\\|\\Program Files') {
                        & $addFinding $results 'DnsQuery' 'T1071.004' 'Low' ([PSCustomObject]@{
                            Indicator = 'DNS query issued by an unexpected process (not a browser/system service and outside System32/Program Files)'
                            Image = $image
                            QueryName = $queryName
                            QueryResults = $queryResults
                            Note = 'HEURISTIC - portable applications legitimately resolve DNS; prioritize when combined with DGA or TLD signals'
                        }) $timestamp
                    }
                }
            }
            catch {
                Write-Warning "DNS query (ID 22) analysis failed: $_"
            }
        }

        $results.Summary.TotalFindings = @($results.Findings).Count

        # Recommendations based on findings
        if ($results.Summary.MaxEventsReached) {
            $results.Recommendations += "MaxEvents cap ($MaxEvents) was reached - re-run with a higher -MaxEvents or a smaller -Hours window for complete coverage"
        }
        if ($results.Summary.High -gt 0 -or $results.Summary.Critical -gt 0) {
            $results.Recommendations += 'High-severity Sysmon findings present - isolate affected hosts, preserve the Sysmon log, and validate each finding against the referenced MITRE technique before remediation'
        }
        if (@($results.Findings | Where-Object { $_.Technique -eq 'T1003.001' }).Count -gt 0) {
            $results.Recommendations += 'lsass.exe access with read-capable masks detected (T1003.001) - treat as potential credential theft; capture memory and reset exposed credentials'
        }
        if (@($results.Findings | Where-Object { $_.Technique -match '^T1547|^T1546' }).Count -gt 0) {
            $results.Recommendations += 'Persistence-oriented writes detected - cross-check with Find-PersistenceMechanisms to confirm the mechanism is active and remove unauthorized autostart entries'
        }
        if ($results.Summary.TotalFindings -eq 0) {
            $results.Recommendations += 'No suspicious Sysmon activity detected in the window - maintain Sysmon with a hardened configuration and forward the Operational log to a SIEM for long-term correlation'
        }
    }

    end {
        Write-Host "`nSysmon Analytics Complete!" -ForegroundColor Green
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "Sysmon present: $($results.Summary.SysmonPresent)" -ForegroundColor Yellow
        Write-Host "Events scanned: $($results.Summary.EventsScanned)" -ForegroundColor Yellow
        Write-Host "Total findings: $($results.Summary.TotalFindings)" -ForegroundColor $(if ($results.Summary.TotalFindings -gt 0) { 'Red' } else { 'Green' })
        Write-Host "High/Critical: $($results.Summary.High + $results.Summary.Critical)" -ForegroundColor $(if (($results.Summary.High + $results.Summary.Critical) -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Medium: $($results.Summary.Medium)" -ForegroundColor $(if ($results.Summary.Medium -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "Low: $($results.Summary.Low)" -ForegroundColor Yellow

        if (@($results.Recommendations).Count -gt 0) {
            Write-Host "`n=== Recommendations ===" -ForegroundColor Cyan
            foreach ($recommendation in $results.Recommendations) {
                Write-Host "- $recommendation" -ForegroundColor Yellow
            }
        }

        return $results
    }
}
