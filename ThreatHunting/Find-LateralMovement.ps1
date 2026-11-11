function Find-LateralMovement {
    <#
    .SYNOPSIS
        Detects lateral movement indicators in the environment
    .DESCRIPTION
        Identifies signs of lateral movement including remote connections,
        pass-the-hash, PSRemoting, RDP, SMB shares, credential access, suspicious
        service creation, scheduled tasks, and WMI activity. Event-log fields are
        read from structured EventData by name, not from localized message text.
        Behavioral matches are heuristic and should be validated before response.
    .PARAMETER CheckNetworkConnections
        Check for suspicious network connections
    .PARAMETER CheckRemoteExecution
        Check for remote execution indicators
    .PARAMETER CheckAuthentication
        Check authentication logs for lateral movement
    .PARAMETER CheckSMBShares
        Check SMB share access
    .PARAMETER CheckServiceCreation
        Check System event 7045 for suspicious service creation
    .PARAMETER CheckScheduledTasks
        Check Security events 4698, 4699, 4700, and 4702 for suspicious tasks
    .PARAMETER CheckWMI
        Check Security and optional Sysmon logs for WMI lateral movement
    .PARAMETER Days
        Number of days to check in event logs (default: 7)
    .PARAMETER MaxEvents
        Maximum events returned by each event-log query (default: 500). A section
        is marked Truncated when one of its queries reaches this cap
    .EXAMPLE
        Find-LateralMovement -CheckNetworkConnections -CheckAuthentication
        Find-LateralMovement -CheckNetworkConnections -CheckRemoteExecution -CheckAuthentication -Days 1
        Find-LateralMovement -CheckServiceCreation -CheckScheduledTasks -CheckWMI -Days 3 -MaxEvents 1000
    .OUTPUTS
        PSCustomObject with lateral movement indicators, per-section Truncated
        flags, SourcesChecked notes, summary counts, and recommendations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$CheckNetworkConnections,
        
        [Parameter()]
        [switch]$CheckRemoteExecution,
        
        [Parameter()]
        [switch]$CheckAuthentication,
        
        [Parameter()]
        [switch]$CheckSMBShares,

        [Parameter()]
        [switch]$CheckServiceCreation,

        [Parameter()]
        [switch]$CheckScheduledTasks,

        [Parameter()]
        [switch]$CheckWMI,
        
        [Parameter()]
        [int]$Days = 7,

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxEvents = 500
    )
    
    begin {
        Write-Host "=== LATERAL MOVEMENT DETECTION ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Analysis Period: Last $Days days" -ForegroundColor Yellow
        
        if (-not ($CheckNetworkConnections -or $CheckRemoteExecution -or $CheckAuthentication -or $CheckSMBShares -or $CheckServiceCreation -or $CheckScheduledTasks -or $CheckWMI)) {
            $CheckNetworkConnections = $true
            $CheckAuthentication = $true
            Write-Host "No specific check selected - enabling default checks" -ForegroundColor Yellow
        }
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            AnalysisPeriod = $Days
            Indicators = @{
                NetworkConnections = @()
                RemoteExecution = @()
                SuspiciousAuthentication = @()
                SMBAccess = @()
                ServiceCreation = @()
                ScheduledTasks = @()
                WMI = @()
            }
            # A cap hit means that matching events may remain beyond the returned set.
            Truncated = @{
                NetworkConnections = $false
                RemoteExecution = $false
                SuspiciousAuthentication = $false
                SMBAccess = $false
                ServiceCreation = $false
                ScheduledTasks = $false
                WMI = $false
            }
            SourcesChecked = @()
            Summary = @{
                TotalIndicators = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
                LowFindings = 0
            }
            Recommendations = @()
        }

        function Get-LateralEventProperty {
            param(
                [Parameter()]
                $WinEvent,

                [Parameter(Mandatory = $true)]
                [string]$Name,

                [Parameter()]
                [int]$Index = -1
            )

            if ($null -eq $WinEvent) { return $null }

            if ($WinEvent.PSObject.Properties['EventData'] -and $null -ne $WinEvent.EventData) {
                $eventData = $WinEvent.EventData
                if ($eventData -is [System.Collections.IDictionary]) {
                    if ($eventData.Contains($Name)) { return [string]$eventData[$Name] }
                }
                elseif ($eventData.PSObject.Properties[$Name]) {
                    return [string]$eventData.$Name
                }
            }

            try {
                $xml = [xml]$WinEvent.ToXml()
                $dataNodes = @($xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]'))
                $hasNamedData = $false
                foreach ($node in $dataNodes) {
                    $nodeName = ''
                    if ($node -is [System.Xml.XmlElement]) {
                        $nodeName = $node.GetAttribute('Name')
                    }
                    elseif ($node.PSObject.Properties['Name']) {
                        $nodeName = [string]$node.Name
                    }

                    if (-not [string]::IsNullOrEmpty($nodeName)) { $hasNamedData = $true }
                    if ($nodeName -eq $Name) {
                        return [string]$node.InnerText
                    }
                }

                # Some schemas, notably System 7045, use unnamed Data elements.
                # Never map a missing named field to an unrelated positional field.
                if (-not $hasNamedData -and $Index -ge 0 -and $Index -lt $dataNodes.Count) {
                    $node = $dataNodes[$Index]
                    $nodeName = ''
                    if ($node -is [System.Xml.XmlElement]) {
                        $nodeName = $node.GetAttribute('Name')
                    }
                    elseif ($node.PSObject.Properties['Name']) {
                        $nodeName = [string]$node.Name
                    }
                    if ([string]::IsNullOrEmpty($nodeName)) {
                        return [string]$node.InnerText
                    }
                }
            }
            catch {
                Write-Debug "Could not parse EventData field '$Name': $_"
            }

            if ($Index -ge 0 -and $WinEvent.PSObject.Properties['Properties'] -and $null -ne $WinEvent.Properties) {
                $properties = @($WinEvent.Properties)
                if ($Index -lt $properties.Count -and $null -ne $properties[$Index]) {
                    if ($properties[$Index].PSObject.Properties['Value']) {
                        return [string]$properties[$Index].Value
                    }
                    return [string]$properties[$Index]
                }
            }

            return $null
        }

        function Get-LateralEventTime {
            param([Parameter()]$WinEvent)
            if ($null -ne $WinEvent -and $WinEvent.PSObject.Properties['TimeCreated']) {
                return $WinEvent.TimeCreated
            }
            return $null
        }

        function Get-LateralTaskInfo {
            param([Parameter(Mandatory = $true)]$WinEvent)

            $author = Get-LateralEventProperty -WinEvent $WinEvent -Name 'Author'
            $runAs = Get-LateralEventProperty -WinEvent $WinEvent -Name 'RunAs'
            if ([string]::IsNullOrWhiteSpace($runAs)) {
                $runAs = Get-LateralEventProperty -WinEvent $WinEvent -Name 'RunAsUser'
            }
            if ([string]::IsNullOrWhiteSpace($runAs)) {
                $runAs = Get-LateralEventProperty -WinEvent $WinEvent -Name 'PrincipalUserId'
            }

            $actionParts = @()
            foreach ($fieldName in @('Action', 'TaskAction', 'Command', 'Arguments')) {
                $value = Get-LateralEventProperty -WinEvent $WinEvent -Name $fieldName
                if (-not [string]::IsNullOrWhiteSpace($value)) { $actionParts += $value }
            }

            $logonTrigger = $false
            $bootTrigger = $false
            $oneTimeTrigger = $false
            $taskContent = Get-LateralEventProperty -WinEvent $WinEvent -Name 'TaskContent'
            $contentParsed = $false

            if (-not [string]::IsNullOrWhiteSpace($taskContent)) {
                try {
                    $taskDocument = [xml]$taskContent
                    $contentParsed = $true

                    if ([string]::IsNullOrWhiteSpace($author)) {
                        $authorNode = $taskDocument.SelectSingleNode('//*[local-name()="RegistrationInfo"]/*[local-name()="Author"]')
                        if ($null -ne $authorNode) { $author = $authorNode.InnerText }
                    }

                    if ([string]::IsNullOrWhiteSpace($runAs)) {
                        $principalNode = $taskDocument.SelectSingleNode('//*[local-name()="Principals"]/*[local-name()="Principal"]/*[local-name()="UserId"]')
                        if ($null -ne $principalNode) { $runAs = $principalNode.InnerText }
                    }

                    $execNodes = @($taskDocument.SelectNodes('//*[local-name()="Actions"]/*[local-name()="Exec"]'))
                    foreach ($execNode in $execNodes) {
                        $commandNode = $execNode.SelectSingleNode('./*[local-name()="Command"]')
                        $argumentsNode = $execNode.SelectSingleNode('./*[local-name()="Arguments"]')
                        $command = ''
                        $arguments = ''
                        if ($null -ne $commandNode) { $command = $commandNode.InnerText }
                        if ($null -ne $argumentsNode) { $arguments = $argumentsNode.InnerText }
                        $action = "$command $arguments".Trim()
                        if (-not [string]::IsNullOrWhiteSpace($action)) { $actionParts += $action }
                    }

                    $triggerNodes = @($taskDocument.SelectNodes('//*[local-name()="Triggers"]/*'))
                    foreach ($triggerNode in $triggerNodes) {
                        if ($triggerNode.LocalName -eq 'LogonTrigger') { $logonTrigger = $true }
                        if ($triggerNode.LocalName -eq 'BootTrigger') { $bootTrigger = $true }
                        if ($triggerNode.LocalName -eq 'TimeTrigger') {
                            $repetitionNode = $triggerNode.SelectSingleNode('./*[local-name()="Repetition"]')
                            if ($null -eq $repetitionNode) { $oneTimeTrigger = $true }
                        }
                    }
                }
                catch {
                    Write-Debug "Scheduled task TaskContent was not valid XML: $_"
                }

                if (-not $contentParsed -and $actionParts.Count -eq 0) {
                    $actionParts += $taskContent
                }
            }

            $triggerText = ''
            foreach ($fieldName in @('Triggers', 'Trigger', 'TriggerType')) {
                $value = Get-LateralEventProperty -WinEvent $WinEvent -Name $fieldName
                if (-not [string]::IsNullOrWhiteSpace($value)) { $triggerText += " $value" }
            }
            if ($triggerText -match '(?i)LogonTrigger|Logon') { $logonTrigger = $true }
            if ($triggerText -match '(?i)BootTrigger|Boot') { $bootTrigger = $true }
            if ($triggerText -match '(?i)TimeTrigger|OneTime') { $oneTimeTrigger = $true }

            $actionParts = @($actionParts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            return [PSCustomObject]@{
                Author = $author
                RunAs = $runAs
                Action = ($actionParts -join ' ')
                LogonTrigger = $logonTrigger
                BootTrigger = $bootTrigger
                OneTimeTrigger = $oneTimeTrigger
            }
        }

        function Add-LateralSourceNote {
            param([Parameter(Mandatory = $true)][string]$Note)
            if ($results.SourcesChecked -notcontains $Note) {
                $results.SourcesChecked += $Note
            }
        }

        function Test-LateralLog {
            param(
                [Parameter(Mandatory = $true)][string]$LogName,
                [Parameter(Mandatory = $true)][string]$Purpose
            )

            try {
                $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
                Add-LateralSourceNote -Note "$LogName log present; $Purpose."
                return $true
            }
            catch {
                Add-LateralSourceNote -Note "$LogName log unavailable (not present or not accessible); $Purpose was not checked."
                return $false
            }
        }

        $addFinding = {
            param(
                [Parameter(Mandatory = $true)][string]$Section,
                [Parameter(Mandatory = $true)]$Finding
            )

            $results.Indicators[$Section] += $Finding
            switch ($Finding.Severity) {
                'Critical' { $results.Summary.CriticalFindings++ }
                'High' { $results.Summary.HighFindings++ }
                'Medium' { $results.Summary.MediumFindings++ }
                'Low' { $results.Summary.LowFindings++ }
            }
        }
        
        $startDate = (Get-Date).AddDays(-$Days)
    }
    
    process {
        try {
            # 1. Check Network Connections for Lateral Movement
            if ($CheckNetworkConnections) {
                Write-Host "`n[1/7] Checking network connections..." -ForegroundColor Cyan
                
                try {
                    # Check for established connections to internal IPs on suspicious ports
                    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                    
                    $suspiciousPorts = @{
                        445 = 'SMB'
                        135 = 'RPC'
                        139 = 'NetBIOS'
                        5985 = 'WinRM HTTP'
                        5986 = 'WinRM HTTPS'
                        3389 = 'RDP'
                    }
                    
                    $foundCount = 0
                    
                    foreach ($conn in $connections) {
                        if ($conn.RemotePort -in $suspiciousPorts.Keys) {
                            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                            
                            if (-not $process) {
                                continue
                            }
                            
                            # Skip if it's a standard system process in expected scenarios
                            if ($process.Name -in @('svchost', 'System')) {
                                continue
                            }
                            
                            $indicator = [PSCustomObject]@{
                                Type = 'NetworkConnection'
                                Process = $process.Name
                                ProcessId = $conn.OwningProcess
                                LocalAddress = "$($conn.LocalAddress):$($conn.LocalPort)"
                                RemoteAddress = "$($conn.RemoteAddress):$($conn.RemotePort)"
                                Protocol = $suspiciousPorts[$conn.RemotePort]
                                Severity = 'Medium'
                                Description = "Connection to $($suspiciousPorts[$conn.RemotePort]) port from $($process.Name)"
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            
                            $results.Indicators.NetworkConnections += $indicator
                            $results.Summary.MediumFindings++
                            $foundCount++
                            
                            if ($foundCount -le 5) {
                                Write-Host "  [!] $($process.Name) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($suspiciousPorts[$conn.RemotePort])]" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    if ($foundCount -gt 5) {
                        Write-Host "  ... and $($foundCount - 5) more connections" -ForegroundColor Gray
                    }
                    
                    if ($foundCount -eq 0) {
                        Write-Host "  No suspicious network connections detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking network connections: $_"
                }
            }
            
            # 2. Check Remote Execution Indicators
            if ($CheckRemoteExecution) {
                Write-Host "`n[2/7] Checking remote execution indicators..." -ForegroundColor Cyan
                
                try {
                    # Check for PSRemoting activity (Event ID 4648 - Explicit credential logon)
                    $maxRemoteEvents = $MaxEvents
                    $remoteEvents = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4648
                        StartTime = $startDate
                    } -MaxEvents $maxRemoteEvents -ErrorAction SilentlyContinue)

                    # Get-WinEvent returns exactly MaxEvents when more matching
                    # events exist - flag the cap instead of silently truncating
                    if ($remoteEvents.Count -ge $maxRemoteEvents) {
                        $results.Truncated.RemoteExecution = $true
                        Write-Warning "Remote execution check (Event ID 4648) hit the $maxRemoteEvents-event cap - results are likely TRUNCATED. Narrow -Days for complete coverage."
                    }
                    
                    if ($remoteEvents) {
                        $groupedEvents = $remoteEvents | Group-Object -Property { 
                            $_.Properties[8].Value 
                        } | Sort-Object Count -Descending
                        
                        foreach ($group in $groupedEvents | Select-Object -First 5) {
                            $event = $group.Group[0]
                            
                            $indicator = [PSCustomObject]@{
                                Type = 'RemoteExecution'
                                Process = 'N/A'
                                ProcessId = 'N/A'
                                TargetServer = $event.Properties[8].Value
                                Account = $event.Properties[1].Value
                                Count = $group.Count
                                Severity = if ($group.Count -gt 10) { 'High' } else { 'Medium' }
                                Description = "Explicit credential logon to $($event.Properties[8].Value) - $($group.Count) times"
                                Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                            
                            $results.Indicators.RemoteExecution += $indicator
                            
                            if ($group.Count -gt 10) {
                                $results.Summary.HighFindings++
                            } else {
                                $results.Summary.MediumFindings++
                            }
                            
                            Write-Host "  [!] Explicit credential logon: $($event.Properties[8].Value) ($($group.Count) times)" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "  No remote execution indicators detected" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error checking remote execution: $_"
                }
            }
            
            # 3. Check Authentication Logs for Lateral Movement
            if ($CheckAuthentication) {
                Write-Host "`n[3/7] Checking authentication logs..." -ForegroundColor Cyan
                
                try {
                    # Event ID 4624 - Successful logon (Type 3 = Network, Type 10 = RemoteInteractive/RDP)
                    $maxLogonEvents = $MaxEvents
                    $logonEvents = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 4624
                        StartTime = $startDate
                    } -MaxEvents $maxLogonEvents -ErrorAction SilentlyContinue)

                    # Get-WinEvent returns exactly MaxEvents when more matching
                    # events exist - flag the cap instead of silently truncating
                    if ($logonEvents.Count -ge $maxLogonEvents) {
                        $results.Truncated.SuspiciousAuthentication = $true
                        Write-Warning "Authentication check (Event ID 4624) hit the $maxLogonEvents-event cap - results are likely TRUNCATED. Narrow -Days for complete coverage."
                    }
                    
                    if ($logonEvents) {
                        # Filter for Type 3 (Network) and Type 10 (RemoteInteractive)
                        $suspiciousLogons = $logonEvents | Where-Object {
                            $logonType = $_.Properties[8].Value
                            $logonType -in @(3, 10)
                        }
                        
                        if ($suspiciousLogons) {
                            # Group by source IP
                            $groupedByIP = $suspiciousLogons | Group-Object -Property { 
                                $_.Properties[18].Value 
                            } | Where-Object { $_.Name -ne '-' -and $_.Name -ne '127.0.0.1' } |
                            Sort-Object Count -Descending
                            
                            foreach ($group in $groupedByIP | Select-Object -First 5) {
                                $event = $group.Group[0]
                                $logonType = $event.Properties[8].Value
                                $logonTypeName = switch ($logonType) {
                                    3 { 'Network' }
                                    10 { 'RemoteInteractive/RDP' }
                                    default { "Type $logonType" }
                                }
                                
                                $indicator = [PSCustomObject]@{
                                    Type = 'SuspiciousAuthentication'
                                    Process = 'N/A'
                                    ProcessId = 'N/A'
                                    SourceIP = $group.Name
                                    Account = $event.Properties[5].Value
                                    LogonType = $logonTypeName
                                    Count = $group.Count
                                    Severity = if ($group.Count -gt 20) { 'High' } else { 'Medium' }
                                    Description = "$logonTypeName logon from $($group.Name) - $($group.Count) times"
                                    Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                                }
                                
                                $results.Indicators.SuspiciousAuthentication += $indicator
                                
                                if ($group.Count -gt 20) {
                                    $results.Summary.HighFindings++
                                } else {
                                    $results.Summary.MediumFindings++
                                }
                                
                                Write-Host "  [!] $logonTypeName from $($group.Name): $($group.Count) times" -ForegroundColor Yellow
                            }
                        }
                        else {
                            Write-Host "  No suspicious authentication events detected" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "  No authentication events found in specified period" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Error checking authentication logs: $_"
                }
            }
            
            # 4. Check SMB Share Access
            if ($CheckSMBShares) {
                Write-Host "`n[4/7] Checking SMB share access..." -ForegroundColor Cyan
                
                try {
                    # Event ID 5140 - Network share object accessed
                    $maxShareEvents = $MaxEvents
                    $shareEvents = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        ID = 5140
                        StartTime = $startDate
                    } -MaxEvents $maxShareEvents -ErrorAction SilentlyContinue)

                    # Get-WinEvent returns exactly MaxEvents when more matching
                    # events exist - flag the cap instead of silently truncating
                    if ($shareEvents.Count -ge $maxShareEvents) {
                        $results.Truncated.SMBAccess = $true
                        Write-Warning "SMB share access check (Event ID 5140) hit the $maxShareEvents-event cap - results are likely TRUNCATED. Narrow -Days for complete coverage."
                    }
                    
                    if ($shareEvents) {
                        # Split share access: admin/hidden shares (IPC$, ADMIN$, C$, ...)
                        # are the PRIMARY lateral movement signal; other shares are noise
                        $adminShareEvents = @($shareEvents | Where-Object {
                            $shareName = $_.Properties[7].Value
                            $shareName -match 'IPC\$|ADMIN\$|[A-Za-z]\$'
                        })
                        $otherShareEvents = @($shareEvents | Where-Object {
                            $shareName = $_.Properties[7].Value
                            $shareName -notmatch 'IPC\$|ADMIN\$|[A-Za-z]\$'
                        })

                        $shareSets = @(
                            @{ Events = $adminShareEvents; Severity = 'High'; Label = 'Admin share' }
                            @{ Events = $otherShareEvents; Severity = 'Low';  Label = 'Share' }
                        )

                        $foundShares = $false

                        foreach ($shareSet in $shareSets) {
                            if ($shareSet.Events.Count -eq 0) {
                                continue
                            }

                            $foundShares = $true

                            $groupedShares = $shareSet.Events | Group-Object -Property {
                                "$($_.Properties[1].Value)|$($_.Properties[7].Value)"
                            } | Sort-Object Count -Descending

                            foreach ($group in $groupedShares | Select-Object -First 5) {
                                $parts = $group.Name -split '\|'
                                $event = $group.Group[0]

                                $indicator = [PSCustomObject]@{
                                    Type = 'SMBAccess'
                                    Process = 'N/A'
                                    ProcessId = 'N/A'
                                    Account = $parts[0]
                                    ShareName = $parts[1]
                                    Count = $group.Count
                                    Severity = $shareSet.Severity
                                    Description = "$($shareSet.Label) access: $($parts[1]) by $($parts[0]) - $($group.Count) times"
                                    Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                                }

                                $results.Indicators.SMBAccess += $indicator

                                if ($shareSet.Severity -eq 'High') {
                                    $results.Summary.HighFindings++
                                    Write-Host "  [!] ADMIN SHARE: $($parts[1]) by $($parts[0]) ($($group.Count) times)" -ForegroundColor Red
                                }
                                else {
                                    $results.Summary.LowFindings++
                                    Write-Host "  [!] Share: $($parts[1]) by $($parts[0]) ($($group.Count) times)" -ForegroundColor Yellow
                                }
                            }
                        }

                        if (-not $foundShares) {
                            Write-Host "  No suspicious SMB share access detected" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "  No SMB share access events found" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Error checking SMB share access: $_"
                }
            }
            
            # 5. Check service creation (System 7045)
            if ($CheckServiceCreation) {
                Write-Host "`n[5/7] Checking suspicious service creation..." -ForegroundColor Cyan
                if (Test-LateralLog -LogName 'System' -Purpose 'service creation events (7045) were queried') {
                    try {
                        $serviceEvents = @(Get-WinEvent -FilterHashtable @{
                            LogName = 'System'
                            ID = 7045
                            StartTime = $startDate
                        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

                        if ($serviceEvents.Count -ge $MaxEvents) {
                            $results.Truncated.ServiceCreation = $true
                            Write-Warning "Service creation check (Event ID 7045) hit the $MaxEvents-event cap - results are likely TRUNCATED. Narrow -Days or raise -MaxEvents for complete coverage."
                        }

                        $allowedServicePrefix = '^(?i:WinDefend|WdNis|WdBoot|WdFilter|Sense|SecurityHealth|MpSvc|MDCoreSvc|MsMpEng|MsSecCore|wuauserv|UsoSvc|WaaSMedicSvc|WindowsUpdate|BITS|TrustedInstaller|GoogleUpdate|gupdate|gupdatem|MicrosoftEdgeUpdate|edgeupdate|edgeupdatem|AdobeARMservice|AdobeUpdateService)'
                        $knownServiceNames = @('PSEXESVC', 'RemCom', 'RemComSvc', 'cscript', 'wscript')
                        $serviceBinaryNames = @('powershell.exe', 'cmd.exe', 'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'cscript.exe', 'wscript.exe')
                        $servicePathPattern = '(?i)(\\Windows\\Temp\\|\\Temp\\|\\AppData\\|\\Users\\Public(?:\\|$)|\\ProgramData(?:\\|$)|^[A-Za-z]:\\Temp(?:\\|$)|%TEMP%|%LOCALAPPDATA%|%APPDATA%|%PUBLIC%|%PROGRAMDATA%)'
                        $foundServices = 0

                        foreach ($event in $serviceEvents) {
                            if ($null -eq $event) { continue }
                            $serviceName = Get-LateralEventProperty -WinEvent $event -Name 'ServiceName' -Index 0
                            $imagePath = Get-LateralEventProperty -WinEvent $event -Name 'ImagePath' -Index 1
                            $accountName = Get-LateralEventProperty -WinEvent $event -Name 'AccountName' -Index 2

                            if (-not [string]::IsNullOrWhiteSpace($serviceName) -and $serviceName -match $allowedServicePrefix) {
                                continue
                            }

                            $reasons = @()
                            $severity = 'Medium'
                            if (-not [string]::IsNullOrWhiteSpace($imagePath)) {
                                if ($imagePath -match $servicePathPattern) {
                                    $reasons += 'Service binary is under a temporary, user-writable, public, or ProgramData path'
                                }

                                $trimmedImage = $imagePath.Trim()
                                $unquotedImage = $trimmedImage.Trim('"').Trim("'")
                                if ($unquotedImage.StartsWith('\\')) {
                                    $reasons += 'Service binary uses a UNC path'
                                    $severity = 'High'
                                }

                                $serviceBinary = $trimmedImage
                                if ($trimmedImage.StartsWith('"')) {
                                    $binaryMatch = [regex]::Match($trimmedImage, '^"([^"]+)"')
                                    if ($binaryMatch.Success) { $serviceBinary = $binaryMatch.Groups[1].Value }
                                }
                                else {
                                    $serviceBinary = ($trimmedImage -split '\s+', 2)[0]
                                }

                                $binaryName = ''
                                if ($serviceBinary -match '([^\\/]+)$') {
                                    $binaryName = $Matches[1].ToLowerInvariant()
                                }
                                if ($serviceBinaryNames -contains $binaryName) {
                                    $reasons += "Service uses a script or proxy-execution binary ($binaryName)"
                                    $severity = 'High'
                                }
                            }

                            if ($knownServiceNames -contains $serviceName) {
                                $reasons += "Service name matches a known remote-execution or LOLBin launcher ($serviceName)"
                                $severity = 'High'
                            }

                            if ($reasons.Count -eq 0) { continue }
                            $reasons = @($reasons | Select-Object -Unique)
                            $details = "Service '$serviceName' created with image '$imagePath' as '$accountName'. Reasons: $($reasons -join '; ')"
                            $finding = [PSCustomObject]@{
                                TimeCreated = Get-LateralEventTime -WinEvent $event
                                Source = if ([string]::IsNullOrWhiteSpace($serviceName)) { 'System event 7045' } else { "Service: $serviceName" }
                                Details = $details
                                Severity = $severity
                                Technique = 'T1543.003'
                                Type = 'ServiceCreation'
                                EventId = 7045
                                ServiceName = $serviceName
                                ImagePath = $imagePath
                                AccountName = $accountName
                                Reasons = @($reasons)
                            }
                            & $addFinding 'ServiceCreation' $finding
                            $foundServices++
                            Write-Host "  [!] Suspicious service '$serviceName': $($reasons -join '; ')" -ForegroundColor Yellow
                        }

                        if ($foundServices -eq 0) {
                            Write-Host "  No suspicious service creation events detected" -ForegroundColor Green
                        }
                    }
                    catch {
                        Add-LateralSourceNote -Note "System service creation query (7045) failed: $($_.Exception.Message)"
                        Write-Warning "Error checking service creation: $_"
                    }
                }
            }

            # 6. Check scheduled task lifecycle events (Security 4698/4699/4700/4702)
            if ($CheckScheduledTasks) {
                Write-Host "`n[6/7] Checking suspicious scheduled tasks..." -ForegroundColor Cyan
                if (Test-LateralLog -LogName 'Security' -Purpose 'scheduled task events (4698/4699/4700/4702) were queried') {
                    try {
                        $taskEvents = @(Get-WinEvent -FilterHashtable @{
                            LogName = 'Security'
                            ID = 4698, 4699, 4700, 4702
                            StartTime = $startDate
                        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

                        if ($taskEvents.Count -ge $MaxEvents) {
                            $results.Truncated.ScheduledTasks = $true
                            Write-Warning "Scheduled task check hit the $MaxEvents-event cap - results are likely TRUNCATED. Narrow -Days or raise -MaxEvents for complete coverage."
                        }

                        $taskPathPattern = '(?i)(\\Windows\\Temp\\|\\Temp\\|\\AppData\\|\\Users\\Public(?:\\|$)|^[A-Za-z]:\\Temp(?:\\|$)|%TEMP%|%LOCALAPPDATA%|%APPDATA%|%PUBLIC%)'
                        $userContextPattern = '(?i)(\\Users\\|\\AppData\\|\\Temp\\|%TEMP%|%LOCALAPPDATA%|%APPDATA%)'
                        $scriptLauncherPattern = '(?i)(powershell|pwsh|cmd|cscript|wscript|mshta|rundll32|regsvr32)(\.exe)?\b'
                        $encodedCommandPattern = '(?i)(?:^|\s)-(?:enc|encodedcommand)(?:\s+|=|:)'
                        $foundTasks = 0

                        foreach ($event in $taskEvents) {
                            if ($null -eq $event) { continue }
                            $eventId = 0
                            if ($event.PSObject.Properties['Id']) { $eventId = [int]$event.Id }
                            $taskName = Get-LateralEventProperty -WinEvent $event -Name 'TaskName' -Index 4
                            $taskInfo = Get-LateralTaskInfo -WinEvent $event
                            $reasons = @()
                            $severity = 'Medium'

                            if ($taskInfo.Action -match $taskPathPattern) {
                                $reasons += 'Task action executes from a temporary, AppData, or public user-writable path'
                            }
                            if ($taskInfo.Action -match $encodedCommandPattern) {
                                $reasons += 'Task action contains an encoded PowerShell command'
                                $severity = 'High'
                            }

                            $runsAsSystem = $false
                            if (-not [string]::IsNullOrWhiteSpace($taskInfo.RunAs) -and $taskInfo.RunAs.Trim() -match '^(?i:SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$') {
                                $runsAsSystem = $true
                            }
                            if ($runsAsSystem -and $taskInfo.Action -match $scriptLauncherPattern -and $taskInfo.Action -match $userContextPattern) {
                                $reasons += 'Task runs a user-context script as SYSTEM'
                                $severity = 'High'
                            }
                            if ($taskInfo.LogonTrigger) { $reasons += 'Task uses a logon trigger' }
                            if ($taskInfo.BootTrigger) { $reasons += 'Task uses a boot trigger' }
                            if ($taskInfo.OneTimeTrigger) { $reasons += 'Task uses a one-time trigger' }

                            if ($reasons.Count -eq 0) { continue }
                            $reasons = @($reasons | Select-Object -Unique)
                            $details = "Scheduled task '$taskName' (event $eventId) by '$($taskInfo.Author)', run as '$($taskInfo.RunAs)'. Action: $($taskInfo.Action). Reasons: $($reasons -join '; ')"
                            $finding = [PSCustomObject]@{
                                TimeCreated = Get-LateralEventTime -WinEvent $event
                                Source = if ([string]::IsNullOrWhiteSpace($taskName)) { "Security event $eventId" } else { "Scheduled task: $taskName" }
                                Details = $details
                                Severity = $severity
                                Technique = 'T1053.005'
                                Type = 'ScheduledTask'
                                EventId = $eventId
                                TaskName = $taskName
                                Author = $taskInfo.Author
                                RunAs = $taskInfo.RunAs
                                Action = $taskInfo.Action
                                Reasons = @($reasons)
                            }
                            & $addFinding 'ScheduledTasks' $finding
                            $foundTasks++
                            Write-Host "  [!] Suspicious scheduled task '$taskName': $($reasons -join '; ')" -ForegroundColor Yellow
                        }

                        if ($foundTasks -eq 0) {
                            Write-Host "  No suspicious scheduled task content detected" -ForegroundColor Green
                        }
                    }
                    catch {
                        Add-LateralSourceNote -Note "Security scheduled task query failed: $($_.Exception.Message)"
                        Write-Warning "Error checking scheduled tasks: $_"
                    }
                }
            }

            # 7. Check WMI explicit credentials, network logons, and Sysmon subscriptions
            if ($CheckWMI) {
                Write-Host "`n[7/7] Checking WMI lateral movement..." -ForegroundColor Cyan
                $securityAvailable = Test-LateralLog -LogName 'Security' -Purpose 'WMI Security events (4648/4624) were queried'
                if ($securityAvailable) {
                    try {
                        $wmiSecurityEvents = @(Get-WinEvent -FilterHashtable @{
                            LogName = 'Security'
                            ID = 4648, 4624
                            StartTime = $startDate
                        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

                        if ($wmiSecurityEvents.Count -ge $MaxEvents) {
                            $results.Truncated.WMI = $true
                            Write-Warning "WMI Security query hit the $MaxEvents-event cap - results are likely TRUNCATED. Narrow -Days or raise -MaxEvents for complete coverage."
                        }

                        foreach ($event in $wmiSecurityEvents) {
                            if ($null -eq $event -or -not $event.PSObject.Properties['Id']) { continue }
                            $eventId = [int]$event.Id
                            $processIndex = 11
                            if ($eventId -eq 4624) { $processIndex = 17 }
                            $processName = Get-LateralEventProperty -WinEvent $event -Name 'ProcessName' -Index $processIndex
                            if ([string]::IsNullOrWhiteSpace($processName)) {
                                $processName = Get-LateralEventProperty -WinEvent $event -Name 'SourceProcessName'
                            }
                            if ([string]::IsNullOrWhiteSpace($processName)) {
                                $processName = Get-LateralEventProperty -WinEvent $event -Name 'SubjectProcessName'
                            }
                            $processAttributed = (-not [string]::IsNullOrWhiteSpace($processName) -and $processName -match '(?i)(^|[\\/])wmiprvse\.exe$')

                            if ($eventId -eq 4624) {
                                $logonType = Get-LateralEventProperty -WinEvent $event -Name 'LogonType' -Index 8
                                if ([string]$logonType -ne '3' -or -not $processAttributed) { continue }
                            }
                            elseif ($eventId -ne 4648) {
                                continue
                            }

                            $targetAccount = Get-LateralEventProperty -WinEvent $event -Name 'TargetUserName' -Index 5
                            $subjectAccount = Get-LateralEventProperty -WinEvent $event -Name 'SubjectUserName' -Index 1
                            $targetServer = $null
                            if ($eventId -eq 4648) {
                                $targetServer = Get-LateralEventProperty -WinEvent $event -Name 'TargetServerName' -Index 8
                            }
                            $sourceIP = Get-LateralEventProperty -WinEvent $event -Name 'IpAddress' -Index 18
                            $attribution = 'Explicit credential use; correlate with wmiprvse.exe activity for WMI attribution'
                            $severity = 'Low'
                            if ($processAttributed) {
                                $attribution = "Source process '$processName' attributes this activity to WMI"
                                $severity = 'High'
                            }
                            if ($eventId -eq 4624) {
                                $attribution = "WMI-attributed network logon (Type 3) from '$sourceIP' by process '$processName'"
                                $severity = 'Medium'
                            }

                            $details = "$attribution. Subject '$subjectAccount', target account '$targetAccount', target server '$targetServer', source IP '$sourceIP'"
                            $finding = [PSCustomObject]@{
                                TimeCreated = Get-LateralEventTime -WinEvent $event
                                Source = if (-not [string]::IsNullOrWhiteSpace($processName)) { $processName } elseif (-not [string]::IsNullOrWhiteSpace($sourceIP)) { $sourceIP } else { "Security event $eventId" }
                                Details = $details
                                Severity = $severity
                                Technique = 'T1021.004'
                                Type = 'WMI'
                                EventId = $eventId
                                ProcessName = $processName
                                SubjectAccount = $subjectAccount
                                TargetAccount = $targetAccount
                                TargetServer = $targetServer
                                SourceIP = $sourceIP
                            }
                            & $addFinding 'WMI' $finding
                            Write-Host "  [!] WMI indicator (event $eventId): $attribution" -ForegroundColor Yellow
                        }
                    }
                    catch {
                        Add-LateralSourceNote -Note "Security WMI query (4648/4624) failed: $($_.Exception.Message)"
                        Write-Warning "Error checking WMI Security events: $_"
                    }
                }

                $sysmonLogName = 'Microsoft-Windows-Sysmon/Operational'
                $sysmonAvailable = Test-LateralLog -LogName $sysmonLogName -Purpose 'WMI subscription events (19/20/21) were queried'
                if ($sysmonAvailable) {
                    try {
                        $sysmonWmiEvents = @(Get-WinEvent -FilterHashtable @{
                            LogName = $sysmonLogName
                            ID = 19, 20, 21
                            StartTime = $startDate
                        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)

                        if ($sysmonWmiEvents.Count -ge $MaxEvents) {
                            $results.Truncated.WMI = $true
                            Write-Warning "Sysmon WMI query (19/20/21) hit the $MaxEvents-event cap - results are likely TRUNCATED. Narrow -Days or raise -MaxEvents for complete coverage."
                        }

                        foreach ($event in $sysmonWmiEvents) {
                            if ($null -eq $event -or -not $event.PSObject.Properties['Id']) { continue }
                            $eventId = [int]$event.Id
                            if ($eventId -notin @(19, 20, 21)) { continue }

                            $eventFields = [ordered]@{}
                            foreach ($fieldName in @('Operation', 'User', 'EventNamespace', 'Name', 'Query', 'Type', 'Destination', 'CommandLineTemplate', 'ScriptText', 'Consumer', 'Filter')) {
                                $value = Get-LateralEventProperty -WinEvent $event -Name $fieldName
                                if (-not [string]::IsNullOrWhiteSpace($value)) { $eventFields[$fieldName] = $value }
                            }
                            $fieldDetails = @()
                            foreach ($fieldName in $eventFields.Keys) {
                                $fieldDetails += "$fieldName=$($eventFields[$fieldName])"
                            }
                            $details = "Sysmon WMI subscription event $eventId. $($fieldDetails -join '; ')"
                            $finding = [PSCustomObject]@{
                                TimeCreated = Get-LateralEventTime -WinEvent $event
                                Source = "Sysmon event $eventId"
                                Details = $details
                                Severity = if ($eventId -eq 20) { 'High' } else { 'Medium' }
                                Technique = 'T1021.004'
                                RelatedTechnique = 'T1546.003'
                                Type = 'WMISubscription'
                                EventId = $eventId
                                EventData = $eventFields
                            }
                            & $addFinding 'WMI' $finding
                            Write-Host "  [!] Sysmon WMI subscription event $eventId" -ForegroundColor Yellow
                        }
                    }
                    catch {
                        Add-LateralSourceNote -Note "Sysmon WMI query (19/20/21) failed: $($_.Exception.Message)"
                        Write-Warning "Error checking Sysmon WMI events: $_"
                    }
                }
            }

            # Add the standard finding fields to legacy indicator objects without
            # removing their original properties (backward-compatible consumers).
            foreach ($sectionName in @('NetworkConnections', 'RemoteExecution', 'SuspiciousAuthentication', 'SMBAccess')) {
                foreach ($finding in @($results.Indicators[$sectionName])) {
                    if (-not $finding.PSObject.Properties['TimeCreated']) {
                        $finding | Add-Member -NotePropertyName TimeCreated -NotePropertyValue $finding.Timestamp
                    }
                    if (-not $finding.PSObject.Properties['Details']) {
                        $finding | Add-Member -NotePropertyName Details -NotePropertyValue $finding.Description
                    }
                    if (-not $finding.PSObject.Properties['Source']) {
                        $source = 'Unknown'
                        switch ($sectionName) {
                            'NetworkConnections' { $source = $finding.RemoteAddress }
                            'RemoteExecution' { $source = $finding.TargetServer }
                            'SuspiciousAuthentication' { $source = $finding.SourceIP }
                            'SMBAccess' { $source = $finding.Account }
                        }
                        $finding | Add-Member -NotePropertyName Source -NotePropertyValue $source
                    }
                    if (-not $finding.PSObject.Properties['Technique']) {
                        $technique = 'T1021'
                        switch ($sectionName) {
                            'NetworkConnections' {
                                switch ($finding.Protocol) {
                                    'RDP' { $technique = 'T1021.001' }
                                    'SMB' { $technique = 'T1021.002' }
                                    'NetBIOS' { $technique = 'T1021.002' }
                                    'RPC' { $technique = 'T1021.003' }
                                    'WinRM HTTP' { $technique = 'T1021.006' }
                                    'WinRM HTTPS' { $technique = 'T1021.006' }
                                }
                            }
                            'RemoteExecution' { $technique = 'T1021.006' }
                            'SuspiciousAuthentication' {
                                if ($finding.LogonType -eq 'RemoteInteractive/RDP') { $technique = 'T1021.001' }
                                else { $technique = 'T1021.002' }
                            }
                            'SMBAccess' { $technique = 'T1021.002' }
                        }
                        $finding | Add-Member -NotePropertyName Technique -NotePropertyValue $technique
                    }
                }
            }

            # Calculate summary
            $results.Summary.TotalIndicators = 
                $results.Indicators.NetworkConnections.Count +
                $results.Indicators.RemoteExecution.Count +
                $results.Indicators.SuspiciousAuthentication.Count +
                $results.Indicators.SMBAccess.Count +
                $results.Indicators.ServiceCreation.Count +
                $results.Indicators.ScheduledTasks.Count +
                $results.Indicators.WMI.Count
            
            # Generate recommendations
            if ($results.Summary.TotalIndicators -gt 0) {
                if ($results.Summary.HighFindings -gt 0) {
                    $results.Recommendations += "HIGH: Investigate high-severity lateral movement indicators immediately"
                }
                
                $results.Recommendations += "Review source IPs and accounts for suspicious activity"
                $results.Recommendations += "Check for compromised credentials"
                $results.Recommendations += "Enable enhanced logging (Sysmon, PowerShell logging)"
                $results.Recommendations += "Implement network segmentation"
                $results.Recommendations += "Deploy EDR solution for behavioral detection"
                
                if ($results.Indicators.RemoteExecution.Count -gt 0) {
                    $results.Recommendations += "Review PSRemoting and WinRM usage policies"
                }
                
                if ($results.Indicators.SuspiciousAuthentication.Count -gt 0) {
                    $results.Recommendations += "Investigate authentication patterns for pass-the-hash indicators"
                }

                if ($results.Indicators.ServiceCreation.Count -gt 0) {
                    $results.Recommendations += "Validate suspicious services against approved change records; inspect the binary, signer, creator account, and remote source before removal"
                }

                if ($results.Indicators.ScheduledTasks.Count -gt 0) {
                    $results.Recommendations += "Review flagged task XML, author, run-as principal, triggers, and actions; preserve a copy before disabling unauthorized tasks"
                }

                if ($results.Indicators.WMI.Count -gt 0) {
                    $results.Recommendations += "Correlate WMI activity with wmiprvse.exe, explicit credentials, source hosts, and Sysmon subscription events; validate administrative use"
                }
            }
            
        }
        catch {
            Write-Error "Error during lateral movement detection: $_"
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
        Write-Host "  Low: $($results.Summary.LowFindings)" -ForegroundColor White

        $truncatedSections = @($results.Truncated.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
        if ($truncatedSections.Count -gt 0) {
            Write-Host "  TRUNCATED (event cap hit, partial data): $($truncatedSections -join ', ')" -ForegroundColor Red
            $results.Recommendations += "Event log queries hit their -MaxEvents cap in: $($truncatedSections -join ', ') - narrow -Days or raise -MaxEvents and re-run for complete coverage"
        }
        
        if ($results.Summary.TotalIndicators -gt 0) {
            Write-Host "`nIndicator Breakdown:" -ForegroundColor Cyan
            if ($results.Indicators.NetworkConnections.Count -gt 0) {
                Write-Host "  Network Connections: $($results.Indicators.NetworkConnections.Count)" -ForegroundColor White
            }
            if ($results.Indicators.RemoteExecution.Count -gt 0) {
                Write-Host "  Remote Execution: $($results.Indicators.RemoteExecution.Count)" -ForegroundColor White
            }
            if ($results.Indicators.SuspiciousAuthentication.Count -gt 0) {
                Write-Host "  Suspicious Authentication: $($results.Indicators.SuspiciousAuthentication.Count)" -ForegroundColor White
            }
            if ($results.Indicators.SMBAccess.Count -gt 0) {
                Write-Host "  SMB Access: $($results.Indicators.SMBAccess.Count)" -ForegroundColor White
            }
            if ($results.Indicators.ServiceCreation.Count -gt 0) {
                Write-Host "  Service Creation: $($results.Indicators.ServiceCreation.Count)" -ForegroundColor White
            }
            if ($results.Indicators.ScheduledTasks.Count -gt 0) {
                Write-Host "  Scheduled Tasks: $($results.Indicators.ScheduledTasks.Count)" -ForegroundColor White
            }
            if ($results.Indicators.WMI.Count -gt 0) {
                Write-Host "  WMI: $($results.Indicators.WMI.Count)" -ForegroundColor White
            }
        }
        else {
            Write-Host "`nNo lateral movement indicators detected" -ForegroundColor Green
        }

        if ($results.SourcesChecked.Count -gt 0) {
            Write-Host "`nSources Checked:" -ForegroundColor Cyan
            foreach ($sourceNote in $results.SourcesChecked) {
                Write-Host "  $sourceNote" -ForegroundColor Gray
            }
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