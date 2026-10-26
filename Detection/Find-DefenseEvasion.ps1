function Find-DefenseEvasion {
    <#
    .SYNOPSIS
        Detects defense-evasion and security-tampering activity
    .DESCRIPTION
        Scans for indicators that attackers attempted to blind or weaken host defenses:
        AMSI bypass patterns in PowerShell script-block logging (4104), ETW tampering,
        Windows Defender tampering (exclusions, disabled real-time monitoring, 5001/5007
        events), event log tampering (1102/104/4719), and optional heuristic log-gap
        analysis across major logs
    .PARAMETER Hours
        Number of hours to look back in event logs (default: 24)
    .PARAMETER IncludeLogGapAnalysis
        Perform heuristic analysis of time gaps between consecutive events in major logs
    .EXAMPLE
        Find-DefenseEvasion
        Find-DefenseEvasion -Hours 48 -IncludeLogGapAnalysis
    .OUTPUTS
        PSCustomObject with EvasionFindings, Summary, Recommendations, and per-check status
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Hours = 24,

        [Parameter()]
        [switch]$IncludeLogGapAnalysis
    )

    begin {
        Write-Host "Scanning for defense-evasion and tampering activity (last $Hours hours)..." -ForegroundColor Cyan

        $results = [PSCustomObject]@{
            ScanDate         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName     = $env:COMPUTERNAME
            TimeRange        = "$Hours hours"
            EvasionFindings  = @()
            Summary          = [PSCustomObject]@{
                TotalFindings = 0
                Critical      = 0
                High          = 0
                Medium        = 0
                Low           = 0
                Info          = 0
                ChecksRun     = 0
            }
            CheckStatus      = [PSCustomObject]@{
                ScriptBlockLogQuery = 'Unknown'
                AmsiProviderCheck   = 'Unknown'
                AmsiPatternScan     = 'Unknown'
                EtwPatternScan      = 'Unknown'
                PowerShellLoggingGpo= 'Unknown'
                DefenderPreferences = 'Unknown'
                DefenderStatus      = 'Unknown'
                DefenderEvents      = 'Unknown'
                SecurityLogCleared  = 'Unknown'
                SystemLogCleared    = 'Unknown'
                AuditPolicyChanged  = 'Unknown'
                LogGapAnalysis      = 'NotRequested'
            }
            Recommendations  = @()
        }

        $startTime = (Get-Date).AddHours(-$Hours)

        function Get-EventDataValue {
            param(
                [Parameter()]
                $WinEvent,

                [Parameter()]
                [string]$Name
            )
            try {
                if ($null -eq $WinEvent) { return $null }
                $xml = [xml]$WinEvent.ToXml()
                if ($null -eq $xml -or $null -eq $xml.Event -or $null -eq $xml.Event.EventData) { return $null }
                $data = $xml.Event.EventData.Data
                if ($null -eq $data) { return $null }
                $item = @($data | Where-Object { $null -ne $_.Name -and $_.Name -eq $Name } | Select-Object -First 1)
                if ($item.Count -eq 0) { return $null }
                $node = $item[0]
                if ($node.PSObject.Properties['#text']) { return $node.'#text' }
                return [string]$node
            }
            catch {
                return $null
            }
        }

        function Get-EventMessage {
            param(
                [Parameter()]
                $WinEvent
            )
            if ($null -eq $WinEvent) { return $null }
            if ($WinEvent.PSObject.Properties['Message'] -and $WinEvent.Message) { return [string]$WinEvent.Message }
            return $null
        }

        function Get-EventTimestamp {
            param(
                [Parameter()]
                $WinEvent
            )
            if ($null -eq $WinEvent) { return $null }
            if ($WinEvent.PSObject.Properties['TimeCreated']) { return $WinEvent.TimeCreated }
            return $null
        }

        function Get-MessageSnippet {
            param(
                [Parameter()]
                [string]$Message,

                [Parameter()]
                [int]$MaxLength = 200
            )
            if ([string]::IsNullOrEmpty($Message)) { return '' }
            if ($Message.Length -gt $MaxLength) {
                return ($Message.Substring(0, $MaxLength) + '...')
            }
            return $Message
        }

        # AMSI bypass indicator patterns (T1562.001 - Impair Defenses: Disable or Modify Tools)
        $amsiPatterns = @(
            [PSCustomObject]@{ Name = 'AmsiScanBuffer patch/reference';    Pattern = 'AmsiScanBuffer';                          Combo = $null;                                              Severity = 'High' }
            [PSCustomObject]@{ Name = 'amsiInitFailed forced';             Pattern = 'amsiInitFailed';                          Combo = $null;                                              Severity = 'High' }
            [PSCustomObject]@{ Name = 'amsi.dll memory patch';             Pattern = 'amsi\.dll';                               Combo = '(?i)(patch|VirtualProtect|WriteProcessMemory|Marshal)'; Severity = 'High' }
            [PSCustomObject]@{ Name = 'Reflection-based amsiUtils tamper'; Pattern = '\[Ref\]\.Assembly\.GetType';              Combo = '(?i)amsiUtils';                                    Severity = 'High' }
            [PSCustomObject]@{ Name = 'Marshal::Copy near AMSI';           Pattern = 'Marshal::Copy';                           Combo = '(?i)amsi';                                         Severity = 'Medium' }
        )

        # ETW tamper indicator patterns (T1562.006 - Impair Defenses: Indicator Blocking)
        $etwPatterns = @(
            [PSCustomObject]@{ Name = 'EtwEventWrite patch';               Pattern = 'EtwEventWrite';                           Combo = '(?i)(patch|VirtualProtect|Marshal|GetProcAddress)'; Severity = 'High' }
            [PSCustomObject]@{ Name = 'Generic ETW patch reference';       Pattern = '(?i)etw';                                 Combo = '(?i)patch';                                        Severity = 'Medium' }
        )

        $scriptBlockEvents = $null
    }

    process {
        try {
            # Shared query: PowerShell script-block logging events (4104)
            try {
                $scriptBlockEvents = @(Get-WinEvent -FilterHashtable @{
                    LogName   = 'Microsoft-Windows-PowerShell/Operational'
                    ID        = 4104
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue)
                $results.CheckStatus.ScriptBlockLogQuery = 'OK'
                $results.Summary.ChecksRun++
            }
            catch {
                Write-Warning "Could not query PowerShell Operational log (4104): $_"
                $results.CheckStatus.ScriptBlockLogQuery = 'Unknown'
            }

            # 1a. AMSI provider registration (informational baseline)
            Write-Verbose "Checking AMSI provider registration..."
            try {
                $results.Summary.ChecksRun++
                $amsiProviderPath = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
                $providerKeyExists = $false
                try { $providerKeyExists = Test-Path $amsiProviderPath -ErrorAction SilentlyContinue } catch { $providerKeyExists = $false }

                if ($providerKeyExists) {
                    $providers = @(Get-ChildItem -Path $amsiProviderPath -ErrorAction SilentlyContinue)
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.001'
                        Severity  = 'Info'
                        Evidence  = "AMSI provider registration present with $($providers.Count) provider(s) - AMSI appears registered (informational baseline)"
                        Timestamp = $null
                    }
                }
                else {
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.001'
                        Severity  = 'Info'
                        Evidence  = 'AMSI provider registry key not found - AMSI providers absent or AMSI unavailable on this host (informational baseline)'
                        Timestamp = $null
                    }
                }
                $results.CheckStatus.AmsiProviderCheck = 'OK'
            }
            catch {
                Write-Warning "Could not check AMSI provider registration: $_"
                $results.CheckStatus.AmsiProviderCheck = 'Unknown'
            }

            # 1b. AMSI bypass patterns in script-block logs
            Write-Verbose "Scanning script blocks for AMSI bypass patterns..."
            try {
                $results.Summary.ChecksRun++
                if ($results.CheckStatus.ScriptBlockLogQuery -eq 'OK') {
                    foreach ($evt in $scriptBlockEvents) {
                        $msg = Get-EventMessage -WinEvent $evt
                        if ([string]::IsNullOrEmpty($msg)) { continue }

                        foreach ($indicator in $amsiPatterns) {
                            $matched = $false
                            if ($msg -match $indicator.Pattern) {
                                if ($null -eq $indicator.Combo -or $msg -match $indicator.Combo) {
                                    $matched = $true
                                }
                            }
                            if ($matched) {
                                $results.EvasionFindings += [PSCustomObject]@{
                                    Technique = 'T1562.001'
                                    Severity  = $indicator.Severity
                                    Evidence  = "AMSI bypass indicator '$($indicator.Name)' in PowerShell script block (4104): $(Get-MessageSnippet -Message $msg)"
                                    Timestamp = Get-EventTimestamp -WinEvent $evt
                                }
                                break
                            }
                        }
                    }
                    $results.CheckStatus.AmsiPatternScan = 'OK'
                }
                else {
                    $results.CheckStatus.AmsiPatternScan = 'Unknown'
                }
            }
            catch {
                Write-Warning "Error scanning script blocks for AMSI bypass patterns: $_"
                $results.CheckStatus.AmsiPatternScan = 'Unknown'
            }

            # 2a. ETW tamper patterns in script-block logs
            Write-Verbose "Scanning script blocks for ETW tamper patterns..."
            try {
                $results.Summary.ChecksRun++
                if ($results.CheckStatus.ScriptBlockLogQuery -eq 'OK') {
                    foreach ($evt in $scriptBlockEvents) {
                        $msg = Get-EventMessage -WinEvent $evt
                        if ([string]::IsNullOrEmpty($msg)) { continue }

                        foreach ($indicator in $etwPatterns) {
                            $matched = $false
                            if ($msg -match $indicator.Pattern) {
                                if ($null -eq $indicator.Combo -or $msg -match $indicator.Combo) {
                                    $matched = $true
                                }
                            }
                            if ($matched) {
                                $results.EvasionFindings += [PSCustomObject]@{
                                    Technique = 'T1562.006'
                                    Severity  = $indicator.Severity
                                    Evidence  = "ETW tamper indicator '$($indicator.Name)' in PowerShell script block (4104): $(Get-MessageSnippet -Message $msg)"
                                    Timestamp = Get-EventTimestamp -WinEvent $evt
                                }
                                break
                            }
                        }
                    }
                    $results.CheckStatus.EtwPatternScan = 'OK'
                }
                else {
                    $results.CheckStatus.EtwPatternScan = 'Unknown'
                }
            }
            catch {
                Write-Warning "Error scanning script blocks for ETW tamper patterns: $_"
                $results.CheckStatus.EtwPatternScan = 'Unknown'
            }

            # 2b. PowerShell script-block logging GPO state (current-state check; cannot establish when it changed)
            Write-Verbose "Checking PowerShell logging GPO state..."
            try {
                $results.Summary.ChecksRun++
                $gpoPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                $gpoExists = $false
                try { $gpoExists = Test-Path $gpoPath -ErrorAction SilentlyContinue } catch { $gpoExists = $false }

                if ($gpoExists) {
                    $gpo = Get-ItemProperty -Path $gpoPath -ErrorAction SilentlyContinue
                    $sblEnabled = $null
                    if ($null -ne $gpo -and $gpo.PSObject.Properties['EnableScriptBlockLogging']) {
                        $sblEnabled = $gpo.EnableScriptBlockLogging
                    }
                    if ($null -ne $sblEnabled -and 0 -eq [int]$sblEnabled) {
                        $results.EvasionFindings += [PSCustomObject]@{
                            Technique = 'T1562.002'
                            Severity  = 'Medium'
                            Evidence  = 'PowerShell script-block logging explicitly disabled via GPO (EnableScriptBlockLogging=0) - current-state check, change time unknown'
                            Timestamp = $null
                        }
                    }
                    elseif ($null -ne $sblEnabled -and 1 -eq [int]$sblEnabled) {
                        $results.EvasionFindings += [PSCustomObject]@{
                            Technique = 'T1562.002'
                            Severity  = 'Info'
                            Evidence  = 'PowerShell script-block logging enabled via GPO (informational baseline)'
                            Timestamp = $null
                        }
                    }
                }
                else {
                    Write-Verbose "PowerShell logging GPO key not present (default state)"
                }
                $results.CheckStatus.PowerShellLoggingGpo = 'OK'
            }
            catch {
                Write-Warning "Could not check PowerShell logging GPO state: $_"
                $results.CheckStatus.PowerShellLoggingGpo = 'Unknown'
            }

            # 3a. Defender preference tampering
            Write-Verbose "Checking Windows Defender preferences..."
            try {
                $results.Summary.ChecksRun++
                $mpPref = Get-MpPreference -ErrorAction Stop
                $results.CheckStatus.DefenderPreferences = 'OK'

                $exclusionPaths = @()
                $exclusionProcesses = @()
                $exclusionExtensions = @()
                if ($null -ne $mpPref) {
                    if ($mpPref.PSObject.Properties['ExclusionPath'] -and $null -ne $mpPref.ExclusionPath) { $exclusionPaths = @($mpPref.ExclusionPath) }
                    if ($mpPref.PSObject.Properties['ExclusionProcess'] -and $null -ne $mpPref.ExclusionProcess) { $exclusionProcesses = @($mpPref.ExclusionProcess) }
                    if ($mpPref.PSObject.Properties['ExclusionExtension'] -and $null -ne $mpPref.ExclusionExtension) { $exclusionExtensions = @($mpPref.ExclusionExtension) }
                }

                $totalExclusions = $exclusionPaths.Count + $exclusionProcesses.Count + $exclusionExtensions.Count
                if ($totalExclusions -gt 0) {
                    $exclSeverity = 'Medium'
                    if ($totalExclusions -gt 3) { $exclSeverity = 'High' }

                    $evidenceParts = @()
                    if ($exclusionPaths.Count -gt 0) { $evidenceParts += "Paths: $($exclusionPaths -join ', ')" }
                    if ($exclusionProcesses.Count -gt 0) { $evidenceParts += "Processes: $($exclusionProcesses -join ', ')" }
                    if ($exclusionExtensions.Count -gt 0) { $evidenceParts += "Extensions: $($exclusionExtensions -join ', ')" }

                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.001'
                        Severity  = $exclSeverity
                        Evidence  = "Windows Defender exclusions configured ($totalExclusions total) - $($evidenceParts -join '; ')"
                        Timestamp = $null
                    }
                }

                if ($null -ne $mpPref -and $mpPref.PSObject.Properties['DisableRealtimeMonitoring'] -and $mpPref.DisableRealtimeMonitoring -eq $true) {
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.001'
                        Severity  = 'High'
                        Evidence  = 'DisableRealtimeMonitoring is set to true in Defender preferences'
                        Timestamp = $null
                    }
                }
                if ($null -ne $mpPref -and $mpPref.PSObject.Properties['DisableBehaviorMonitoring'] -and $mpPref.DisableBehaviorMonitoring -eq $true) {
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.001'
                        Severity  = 'High'
                        Evidence  = 'DisableBehaviorMonitoring is set to true in Defender preferences'
                        Timestamp = $null
                    }
                }
            }
            catch {
                Write-Warning "Could not query Windows Defender preferences: $_"
                $results.CheckStatus.DefenderPreferences = 'Unknown'
            }

            # 3b. Defender real-time protection status
            Write-Verbose "Checking Windows Defender real-time protection status..."
            try {
                $results.Summary.ChecksRun++
                $mpStatus = Get-MpComputerStatus -ErrorAction Stop
                if ($null -ne $mpStatus -and $mpStatus.PSObject.Properties['RealTimeProtectionEnabled'] -and $mpStatus.RealTimeProtectionEnabled -eq $false) {
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.001'
                        Severity  = 'High'
                        Evidence  = 'Windows Defender real-time protection is currently disabled'
                        Timestamp = $null
                    }
                }
                $results.CheckStatus.DefenderStatus = 'OK'
            }
            catch {
                Write-Warning "Could not query Windows Defender computer status: $_"
                $results.CheckStatus.DefenderStatus = 'Unknown'
            }

            # 3c. Defender Operational events 5001 (real-time protection disabled) / 5007 (configuration changed)
            Write-Verbose "Checking Defender Operational log for tampering events..."
            try {
                $results.Summary.ChecksRun++
                $defenderEvents = @(Get-WinEvent -FilterHashtable @{
                    LogName   = 'Microsoft-Windows-Windows Defender/Operational'
                    ID        = 5001, 5007
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue)

                foreach ($evt in $defenderEvents) {
                    $msg = Get-EventMessage -WinEvent $evt
                    $eventId = $null
                    if ($null -ne $evt -and $evt.PSObject.Properties['Id']) { $eventId = $evt.Id }

                    if (5001 -eq $eventId) {
                        $results.EvasionFindings += [PSCustomObject]@{
                            Technique = 'T1562.001'
                            Severity  = 'High'
                            Evidence  = "Defender event 5001 - real-time protection disabled: $(Get-MessageSnippet -Message $msg)"
                            Timestamp = Get-EventTimestamp -WinEvent $evt
                        }
                    }
                    elseif (5007 -eq $eventId) {
                        $sev = 'Medium'
                        $desc = 'Defender configuration changed'
                        $exclusionPath = $null
                        if ($null -ne $evt.PSObject.Properties['Properties'] -and $null -ne $evt.Properties) {
                            foreach ($prop in $evt.Properties) {
                                if ($null -ne $prop -and $null -ne $prop.Value -and
                                    $prop.Value -is [string] -and $prop.Value -match '(?i)\\Exclusions\\') {
                                    $exclusionPath = $prop.Value
                                    break
                                }
                            }
                        }
                        if ($null -ne $exclusionPath) {
                            $sev = 'High'
                            $desc = 'Defender exclusion changed'
                        }
                        $results.EvasionFindings += [PSCustomObject]@{
                            Technique = 'T1562.001'
                            Severity  = $sev
                            Evidence  = "Defender event 5007 - ${desc}: $(Get-MessageSnippet -Message $msg)"
                            Timestamp = Get-EventTimestamp -WinEvent $evt
                        }
                    }
                }
                $results.CheckStatus.DefenderEvents = 'OK'
            }
            catch {
                Write-Warning "Could not query Defender Operational log: $_"
                $results.CheckStatus.DefenderEvents = 'Unknown'
            }

            # 4a. Security log cleared (1102)
            Write-Verbose "Checking for Security log cleared events (1102)..."
            try {
                $results.Summary.ChecksRun++
                $clearedSecurity = @(Get-WinEvent -FilterHashtable @{
                    LogName   = 'Security'
                    ID        = 1102
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue)

                foreach ($evt in $clearedSecurity) {
                    $subjectUser = Get-EventDataValue -WinEvent $evt -Name 'SubjectUserName'
                    $subjectDomain = Get-EventDataValue -WinEvent $evt -Name 'SubjectDomainName'
                    $who = 'Unknown'
                    if (-not [string]::IsNullOrEmpty($subjectUser)) {
                        if (-not [string]::IsNullOrEmpty($subjectDomain)) { $who = "$subjectDomain\$subjectUser" }
                        else { $who = $subjectUser }
                    }
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1070.001'
                        Severity  = 'High'
                        Evidence  = "Security event log was cleared (event 1102) by '$who'"
                        Timestamp = Get-EventTimestamp -WinEvent $evt
                    }
                }
                $results.CheckStatus.SecurityLogCleared = 'OK'
            }
            catch {
                Write-Warning "Could not query Security log for 1102 events: $_"
                $results.CheckStatus.SecurityLogCleared = 'Unknown'
            }

            # 4b. System log cleared (104)
            Write-Verbose "Checking for System log cleared events (104)..."
            try {
                $results.Summary.ChecksRun++
                $clearedSystem = @(Get-WinEvent -FilterHashtable @{
                    LogName   = 'System'
                    ID        = 104
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue)

                foreach ($evt in $clearedSystem) {
                    $subjectUser = Get-EventDataValue -WinEvent $evt -Name 'SubjectUserName'
                    $subjectDomain = Get-EventDataValue -WinEvent $evt -Name 'SubjectDomainName'
                    $who = 'Unknown'
                    if (-not [string]::IsNullOrEmpty($subjectUser)) {
                        if (-not [string]::IsNullOrEmpty($subjectDomain)) { $who = "$subjectDomain\$subjectUser" }
                        else { $who = $subjectUser }
                    }
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1070.001'
                        Severity  = 'High'
                        Evidence  = "System event log was cleared (event 104) by '$who'"
                        Timestamp = Get-EventTimestamp -WinEvent $evt
                    }
                }
                $results.CheckStatus.SystemLogCleared = 'OK'
            }
            catch {
                Write-Warning "Could not query System log for 104 events: $_"
                $results.CheckStatus.SystemLogCleared = 'Unknown'
            }

            # 4c. Audit policy changed (4719)
            Write-Verbose "Checking for audit policy change events (4719)..."
            try {
                $results.Summary.ChecksRun++
                $auditChanges = @(Get-WinEvent -FilterHashtable @{
                    LogName   = 'Security'
                    ID        = 4719
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue)

                foreach ($evt in $auditChanges) {
                    $subjectUser = Get-EventDataValue -WinEvent $evt -Name 'SubjectUserName'
                    $subjectDomain = Get-EventDataValue -WinEvent $evt -Name 'SubjectDomainName'
                    $category = Get-EventDataValue -WinEvent $evt -Name 'CategoryId'
                    $who = 'Unknown'
                    if (-not [string]::IsNullOrEmpty($subjectUser)) {
                        if (-not [string]::IsNullOrEmpty($subjectDomain)) { $who = "$subjectDomain\$subjectUser" }
                        else { $who = $subjectUser }
                    }
                    $catText = 'Unknown category'
                    if (-not [string]::IsNullOrEmpty($category)) { $catText = "category $category" }
                    $results.EvasionFindings += [PSCustomObject]@{
                        Technique = 'T1562.002'
                        Severity  = 'High'
                        Evidence  = "System audit policy was changed (event 4719, $catText) by '$who'"
                        Timestamp = Get-EventTimestamp -WinEvent $evt
                    }
                }
                $results.CheckStatus.AuditPolicyChanged = 'OK'
            }
            catch {
                Write-Warning "Could not query Security log for 4719 events: $_"
                $results.CheckStatus.AuditPolicyChanged = 'Unknown'
            }

            # 5. Log-gap analysis (heuristic)
            if ($IncludeLogGapAnalysis) {
                Write-Verbose "Performing heuristic log-gap analysis..."
                $gapLogs = @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational')
                $gapStatus = 'OK'

                foreach ($logName in $gapLogs) {
                    try {
                        $results.Summary.ChecksRun++
                        $logEvents = @(Get-WinEvent -FilterHashtable @{
                            LogName   = $logName
                            StartTime = $startTime
                        } -ErrorAction SilentlyContinue)

                        $timedEvents = @($logEvents | Where-Object {
                            $null -ne $_ -and $_.PSObject.Properties['TimeCreated'] -and $null -ne $_.TimeCreated
                        })
                        if ($timedEvents.Count -lt 5) {
                            Write-Verbose "Not enough events in '$logName' for gap analysis ($($timedEvents.Count) events)"
                            continue
                        }

                        $sorted = @($timedEvents | Sort-Object -Property TimeCreated)

                        $maxGapHours = 0.0
                        $gapStart = $null
                        $gapEnd = $null
                        $gapIndex = -1
                        for ($i = 1; $i -lt $sorted.Count; $i++) {
                            $gapHours = ($sorted[$i].TimeCreated - $sorted[$i - 1].TimeCreated).TotalHours
                            if ($gapHours -gt $maxGapHours) {
                                $maxGapHours = $gapHours
                                $gapStart = $sorted[$i - 1].TimeCreated
                                $gapEnd = $sorted[$i].TimeCreated
                                $gapIndex = $i
                            }
                        }

                        $activeBefore = ($gapIndex -ge 2)
                        $activeAfter = (($sorted.Count - $gapIndex) -ge 2)

                        if ($maxGapHours -gt 2 -and $activeBefore -and $activeAfter) {
                            $results.EvasionFindings += [PSCustomObject]@{
                                Technique = 'T1070'
                                Severity  = 'Low'
                                Evidence  = "Suspicious gap (heuristic): largest gap of $([math]::Round($maxGapHours, 2)) hours with no events in '$logName' between $gapStart and $gapEnd during an otherwise-active period - may indicate log tampering or service downtime"
                                Timestamp = $gapEnd
                            }
                        }
                    }
                    catch {
                        Write-Warning "Could not perform gap analysis on '$logName': $_"
                        $gapStatus = 'Unknown'
                    }
                }
                $results.CheckStatus.LogGapAnalysis = $gapStatus
            }
        }
        catch {
            Write-Error "Error during defense-evasion scan: $_"
            throw
        }
    }

    end {
        # Summarize findings by severity
        $allFindings = @($results.EvasionFindings)
        $results.Summary.TotalFindings = $allFindings.Count
        $results.Summary.Critical = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $results.Summary.High     = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
        $results.Summary.Medium   = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        $results.Summary.Low      = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        $results.Summary.Info     = @($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count

        # Build recommendations
        $recommendations = @(
            'Enable and centrally forward PowerShell script-block logging (4104), Defender Operational, and Security/System logs to a tamper-resistant SIEM'
            'Enable Windows Defender Tamper Protection to prevent unauthorized changes to exclusions and real-time monitoring'
            'Alert on event IDs 1102 (Security log cleared), 104 (System log cleared), and 4719 (audit policy changed) as high-priority detections'
        )

        if (@($allFindings | Where-Object { $_.Technique -eq 'T1562.001' -and $_.Severity -in @('High', 'Medium') }).Count -gt 0) {
            $recommendations += 'Investigate AMSI/Defender tampering findings: review the flagged script blocks and validate every Defender exclusion against change records'
        }
        if (@($allFindings | Where-Object { $_.Technique -eq 'T1562.006' }).Count -gt 0) {
            $recommendations += 'Investigate ETW tampering indicators and consider deploying ETW-based tamper detection (e.g., monitoring for EtwEventWrite patching)'
        }
        if (@($allFindings | Where-Object { $_.Technique -eq 'T1070.001' }).Count -gt 0) {
            $recommendations += 'Treat cleared event logs as a potential intrusion in progress: identify the clearing account, review activity around the clear time, and verify log-forwarding coverage'
        }
        if (@($allFindings | Where-Object { $_.Technique -eq 'T1562.002' }).Count -gt 0) {
            $recommendations += 'Review audit policy and PowerShell logging GPO changes; re-enable logging and investigate who disabled it'
        }
        if (@($allFindings | Where-Object { $_.Technique -eq 'T1070' }).Count -gt 0) {
            $recommendations += 'Log-gap findings are heuristic only: corroborate gaps with service uptime and SIEM ingestion health before treating them as tampering'
        }
        $results.Recommendations = $recommendations

        Write-Host "`nDefense-evasion scan complete!" -ForegroundColor Green
        Write-Host "Total findings: $($results.Summary.TotalFindings)" -ForegroundColor $(if ($results.Summary.TotalFindings -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "  High:   $($results.Summary.High)" -ForegroundColor $(if ($results.Summary.High -gt 0) { 'Red' } else { 'Green' })
        Write-Host "  Medium: $($results.Summary.Medium)" -ForegroundColor $(if ($results.Summary.Medium -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "  Low:    $($results.Summary.Low)" -ForegroundColor Cyan
        Write-Host "  Info:   $($results.Summary.Info)" -ForegroundColor Cyan
        Write-Host "Checks run: $($results.Summary.ChecksRun)" -ForegroundColor Cyan

        return $results
    }
}
