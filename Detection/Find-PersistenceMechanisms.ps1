function Find-PersistenceMechanisms {
    <#
    .SYNOPSIS
        Detects common Windows persistence mechanisms used by malware
    .DESCRIPTION
        Scans Registry Run keys, Startup folder items, Scheduled Tasks, Services,
        WMI subscriptions, AppInit DLLs, LSA providers, and Print Monitors.
        Binary trust is based on Authenticode signature status (including catalog
        signatures) and location, including user-profile, AppData, and Windows
        Temp paths. Script hosts and LOLBins remain suspicious so their arguments
        can be reviewed. Findings include ResolvedPath, Reasons, Signer, and
        SignatureStatus metadata to explain the trust decision. Reasons is a
        semicolon-delimited string; Signer is the certificate simple name and
        SignatureStatus preserves the Authenticode result or an unavailable state.
    .PARAMETER IncludeKnownGood
        Include trusted persistence mechanisms with Suspicious set to false.
        Items flagged by the non-Microsoft SYSTEM task heuristic remain suspicious.
    .PARAMETER ExportPath
        Path to export detailed results
    .EXAMPLE
        Find-PersistenceMechanisms
        Find-PersistenceMechanisms -IncludeKnownGood -ExportPath "C:\Audits"
    .OUTPUTS
        PSCustomObject with detected persistence mechanisms
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeKnownGood,

        [Parameter()]
        [string]$ExportPath
    )

    begin {
        Write-Host "Scanning for persistence mechanisms..." -ForegroundColor Cyan

        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            RegistryRunKeys = @()
            StartupFolder = @()
            ScheduledTasks = @()
            Services = @()
            WMISubscriptions = @()
            AppInitDLLs = @()
            LSAProviders = @()
            PrintMonitors = @()
            TotalFindings = 0
            SuspiciousCount = 0
        }

        $signatureCache = @{}
        $registryMetadataNames = @(
            'PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive',
            'PSIsContainer', 'PSComputerName', 'PSUser', 'PSRemoteRegistry'
        )
        $shellCom = $null
        $shellComInitialized = $false
        $shellComAvailable = $false

        $getWmiReferenceInfo = {
            param([AllowNull()]$Reference)

            $name = $null
            $type = $null
            if ($Reference -is [string]) {
                $regexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
                $referenceMatch = [Text.RegularExpressions.Regex]::Match($Reference, '(?<type>[A-Za-z_][A-Za-z0-9_]*)\.Name\s*=\s*"(?<name>[^"]*)"', $regexOptions)
                if (-not $referenceMatch.Success) {
                    $referenceMatch = [Text.RegularExpressions.Regex]::Match($Reference, "(?<type>[A-Za-z_][A-Za-z0-9_]*)\.Name\s*=\s*'(?<name>[^']*)'", $regexOptions)
                }
                if ($referenceMatch.Success) {
                    $name = $referenceMatch.Groups['name'].Value
                    $type = $referenceMatch.Groups['type'].Value
                }
            }
            elseif ($null -ne $Reference) {
                if ($Reference -is [Collections.IDictionary]) {
                    if ($Reference.Contains('Name')) { $name = [string]$Reference['Name'] }
                    foreach ($propertyName in @('__CLASS', 'ClassName', 'Type', 'CimClassName')) {
                        if ($Reference.Contains($propertyName) -and $null -ne $Reference[$propertyName]) {
                            $type = [string]$Reference[$propertyName]
                            break
                        }
                    }
                    if ([string]::IsNullOrEmpty($type) -and $Reference.Contains('CimClass') -and $null -ne $Reference['CimClass']) {
                        $cimClass = $Reference['CimClass']
                        if ($cimClass -is [string]) {
                            $type = $cimClass
                        }
                        elseif ($cimClass.PSObject.Properties['CimClassName']) {
                            $type = [string]$cimClass.CimClassName
                        }
                    }
                }
                else {
                    if ($Reference.PSObject.Properties['Name']) { $name = [string]$Reference.Name }
                    foreach ($propertyName in @('__CLASS', 'ClassName', 'Type', 'CimClassName')) {
                        $typeProperty = $Reference.PSObject.Properties[$propertyName]
                        if ($null -ne $typeProperty -and $null -ne $typeProperty.Value) {
                            $type = [string]$typeProperty.Value
                            break
                        }
                    }
                    if ([string]::IsNullOrEmpty($type) -and $Reference.PSObject.Properties['CimClass'] -and $null -ne $Reference.CimClass) {
                        $cimClass = $Reference.CimClass
                        if ($cimClass -is [string]) {
                            $type = $cimClass
                        }
                        elseif ($cimClass.PSObject.Properties['CimClassName']) {
                            $type = [string]$cimClass.CimClassName
                        }
                    }
                }
            }

            return [PSCustomObject]@{
                Name = $name
                Type = $type
                HasTypeInformation = (-not [string]::IsNullOrWhiteSpace($type))
            }
        }
    }

    process {
        try {
            # 1. Registry Run Keys
            Write-Verbose "Checking Registry Run keys..."
            $runKeyPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            )

            foreach ($keyPath in $runKeyPaths) {
                if (Test-Path $keyPath) {
                    $items = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                    if ($items) {
                        foreach ($property in $items.PSObject.Properties) {
                            if ($registryMetadataNames -contains $property.Name) { continue }
                            $trust = Test-WsaTrustedBinary -CommandLine ([string]$property.Value) -SignatureCache $signatureCache
                            $isSuspicious = -not $trust.Trusted

                            if ($isSuspicious -or $IncludeKnownGood) {
                                $results.RegistryRunKeys += [PSCustomObject]@{
                                    Location = $keyPath
                                    Name = $property.Name
                                    Value = $property.Value
                                    ResolvedPath = $trust.ResolvedPath
                                    Signer = $trust.Signer
                                    SignatureStatus = $trust.SignatureStatus
                                    Reasons = (@($trust.Reasons) -join '; ')
                                    Suspicious = $isSuspicious
                                }
                            }
                        }
                    }
                }
            }

            # 2. Startup Folders
            Write-Verbose "Checking Startup folders..."
            $startupPaths = @(
                "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            )

            foreach ($path in $startupPaths) {
                if (Test-Path $path) {
                    $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        if ($null -eq $item) { continue }
                        if ($item.PSObject.Properties['PSIsContainer'] -and $item.PSIsContainer) { continue }
                        if ($item.Name.Equals('desktop.ini', [StringComparison]::OrdinalIgnoreCase)) { continue }

                        $target = 'N/A'
                        $targetArguments = $null
                        $trust = $null
                        if ($item.Name.EndsWith('.lnk', [StringComparison]::OrdinalIgnoreCase)) {
                            $shortcutTarget = $null
                            $shortcutResolved = $false
                            if (-not $shellComInitialized) {
                                $shellComInitialized = $true
                                try {
                                    $shellCom = New-Object -ComObject WScript.Shell -ErrorAction Stop
                                    $shellComAvailable = $true
                                }
                                catch {
                                    Write-Verbose "WScript.Shell COM unavailable; startup shortcuts will have unresolved targets"
                                }
                            }

                            if ($shellComAvailable) {
                                try {
                                    $shortcut = $shellCom.CreateShortcut($item.FullName)
                                    if ($null -ne $shortcut -and $shortcut.PSObject.Properties['TargetPath']) {
                                        $shortcutTarget = $shortcut.TargetPath
                                    }
                                    if ($null -ne $shortcut -and $shortcut.PSObject.Properties['Arguments']) {
                                        $targetArguments = $shortcut.Arguments
                                    }
                                    if (-not [string]::IsNullOrWhiteSpace([string]$shortcutTarget)) {
                                        $shortcutResolved = $true
                                    }
                                }
                                catch {
                                    Write-Verbose "Could not resolve startup shortcut $($item.FullName): $($_.Exception.Message)"
                                }
                            }

                            if ($shortcutResolved) {
                                $target = $shortcutTarget
                                $shortcutCommand = [string]$shortcutTarget
                                if ($shortcutCommand.IndexOfAny([char[]]@(' ', "`t")) -ge 0 -and -not $shortcutCommand.StartsWith('"', [StringComparison]::Ordinal)) {
                                    $shortcutCommand = '"' + $shortcutCommand + '"'
                                }
                                if (-not [string]::IsNullOrEmpty([string]$targetArguments)) {
                                    $shortcutCommand += ' ' + [string]$targetArguments
                                }
                                $trust = Test-WsaTrustedBinary -CommandLine $shortcutCommand -SignatureCache $signatureCache
                            }
                            else {
                                $trust = [PSCustomObject]@{
                                    ResolvedPath = $null
                                    Exists = $false
                                    SignatureStatus = 'Unknown'
                                    Signer = 'N/A'
                                    UserWritable = $false
                                    Trusted = $false
                                    Reasons = 'Unable to resolve shortcut target'
                                }
                            }
                        }
                        else {
                            if ($item.PSObject.Properties['LinkType'] -and $item.LinkType -eq 'SymbolicLink' -and $item.PSObject.Properties['Target']) {
                                $target = $item.Target
                            }
                            $trust = Test-WsaTrustedBinary -CommandLine ([string]$item.FullName) -SignatureCache $signatureCache
                        }

                        if ($item.Name.EndsWith('.lnk', [StringComparison]::OrdinalIgnoreCase) -and
                            [string]::IsNullOrEmpty([string]$trust.ResolvedPath) -and
                            @($trust.Reasons) -notcontains 'Unable to resolve shortcut target') {
                            $trust.Reasons = (@($trust.Reasons) + 'Unable to resolve shortcut target') -join '; '
                        }
                        $isSuspicious = -not $trust.Trusted
                        if ($isSuspicious -or $IncludeKnownGood) {
                            $creationTime = $null
                            if ($item.PSObject.Properties['CreationTime']) { $creationTime = $item.CreationTime }
                            $results.StartupFolder += [PSCustomObject]@{
                                Location = $path
                                Name = $item.Name
                                FullPath = $item.FullName
                                Target = $target
                                TargetArguments = $targetArguments
                                CreationTime = $creationTime
                                ResolvedPath = $trust.ResolvedPath
                                Signer = $trust.Signer
                                SignatureStatus = $trust.SignatureStatus
                                Reasons = (@($trust.Reasons) -join '; ')
                                Suspicious = $isSuspicious
                            }
                        }
                    }
                }
            }

            # 3. Scheduled Tasks
            Write-Verbose "Checking Scheduled Tasks..."
            $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                $null -ne $_ -and $_.PSObject.Properties['State'] -and $_.State -ne 'Disabled'
            })

            foreach ($task in $tasks) {
                try {
                    $taskName = [string]$task.TaskName
                    $taskPath = if ($task.PSObject.Properties['TaskPath']) { [string]$task.TaskPath } else { '' }
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                    $taskActions = if ($task.PSObject.Properties['Actions']) { @($task.Actions) } else { @() }
                    $actionChecks = @()
                    $actionDescriptions = @()
                    $taskReasons = @()
                    $isSuspicious = $false

                    $runAsUser = 'N/A'
                    if ($task.PSObject.Properties['Principal'] -and $null -ne $task.Principal -and $task.Principal.PSObject.Properties['UserId']) {
                        $runAsUser = [string]$task.Principal.UserId
                    }
                    $isSystem = $false
                    foreach ($systemIdentity in @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')) {
                        if ($runAsUser.Equals($systemIdentity, [StringComparison]::OrdinalIgnoreCase)) {
                            $isSystem = $true
                            break
                        }
                    }
                    if ($isSystem -and $taskPath -notmatch '\\Microsoft\\') {
                        $isSuspicious = $true
                        $taskReasons += 'Non-Microsoft task running as SYSTEM'
                    }

                    foreach ($action in $taskActions) {
                        if ($null -eq $action -or -not $action.PSObject.Properties['Execute']) {
                            $isSuspicious = $true
                            $unevaluatedReason = 'Non-Exec task action could not be evaluated'
                            if ($taskReasons -notcontains $unevaluatedReason) { $taskReasons += $unevaluatedReason }
                            $actionDescriptions += 'Non-Exec action (not evaluated)'
                            $actionChecks += [PSCustomObject]@{
                                Action = 'Non-Exec action (not evaluated)'
                                Execute = $null
                                Arguments = $null
                                ResolvedPath = $null
                                Exists = $false
                                Signer = 'N/A'
                                SignatureStatus = 'NotEvaluated'
                                UserWritable = $false
                                Trusted = $false
                                Reasons = $unevaluatedReason
                            }
                            continue
                        }
                        $execute = [string]$action.Execute
                        $arguments = ''
                        if ($action.PSObject.Properties['Arguments'] -and $null -ne $action.Arguments) {
                            $arguments = [string]$action.Arguments
                        }

                        $actionCommand = $execute
                        if (-not [string]::IsNullOrEmpty($arguments)) {
                            if ($actionCommand.Length -gt 0) { $actionCommand += ' ' }
                            $actionCommand += $arguments
                        }
                        $actionDescriptions += $actionCommand

                        $commandToEvaluate = if ([string]::IsNullOrWhiteSpace($execute)) { $null } else { $actionCommand }
                        $trust = Test-WsaTrustedBinary -CommandLine $commandToEvaluate -SignatureCache $signatureCache
                        if (-not $trust.Trusted) { $isSuspicious = $true }
                        foreach ($reason in @($trust.Reasons)) {
                            if ($taskReasons -notcontains $reason) { $taskReasons += $reason }
                        }

                        $actionChecks += [PSCustomObject]@{
                            Action = $actionCommand
                            Execute = $execute
                            Arguments = $arguments
                            ResolvedPath = $trust.ResolvedPath
                            Exists = $trust.Exists
                            Signer = $trust.Signer
                            SignatureStatus = $trust.SignatureStatus
                            UserWritable = $trust.UserWritable
                            Trusted = $trust.Trusted
                            Reasons = (@($trust.Reasons) -join '; ')
                        }
                    }

                    if ($actionChecks.Count -eq 0) {
                        $isSuspicious = $true
                        $taskReasons += 'No executable action could be evaluated'
                    }

                    if ($isSuspicious -or $IncludeKnownGood) {
                        $lastRunTime = 'Never'
                        if ($null -ne $taskInfo -and $taskInfo.PSObject.Properties['LastRunTime'] -and $taskInfo.LastRunTime) {
                            $lastRunTime = $taskInfo.LastRunTime
                        }
                        $nextRunTime = 'Not scheduled'
                        if ($null -ne $taskInfo -and $taskInfo.PSObject.Properties['NextRunTime'] -and $taskInfo.NextRunTime) {
                            $nextRunTime = $taskInfo.NextRunTime
                        }

                        $results.ScheduledTasks += [PSCustomObject]@{
                            Name = $task.TaskName
                            Path = $taskPath
                            State = $task.State
                            Actions = if ($actionDescriptions.Count -gt 0) { ($actionDescriptions -join '; ') } else { 'N/A' }
                            RunAsUser = $runAsUser
                            LastRunTime = $lastRunTime
                            NextRunTime = $nextRunTime
                            ResolvedPath = if ($actionChecks.Count -gt 0) { ($actionChecks.ResolvedPath -join '; ') } else { 'N/A' }
                            Signer = if ($actionChecks.Count -gt 0) { ($actionChecks.Signer -join '; ') } else { 'N/A' }
                            SignatureStatus = if ($actionChecks.Count -gt 0) { ($actionChecks.SignatureStatus -join '; ') } else { 'NotEvaluated' }
                            Reasons = ($taskReasons -join '; ')
                            ActionChecks = @($actionChecks)
                            Suspicious = $isSuspicious
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not process task: $($task.TaskName)"
                }
            }

            # 4. Services
            Write-Verbose "Checking Services..."
            $services = @(Get-CimInstance -ClassName Win32_Service)

            foreach ($service in $services) {
                if ($null -eq $service) { continue }
                if ($service.PSObject.Properties['StartMode'] -and $service.StartMode -eq 'Disabled') { continue }

                $servicePath = $null
                if ($service.PSObject.Properties['PathName']) { $servicePath = $service.PathName }
                $expandedServicePath = if ([string]::IsNullOrWhiteSpace([string]$servicePath)) { '' } else { [Environment]::ExpandEnvironmentVariables([string]$servicePath) }
                $serviceCandidates = @($servicePath)
                $isSuspicious = $false
                $serviceReasons = @()
                if (-not $expandedServicePath.StartsWith('"', [StringComparison]::Ordinal) -and
                    $expandedServicePath -match '^[A-Za-z]:\\[^\\]+\s') {
                    $isSuspicious = $true
                    $serviceReasons += 'Unquoted service path contains spaces; ambiguous executable resolution'
                    $prefixCandidate = $expandedServicePath.Substring(0, 3) + (@($expandedServicePath.Substring(3) -split '\s+')[0]) + '.exe'
                    $serviceCandidates = @($prefixCandidate, $servicePath)
                }

                $serviceChecks = @()
                foreach ($candidate in $serviceCandidates) {
                    $trust = Test-WsaTrustedBinary -CommandLine ([string]$candidate) -SignatureCache $signatureCache
                    $serviceChecks += $trust
                    if (-not $trust.Trusted) { $isSuspicious = $true }
                    foreach ($reason in @($trust.Reasons)) {
                        if ($serviceReasons -notcontains $reason) { $serviceReasons += $reason }
                    }
                }
                if ([string]::IsNullOrWhiteSpace([string]$servicePath)) {
                    $serviceReasons = @('Service PathName is null or empty; service path was not provided') + $serviceReasons
                }

                if ($isSuspicious -or $IncludeKnownGood) {
                    $resolvedPaths = @($serviceChecks.ResolvedPath | Where-Object { $_ } | Select-Object -Unique)
                    $signers = @($serviceChecks.Signer | Where-Object { $_ -and $_ -ne 'N/A' } | Select-Object -Unique)
                    $signatureStatuses = @($serviceChecks.SignatureStatus | Select-Object -Unique)
                    $results.Services += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        PathName = $servicePath
                        StartMode = $service.StartMode
                        State = $service.State
                        StartName = $service.StartName
                        ResolvedPath = if ($resolvedPaths.Count -gt 0) { ($resolvedPaths -join '; ') } else { 'N/A' }
                        Signer = if ($signers.Count -gt 0) { ($signers -join '; ') } else { 'N/A' }
                        SignatureStatus = if ($signatureStatuses.Count -gt 0) { ($signatureStatuses -join '; ') } else { 'Unknown' }
                        Reasons = ($serviceReasons -join '; ')
                        BinaryChecks = @($serviceChecks)
                        Suspicious = $isSuspicious
                    }
                }
            }

            # 5. WMI Event Subscriptions
            Write-Verbose "Checking WMI Event Subscriptions..."
            try {
                $wmiBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)

                foreach ($binding in $wmiBindings) {
                    if ($null -eq $binding) { continue }
                    $filterReference = if ($binding.PSObject.Properties['Filter']) { $binding.Filter } else { $null }
                    $consumerReference = if ($binding.PSObject.Properties['Consumer']) { $binding.Consumer } else { $null }
                    $filterInfo = & $getWmiReferenceInfo $filterReference
                    $consumerInfo = & $getWmiReferenceInfo $consumerReference

                    $defaultNames = [string]::Equals($filterInfo.Name, 'SCM Event Log Filter', [StringComparison]::OrdinalIgnoreCase) -and
                        [string]::Equals($consumerInfo.Name, 'SCM Event Log Consumer', [StringComparison]::OrdinalIgnoreCase)
                    $filterTypeValid = $filterInfo.HasTypeInformation -and
                        [string]::Equals($filterInfo.Type, '__EventFilter', [StringComparison]::OrdinalIgnoreCase)
                    $consumerTypeValid = $consumerInfo.HasTypeInformation -and
                        [string]::Equals($consumerInfo.Type, 'NTEventLogEventConsumer', [StringComparison]::OrdinalIgnoreCase)
                    $isSuspicious = -not ($defaultNames -and $filterTypeValid -and $consumerTypeValid)
                    $reasons = @()
                    if (-not $defaultNames) { $reasons += 'Non-default WMI filter or consumer' }
                    if (-not $filterTypeValid) { $reasons += 'Unexpected WMI filter type' }
                    if (-not $consumerTypeValid) { $reasons += 'WMI consumer type is not NTEventLogEventConsumer' }

                    if ($isSuspicious -or $IncludeKnownGood) {
                        $results.WMISubscriptions += [PSCustomObject]@{
                            Filter = $filterReference
                            Consumer = $consumerReference
                            ResolvedPath = 'N/A'
                            Signer = 'N/A'
                            SignatureStatus = 'N/A'
                            Reasons = ($reasons -join '; ')
                            Suspicious = $isSuspicious
                        }
                    }
                }
            }
            catch {
                Write-Warning "Could not check WMI subscriptions: $_"
            }

            # 6. AppInit DLLs
            Write-Verbose "Checking AppInit DLLs..."
            $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            if (Test-Path $appInitPath) {
                $appInit = Get-ItemProperty -Path $appInitPath -ErrorAction SilentlyContinue
                if ($appInit -and $appInit.PSObject.Properties['AppInit_DLLs'] -and $appInit.AppInit_DLLs) {
                    $appInitText = ([string]$appInit.AppInit_DLLs).Trim()
                    $appInitEntries = @()
                    $quotedEntries = [Text.RegularExpressions.Regex]::Matches($appInitText, '"([^"]+)"')
                    if ($quotedEntries.Count -gt 0) {
                        foreach ($entry in $quotedEntries) {
                            if (-not [string]::IsNullOrWhiteSpace($entry.Groups[1].Value)) {
                                $appInitEntries += $entry.Groups[1].Value
                            }
                        }
                        $appInitText = [Text.RegularExpressions.Regex]::Replace($appInitText, '"[^"]*"', ' ')
                    }
                    elseif ($appInitText.Contains(',')) {
                        $appInitEntries += @($appInitText -split '[\s,]+' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                        $appInitText = ''
                    }
                    else {
                        $extensionPattern = '\.(?:exe|dll|sys|com|scr|cpl|ocx|bat|cmd|ps1|vbs|js|jse|wsf|hta)(?=$|\s)'
                        $regexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
                        if ([Text.RegularExpressions.Regex]::Matches($appInitText, $extensionPattern, $regexOptions).Count -le 1) {
                            $appInitEntries += $appInitText
                        }
                    }
                    if ($quotedEntries.Count -gt 0 -or $appInitEntries.Count -eq 0) {
                        $appInitEntries += @($appInitText -split '[\s,]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    }

                    $appInitChecks = @()
                    $appInitReasons = @()
                    $isSuspicious = $false
                    foreach ($entry in $appInitEntries) {
                        $trust = Test-WsaTrustedBinary -CommandLine ([string]$entry) -SignatureCache $signatureCache
                        $appInitChecks += $trust
                        if (-not $trust.Trusted) { $isSuspicious = $true }
                        foreach ($reason in @($trust.Reasons)) {
                            if ($appInitReasons -notcontains $reason) { $appInitReasons += $reason }
                        }
                    }
                    if ($appInitChecks.Count -eq 0) {
                        $isSuspicious = $true
                        $appInitReasons += 'Unable to resolve AppInit DLL entries'
                    }

                    if ($isSuspicious -or $IncludeKnownGood) {
                        $resolvedPaths = if ($appInitChecks.Count -gt 0) { ($appInitChecks.ResolvedPath -join '; ') } else { 'N/A' }
                        $signers = @($appInitChecks.Signer | Where-Object { $_ -and $_ -ne 'N/A' } | Select-Object -Unique)
                        $signatureStatuses = @($appInitChecks.SignatureStatus | Select-Object -Unique)
                        $results.AppInitDLLs += [PSCustomObject]@{
                            Value = $appInit.AppInit_DLLs
                            LoadAppInit = if ($appInit.PSObject.Properties['LoadAppInit_DLLs']) { $appInit.LoadAppInit_DLLs } else { 'N/A' }
                            ResolvedPath = $resolvedPaths
                            Signer = if ($signers.Count -gt 0) { ($signers -join '; ') } else { 'N/A' }
                            SignatureStatus = if ($signatureStatuses.Count -gt 0) { ($signatureStatuses -join '; ') } else { 'Unknown' }
                            Reasons = ($appInitReasons -join '; ')
                            BinaryChecks = @($appInitChecks)
                            Suspicious = $isSuspicious
                        }
                    }
                }
            }

            # 7. LSA Authentication Packages
            Write-Verbose "Checking LSA providers..."
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (Test-Path $lsaPath) {
                $lsa = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue

                if ($lsa -and $lsa.PSObject.Properties['Authentication Packages'] -and $lsa.'Authentication Packages') {
                    foreach ($pkg in @($lsa.'Authentication Packages')) {
                        $trust = Test-WsaTrustedBinary -CommandLine ([string]$pkg) -SignatureCache $signatureCache -AppendDll
                        $isSuspicious = -not $trust.Trusted
                        if ($isSuspicious -or $IncludeKnownGood) {
                            $results.LSAProviders += [PSCustomObject]@{
                                Type = "Authentication Package"
                                Value = $pkg
                                ResolvedPath = $trust.ResolvedPath
                                Signer = $trust.Signer
                                SignatureStatus = $trust.SignatureStatus
                                Reasons = (@($trust.Reasons) -join '; ')
                                Suspicious = $isSuspicious
                            }
                        }
                    }
                }

                if ($lsa -and $lsa.PSObject.Properties['Notification Packages'] -and $lsa.'Notification Packages') {
                    foreach ($pkg in @($lsa.'Notification Packages')) {
                        $trust = Test-WsaTrustedBinary -CommandLine ([string]$pkg) -SignatureCache $signatureCache -AppendDll
                        $isSuspicious = -not $trust.Trusted
                        if ($isSuspicious -or $IncludeKnownGood) {
                            $results.LSAProviders += [PSCustomObject]@{
                                Type = "Notification Package"
                                Value = $pkg
                                ResolvedPath = $trust.ResolvedPath
                                Signer = $trust.Signer
                                SignatureStatus = $trust.SignatureStatus
                                Reasons = (@($trust.Reasons) -join '; ')
                                Suspicious = $isSuspicious
                            }
                        }
                    }
                }
            }

            # 8. Print Monitors
            Write-Verbose "Checking Print Monitors..."
            $monitorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
            if (Test-Path $monitorPath) {
                $monitors = @(Get-ChildItem -Path $monitorPath -ErrorAction SilentlyContinue)
                foreach ($monitor in $monitors) {
                    if ($null -eq $monitor) { continue }
                    $monitorProps = Get-ItemProperty -Path $monitor.PSPath -ErrorAction SilentlyContinue
                    $driverValue = if ($monitorProps -and $monitorProps.PSObject.Properties['Driver']) { $monitorProps.Driver } else { $null }
                    $trust = Test-WsaTrustedBinary -CommandLine ([string]$driverValue) -SignatureCache $signatureCache
                    $isSuspicious = -not $trust.Trusted

                    if ($isSuspicious -or $IncludeKnownGood) {
                        $results.PrintMonitors += [PSCustomObject]@{
                            Name = $monitor.PSChildName
                            Driver = $driverValue
                            ResolvedPath = $trust.ResolvedPath
                            Signer = $trust.Signer
                            SignatureStatus = $trust.SignatureStatus
                            Reasons = (@($trust.Reasons) -join '; ')
                            Suspicious = $isSuspicious
                        }
                    }
                }
            }

            $collectionNames = @(
                'RegistryRunKeys', 'StartupFolder', 'ScheduledTasks', 'Services',
                'WMISubscriptions', 'AppInitDLLs', 'LSAProviders', 'PrintMonitors'
            )
            $results.TotalFindings = 0
            $results.SuspiciousCount = 0
            foreach ($collectionName in $collectionNames) {
                $results.TotalFindings += @($results.$collectionName).Count
                $results.SuspiciousCount += @($results.$collectionName | Where-Object { $_.Suspicious }).Count
            }
        }
        catch {
            Write-Error "Error during persistence scan: $_"
            throw
        }
    }

    end {
        Write-Host "`nScan complete!" -ForegroundColor Green
        Write-Host "Total findings: $($results.TotalFindings)" -ForegroundColor Yellow
        Write-Host "Suspicious items: $($results.SuspiciousCount)" -ForegroundColor $(if ($results.SuspiciousCount -gt 0) { 'Red' } else { 'Green' })

        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
            $exportFile = Join-Path -Path $ExportPath -ChildPath "PersistenceScan_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
            Write-Host "Results exported to: $exportFile" -ForegroundColor Cyan
        }

        return $results
    }
}
