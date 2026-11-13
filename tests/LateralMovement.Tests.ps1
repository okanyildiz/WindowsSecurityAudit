#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psd1"
    $script:SysmonLogName = 'Microsoft-Windows-Sysmon/Operational'
    $script:CreatedWinEventStub = $false

    # Use the same mockable function on every platform. On Windows, mocking the
    # native cmdlet by module name lets calls through to the real event logs.
    function global:Get-WinEvent { }
    $script:CreatedWinEventStub = $true

    Import-Module -Name $script:ModulePath -Force

    function New-TestEvent {
        param(
            [Parameter(Mandatory = $true)][int]$Id,
            [string]$LogName = 'Security',
            [System.Collections.IDictionary]$Data = ([ordered]@{}),
            [int]$Level = 0,
            [datetime]$TimeCreated = (Get-Date),
            [string]$ProviderName = 'TestProvider',
            [switch]$UnnamedData
        )

        $dataNodes = @()
        foreach ($key in $Data.Keys) {
            $escapedName = [System.Security.SecurityElement]::Escape([string]$key)
            $escapedValue = [System.Security.SecurityElement]::Escape([string]$Data[$key])
            if ($UnnamedData) {
                $dataNodes += "<Data>$escapedValue</Data>"
            }
            else {
                $dataNodes += "<Data Name='$escapedName'>$escapedValue</Data>"
            }
        }

        $eventXml = "<Event><System><Provider Name='$ProviderName'/><EventID>$Id</EventID><Level>$Level</Level></System><EventData>$($dataNodes -join '')</EventData></Event>"
        $properties = @(
            foreach ($value in $Data.Values) {
                [PSCustomObject]@{ Value = $value }
            }
        )
        $event = [PSCustomObject]@{
            Id = $Id
            LogName = $LogName
            Level = $Level
            TimeCreated = $TimeCreated
            ProviderName = $ProviderName
            Message = 'Fixture event'
            Properties = $properties
            EventXml = $eventXml
        }
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.EventXml }
        return $event
    }

    function New-TestTaskContent {
        param(
            [Parameter(Mandatory = $true)][string]$Author,
            [Parameter(Mandatory = $true)][string]$RunAs,
            [Parameter(Mandatory = $true)][string]$TriggerXml,
            [Parameter(Mandatory = $true)][string]$Command,
            [string]$Arguments = ''
        )

        return @"
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$Author</Author></RegistrationInfo>
  <Triggers>$TriggerXml</Triggers>
  <Principals><Principal><UserId>$RunAs</UserId></Principal></Principals>
  <Actions><Exec><Command>$Command</Command><Arguments>$Arguments</Arguments></Exec></Actions>
</Task>
"@
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
    if ($script:CreatedWinEventStub) {
        Remove-Item -Path 'Function:\global:Get-WinEvent' -ErrorAction SilentlyContinue
    }
}

Describe 'Lateral movement event-log expansion' {
    BeforeEach {
        $script:TestEvents = @()
        $script:TestQueries = @()
        $script:MissingLogs = @($script:SysmonLogName)

        Mock -ModuleName $script:ModuleName Get-WinEvent {
            param($FilterHashtable, $ListLog, $MaxEvents, $ErrorAction)

            if ($PSBoundParameters.ContainsKey('ListLog')) {
                if ($script:MissingLogs -contains [string]$ListLog) {
                    throw "Log '$ListLog' is not present"
                }
                return [PSCustomObject]@{ LogName = [string]$ListLog }
            }

            $script:TestQueries += [PSCustomObject]@{
                FilterHashtable = $FilterHashtable
                MaxEvents = $MaxEvents
                HasMaxEvents = $PSBoundParameters.ContainsKey('MaxEvents')
            }
            $filtered = @(
                $script:TestEvents | Where-Object {
                    $ids = @($FilterHashtable['Id'])
                    $_.LogName -eq [string]$FilterHashtable['LogName'] -and
                        ($ids.Count -eq 0 -or $ids -contains $_.Id)
                }
            )
            if ($PSBoundParameters.ContainsKey('MaxEvents')) {
                $filtered = @($filtered | Select-Object -First ([int]$MaxEvents))
            }
            return $filtered
        }
    }

    It 'flags a suspicious service in Temp with the standard finding shape' {
        $when = Get-Date
        $script:TestEvents = @(
            New-TestEvent -Id 7045 -LogName System -TimeCreated $when -Data ([ordered]@{
                ServiceName = 'EvilSvc'
                ImagePath = 'C:\Users\bob\AppData\Local\Temp\evil.exe'
                ServiceType = 'user mode service'
                StartType = 'auto start'
                AccountName = 'LocalSystem'
            }) -UnnamedData
        )

        $result = Find-LateralMovement -CheckServiceCreation -Days 1 -MaxEvents 100 6>$null 3>$null
        @($result.Indicators.ServiceCreation).Count | Should -Be 1
        $finding = $result.Indicators.ServiceCreation[0]
        foreach ($propertyName in @('TimeCreated', 'Source', 'Details', 'Severity', 'Technique')) {
            $finding.PSObject.Properties.Name | Should -Contain $propertyName
        }
        $finding.TimeCreated | Should -Be $when
        $finding.Technique | Should -Be 'T1543.003'
        $finding.Details | Should -Match 'Temp'
        $finding.ServiceName | Should -Be 'EvilSvc'
        $finding.AccountName | Should -Be 'LocalSystem'
        $result.Summary.TotalIndicators | Should -Be 1
        $result.SourcesChecked -join "`n" | Should -Match 'System log present'
        $serviceQueries = @(
            $script:TestQueries | Where-Object {
                $_.FilterHashtable['LogName'] -eq 'System' -and
                    @($_.FilterHashtable['Id']) -contains 7045
            }
        )
        $serviceQueries.Count | Should -Be 1
        $serviceQueries[0].FilterHashtable.ContainsKey('StartTime') | Should -BeTrue
    }

    It 'does not flag the inbox Windows Update service even under a temporary path' {
        $script:TestEvents = @(
            New-TestEvent -Id 7045 -LogName System -Data ([ordered]@{
                ServiceName = 'wuauserv'
                ImagePath = 'C:\Windows\Temp\wu-update\update.exe'
                AccountName = 'LocalSystem'
            })
        )

        $result = Find-LateralMovement -CheckServiceCreation -Days 1 6>$null 3>$null
        @($result.Indicators.ServiceCreation).Count | Should -Be 0
        $result.Summary.TotalIndicators | Should -Be 0
    }

    It 'does not treat an allowlisted service prefix as an exact name' {
        $script:TestEvents = @(
            New-TestEvent -Id 7045 -LogName System -Data ([ordered]@{
                ServiceName = 'wuauserv.evil'
                ImagePath = 'C:\Users\bob\AppData\Local\Temp\evil.exe'
                AccountName = 'LocalSystem'
            })
        )

        $result = Find-LateralMovement -CheckServiceCreation -Days 1 6>$null 3>$null
        @($result.Indicators.ServiceCreation).Count | Should -Be 1
        $result.Indicators.ServiceCreation[0].ServiceName | Should -Be 'wuauserv.evil'
        $result.Indicators.ServiceCreation[0].Reasons -join '; ' | Should -Match 'user-writable'
    }

    It 'does not allowlist high-confidence service evidence for <ServiceName>: <ImagePath>' -ForEach @(
        @{ ServiceName = 'wuauserv'; ImagePath = 'C:\Windows\System32\cmd.exe'; ExpectedReason = 'cmd.exe' },
        @{ ServiceName = 'wuauserv'; ImagePath = '"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile'; ExpectedReason = 'pwsh.exe' },
        @{ ServiceName = 'wuauserv'; ImagePath = 'C:\Windows\System32\psexec.exe'; ExpectedReason = 'psexec.exe' },
        @{ ServiceName = 'BITS'; ImagePath = '\\server\share\update.exe'; ExpectedReason = 'UNC path' }
    ) {
        $case = $_
        $script:TestEvents = @(
            New-TestEvent -Id 7045 -LogName System -Data ([ordered]@{
                ServiceName = $case.ServiceName
                ImagePath = $case.ImagePath
                AccountName = 'LocalSystem'
            })
        )

        $result = Find-LateralMovement -CheckServiceCreation -Days 1 6>$null 3>$null
        @($result.Indicators.ServiceCreation).Count | Should -Be 1
        $finding = $result.Indicators.ServiceCreation[0]
        $finding.Severity | Should -Be 'High'
        $finding.Technique | Should -Be 'T1543.003'
        $finding.Reasons -join '; ' | Should -Match ([regex]::Escape($case.ExpectedReason))
    }

    It 'flags an encoded PowerShell task and extracts XML fields by name' {
        $content = New-TestTaskContent -Author 'CONTOSO\bob' -RunAs 'S-1-5-18' `
            -TriggerXml '<LogonTrigger><Enabled>true</Enabled></LogonTrigger>' `
            -Command 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Arguments '-NoProfile -enc SQBFAFgAIAAoACcAdABlAHMAdAAnACkA'
        $script:TestEvents = @(
            New-TestEvent -Id 4698 -Data ([ordered]@{
                TaskName = '\Contoso\EncodedTask'
                TaskContent = $content
            })
        )

        $result = Find-LateralMovement -CheckScheduledTasks -Days 1 6>$null 3>$null
        @($result.Indicators.ScheduledTasks).Count | Should -Be 1
        $finding = $result.Indicators.ScheduledTasks[0]
        $finding.Technique | Should -Be 'T1053.005'
        $finding.Author | Should -Be 'CONTOSO\bob'
        $finding.RunAs | Should -Be 'S-1-5-18'
        $finding.Action | Should -Match '-enc'
        $finding.Reasons -join '; ' | Should -Match 'encoded PowerShell'
        $finding.Reasons -join '; ' | Should -Match 'logon trigger'
    }

    It 'recognizes <Option> as an encoded command for <Launcher>' -ForEach @(
        @{ Option = '-e'; Launcher = 'powershell.exe' },
        @{ Option = '-ec'; Launcher = 'pwsh.exe' },
        @{ Option = '-enc'; Launcher = 'powershell.exe' },
        @{ Option = '-encodedcommand'; Launcher = 'pwsh.exe' }
    ) {
        $case = $_
        $content = New-TestTaskContent -Author 'CONTOSO\bob' -RunAs 'CONTOSO\service' `
            -TriggerXml '<CalendarTrigger><StartBoundary>2026-01-01T01:00:00</StartBoundary></CalendarTrigger>' `
            -Command $case.Launcher -Arguments "$($case.Option) SQBFAFgA"
        $script:TestEvents = @(
            New-TestEvent -Id 4698 -Data ([ordered]@{
                TaskName = '\Contoso\ShortEncodedTask'
                TaskContent = $content
            })
        )

        $result = Find-LateralMovement -CheckScheduledTasks -Days 1 6>$null 3>$null
        @($result.Indicators.ScheduledTasks).Count | Should -Be 1
        $result.Indicators.ScheduledTasks[0].Severity | Should -Be 'High'
        $result.Indicators.ScheduledTasks[0].Technique | Should -Be 'T1053.005'
        $result.Indicators.ScheduledTasks[0].Reasons -join '; ' | Should -Match 'encoded PowerShell'
    }

    It 'does not flag a normal scheduled task' {
        $content = New-TestTaskContent -Author 'CONTOSO\operations' -RunAs 'CONTOSO\service' `
            -TriggerXml '<CalendarTrigger><StartBoundary>2026-01-01T01:00:00</StartBoundary></CalendarTrigger>' `
            -Command 'C:\Program Files\Contoso\report.exe' -Arguments '--daily'
        $script:TestEvents = @(
            New-TestEvent -Id 4702 -Data ([ordered]@{
                TaskName = '\Contoso\DailyReport'
                TaskContent = $content
            })
        )

        $result = Find-LateralMovement -CheckScheduledTasks -Days 1 6>$null 3>$null
        @($result.Indicators.ScheduledTasks).Count | Should -Be 0
        $result.Summary.TotalIndicators | Should -Be 0
    }

    It 'flags a SYSTEM task launching a user-context script at boot' {
        $content = New-TestTaskContent -Author 'CONTOSO\bob' -RunAs 'NT AUTHORITY\SYSTEM' `
            -TriggerXml '<BootTrigger><Enabled>true</Enabled></BootTrigger>' `
            -Command 'C:\Windows\System32\cmd.exe' `
            -Arguments '/c C:\Users\bob\AppData\Local\Temp\payload.ps1'
        $script:TestEvents = @(
            New-TestEvent -Id 4698 -Data ([ordered]@{
                TaskName = '\Contoso\BootScript'
                TaskContent = $content
            })
        )

        $result = Find-LateralMovement -CheckScheduledTasks -Days 1 6>$null 3>$null
        @($result.Indicators.ScheduledTasks).Count | Should -Be 1
        $result.Indicators.ScheduledTasks[0].Severity | Should -Be 'High'
        $result.Indicators.ScheduledTasks[0].Reasons -join '; ' | Should -Match 'user-context script as SYSTEM'
        $result.Indicators.ScheduledTasks[0].Reasons -join '; ' | Should -Match 'boot trigger'
    }

    It 'flags a direct SYSTEM executable under a user <Folder> folder' -ForEach @(
        @{ Folder = 'Downloads' },
        @{ Folder = 'Desktop' },
        @{ Folder = 'Documents' }
    ) {
        $folder = $_.Folder
        $content = New-TestTaskContent -Author 'CONTOSO\bob' -RunAs 'S-1-5-18' `
            -TriggerXml '<CalendarTrigger><StartBoundary>2026-01-01T01:00:00</StartBoundary></CalendarTrigger>' `
            -Command "C:\Users\bob\$folder\payload.exe"
        $script:TestEvents = @(
            New-TestEvent -Id 4698 -Data ([ordered]@{
                TaskName = '\Contoso\DirectUserExecutable'
                TaskContent = $content
            })
        )

        $result = Find-LateralMovement -CheckScheduledTasks -Days 1 6>$null 3>$null
        @($result.Indicators.ScheduledTasks).Count | Should -Be 1
        $result.Indicators.ScheduledTasks[0].Severity | Should -Be 'High'
        $result.Indicators.ScheduledTasks[0].Technique | Should -Be 'T1053.005'
        $result.Indicators.ScheduledTasks[0].Reasons -join '; ' | Should -Match 'user-profile executable as SYSTEM'
    }

    It 'flags WMI explicit-credential use' {
        $script:TestEvents = @(
            New-TestEvent -Id 4648 -Data ([ordered]@{
                SubjectUserName = 'bob'
                TargetUserName = 'admin'
                TargetServerName = 'SERVER02'
                ProcessName = 'C:\Windows\System32\wbem\wmiprvse.exe'
            })
        )

        $result = Find-LateralMovement -CheckWMI -Days 1 6>$null 3>$null
        @($result.Indicators.WMI).Count | Should -Be 1
        $finding = $result.Indicators.WMI[0]
        $finding.Technique | Should -Be 'T1047'
        $finding.EventId | Should -Be 4648
        $finding.TargetServer | Should -Be 'SERVER02'
        $finding.Severity | Should -Be 'High'
        $finding.Details | Should -Match 'Explicit|WMI'
    }

    It 'does not attribute non-WMI explicit credentials to WMI' {
        $script:TestEvents = @(
            New-TestEvent -Id 4648 -Data ([ordered]@{
                SubjectUserName = 'bob'
                TargetUserName = 'admin'
                TargetServerName = 'SERVER02'
                ProcessName = 'C:\Windows\System32\cmd.exe'
            })
        )

        $result = Find-LateralMovement -CheckWMI -Days 1 6>$null 3>$null
        @($result.Indicators.WMI).Count | Should -Be 0
        $result.Summary.TotalIndicators | Should -Be 0
    }

    It 'attributes only wmiprvse.exe Type 3 logons to WMI' {
        $commonData = [ordered]@{
            SubjectUserName = 'SYSTEM'
            TargetUserName = 'admin'
            LogonType = '3'
            IpAddress = '10.0.0.25'
        }
        $wmiData = [ordered]@{}
        foreach ($key in $commonData.Keys) { $wmiData[$key] = $commonData[$key] }
        $wmiData['ProcessName'] = 'C:\Windows\System32\wbem\wmiprvse.exe'
        $otherData = [ordered]@{}
        foreach ($key in $commonData.Keys) { $otherData[$key] = $commonData[$key] }
        $otherData['ProcessName'] = 'C:\Windows\System32\svchost.exe'
        $script:TestEvents = @(
            (New-TestEvent -Id 4624 -Data $wmiData),
            (New-TestEvent -Id 4624 -Data $otherData)
        )

        $result = Find-LateralMovement -CheckWMI -Days 1 6>$null 3>$null
        @($result.Indicators.WMI).Count | Should -Be 1
        $result.Indicators.WMI[0].EventId | Should -Be 4624
        $result.Indicators.WMI[0].SourceIP | Should -Be '10.0.0.25'
        $result.Indicators.WMI[0].Details | Should -Match 'Type 3'
    }

    It 'records Sysmon absence as an honest coverage note, not an error' {
        $result = Find-LateralMovement -CheckWMI -Days 1 6>$null 3>$null
        @($result.Indicators.WMI).Count | Should -Be 0
        $result.SourcesChecked -join "`n" | Should -Match 'Microsoft-Windows-Sysmon/Operational log unavailable'
        $result.SourcesChecked -join "`n" | Should -Match '19/20/21.*not checked'
        $result.Truncated.WMI | Should -BeFalse
    }

    It 'collects Sysmon WMI subscription events when the log exists' {
        $script:MissingLogs = @()
        $script:TestEvents = @(
            New-TestEvent -Id 20 -LogName $script:SysmonLogName -Data ([ordered]@{
                Operation = 'Created'
                Name = 'UpdaterConsumer'
                CommandLineTemplate = 'powershell.exe -enc SQBFAFgA'
            })
        )

        $result = Find-LateralMovement -CheckWMI -Days 1 6>$null 3>$null
        @($result.Indicators.WMI).Count | Should -Be 1
        $result.Indicators.WMI[0].EventId | Should -Be 20
        $result.Indicators.WMI[0].Technique | Should -Be 'T1546.003'
        $result.Indicators.WMI[0].RelatedTechnique | Should -Be 'T1546.003'
        $result.SourcesChecked -join "`n" | Should -Match 'Sysmon/Operational log present'
    }

    It 'handles a single event under module strict mode' {
        $script:TestEvents = @(
            New-TestEvent -Id 4699 -Data ([ordered]@{ TaskName = '\Contoso\DeletedTask' })
        )

        { $script:SingleEventResult = Find-LateralMovement -CheckScheduledTasks -Days 1 6>$null 3>$null } |
            Should -Not -Throw
        @($script:SingleEventResult.Indicators.ScheduledTasks).Count | Should -Be 0
        $script:SingleEventResult.Summary.TotalIndicators | Should -Be 0
    }

    It 'sets the section Truncated flag when the event cap is reached' {
        $script:TestEvents = @(
            (New-TestEvent -Id 7045 -LogName System -Data ([ordered]@{
                ServiceName = 'TempSvc1'
                ImagePath = 'C:\Temp\one.exe'
                AccountName = 'LocalSystem'
            })),
            (New-TestEvent -Id 7045 -LogName System -Data ([ordered]@{
                ServiceName = 'TempSvc2'
                ImagePath = 'C:\Temp\two.exe'
                AccountName = 'LocalSystem'
            }))
        )

        $result = Find-LateralMovement -CheckServiceCreation -Days 1 -MaxEvents 1 -WarningVariable capWarnings -WarningAction SilentlyContinue 6>$null
        @($result.Indicators.ServiceCreation).Count | Should -Be 1
        $result.Truncated.ServiceCreation | Should -BeTrue
        @($capWarnings | Where-Object { "$_" -match 'TRUNCATED' }).Count | Should -BeGreaterThan 0
        @(
            $script:TestQueries | Where-Object {
                $_.FilterHashtable['LogName'] -eq 'System' -and
                    $_.FilterHashtable['Id'] -eq 7045 -and
                    $_.HasMaxEvents -and $_.MaxEvents -eq 1
            }
        ).Count | Should -Be 1
    }
}

Describe 'Security event analysis level independence' {
    BeforeEach {
        $script:TestEvents = @()
        $script:TestQueries = @()
        $script:MissingLogs = @($script:SysmonLogName)

        Mock -ModuleName $script:ModuleName Get-WinEvent {
            param($FilterHashtable, $ListLog, $MaxEvents, $ErrorAction)
            $script:TestQueries += [PSCustomObject]@{ FilterHashtable = $FilterHashtable }
            $ids = @($FilterHashtable['Id'])
            return @(
                $script:TestEvents | Where-Object {
                    $_.LogName -eq [string]$FilterHashtable['LogName'] -and
                        ($ids.Count -eq 0 -or $ids -contains $_.Id)
                }
            )
        }
    }

    It 'includes a Security audit event with Level 0 using ID-based filtering' {
        $script:TestEvents = @(
            New-TestEvent -Id 4625 -LogName Security -Level 0 -ProviderName 'Microsoft-Windows-Security-Auditing'
        )

        $result = Get-EventLogAnalysis -Hours 1 -LogNames Security 6>$null 3>$null
        @($result.SecurityEvents).Count | Should -Be 1
        $result.SecurityEvents[0].EventId | Should -Be 4625
        $result.SecurityEvents[0].Level | Should -Be 'Unknown'
        $result.Statistics.TotalEventsAnalyzed | Should -Be 1
        $script:TestQueries.Count | Should -Be 1
        $query = $script:TestQueries[0].FilterHashtable
        $query['LogName'] | Should -Be 'Security'
        $query.ContainsKey('Id') | Should -BeTrue
        @($query['Id']) | Should -Contain 4625
        $query.ContainsKey('Level') | Should -BeFalse
    }
}

Describe 'JEA integration fail-closed regressions' {
    BeforeAll {
        $script:IntegrationScriptPath = Join-Path $script:ModuleRoot 'integration/Invoke-WindowsIntegrationChecks.ps1'
        $tokens = $null
        $parseErrors = $null
        $integrationAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:IntegrationScriptPath, [ref]$tokens, [ref]$parseErrors
        )
        if (@($parseErrors).Count -gt 0) {
            throw "Integration script parse errors: $($parseErrors -join '; ')"
        }

        $checkNames = @('JEA temporary endpoint', 'Module import and AMSI/Defender history')
        foreach ($checkName in $checkNames) {
            $definition = @(
                $integrationAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.HashtableAst]
                }, $true) | Where-Object { $_.Extent.Text -like "*Name = '$checkName'*" } |
                    Select-Object -First 1
            )[0]
            $actionPair = @($definition.KeyValuePairs | Where-Object { $_.Item1.Value -eq 'Action' })[0]
            $actionAst = $actionPair.Item2.Find({
                param($node)
                $node -is [System.Management.Automation.Language.ScriptBlockExpressionAst]
            }, $true)
            $action = $actionAst.ScriptBlock.GetScriptBlock()
            if ($checkName -eq 'JEA temporary endpoint') {
                $script:JeaIntegrationAction = $action
            }
            else {
                $script:ModuleIntegrationAction = $action
            }
        }

        $helperNames = @(
            'ConvertTo-WsaIntegrationSafeText', 'New-WsaIntegrationOutcome',
            'Get-WsaIntegrationObjectKeys', 'Invoke-WsaIntegrationCheck'
        )
        foreach ($helperName in $helperNames) {
            $functionAst = $integrationAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $helperName
            }, $true)
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }
    }

    BeforeEach {
        $script:WsaModule = Get-Module -Name $script:ModuleName | Select-Object -First 1
        $script:AvailableModule = $script:WsaModule
        $script:WsaRepositoryRoot = $script:ModuleRoot
        $script:WsaModuleImportError = $null
        $script:WsaCurrentIdentity = [PSCustomObject]@{ Name = 'CONTOSO\tester' }
        $script:EndpointQueryCalls = 0
        $script:RegistrationCalls = 0
        $script:UnregistrationCalls = 0
        $script:FailInitialEndpointQuery = $false
        $script:FailCleanupEndpointQuery = $false
        $script:JeaTestRoot = Join-Path $TestDrive 'JeaIntegration'
        [void][IO.Directory]::CreateDirectory($script:JeaTestRoot)

        function Test-WsaIntegrationWindows { $true }
        function Test-WsaIntegrationElevated { $true }
        function Get-Command {
            param($Name, $ErrorAction)
            return [PSCustomObject]@{ Parameters = @{} }
        }
        function Get-PSSessionConfiguration {
            param($Name, $ErrorAction)
            $script:EndpointQueryCalls++
            $queryFails = (
                ($script:EndpointQueryCalls -eq 1 -and $script:FailInitialEndpointQuery) -or
                ($script:EndpointQueryCalls -gt 1 -and $script:FailCleanupEndpointQuery)
            )
            if ($queryFails) {
                if ([string]$ErrorAction -eq 'Stop') {
                    $stage = if ($script:EndpointQueryCalls -eq 1) { 'initial' } else { 'cleanup' }
                    throw "$stage endpoint query failed"
                }
                return @()
            }
            return @()
        }
        function Get-Module {
            param($Name, [switch]$ListAvailable, $ErrorAction)
            return $script:AvailableModule
        }
        function Test-PSSessionConfigurationFile {
            param($Path, $ErrorAction)
            return $true
        }
        function New-WsaIntegrationTempDirectory {
            param($Purpose)
            $path = Join-Path $script:JeaTestRoot ([Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($path)
            return $path
        }
        function Register-PSSessionConfiguration {
            param($Name, $Path, $Force, $ErrorAction)
            $script:RegistrationCalls++
        }
        function New-PSSession {
            param($ComputerName, $ConfigurationName, $ErrorAction)
            return [PSCustomObject]@{ ComputerName = $ComputerName }
        }
        function Invoke-Command {
            param($Session, $ScriptBlock, $ErrorAction)
            if ($ScriptBlock.ToString() -match 'Get-Process') { throw 'Access denied by fixture' }
            return [PSCustomObject]@{
                FunctionSet = 'Quick'
                Results = [ordered]@{
                    'Get-SecurityBaseline' = [PSCustomObject]@{ Findings = @() }
                    'Get-DefenderStatus' = [PSCustomObject]@{ Findings = @() }
                }
                Errors = @()
                EffectiveLanguageMode = 'FullLanguage'
                DynamicCompilationExpected = $true
            }
        }
        function Remove-PSSession { param($Session, $ErrorAction) }
        function Unregister-PSSessionConfiguration {
            param($Name, $Force, $ErrorAction)
            $script:UnregistrationCalls++
        }
        function Get-MpThreatDetection { param($ErrorAction) return @() }
    }

    It 'returns FAIL without registration when initial endpoint enumeration fails' {
        $script:FailInitialEndpointQuery = $true
        $result = Invoke-WsaIntegrationCheck -Name 'JEA test' -Required $true -Action $script:JeaIntegrationAction

        $result.Status | Should -Be 'FAIL'
        $result.Evidence | Should -Match 'initial endpoint query failed'
        $script:EndpointQueryCalls | Should -Be 1
        $script:RegistrationCalls | Should -Be 0
        $script:UnregistrationCalls | Should -Be 0
    }

    It 'returns FAIL when post-removal endpoint verification fails' {
        $script:FailCleanupEndpointQuery = $true
        $result = Invoke-WsaIntegrationCheck -Name 'JEA test' -Required $true -Action $script:JeaIntegrationAction

        $result.Status | Should -Be 'FAIL'
        $result.Evidence | Should -Match 'JEA cleanup failed.*verification.*cleanup endpoint query failed'
        $script:EndpointQueryCalls | Should -Be 2
        $script:RegistrationCalls | Should -Be 1
        $script:UnregistrationCalls | Should -Be 1
    }

    It 'passes the JEA fixture only after successful removal verification' {
        $result = Invoke-WsaIntegrationCheck -Name 'JEA test' -Required $true -Action $script:JeaIntegrationAction

        $result.Status | Should -Be 'PASS'
        $result.Details.ArbitraryScriptBlockDenied | Should -BeTrue
        $script:EndpointQueryCalls | Should -Be 2
        $script:RegistrationCalls | Should -Be 1
        $script:UnregistrationCalls | Should -Be 1
    }

    It 'does not substitute a different installed module for the imported JEA target' {
        $script:AvailableModule = @(
            $script:WsaModule,
            [PSCustomObject]@{
                Version = [version]'99.0.0'
                ModuleBase = 'C:\DifferentModule'
            }
        )
        $result = Invoke-WsaIntegrationCheck -Name 'JEA test' -Required $true -Action $script:JeaIntegrationAction

        $result.Status | Should -Be 'UNVERIFIED'
        $result.Evidence | Should -Match 'JEA resolves version 99.0.0.*imported target'
        $script:RegistrationCalls | Should -Be 0
    }

    It 'rejects <Count> exported functions instead of accepting the old threshold' -ForEach @(
        @{ Count = 76 },
        @{ Count = 78 }
    ) {
        $count = $_.Count
        $functions = @{}
        for ($index = 0; $index -lt $count; $index++) { $functions["Function$index"] = $null }
        $script:WsaModule = [PSCustomObject]@{
            ExportedFunctions = $functions
            ModuleBase = 'C:\Module'
            Path = 'C:\Module\WindowsSecurityAudit.psd1'
            Version = [version]'1.9.1'
        }

        $result = Invoke-WsaIntegrationCheck -Name 'Module test' -Required $true -Action $script:ModuleIntegrationAction
        $result.Status | Should -Be 'FAIL'
        $result.Evidence | Should -Match 'exactly 77'
        $result.Details.ExportedFunctionCount | Should -Be $count
    }

    It 'accepts exactly 77 exports with clean Defender history' {
        $functions = @{}
        for ($index = 0; $index -lt 77; $index++) { $functions["Function$index"] = $null }
        $script:WsaModule = [PSCustomObject]@{
            ExportedFunctions = $functions
            ModuleBase = 'C:\Module'
            Path = 'C:\Module\WindowsSecurityAudit.psd1'
            Version = [version]'1.9.1'
        }

        $result = Invoke-WsaIntegrationCheck -Name 'Module test' -Required $true -Action $script:ModuleIntegrationAction
        $result.Status | Should -Be 'PASS'
        $result.Details.ExportedFunctionCount | Should -Be 77
        $result.Details.ModuleFileDetectionCount | Should -Be 0
    }
}

Describe 'Release package verification regression' {
    It 'diffs every staged file and names all PowerShell data extensions' {
        $releasePath = Join-Path $script:ModuleRoot '.kimi-code/skills/release/SKILL.md'
        $releaseSkill = Get-Content -LiteralPath $releasePath -Raw
        $releaseSkill | Should -Match 'diff every staged file'
        foreach ($extension in @('.ps1', '.psm1', '.psd1', '.pssc', '.psrc')) {
            $releaseSkill | Should -Match ([regex]::Escape($extension))
        }
    }
}
