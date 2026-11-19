#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.2.0' }

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psd1"
    $script:RunKeyPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    $script:MonitorPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $script:StartupPath = 'C:\Users\fixture\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    $script:EnvironmentNames = @(
        'APPDATA', 'COMPUTERNAME', 'LOCALAPPDATA', 'ProgramData', 'ProgramFiles',
        'ProgramFiles(x86)', 'SystemDrive', 'SystemRoot', 'USERPROFILE', 'windir'
    )
    $script:OriginalEnvironment = @{}
    foreach ($name in $script:EnvironmentNames) {
        $script:OriginalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    }

    $env:APPDATA = 'C:\Users\fixture\AppData\Roaming'
    $env:COMPUTERNAME = 'WSA-TEST'
    $env:LOCALAPPDATA = 'C:\Users\fixture\AppData\Local'
    $env:ProgramData = 'C:\ProgramData'
    $env:ProgramFiles = 'C:\Program Files'
    [Environment]::SetEnvironmentVariable('ProgramFiles(x86)', 'C:\Program Files (x86)')
    $env:SystemDrive = 'C:'
    $env:SystemRoot = 'C:\Windows'
    $env:USERPROFILE = 'C:\Users\fixture'
    $env:windir = 'C:\Windows'

    Import-Module -Name $script:ModulePath -Force

    $script:StubNames = @(
        'Get-CimInstance', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo',
        'Get-AuthenticodeSignature', 'New-Object'
    )
    InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
        function global:Get-CimInstance {
            param($ClassName, $Namespace, $Filter, $Query, $CimSession, $ErrorAction)
        }
        function global:Get-ScheduledTask {
            param($TaskName, $TaskPath, $CimSession, $ErrorAction)
        }
        function global:Get-ScheduledTaskInfo {
            param($TaskName, $TaskPath, $CimSession, $ErrorAction)
        }
        function global:Get-AuthenticodeSignature {
            param($FilePath, $LiteralPath, $Path, $Content, $Certificate, $HashAlgorithm, $IncludeChain, $ShowFullChain, $ErrorAction)
        }
        function global:New-Object {
            param($TypeName, $ComObject, $ArgumentList, $Property, $PassThru, $ErrorAction)
        }
    }

    function New-TestSignature {
        param(
            [Parameter(Mandatory = $true)][string]$Status,
            [AllowNull()][string]$SignerName,
            [string]$Path = ''
        )

        $certificate = $null
        if ($null -ne $SignerName) {
            $certificate = [PSCustomObject]@{
                SimpleName = $SignerName
                Subject = "CN=$SignerName"
                Issuer = "CN=$SignerName Test CA"
                Thumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
                NotBefore = [datetime]'2020-01-01T00:00:00Z'
                NotAfter = [datetime]'2099-01-01T00:00:00Z'
            }
            $certificate | Add-Member -MemberType ScriptMethod -Name GetNameInfo -Value {
                param($NameType, $Issuer)
                return $this.SimpleName
            }
        }

        return [PSCustomObject]@{
            Path = $Path
            Status = $Status
            StatusMessage = "Fixture signature status: $Status"
            SignerCertificate = $certificate
            TimeStamperCertificate = $null
        }
    }

    function New-TestService {
        param(
            [Parameter(Mandatory = $true)][string]$Name,
            [string]$DisplayName = $Name,
            [AllowNull()][string]$PathName,
            [string]$StartMode = 'Auto',
            [string]$State = 'Running',
            [string]$StartName = 'LocalSystem'
        )

        return [PSCustomObject]@{
            Name = $Name
            DisplayName = $DisplayName
            PathName = $PathName
            StartMode = $StartMode
            State = $State
            StartName = $StartName
            ServiceType = 'Own Process'
            ProcessId = 1234
            AcceptStop = $true
            AcceptPause = $false
            Description = "Fixture service $DisplayName"
        }
    }

    function New-TestTask {
        param(
            [Parameter(Mandatory = $true)][string]$TaskName,
            [Parameter(Mandatory = $true)][string]$TaskPath,
            [Parameter(Mandatory = $true)][string]$Execute,
            [string]$Arguments = '',
            [string]$State = 'Ready',
            [string]$UserId = 'CONTOSO\operator'
        )

        $action = [PSCustomObject]@{
            Execute = $Execute
            Arguments = $Arguments
            WorkingDirectory = 'C:\Windows\System32'
        }
        $principal = [PSCustomObject]@{
            UserId = $UserId
            GroupId = $null
            DisplayName = $UserId
            LogonType = 'S4U'
            RunLevel = 'LeastPrivilege'
            Enabled = $true
        }
        $trigger = [PSCustomObject]@{
            Enabled = $true
            StartBoundary = '2099-01-01T00:00:00Z'
            EndBoundary = '2099-12-31T00:00:00Z'
        }

        return [PSCustomObject]@{
            TaskName = $TaskName
            TaskPath = $TaskPath
            State = $State
            Actions = @($action)
            Principal = $principal
            Triggers = @($trigger)
            Author = 'CONTOSO\fixture-author'
            Description = 'Deterministic scheduled task fixture'
            URI = "$TaskPath$TaskName"
            Version = '1.0'
            Date = '2099-01-01T00:00:00Z'
        }
    }

    function New-TestTaskInfo {
        param(
            [Parameter(Mandatory = $true)][datetime]$LastRunTime,
            [Parameter(Mandatory = $true)][datetime]$NextRunTime,
            [int]$LastTaskResult = 0
        )

        return [PSCustomObject]@{
            LastRunTime = $LastRunTime
            NextRunTime = $NextRunTime
            LastTaskResult = $LastTaskResult
            NumberOfMissedRuns = 0
            TaskName = ''
            TaskPath = ''
        }
    }

    function New-TestMonitor {
        param(
            [Parameter(Mandatory = $true)][string]$Name,
            [Parameter(Mandatory = $true)][string]$Driver
        )

        $monitorKeyPath = "$($script:MonitorPath)\$Name"
        $script:RegistryValues[$monitorKeyPath] = [PSCustomObject]@{
            Driver = $Driver
        }
        return [PSCustomObject]@{
            PSChildName = $Name
            PSPath = $monitorKeyPath
            PSParentPath = $script:MonitorPath
            Name = $Name
            Driver = $Driver
        }
    }

    function New-TestStartupItem {
        param(
            [Parameter(Mandatory = $true)][string]$Name
        )

        return [PSCustomObject]@{
            Name = $Name
            FullName = "$($script:StartupPath)\$Name"
            Extension = [IO.Path]::GetExtension($Name)
            LinkType = $null
            Target = $null
            CreationTime = [datetime]'2099-01-01T00:00:00Z'
            LastWriteTime = [datetime]'2099-01-01T00:00:00Z'
            Length = 1024
            Attributes = 'Archive'
            PSIsContainer = $false
        }
    }

    function Reset-TestPersistenceFixture {
        $script:RegistryValues = @{}
        $script:DirectoryItems = @{}
        $script:PathExistence = @{}
        $script:Signatures = @{}
        $script:SignatureCalls = @()
        $script:ShortcutTargets = @{}
        $script:ComObjectCalls = @()
        $script:TestTasks = @()
        $script:TaskInfo = @{}
        $script:TaskInfoCalls = @()
        $script:TestServices = @()
        $script:WmiFilters = @()
        $script:WmiConsumers = @()
        $script:WmiBindings = @()
    }

    function Set-TestRunValues {
        param(
            [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Values,
            [string]$Path = $script:RunKeyPath
        )

        $script:RegistryValues[$Path] = [PSCustomObject]$Values
        $script:PathExistence[$Path] = $true
    }

    function Add-TestBinary {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [string]$Status = 'Valid',
            [AllowNull()][string]$SignerName = 'Microsoft Windows',
            [bool]$Exists = $true
        )

        if ($Exists) {
            $script:PathExistence[$Path] = $true
        }
        else {
            $script:PathExistence.Remove($Path)
        }
        $script:Signatures[$Path] = New-TestSignature -Status $Status -SignerName $SignerName -Path $Path
    }

    function Get-TestTaskKey {
        param(
            [Parameter(Mandatory = $true)][string]$TaskName,
            [Parameter(Mandatory = $true)][string]$TaskPath
        )
        return "$TaskPath$TaskName"
    }

    function Get-TestPersistenceFindings {
        param([Parameter(Mandatory = $true)]$Result)

        $items = @()
        foreach ($propertyName in @(
            'RegistryRunKeys', 'StartupFolder', 'ScheduledTasks', 'Services',
            'WMISubscriptions', 'AppInitDLLs', 'LSAProviders', 'PrintMonitors'
        )) {
            $items += @($Result.$propertyName)
        }
        return @($items)
    }

    function Assert-TestPersistenceFindingShape {
        param([Parameter(Mandatory = $true)]$Finding)

        foreach ($propertyName in @('ResolvedPath', 'Signer', 'SignatureStatus', 'Reasons', 'Suspicious')) {
            $Finding.PSObject.Properties.Name | Should -Contain $propertyName
        }
    }

    function Initialize-TestReportedRegression {
        $securityHealthPath = 'C:\Windows\System32\SecurityHealthSystray.exe'
        $realtekPath = 'C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe'
        $arkSignerPath = 'C:\Users\fixture\AppData\Local\ArkSigner\ArkSignerService.exe'
        $javaPath = 'C:\Program Files\Java\jre1.8.0_451\bin\jusched.exe'
        Set-TestRunValues -Values ([ordered]@{
            SecurityHealth = '%windir%\System32\SecurityHealthSystray.exe'
            RtkAudUService = '"C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe" -background'
            ArkSigner = '"C:\Users\fixture\AppData\Local\ArkSigner\ArkSignerService.exe" --service'
            Java = '"C:\Program Files\Java\jre1.8.0_451\bin\jusched.exe"'
        })
        Add-TestBinary -Path $securityHealthPath -SignerName 'Microsoft Windows'
        Add-TestBinary -Path $realtekPath -SignerName 'Realtek Semiconductor'
        Add-TestBinary -Path $arkSignerPath -SignerName 'ArkSigner'
        Add-TestBinary -Path $javaPath -SignerName 'Oracle Corporation'

        $mdCorePath = 'C:\Program Files\Microsoft Defender Core\MpDefenderCoreService.exe'
        $winDefenderPath = 'C:\Program Files\Windows Defender\MsMpEng.exe'
        $intelXtuPath = 'C:\Program Files\Intel\Intel(R) Extreme Tuning Utility\XtuService.exe'
        $script:TestServices = @(
            (New-TestService -Name 'MDCoreSvc' -DisplayName 'Microsoft Defender Core Service' -PathName "`"$mdCorePath`""),
            (New-TestService -Name 'WinDefend' -DisplayName 'Windows Defender' -PathName "`"$winDefenderPath`""),
            (New-TestService -Name 'XTU3SERVICE' -DisplayName 'Intel Extreme Tuning Utility' -PathName "`"$intelXtuPath`"")
        )
        Add-TestBinary -Path $mdCorePath -SignerName 'Microsoft Windows'
        Add-TestBinary -Path $winDefenderPath -SignerName 'Microsoft Windows'
        Add-TestBinary -Path $intelXtuPath -SignerName 'Intel Corporation'

        $script:WmiFilters = @([PSCustomObject]@{
            Name = 'SCM Event Log Filter'
            EventNamespace = 'root\cimv2'
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Service'"
            QueryLanguage = 'WQL'
        })
        $script:WmiConsumers = @([PSCustomObject]@{
            Name = 'SCM Event Log Consumer'
            EventType = 2
            Category = 0
            SourceName = 'Service Control Manager'
        })
        $script:WmiBindings = @([PSCustomObject]@{
            Filter = '__EventFilter.Name="SCM Event Log Filter"'
            Consumer = 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"'
        })

        $monitors = @(
            (New-TestMonitor -Name 'Local Port' -Driver 'localspl.dll'),
            (New-TestMonitor -Name 'Standard TCP/IP Port' -Driver 'tcpmon.dll'),
            (New-TestMonitor -Name 'USB Monitor' -Driver 'usbmon.dll'),
            (New-TestMonitor -Name 'AppMon' -Driver 'AppMon.dll'),
            (New-TestMonitor -Name 'WSD Port' -Driver 'WSDMon.dll'),
            (New-TestMonitor -Name 'Microsoft Shared Fax Monitor' -Driver 'FXSMON.dll')
        )
        $script:DirectoryItems[$script:MonitorPath] = @($monitors)
        $script:PathExistence[$script:MonitorPath] = $true
        foreach ($driver in @('localspl.dll', 'tcpmon.dll', 'usbmon.dll', 'AppMon.dll', 'WSDMon.dll', 'FXSMON.dll')) {
            Add-TestBinary -Path "C:\Windows\System32\$driver" -SignerName 'Microsoft Windows'
        }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
    foreach ($name in $script:EnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $script:OriginalEnvironment[$name])
    }
    foreach ($name in $script:StubNames) {
        Remove-Item -Path "Function:\global:$name" -ErrorAction SilentlyContinue
    }
}

Describe 'Persistence mechanism signature trust and parsing' {
    BeforeEach {
        Reset-TestPersistenceFixture

        Mock -ModuleName $script:ModuleName Test-Path {
            param($Path, $LiteralPath, $Filter, $Include, $Exclude, $PathType, $IsValid, $ErrorAction)
            $requestedPath = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                [string]$LiteralPath
            }
            else {
                [string]$Path
            }
            return $script:PathExistence.ContainsKey($requestedPath)
        }

        Mock -ModuleName $script:ModuleName Get-ItemProperty {
            param($Path, $LiteralPath, $Name, $ErrorAction)
            $requestedPath = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                [string]$LiteralPath
            }
            else {
                [string]$Path
            }
            if ($script:RegistryValues.ContainsKey($requestedPath)) {
                return $script:RegistryValues[$requestedPath]
            }
            return $null
        }

        Mock -ModuleName $script:ModuleName Get-CimInstance {
            param($ClassName, $Namespace, $Filter, $Query, $CimSession, $ErrorAction)
            switch ([string]$ClassName) {
                'Win32_Service' { return @($script:TestServices) }
                '__EventFilter' { return @($script:WmiFilters) }
                '__EventConsumer' { return @($script:WmiConsumers) }
                '__FilterToConsumerBinding' { return @($script:WmiBindings) }
                default { return @() }
            }
        }

        Mock -ModuleName $script:ModuleName Get-ScheduledTask {
            param($TaskName, $TaskPath, $CimSession, $ErrorAction)
            return @($script:TestTasks)
        }

        Mock -ModuleName $script:ModuleName Get-ScheduledTaskInfo {
            param($TaskName, $TaskPath, $CimSession, $ErrorAction)
            $suppliedPath = if ($PSBoundParameters.ContainsKey('TaskPath')) { [string]$TaskPath } else { $null }
            $script:TaskInfoCalls += [PSCustomObject]@{
                TaskName = [string]$TaskName
                TaskPath = $suppliedPath
            }
            if ($null -ne $suppliedPath) {
                $key = "$suppliedPath$([string]$TaskName)"
                if ($script:TaskInfo.ContainsKey($key)) {
                    return $script:TaskInfo[$key]
                }
            }
            return [PSCustomObject]@{
                LastRunTime = $null
                NextRunTime = $null
                LastTaskResult = 0
                NumberOfMissedRuns = 0
                TaskName = [string]$TaskName
                TaskPath = $suppliedPath
            }
        }

        Mock -ModuleName $script:ModuleName Get-ChildItem {
            param($Path, $LiteralPath, $Filter, $Include, $Exclude, $File, $Directory, $Recurse, $Force, $ErrorAction)
            $requestedPath = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                [string]$LiteralPath
            }
            else {
                [string]$Path
            }
            if ($script:DirectoryItems.ContainsKey($requestedPath)) {
                return @($script:DirectoryItems[$requestedPath])
            }
            return @()
        }

        Mock -ModuleName $script:ModuleName Get-AuthenticodeSignature {
            param($FilePath, $LiteralPath, $Path, $Content, $Certificate, $HashAlgorithm, $IncludeChain, $ShowFullChain, $ErrorAction)
            $requestedPath = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                [string]$LiteralPath
            }
            elseif ($PSBoundParameters.ContainsKey('FilePath')) {
                [string]$FilePath
            }
            else {
                [string]$Path
            }
            $script:SignatureCalls += $requestedPath
            if ($script:Signatures.ContainsKey($requestedPath)) {
                return $script:Signatures[$requestedPath]
            }
            return [PSCustomObject]@{
                Path = $requestedPath
                Status = 'NotSigned'
                StatusMessage = 'Fixture default: no signature configured'
                SignerCertificate = $null
                TimeStamperCertificate = $null
            }
        }

        Mock -ModuleName $script:ModuleName New-Object {
            param($TypeName, $ComObject, $ArgumentList, $Property, $PassThru, $ErrorAction)
            $script:ComObjectCalls += [string]$ComObject
            if ([string]$ComObject -ne 'WScript.Shell') {
                throw "Unexpected New-Object call. TypeName='$TypeName' ComObject='$ComObject'"
            }
            $shell = [PSCustomObject]@{
                ShortcutTargets = $script:ShortcutTargets
            }
            $shell | Add-Member -MemberType ScriptMethod -Name CreateShortcut -Value {
                param($ShortcutPath)
                if ($this.ShortcutTargets.ContainsKey($ShortcutPath)) {
                    return $this.ShortcutTargets[$ShortcutPath]
                }
                return [PSCustomObject]@{
                    TargetPath = ''
                    Arguments = ''
                    WorkingDirectory = ''
                }
            }
            return $shell
        }
    }

    It 'retains the public IncludeKnownGood and ExportPath parameters' {
        $command = Get-Command -Name Find-PersistenceMechanisms -Module $script:ModuleName
        $command.Parameters.Keys | Should -Contain 'IncludeKnownGood'
        $command.Parameters.Keys | Should -Contain 'ExportPath'
    }

    It 'classifies exactly the 14 reported entries by path and signature, with only ArkSigner suspicious' {
        Initialize-TestReportedRegression

        $included = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null
        $all = @(Get-TestPersistenceFindings -Result $included)
        $trusted = @($all | Where-Object { -not $_.Suspicious })
        $suspicious = @($all | Where-Object { $_.Suspicious })

        $all.Count | Should -Be 14
        $included.TotalFindings | Should -Be 14
        $included.SuspiciousCount | Should -Be 1
        $trusted.Count | Should -Be 13
        $suspicious.Count | Should -Be 1
        $included.RegistryRunKeys.Count | Should -Be 4
        $included.Services.Count | Should -Be 3
        $included.WMISubscriptions.Count | Should -Be 1
        $included.PrintMonitors.Count | Should -Be 6
        $included.StartupFolder.Count | Should -Be 0
        $included.ScheduledTasks.Count | Should -Be 0
        $included.AppInitDLLs.Count | Should -Be 0
        $included.LSAProviders.Count | Should -Be 0

        @($included.RegistryRunKeys.Name | Sort-Object) | Should -Be @('ArkSigner', 'Java', 'RtkAudUService', 'SecurityHealth')
        @($included.Services.Name | Sort-Object) | Should -Be @('MDCoreSvc', 'WinDefend', 'XTU3SERVICE')
        @($included.PrintMonitors.Name | Sort-Object) | Should -Be @(
            'AppMon', 'Local Port', 'Microsoft Shared Fax Monitor',
            'Standard TCP/IP Port', 'USB Monitor', 'WSD Port'
        )

        $expectedRunPaths = @{
            SecurityHealth = 'C:\Windows\System32\SecurityHealthSystray.exe'
            RtkAudUService = 'C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe'
            ArkSigner = 'C:\Users\fixture\AppData\Local\ArkSigner\ArkSignerService.exe'
            Java = 'C:\Program Files\Java\jre1.8.0_451\bin\jusched.exe'
        }
        foreach ($finding in $all) {
            Assert-TestPersistenceFindingShape -Finding $finding
        }
        foreach ($finding in $included.RegistryRunKeys) {
            $finding.ResolvedPath | Should -Be $expectedRunPaths[$finding.Name]
            $finding.SignatureStatus | Should -Be 'Valid'
            [string]::IsNullOrWhiteSpace([string]$finding.Signer) | Should -BeFalse
        }
        foreach ($finding in @($included.Services) + @($included.PrintMonitors)) {
            $finding.SignatureStatus | Should -Be 'Valid'
            [string]::IsNullOrWhiteSpace([string]$finding.Signer) | Should -BeFalse
            $finding.Suspicious | Should -BeFalse
        }

        $arkSigner = @($included.RegistryRunKeys | Where-Object { $_.Name -eq 'ArkSigner' })[0]
        $arkSigner.Suspicious | Should -BeTrue
        @($arkSigner.Reasons) -join '; ' | Should -Match 'user-writable location'
        $scmBinding = $included.WMISubscriptions[0]
        $scmBinding.Suspicious | Should -BeFalse
        $scmBinding.Consumer | Should -Match 'SCM Event Log Consumer'

        $default = Find-PersistenceMechanisms 6>$null 3>$null
        $defaultItems = @(Get-TestPersistenceFindings -Result $default)
        $default.TotalFindings | Should -Be ($all.Count - $trusted.Count)
        $default.TotalFindings | Should -Be 1
        $default.SuspiciousCount | Should -Be $suspicious.Count
        $defaultItems.Count | Should -Be 1
        $defaultItems[0].Name | Should -Be 'ArkSigner'
        $defaultItems[0].Suspicious | Should -BeTrue
        @($defaultItems[0].Reasons) -join '; ' | Should -Match 'user-writable location'
    }

    It 'flags an unsigned Run target whose path contains Microsoft' {
        $evilPath = 'C:\Users\x\AppData\Roaming\Microsoft\evil.exe'
        Set-TestRunValues -Values ([ordered]@{ Evil = $evilPath })
        Add-TestBinary -Path $evilPath -Status NotSigned -SignerName $null

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $result.RegistryRunKeys.Count | Should -Be 1
        $finding = $result.RegistryRunKeys[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.ResolvedPath | Should -Be $evilPath
        $finding.ResolvedPath | Should -Match 'Microsoft'
        $finding.Suspicious | Should -BeTrue
        $finding.SignatureStatus | Should -Be 'NotSigned'
        @($finding.Reasons) -join '; ' | Should -Match 'not[ -]?signed|unsigned'
    }

    It 'flags validly signed powershell.exe in a non-Microsoft scheduled task as a LOLBin' {
        $powerShellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        Add-TestBinary -Path $powerShellPath -SignerName 'Microsoft Windows'
        $task = New-TestTask -TaskName 'SignedPowerShell' -TaskPath '\Contoso\' `
            -Execute $powerShellPath -Arguments '-NoProfile -EncodedCommand SQBFAFgA'
        $script:TestTasks = @($task)
        $key = Get-TestTaskKey -TaskName $task.TaskName -TaskPath $task.TaskPath
        $script:TaskInfo[$key] = New-TestTaskInfo -LastRunTime '2099-01-02T03:04:05Z' -NextRunTime '2099-01-03T03:04:05Z'

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.ScheduledTasks.Count | Should -Be 1
        $finding = $result.ScheduledTasks[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Suspicious | Should -BeTrue
        $finding.SignatureStatus | Should -Be 'Valid'
        $finding.PSObject.Properties.Name | Should -Contain 'ActionChecks'
        $finding.ActionChecks.Count | Should -Be 1
        $finding.ActionChecks[0].ResolvedPath | Should -Be $powerShellPath
        $finding.ActionChecks[0].SignatureStatus | Should -Be 'Valid'
        $reasonText = (@($finding.Reasons) + @($finding.ActionChecks.Reasons)) -join '; '
        $reasonText | Should -Match 'LOLBin'
    }

    It 'does not hide a malicious Exec action under Microsoft and distinguishes identical task names by folder' {
        $powerShellPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        Add-TestBinary -Path $powerShellPath -SignerName 'Microsoft Windows'
        $microsoftTask = New-TestTask -TaskName 'SameName' -TaskPath '\Microsoft\Contoso\' `
            -Execute $powerShellPath -Arguments '-NoProfile -EncodedCommand SQBFAFgA'
        $contosoTask = New-TestTask -TaskName 'SameName' -TaskPath '\Contoso\' `
            -Execute $powerShellPath -Arguments '-NoProfile -File C:\Users\x\payload.ps1'
        $script:TestTasks = @($microsoftTask, $contosoTask)
        $microsoftInfo = New-TestTaskInfo -LastRunTime '2099-02-01T01:00:00Z' -NextRunTime '2099-02-02T01:00:00Z'
        $contosoInfo = New-TestTaskInfo -LastRunTime '2099-03-01T01:00:00Z' -NextRunTime '2099-03-02T01:00:00Z'
        $script:TaskInfo[(Get-TestTaskKey -TaskName 'SameName' -TaskPath '\Microsoft\Contoso\')] = $microsoftInfo
        $script:TaskInfo[(Get-TestTaskKey -TaskName 'SameName' -TaskPath '\Contoso\')] = $contosoInfo

        $result = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $result.ScheduledTasks.Count | Should -Be 2
        $microsoftFinding = @($result.ScheduledTasks | Where-Object { $_.Path -eq '\Microsoft\Contoso\' })[0]
        $contosoFinding = @($result.ScheduledTasks | Where-Object { $_.Path -eq '\Contoso\' })[0]
        $microsoftFinding.Suspicious | Should -BeTrue
        $contosoFinding.Suspicious | Should -BeTrue
        [datetime]$microsoftFinding.LastRunTime | Should -Be $microsoftInfo.LastRunTime
        [datetime]$contosoFinding.LastRunTime | Should -Be $contosoInfo.LastRunTime
        $microsoftFinding.PSObject.Properties.Name | Should -Contain 'ActionChecks'
        $microsoftFinding.ActionChecks.Count | Should -Be 1
        $microsoftReasons = @($microsoftFinding.Reasons) + @($microsoftFinding.ActionChecks.Reasons)
        $microsoftReasons -join '; ' | Should -Match 'LOLBin'
        $script:TaskInfoCalls.Count | Should -Be 2
        Should -Invoke Get-ScheduledTaskInfo -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $TaskName -eq 'SameName' -and $TaskPath -eq '\Microsoft\Contoso\'
        }
        Should -Invoke Get-ScheduledTaskInfo -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $TaskName -eq 'SameName' -and $TaskPath -eq '\Contoso\'
        }
    }

    It 'flags a CommandLineEventConsumer binding but trusts the default SCM binding only as known-good' {
        $script:WmiBindings = @(
            [PSCustomObject]@{
                Filter = '__EventFilter.Name="SCM Event Log Filter"'
                Consumer = 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"'
            },
            [PSCustomObject]@{
                Filter = '__EventFilter.Name="UpdaterFilter"'
                Consumer = 'CommandLineEventConsumer.Name="UpdaterConsumer"'
            }
        )
        $script:WmiFilters = @(
            [PSCustomObject]@{ Name = 'SCM Event Log Filter'; Query = 'SELECT * FROM Win32_Service'; QueryLanguage = 'WQL'; EventNamespace = 'root\cimv2' },
            [PSCustomObject]@{ Name = 'UpdaterFilter'; Query = 'SELECT * FROM __InstanceCreationEvent'; QueryLanguage = 'WQL'; EventNamespace = 'root\cimv2' }
        )
        $script:WmiConsumers = @(
            [PSCustomObject]@{ Name = 'SCM Event Log Consumer'; SourceName = 'Service Control Manager'; EventType = 2 },
            [PSCustomObject]@{ Name = 'UpdaterConsumer'; CommandLineTemplate = 'powershell.exe -enc SQBFAFgA'; ExecutablePath = 'powershell.exe' }
        )

        $default = Find-PersistenceMechanisms 6>$null 3>$null
        $included = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $default.WMISubscriptions.Count | Should -Be 1
        $default.TotalFindings | Should -Be 1
        $default.SuspiciousCount | Should -Be 1
        $default.WMISubscriptions[0].Consumer | Should -Match 'CommandLineEventConsumer'
        $default.WMISubscriptions[0].Suspicious | Should -BeTrue
        $included.WMISubscriptions.Count | Should -Be 2
        $included.TotalFindings | Should -Be 2
        $included.SuspiciousCount | Should -Be 1
        $scm = @($included.WMISubscriptions | Where-Object { $_.Consumer -match 'SCM Event Log Consumer' })[0]
        $scm.Suspicious | Should -BeFalse
        Assert-TestPersistenceFindingShape -Finding $scm
    }

    It 'flags <Name> with the matching signature status and reason' -ForEach @(
        @{
            Name = 'a missing Run target'
            Path = 'C:\Users\x\AppData\Local\missing.exe'
            Exists = $false
            Status = 'NotSigned'
            ExpectedStatus = 'Unknown'
            Reason = 'missing|not found|does not exist'
        },
        @{
            Name = 'a NotSigned Run target'
            Path = 'C:\Users\x\AppData\Local\unsigned.exe'
            Exists = $true
            Status = 'NotSigned'
            ExpectedStatus = 'NotSigned'
            Reason = 'not[ -]?signed|unsigned'
        },
        @{
            Name = 'a HashMismatch Run target'
            Path = 'C:\Program Files\Contoso\tampered.exe'
            Exists = $true
            Status = 'HashMismatch'
            ExpectedStatus = 'HashMismatch'
            Reason = 'hash[ -]?mismatch|HashMismatch'
        }
    ) {
        $case = $_
        Set-TestRunValues -Values ([ordered]@{ Fixture = $case.Path })
        Add-TestBinary -Path $case.Path -Status $case.Status -SignerName $null -Exists $case.Exists

        $result = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $result.RegistryRunKeys.Count | Should -Be 1
        $finding = $result.RegistryRunKeys[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.ResolvedPath | Should -Be $case.Path
        $finding.Suspicious | Should -BeTrue
        if ($null -ne $case.ExpectedStatus) {
            $finding.SignatureStatus | Should -Be $case.ExpectedStatus
        }
        @($finding.Reasons) -join '; ' | Should -Match $case.Reason
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
    }

    It 'resolves <Name> to a canonical path' -ForEach @(
        @{
            Name = 'a quoted executable with arguments'
            CommandLine = '"C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe" -background'
            Expected = 'C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe'
            AppendDll = $false
        },
        @{
            Name = 'an unquoted executable path containing spaces'
            CommandLine = 'C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe -background'
            Expected = 'C:\Program Files\Realtek\Audio\HDA\RtkAudUService64.exe'
            AppendDll = $false
        },
        @{
            Name = 'a windir environment variable'
            CommandLine = '%windir%\System32\cmd.exe /c whoami'
            Expected = 'C:\Windows\System32\cmd.exe'
            AppendDll = $false
        },
        @{
            Name = 'a SystemRoot alias'
            CommandLine = '\SystemRoot\System32\cmd.exe /c whoami'
            Expected = 'C:\Windows\System32\cmd.exe'
            AppendDll = $false
        },
        @{
            Name = 'an NT object-manager prefix'
            CommandLine = '\??\C:\Windows\System32\cmd.exe'
            Expected = 'C:\Windows\System32\cmd.exe'
            AppendDll = $false
        },
        @{
            Name = 'a bare DLL'
            CommandLine = 'localspl.dll'
            Expected = 'C:\Windows\System32\localspl.dll'
            AppendDll = $true
        }
    ) {
        $case = $_
        $resolved = InModuleScope -ModuleName $script:ModuleName -ArgumentList $case.CommandLine, $case.AppendDll -ScriptBlock {
            param($InputCommandLine, $UseAppendDll)
            if ($UseAppendDll) {
                return Resolve-WsaBinaryPath -CommandLine $InputCommandLine -AppendDll
            }
            return Resolve-WsaBinaryPath -CommandLine $InputCommandLine
        }
        $resolved | Should -Be $case.Expected
    }

    It 'returns all trust fields and hits the signature cache for duplicate resolved paths' {
        $serviceHostPath = 'C:\Windows\System32\svchost.exe'
        Add-TestBinary -Path $serviceHostPath -SignerName 'Microsoft Windows'
        $cache = @{}
        $first = '"C:\Windows\System32\svchost.exe" -k netsvcs'
        $second = 'C:\Windows\System32\svchost.exe -k LocalService'

        $checks = @(InModuleScope -ModuleName $script:ModuleName -ArgumentList $first, $second, $cache -ScriptBlock {
            param($FirstCommand, $SecondCommand, $SignatureCache)
            Test-WsaTrustedBinary -CommandLine $FirstCommand -SignatureCache $SignatureCache
            Test-WsaTrustedBinary -CommandLine $SecondCommand -SignatureCache $SignatureCache
        })

        $checks.Count | Should -Be 2
        $cache.Count | Should -Be 1
        $script:SignatureCalls.Count | Should -Be 1
        $script:SignatureCalls[0] | Should -Be $serviceHostPath
        foreach ($check in $checks) {
            foreach ($propertyName in @('ResolvedPath', 'Exists', 'SignatureStatus', 'Signer', 'UserWritable', 'Trusted', 'Reasons')) {
                $check.PSObject.Properties.Name | Should -Contain $propertyName
            }
            $check.ResolvedPath | Should -Be $serviceHostPath
            $check.Exists | Should -BeTrue
            $check.SignatureStatus | Should -Be 'Valid'
            $check.Signer | Should -Be 'Microsoft Windows'
            $check.UserWritable | Should -BeFalse
            $check.Trusted | Should -BeTrue
        }
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly
    }

    It 'reports a missing direct-helper target without evaluating a signature' {
        $missingPath = 'C:\Users\x\AppData\Local\missing.exe'
        $cache = @{}
        $check = InModuleScope -ModuleName $script:ModuleName -ArgumentList $missingPath, $cache -ScriptBlock {
            param($CommandLine, $SignatureCache)
            Test-WsaTrustedBinary -CommandLine $CommandLine -SignatureCache $SignatureCache
        }

        $check.ResolvedPath | Should -Be $missingPath
        $check.Exists | Should -BeFalse
        $check.SignatureStatus | Should -Be 'Unknown'
        $check.Trusted | Should -BeFalse
        @($check.Reasons) -join '; ' | Should -Match 'missing|not found|does not exist'
        $script:SignatureCalls.Count | Should -Be 0
    }

    It 'resolves a startup shortcut target and skips desktop.ini' {
        $targetPath = 'C:\Users\x\AppData\Roaming\Contoso\contoso.exe'
        $link = New-TestStartupItem -Name 'Contoso.lnk'
        $desktopIni = New-TestStartupItem -Name 'desktop.ini'
        $script:DirectoryItems[$script:StartupPath] = @($link, $desktopIni)
        $script:PathExistence[$script:StartupPath] = $true
        $script:ShortcutTargets[$link.FullName] = [PSCustomObject]@{
            TargetPath = $targetPath
            Arguments = '--minimized'
            WorkingDirectory = 'C:\Users\x\AppData\Roaming\Contoso'
        }
        Add-TestBinary -Path $targetPath -Status NotSigned -SignerName $null

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.StartupFolder.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $finding = $result.StartupFolder[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Name | Should -Be 'Contoso.lnk'
        $finding.Target | Should -Be $targetPath
        $finding.ResolvedPath | Should -Be $targetPath
        $finding.SignatureStatus | Should -Be 'NotSigned'
        $finding.Suspicious | Should -BeTrue
        @($result.StartupFolder.Name) | Should -Not -Contain 'desktop.ini'
        $script:ComObjectCalls.Count | Should -Be 1
        $script:ComObjectCalls[0] | Should -Be 'WScript.Shell'
        Should -Invoke New-Object -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $ComObject -eq 'WScript.Shell'
        }
    }

    It 'returns a null service PathName with an explicit reason' {
        $script:TestServices = @(
            New-TestService -Name 'NullPathSvc' -DisplayName 'Null Path Service' -PathName $null -StartMode Auto
        )

        $result = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $result.Services.Count | Should -Be 1
        $finding = $result.Services[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Name | Should -Be 'NullPathSvc'
        $finding.Suspicious | Should -BeTrue
        @($finding.Reasons) -join '; ' | Should -Match 'PathName|service path|command line'
        @($finding.Reasons) -join '; ' | Should -Match 'missing|null|empty|not provided'
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
    }

    It 'excludes disabled services even when IncludeKnownGood is set' {
        $disabledPath = 'C:\Users\x\AppData\Local\disabled.exe'
        Add-TestBinary -Path $disabledPath -Status NotSigned -SignerName $null
        $script:TestServices = @(
            New-TestService -Name 'DisabledSvc' -PathName $disabledPath -StartMode Disabled -State Stopped
        )

        $result = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $result.Services.Count | Should -Be 0
        $result.TotalFindings | Should -Be 0
        $result.SuspiciousCount | Should -Be 0
    }

    It 'returns a trusted protected valid binary only with IncludeKnownGood and keeps totals consistent' {
        $agentPath = 'C:\Program Files\Contoso\agent.exe'
        Set-TestRunValues -Values ([ordered]@{ ContosoAgent = "`"$agentPath`" --service" })
        Add-TestBinary -Path $agentPath -SignerName 'Contoso Software'

        $default = Find-PersistenceMechanisms 6>$null 3>$null
        $included = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $default.RegistryRunKeys.Count | Should -Be 0
        $default.TotalFindings | Should -Be 0
        $default.SuspiciousCount | Should -Be 0
        $included.RegistryRunKeys.Count | Should -Be 1
        $included.TotalFindings | Should -Be 1
        $included.SuspiciousCount | Should -Be 0
        $finding = $included.RegistryRunKeys[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Suspicious | Should -BeFalse
        $finding.ResolvedPath | Should -Be $agentPath
        $finding.SignatureStatus | Should -Be 'Valid'
        $finding.Signer | Should -Be 'Contoso Software'
        $finding.Reasons | Should -Be ''
        $default.TotalFindings | Should -Be ($included.TotalFindings - 1)
    }

    It 'marks the entire AppInit finding suspicious when any quoted entry is untrusted' {
        $appInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $goodPath = 'C:\Program Files\Contoso\good.dll'
        $evilPath = 'C:\Users\bob\AppData\Local\evil.dll'
        $appInitValue = '"{0}" "{1}"' -f $goodPath, $evilPath
        $script:RegistryValues[$appInitPath] = [PSCustomObject]@{
            AppInit_DLLs = $appInitValue
            LoadAppInit_DLLs = 1
        }
        $script:PathExistence[$appInitPath] = $true
        Add-TestBinary -Path $goodPath -SignerName 'Contoso Software'
        Add-TestBinary -Path $evilPath -Status NotSigned -SignerName $null

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.AppInitDLLs.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.AppInitDLLs[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Value | Should -Be $appInitValue
        $finding.Suspicious | Should -BeTrue
        $finding.PSObject.Properties.Name | Should -Contain 'BinaryChecks'
        $finding.BinaryChecks.Count | Should -Be 2
        $finding.BinaryChecks[0].ResolvedPath | Should -Be $goodPath
        $finding.BinaryChecks[0].SignatureStatus | Should -Be 'Valid'
        $finding.BinaryChecks[0].Trusted | Should -BeTrue
        $finding.BinaryChecks[1].ResolvedPath | Should -Be $evilPath
        $finding.BinaryChecks[1].SignatureStatus | Should -Be 'NotSigned'
        $finding.BinaryChecks[1].UserWritable | Should -BeTrue
        $finding.BinaryChecks[1].Trusted | Should -BeFalse
        $finding.ResolvedPath | Should -Match ([regex]::Escape($goodPath))
        $finding.ResolvedPath | Should -Match ([regex]::Escape($evilPath))
        $finding.SignatureStatus | Should -Match 'Valid'
        $finding.SignatureStatus | Should -Match 'NotSigned'
        $finding.Reasons | Should -Match 'user-writable location'
        $finding.Reasons | Should -Match 'NotSigned|not[ -]?signed|unsigned'
        $script:SignatureCalls.Count | Should -Be 2
        @($script:SignatureCalls) | Should -Contain $goodPath
        @($script:SignatureCalls) | Should -Contain $evilPath
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $goodPath
        }
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $evilPath
        }
    }

    It 'keeps unquoted AppInit DLL paths separate <Name>' -ForEach @(
        @{
            Name = 'without whitespace after the comma'
            Value = 'C:\Windows\System32\good.dll,C:\Windows\System32\other.dll'
        },
        @{
            Name = 'with whitespace after the comma'
            Value = 'C:\Windows\System32\good.dll, C:\Windows\System32\other.dll'
        }
    ) {
        $appInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $goodPath = 'C:\Windows\System32\good.dll'
        $otherPath = 'C:\Windows\System32\other.dll'
        $script:RegistryValues[$appInitPath] = [PSCustomObject]@{
            AppInit_DLLs = $_.Value
            LoadAppInit_DLLs = 1
        }
        $script:PathExistence[$appInitPath] = $true
        Add-TestBinary -Path $goodPath -SignerName 'Microsoft Windows'
        Add-TestBinary -Path $otherPath -SignerName 'Microsoft Windows'

        $result = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $result.AppInitDLLs.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 0
        $finding = $result.AppInitDLLs[0]
        $finding.Value | Should -Be $_.Value
        $finding.Suspicious | Should -BeFalse
        $finding.BinaryChecks.Count | Should -Be 2
        @($finding.BinaryChecks.ResolvedPath) | Should -Be @($goodPath, $otherPath)
        $finding.BinaryChecks[0].SignatureStatus | Should -Be 'Valid'
        $finding.BinaryChecks[1].SignatureStatus | Should -Be 'Valid'
        $finding.BinaryChecks[0].Trusted | Should -BeTrue
        $finding.BinaryChecks[1].Trusted | Should -BeTrue
        $finding.ResolvedPath | Should -Be "$goodPath; $otherPath"
        $finding.SignatureStatus | Should -Be 'Valid'
        $script:SignatureCalls.Count | Should -Be 2
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 2 -Exactly
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $goodPath
        }
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $otherPath
        }
    }

    It 'treats <Name> as user-writable and suspicious despite a valid signature' -ForEach @(
        @{
            Name = 'a drive-qualified user-profile path'
            CommandLine = 'D:\Users\bob\Desktop\evil.exe'
            Expected = 'D:\Users\bob\Desktop\evil.exe'
        },
        @{
            Name = 'an extended-length user-profile path'
            CommandLine = '\\?\C:\Users\bob\Desktop\evil.exe'
            Expected = 'C:\Users\bob\Desktop\evil.exe'
        }
    ) {
        $case = $_
        Add-TestBinary -Path $case.Expected -SignerName 'Microsoft Windows'
        Set-TestRunValues -Values ([ordered]@{ LocationFixture = $case.CommandLine })

        $resolved = InModuleScope -ModuleName $script:ModuleName -ArgumentList $case.CommandLine -ScriptBlock {
            param($CommandLine)
            Resolve-WsaBinaryPath -CommandLine $CommandLine
        }
        $check = InModuleScope -ModuleName $script:ModuleName -ArgumentList $case.CommandLine -ScriptBlock {
            param($CommandLine)
            Test-WsaTrustedBinary -CommandLine $CommandLine -SignatureCache @{}
        }
        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $resolved | Should -Be $case.Expected
        $check.ResolvedPath | Should -Be $case.Expected
        $check.SignatureStatus | Should -Be 'Valid'
        $check.UserWritable | Should -BeTrue
        $check.Trusted | Should -BeFalse
        @($check.Reasons) -join '; ' | Should -Match 'user-writable location'
        $result.RegistryRunKeys.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.RegistryRunKeys[0]
        $finding.ResolvedPath | Should -Be $case.Expected
        $finding.SignatureStatus | Should -Be 'Valid'
        $finding.Suspicious | Should -BeTrue
        $finding.Reasons | Should -Match 'user-writable location'
    }

    It 'trusts the default SCM pair with object and dictionary references carrying __CLASS metadata' {
        $filterReference = [ordered]@{
            Name = 'SCM Event Log Filter'
            __CLASS = '__EventFilter'
        }
        $consumerReference = [PSCustomObject]@{
            Name = 'SCM Event Log Consumer'
            __CLASS = 'NTEventLogEventConsumer'
        }
        $script:WmiBindings = @([PSCustomObject]@{
            Filter = $filterReference
            Consumer = $consumerReference
        })

        $result = Find-PersistenceMechanisms -IncludeKnownGood 6>$null 3>$null

        $result.WMISubscriptions.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 0
        $finding = $result.WMISubscriptions[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Suspicious | Should -BeFalse
        $finding.Filter.Contains('__CLASS') | Should -BeTrue
        $finding.Filter['__CLASS'] | Should -Be '__EventFilter'
        $finding.Consumer.__CLASS | Should -Be 'NTEventLogEventConsumer'
        $finding.Reasons | Should -Be ''
    }

    It 'flags SCM-named object references that omit type metadata' {
        $script:WmiBindings = @([PSCustomObject]@{
            Filter = [ordered]@{ Name = 'SCM Event Log Filter' }
            Consumer = [ordered]@{ Name = 'SCM Event Log Consumer' }
        })

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.WMISubscriptions.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.WMISubscriptions[0]
        $finding.Suspicious | Should -BeTrue
        $finding.Reasons | Should -Match 'Unexpected WMI filter type'
        $finding.Reasons | Should -Match 'WMI consumer type is not NTEventLogEventConsumer'
    }

    It 'flags an SCM-named CommandLineEventConsumer even with a typed default filter' {
        $script:WmiBindings = @([PSCustomObject]@{
            Filter = [PSCustomObject]@{
                Name = 'SCM Event Log Filter'
                __CLASS = '__EventFilter'
            }
            Consumer = [ordered]@{
                Name = 'SCM Event Log Consumer'
                __CLASS = 'CommandLineEventConsumer'
            }
        })

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.WMISubscriptions.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.WMISubscriptions[0]
        $finding.Suspicious | Should -BeTrue
        $finding.Reasons | Should -Match 'WMI consumer type is not NTEventLogEventConsumer'
        $finding.Consumer['__CLASS'] | Should -Be 'CommandLineEventConsumer'
    }

    It 'caches a failed signature lookup and returns identical Unavailable results' {
        $agentPath = 'C:\Program Files\Contoso\agent.exe'
        Add-TestBinary -Path $agentPath -SignerName 'Contoso Software'
        Mock -ModuleName $script:ModuleName Get-AuthenticodeSignature {
            param($LiteralPath, $FilePath, $Path, $ErrorAction)
            $script:SignatureCalls += [string]$LiteralPath
            throw 'Deterministic signature lookup failure'
        }
        $cache = @{}
        $first = '"C:\Program Files\Contoso\agent.exe" --first'
        $second = 'C:\Program Files\Contoso\agent.exe --second'

        $checks = @(InModuleScope -ModuleName $script:ModuleName -ArgumentList $first, $second, $cache -ScriptBlock {
            param($FirstCommand, $SecondCommand, $SignatureCache)
            Test-WsaTrustedBinary -CommandLine $FirstCommand -SignatureCache $SignatureCache
            Test-WsaTrustedBinary -CommandLine $SecondCommand -SignatureCache $SignatureCache
        })

        $checks.Count | Should -Be 2
        $checks[0].SignatureStatus | Should -Be 'Unavailable'
        $checks[1].SignatureStatus | Should -Be 'Unavailable'
        $checks[0].SignatureStatus | Should -Be $checks[1].SignatureStatus
        @($checks[0].Reasons) -join '; ' | Should -Be 'Unavailable'
        @($checks[1].Reasons) -join '; ' | Should -Be 'Unavailable'
        @($checks[0].Reasons) -join '; ' | Should -Be (@($checks[1].Reasons) -join '; ')
        $checks[0].Trusted | Should -BeFalse
        $checks[1].Trusted | Should -BeFalse
        $cache.Count | Should -Be 1
        $cache[$agentPath].Status | Should -Be 'Unavailable'
        $script:SignatureCalls.Count | Should -Be 1
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $agentPath
        }
    }

    It 'marks actionless and non-Exec scheduled tasks suspicious with NotEvaluated status' {
        $actionless = New-TestTask -TaskName 'Actionless' -TaskPath '\Contoso\' -Execute 'placeholder.exe'
        $actionless.Actions = @()
        $nonExec = New-TestTask -TaskName 'NonExec' -TaskPath '\Microsoft\Contoso\' -Execute 'placeholder.exe'
        $nonExec.Actions = @([PSCustomObject]@{
            ActionType = 'ComHandler'
            ClassId = '{00000000-0000-0000-0000-000000000001}'
            Arguments = ''
            Data = 'Deterministic non-Exec action'
        })
        $script:TestTasks = @($actionless, $nonExec)
        foreach ($task in $script:TestTasks) {
            $key = Get-TestTaskKey -TaskName $task.TaskName -TaskPath $task.TaskPath
            $script:TaskInfo[$key] = New-TestTaskInfo -LastRunTime '2099-04-01T00:00:00Z' -NextRunTime '2099-04-02T00:00:00Z'
        }

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.ScheduledTasks.Count | Should -Be 2
        $result.TotalFindings | Should -Be 2
        $result.SuspiciousCount | Should -Be 2
        $actionlessFinding = @($result.ScheduledTasks | Where-Object { $_.Name -eq 'Actionless' })[0]
        Assert-TestPersistenceFindingShape -Finding $actionlessFinding
        $actionlessFinding.PSObject.Properties.Name | Should -Contain 'ActionChecks'
        $actionlessFinding.ActionChecks.Count | Should -Be 0
        $actionlessFinding.Actions | Should -Be 'N/A'
        $actionlessFinding.Suspicious | Should -BeTrue
        $actionlessFinding.SignatureStatus | Should -Be 'NotEvaluated'
        $actionlessFinding.Reasons | Should -Match 'No executable action could be evaluated'

        $nonExecFinding = @($result.ScheduledTasks | Where-Object { $_.Name -eq 'NonExec' })[0]
        Assert-TestPersistenceFindingShape -Finding $nonExecFinding
        $nonExecFinding.PSObject.Properties.Name | Should -Contain 'ActionChecks'
        $nonExecFinding.ActionChecks.Count | Should -Be 1
        $nonExecFinding.ActionChecks[0].Action | Should -Be 'Non-Exec action (not evaluated)'
        $nonExecFinding.ActionChecks[0].SignatureStatus | Should -Be 'NotEvaluated'
        $nonExecFinding.ActionChecks[0].Trusted | Should -BeFalse
        $nonExecFinding.ActionChecks[0].Reasons | Should -Match 'Non-Exec task action could not be evaluated'
        $nonExecFinding.Actions | Should -Be 'Non-Exec action (not evaluated)'
        $nonExecFinding.Suspicious | Should -BeTrue
        $nonExecFinding.SignatureStatus | Should -Be 'NotEvaluated'
        $nonExecFinding.Reasons | Should -Match 'Non-Exec task action could not be evaluated'
        $script:SignatureCalls.Count | Should -Be 0
    }

    It 'evaluates every AppInit entry across mixed whitespace and comma delimiters' {
        $appInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $goodPath = 'C:\Windows\System32\good.dll'
        $evilPath = 'C:\Windows\System32\evil.dll'
        $otherPath = 'C:\Windows\System32\other.dll'
        $script:RegistryValues[$appInitPath] = [PSCustomObject]@{
            AppInit_DLLs = 'good.dll evil.dll,other.dll'
            LoadAppInit_DLLs = 1
        }
        $script:PathExistence[$appInitPath] = $true
        Add-TestBinary -Path $goodPath -SignerName 'Microsoft Windows'
        Add-TestBinary -Path $evilPath -Status NotSigned -SignerName $null
        Add-TestBinary -Path $otherPath -SignerName 'Microsoft Windows'

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.AppInitDLLs.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.AppInitDLLs[0]
        $finding.Value | Should -Be 'good.dll evil.dll,other.dll'
        $finding.Suspicious | Should -BeTrue
        $finding.BinaryChecks.Count | Should -Be 3
        @($finding.BinaryChecks.ResolvedPath) | Should -Be @($goodPath, $evilPath, $otherPath)
        $finding.BinaryChecks[0].Trusted | Should -BeTrue
        $finding.BinaryChecks[1].SignatureStatus | Should -Be 'NotSigned'
        $finding.BinaryChecks[1].Trusted | Should -BeFalse
        $finding.BinaryChecks[2].Trusted | Should -BeTrue
        $finding.Reasons | Should -Match 'NotSigned|not[ -]?signed|unsigned'
        $script:SignatureCalls.Count | Should -Be 3
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 3 -Exactly
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $evilPath
        }
    }

    It 'evaluates PSUpdater while skipping only exact registry provider metadata names' {
        $updaterPath = 'C:\Users\x\AppData\Roaming\Microsoft\PSUpdater.exe'
        $metadataPath = 'C:\Users\x\AppData\Local\metadata.exe'
        Set-TestRunValues -Values ([ordered]@{
            PSUpdater = $updaterPath
            PSPath = $metadataPath
            PSParentPath = $metadataPath
            PSChildName = $metadataPath
            PSProvider = 'Registry'
            PSDrive = 'HKLM'
            PSIsContainer = $false
            PSComputerName = 'fixture-host'
            PSUser = 'CONTOSO\fixture'
            PSRemoteRegistry = $metadataPath
        })
        Add-TestBinary -Path $updaterPath -Status NotSigned -SignerName $null
        Add-TestBinary -Path $metadataPath -Status NotSigned -SignerName $null

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.RegistryRunKeys.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.RegistryRunKeys[0]
        $finding.Name | Should -Be 'PSUpdater'
        $finding.ResolvedPath | Should -Be $updaterPath
        $finding.SignatureStatus | Should -Be 'NotSigned'
        $finding.Suspicious | Should -BeTrue
        @($result.RegistryRunKeys.Name) | Should -Not -Contain 'PSPath'
        @($result.RegistryRunKeys.Name) | Should -Not -Contain 'PSChildName'
        $script:SignatureCalls.Count | Should -Be 1
        $script:SignatureCalls[0] | Should -Be $updaterPath
        @($script:SignatureCalls) | Should -Not -Contain $metadataPath
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $updaterPath
        }
    }

    It 'flags an unquoted service path and evaluates both ambiguous executable candidates' {
        $prefixPath = 'C:\Program.exe'
        $agentPath = 'C:\Program Files\Contoso\agent.exe'
        $script:TestServices = @(
            New-TestService -Name 'AmbiguousSvc' -DisplayName 'Ambiguous Service' -PathName $agentPath -StartMode Auto
        )
        Add-TestBinary -Path $prefixPath -Status NotSigned -SignerName $null
        Add-TestBinary -Path $agentPath -SignerName 'Contoso Software'

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.Services.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.Services[0]
        $finding.PathName | Should -Be $agentPath
        $finding.Suspicious | Should -BeTrue
        $finding.Reasons | Should -Match 'Unquoted service path contains spaces; ambiguous executable resolution'
        $finding.PSObject.Properties.Name | Should -Contain 'BinaryChecks'
        $finding.BinaryChecks.Count | Should -Be 2
        $finding.BinaryChecks[0].ResolvedPath | Should -Be $prefixPath
        $finding.BinaryChecks[0].SignatureStatus | Should -Be 'NotSigned'
        $finding.BinaryChecks[0].Trusted | Should -BeFalse
        $finding.BinaryChecks[1].ResolvedPath | Should -Be $agentPath
        $finding.BinaryChecks[1].SignatureStatus | Should -Be 'Valid'
        $finding.BinaryChecks[1].Trusted | Should -BeTrue
        $finding.ResolvedPath | Should -Be "$prefixPath; $agentPath"
        $finding.SignatureStatus | Should -Be 'NotSigned; Valid'
        $script:SignatureCalls.Count | Should -Be 2
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $prefixPath
        }
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $agentPath
        }
    }

    It 'keeps a validly signed UNC user-profile path suspicious and user-writable' {
        $uncPath = '\\localhost\C$\Users\bob\Desktop\agent.exe'
        Add-TestBinary -Path $uncPath -SignerName 'Contoso Software'
        Set-TestRunValues -Values ([ordered]@{ UncAgent = $uncPath })

        $check = InModuleScope -ModuleName $script:ModuleName -ArgumentList $uncPath -ScriptBlock {
            param($CommandLine)
            Test-WsaTrustedBinary -CommandLine $CommandLine -SignatureCache @{}
        }
        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $check.ResolvedPath | Should -Be $uncPath
        $check.SignatureStatus | Should -Be 'Valid'
        $check.UserWritable | Should -BeTrue
        $check.Trusted | Should -BeFalse
        @($check.Reasons) -join '; ' | Should -Match 'user-writable location'
        $result.RegistryRunKeys.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.RegistryRunKeys[0]
        $finding.ResolvedPath | Should -Be $uncPath
        $finding.SignatureStatus | Should -Be 'Valid'
        $finding.Suspicious | Should -BeTrue
        $finding.Reasons | Should -Match 'user-writable location'
    }

    It 'retains a valid Exec action while flagging its mixed non-Exec task action' {
        $agentPath = 'C:\Program Files\Contoso\agent.exe'
        Add-TestBinary -Path $agentPath -SignerName 'Contoso Software'
        $task = New-TestTask -TaskName 'MixedActions' -TaskPath '\Contoso\' -Execute $agentPath -Arguments '--service'
        $task.Actions = @($task.Actions) + @([PSCustomObject]@{
            ActionType = 'ComHandler'
            ClassId = '{00000000-0000-0000-0000-000000000002}'
            Arguments = ''
            Data = 'Deterministic mixed non-Exec action'
        })
        $script:TestTasks = @($task)
        $key = Get-TestTaskKey -TaskName $task.TaskName -TaskPath $task.TaskPath
        $script:TaskInfo[$key] = New-TestTaskInfo -LastRunTime '2099-05-01T00:00:00Z' -NextRunTime '2099-05-02T00:00:00Z'

        $result = Find-PersistenceMechanisms 6>$null 3>$null

        $result.ScheduledTasks.Count | Should -Be 1
        $result.TotalFindings | Should -Be 1
        $result.SuspiciousCount | Should -Be 1
        $finding = $result.ScheduledTasks[0]
        Assert-TestPersistenceFindingShape -Finding $finding
        $finding.Suspicious | Should -BeTrue
        $finding.ActionChecks.Count | Should -Be 2
        $finding.ActionChecks[0].Execute | Should -Be $agentPath
        $finding.ActionChecks[0].ResolvedPath | Should -Be $agentPath
        $finding.ActionChecks[0].SignatureStatus | Should -Be 'Valid'
        $finding.ActionChecks[0].Trusted | Should -BeTrue
        $finding.ActionChecks[1].Action | Should -Be 'Non-Exec action (not evaluated)'
        $finding.ActionChecks[1].SignatureStatus | Should -Be 'NotEvaluated'
        $finding.ActionChecks[1].Trusted | Should -BeFalse
        $finding.ActionChecks[1].Reasons | Should -Match 'Non-Exec task action could not be evaluated'
        $finding.SignatureStatus | Should -Be 'Valid; NotEvaluated'
        $finding.Reasons | Should -Match 'Non-Exec task action could not be evaluated'
        $finding.Actions | Should -Match ([regex]::Escape($agentPath))
        $finding.Actions | Should -Match 'Non-Exec action \(not evaluated\)'
        $script:SignatureCalls.Count | Should -Be 1
        Should -Invoke Get-AuthenticodeSignature -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $agentPath
        }
    }
}
