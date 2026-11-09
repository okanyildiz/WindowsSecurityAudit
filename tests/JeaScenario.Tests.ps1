#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeDiscovery {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:FunctionSetCases = @(
        @{ FunctionSet = 'Quick'; Expected = @('Get-SecurityBaseline', 'Get-DefenderStatus') },
        @{ FunctionSet = 'Standard'; Expected = @('Get-SecurityBaseline', 'Get-DefenderStatus', 'Find-SuspiciousProcesses', 'Find-PersistenceMechanisms', 'Get-SystemInfo') },
        @{ FunctionSet = 'Deep'; Expected = @('Get-SecurityBaseline', 'Get-DefenderStatus', 'Find-SuspiciousProcesses', 'Find-PersistenceMechanisms', 'Get-SystemInfo', 'Get-CredentialAccessEvents', 'Find-DefenseEvasion', 'Find-LateralMovement', 'Get-VulnerabilityAssessment') }
    )
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psd1"
    Import-Module -Name $script:ModulePath -Force

    function Get-TestDataFile {
        param([Parameter(Mandatory = $true)][string]$Path)

        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
        $hashtableAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.HashtableAst]
        }, $true)
        [PSCustomObject]@{
            Errors = @($parseErrors)
            Data = $hashtableAst.SafeGetValue()
            Ast = $ast
        }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'Effective language capability detection' {
    It 'reports the current language mode and compilation expectation' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $mode = Get-WsaEffectiveLanguageMode
            $mode | Should -Not -BeNullOrEmpty
            Test-WsaDynamicCompilationExpected | Should -Be ($mode -eq 'FullLanguage')
        }
    }

    It 'treats an unavailable language mode as no dynamic compilation' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-WsaEffectiveLanguageMode { 'Unavailable' }
            Test-WsaDynamicCompilationExpected | Should -BeFalse
        }
    }
}

Describe 'Native helper ConstrainedLanguage degradation' {
    It 'Get-LocalPasswordPolicy skips Add-Type and records the reason' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }
            Mock Add-Type { throw 'Add-Type must not be called' }
            Mock Get-Command -ParameterFilter { $Name -in @('secedit.exe', 'secedit') } { $null }
            $policy = Get-LocalPasswordPolicy -WarningVariable warnings -WarningAction SilentlyContinue

            $policy.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
            $policy.DynamicCompilationExpected | Should -BeFalse
            $policy.UnavailableReason | Should -Be 'ConstrainedLanguage'
            @($warnings).Count | Should -BeLessOrEqual 1
            Should -Invoke Add-Type -Times 0 -Exactly
        }
    }

    It 'Get-AuditPolicyTable skips Add-Type and records the reason once per operation' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }
            Mock Add-Type { throw 'Add-Type must not be called' }
            Mock Get-Command -ParameterFilter { $Name -in @('auditpol.exe', 'auditpol') } { $null }
            $table = Get-AuditPolicyTable -Subcategory 'Logon', 'Logoff', 'Process Creation' -Force -WarningVariable warnings -WarningAction SilentlyContinue

            $table.Count | Should -Be 3
            foreach ($entry in $table.Values) {
                $entry.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
                $entry.DynamicCompilationExpected | Should -BeFalse
                $entry.UnavailableReason | Should -Be 'ConstrainedLanguage'
            }
            @($warnings).Count | Should -BeLessOrEqual 1
            Should -Invoke Add-Type -Times 0 -Exactly
        }
    }

    It 'Get-WlanProfileList returns no records with an explicit unavailable reason and one warning' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }
            Mock Add-Type { throw 'Add-Type must not be called' }
            $profiles = @(Get-WlanProfileList -WarningVariable warnings -WarningAction SilentlyContinue)

            $profiles.Count | Should -Be 0
            $script:WlanProfileListStatus | Should -Be 'Unavailable'
            $script:WlanProfileListUnavailableReason | Should -Be 'ConstrainedLanguage'
            $script:WlanProfileListEffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
            $script:WlanProfileListDynamicCompilationExpected | Should -BeFalse
            @($warnings).Count | Should -Be 1
            Should -Invoke Add-Type -Times 0 -Exactly
        }
    }

    It 'Get-UsnJournalNative skips Add-Type and returns the reason with one warning' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }
            Mock Add-Type { throw 'Add-Type must not be called' }
            $native = Get-UsnJournalNative -WarningVariable warnings -WarningAction SilentlyContinue

            $native.Success | Should -BeFalse
            $native.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
            $native.DynamicCompilationExpected | Should -BeFalse
            $native.UnavailableReason | Should -Be 'ConstrainedLanguage'
            @($warnings).Count | Should -Be 1
            Should -Invoke Add-Type -Times 0 -Exactly
        }
    }

    It 'Get-UsnJournalCollection distinguishes ConstrainedLanguage in its fsutil fallback notes' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-UsnJournalNative {
                [PSCustomObject]@{
                    Records = @()
                    Success = $false
                    Error = 'Dynamic compilation is unavailable.'
                    Source = 'Native'
                    NextUsn = [long]0
                    Notes = @()
                    Incomplete = $false
                    UnavailableReason = 'ConstrainedLanguage'
                }
            }
            Mock Get-FsutilOutput { $script:FsutilLastExitCode = 0; return @() }
            Mock ConvertFrom-UsnJournalOutput { return @() }

            $collection = Get-UsnJournalCollection -DriveLetter C -Elevated
            $collection.Source | Should -Be 'Fsutil'
            @($collection.Notes | Where-Object { $_ -match 'ConstrainedLanguage' }).Count | Should -BeGreaterOrEqual 1
            Should -Invoke Get-FsutilOutput -Times 1 -Exactly
        }
    }

    It 'Export-MemoryDump degrades before ShouldProcess or process discovery' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($TestDrive)
            $previousOS = $env:OS
            try {
                $env:OS = 'WsaTestNonWindows'
                $outputPath = Join-Path $TestDrive 'constrained-dump'
                Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }
                Mock Add-Type { throw 'Add-Type must not be called' }
                Mock Get-Process { throw 'Get-Process must not be called' }
                Mock Write-Host { }

                $dump = Export-MemoryDump -ProcessId 123 -OutputPath $outputPath -WarningVariable warnings -WarningAction SilentlyContinue
                $dump.Success | Should -BeFalse
                $dump.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
                $dump.DynamicCompilationExpected | Should -BeFalse
                $dump.UnavailableReason | Should -Be 'ConstrainedLanguage'
                $dump.ErrorMessage | Should -Match 'requires FullLanguage'
                Test-Path -LiteralPath $outputPath | Should -BeFalse
                @($warnings).Count | Should -Be 1
                Should -Invoke Get-Process -Times 0 -Exactly
                Should -Invoke Add-Type -Times 0 -Exactly
            }
            finally {
                $env:OS = $previousOS
            }
        }
    }
}

Describe 'Language-mode-specific unavailable reasons' {
    It 'preserves <Mode> instead of relabeling it ConstrainedLanguage' -ForEach @(
        @{ Mode = 'NoLanguage' },
        @{ Mode = 'RestrictedLanguage' },
        @{ Mode = 'Unavailable' }
    ) {
        $mode = $_.Mode
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $mode, $TestDrive -ScriptBlock {
            param($Mode, $TestDrive)
            Mock Get-WsaEffectiveLanguageMode { $Mode }
            Mock Get-Command -ParameterFilter { $Name -in @('secedit.exe', 'secedit', 'auditpol.exe', 'auditpol') } { $null }
            Mock Get-Process { throw 'Get-Process must not be called' }
            Mock Write-Host { }

            $policy = Get-LocalPasswordPolicy -WarningAction SilentlyContinue
            $table = Get-AuditPolicyTable -Subcategory 'Logon' -Force -WarningAction SilentlyContinue
            $native = Get-UsnJournalNative -WarningAction SilentlyContinue
            $dump = Export-MemoryDump -ProcessId 123 -OutputPath (Join-Path $TestDrive $Mode) -WarningAction SilentlyContinue

            $policy.EffectiveLanguageMode | Should -Be $Mode
            $policy.UnavailableReason | Should -Be $Mode
            foreach ($entry in $table.Values) {
                $entry.EffectiveLanguageMode | Should -Be $Mode
                $entry.UnavailableReason | Should -Be $Mode
            }
            $native.EffectiveLanguageMode | Should -Be $Mode
            $native.UnavailableReason | Should -Be $Mode
            $dump.EffectiveLanguageMode | Should -Be $Mode
            $dump.UnavailableReason | Should -Be $Mode
            Should -Invoke Get-Process -Times 0 -Exactly
        }
    }
}

Describe 'External memory dump validation' {
    BeforeAll {
        function Invoke-ExternalDumpCase {
            param(
                [Parameter(Mandatory = $true)]
                [hashtable]$Case,

                [Parameter(Mandatory = $true)]
                [string]$TestDrive
            )

            InModuleScope -ModuleName $script:ModuleName -ArgumentList $Case, $TestDrive -ScriptBlock {
                param($Case, $TestDrive)
                $previousOS = $env:OS
                $previousSystemRoot = $env:SystemRoot
                try {
                    $env:OS = 'WsaTestNonWindows'
                    $env:SystemRoot = $TestDrive
                    $outputPath = Join-Path $TestDrive ($Case.Method + '-' + $Case.Scenario)
                    $dumpType = if ($Case.Method -eq 'ProcDump') { 'Mini' } else { 'LSASS' }
                    $processName = if ($Case.Method -eq 'ProcDump') { 'fixture' } else { 'lsass' }

                    Mock Get-WsaEffectiveLanguageMode { 'FullLanguage' }
                    Mock Test-WsaDynamicCompilationExpected { $false }
                    Mock Add-Type { throw 'Add-Type must not be called for external tool cases' }
                    Mock Get-Process { [PSCustomObject]@{ ProcessName = $processName; Id = 123 } }
                    Mock Write-Host { }
                    Mock Write-Warning { }
                    Mock Test-Path {
                        $targetPath = $Path
                        if ($null -ne $LiteralPath) { $targetPath = $LiteralPath }
                        if ($PathType -eq 'Leaf') {
                            [System.IO.File]::Exists($targetPath)
                        }
                        elseif ($PathType -eq 'Container') {
                            [System.IO.Directory]::Exists($targetPath)
                        }
                        else {
                            [System.IO.File]::Exists($targetPath) -or [System.IO.Directory]::Exists($targetPath)
                        }
                    }
                    Mock Test-Path -ParameterFilter {
                        $Path -in @('C:\Tools\procdump.exe', 'C:\Tools\procdump64.exe') -or
                        $Path -like '*comsvcs.dll'
                    } { $true }
                    Mock Invoke-WsaExternalDumpCommand {
                        $dumpPath = if ($Case.Method -eq 'ProcDump') { $ArgumentList[-1] } else { $ArgumentList[-2] }
                        $dumpPath = $dumpPath.Trim('"')
                        $exitCode = $null
                        $timedOut = $false
                        $errorMessage = $null

                        switch ($Case.Scenario) {
                            'NonzeroExit' {
                                [System.IO.File]::WriteAllBytes($dumpPath, [byte[]](0x4D, 0x44, 0x4D, 0x50))
                                $exitCode = 17
                            }
                            'Timeout' {
                                [System.IO.File]::WriteAllBytes($dumpPath, [byte[]](0x4D, 0x44, 0x4D, 0x50))
                                $timedOut = $true
                                $errorMessage = 'External dump command exceeded 1 seconds.'
                            }
                            'Empty' {
                                $exitCode = 0
                            }
                            'InvalidSignature' {
                                [System.IO.File]::WriteAllBytes($dumpPath, [byte[]](0x4E, 0x4F, 0x50, 0x45))
                                $exitCode = 0
                            }
                            'Valid' {
                                [System.IO.File]::WriteAllBytes($dumpPath, [byte[]](0x4D, 0x44, 0x4D, 0x50, 1, 2))
                                $exitCode = 0
                            }
                        }

                        New-Object PSObject -Property ([ordered]@{
                            ExitCode = $exitCode
                            Output = @()
                            TimedOut = $timedOut
                            ErrorMessage = $errorMessage
                        })
                    }

                    $parameters = @{
                        ProcessId = 123
                        DumpType = $dumpType
                        OutputPath = $outputPath
                        Confirm = $false
                        WarningAction = 'SilentlyContinue'
                    }
                    if ($Case.Method -eq 'ProcDump') { $parameters.UseProcDump = $true }
                    $dump = Export-MemoryDump @parameters

                    Should -Invoke Invoke-WsaExternalDumpCommand -Times 1 -Exactly
                    Should -Invoke Add-Type -Times 0 -Exactly
                    [PSCustomObject]@{
                        Result = $dump
                        OutputPath = $outputPath
                    }
                }
                finally {
                    $env:OS = $previousOS
                    $env:SystemRoot = $previousSystemRoot
                }
            }
        }
    }

    It '<Method> rejects <Scenario> and removes the failed artifact' -ForEach @(
        @{ Method = 'ProcDump'; Scenario = 'NonzeroExit' },
        @{ Method = 'ProcDump'; Scenario = 'Timeout' },
        @{ Method = 'ProcDump'; Scenario = 'Empty' },
        @{ Method = 'ProcDump'; Scenario = 'InvalidSignature' },
        @{ Method = 'comsvcs.dll'; Scenario = 'NonzeroExit' },
        @{ Method = 'comsvcs.dll'; Scenario = 'Timeout' },
        @{ Method = 'comsvcs.dll'; Scenario = 'Empty' },
        @{ Method = 'comsvcs.dll'; Scenario = 'InvalidSignature' }
    ) {
        $probe = Invoke-ExternalDumpCase -Case $_ -TestDrive $TestDrive
        $probe.Result.Success | Should -BeFalse
        $probe.Result.DumpFile | Should -BeNullOrEmpty
        switch ($_.Scenario) {
            'NonzeroExit' { $probe.Result.ErrorMessage | Should -Match "exited with code '17'" }
            'Timeout' { $probe.Result.ErrorMessage | Should -Match 'timed out' }
            'Empty' { $probe.Result.ErrorMessage | Should -Match 'Dump file is empty' }
            'InvalidSignature' { $probe.Result.ErrorMessage | Should -Match 'valid MDMP signature' }
        }
        @(Get-ChildItem -LiteralPath $probe.OutputPath -Filter '*.dmp' -File).Count | Should -Be 0
    }

    It '<Method> accepts a completed nonempty MDMP file' -ForEach @(
        @{ Method = 'ProcDump'; Scenario = 'Valid'; ExpectedMethod = 'ProcDump' },
        @{ Method = 'comsvcs.dll'; Scenario = 'Valid'; ExpectedMethod = 'comsvcs.dll' }
    ) {
        $probe = Invoke-ExternalDumpCase -Case $_ -TestDrive $TestDrive
        $probe.Result.Success | Should -BeTrue
        $probe.Result.Method | Should -Be $_.ExpectedMethod
        $probe.Result.FileSize | Should -BeGreaterThan 0
        $probe.Result.ErrorMessage | Should -BeNullOrEmpty
        Test-Path -LiteralPath $probe.Result.DumpFile | Should -BeTrue
        $signature = [System.IO.File]::ReadAllBytes($probe.Result.DumpFile)[0..3]
        [string]::Join('', @($signature | ForEach-Object { $_.ToString('X2') })) | Should -Be '4D444D50'
    }
}

Describe 'External dump command execution' {
    It 'captures a real nonzero native exit code' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            if ($env:OS -eq 'Windows_NT') {
                $filePath = "$env:SystemRoot\System32\cmd.exe"
                $arguments = @('/c', 'exit 17')
            }
            else {
                $filePath = '/bin/sh'
                $arguments = @('-c', 'exit 17')
            }

            $native = Invoke-WsaExternalDumpCommand -FilePath $filePath -ArgumentList $arguments -TimeoutSeconds 10
            $native.TimedOut | Should -BeFalse
            $native.ExitCode | Should -Be 17
            $native.ErrorMessage | Should -BeNullOrEmpty
        }
    }

    It 'reports a real native command timeout' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            if ($env:OS -eq 'Windows_NT') {
                $filePath = "$env:SystemRoot\System32\cmd.exe"
                $arguments = @('/c', 'ping -n 6 127.0.0.1 >nul')
            }
            else {
                $filePath = '/bin/sh'
                $arguments = @('-c', 'sleep 10')
            }

            $native = Invoke-WsaExternalDumpCommand -FilePath $filePath -ArgumentList $arguments -TimeoutSeconds 1
            $native.TimedOut | Should -BeTrue
            $native.ExitCode | Should -BeNullOrEmpty
            $native.ErrorMessage | Should -Match 'exceeded 1 seconds'
        }
    }
}

Describe 'Narrow JEA data files' {
    It 'role capability parses and exposes only the qualified scan wrapper' {
        $path = Join-Path $script:ModuleRoot 'RoleCapabilities/WindowsSecurityAudit.Scan.psrc'
        $parsed = Get-TestDataFile -Path $path
        $parsed.Errors.Count | Should -Be 0
        $parsed.Data.ModulesToImport | Should -Be @('WindowsSecurityAudit')
        @($parsed.Data.VisibleFunctions).Count | Should -Be 1
        $parsed.Data.VisibleFunctions[0] | Should -Be 'WindowsSecurityAudit\Invoke-WsaRemoteFunctionSet'
        $parsed.Data.VisibleFunctions[0] | Should -Not -Match '[*?]'
        $parsed.Data.ContainsKey('VisibleProviders') | Should -BeFalse
        $parsed.Data.ContainsKey('VisibleExternalCommands') | Should -BeFalse
    }

    It 'role capability contains no commands or dangerous exports' {
        $path = Join-Path $script:ModuleRoot 'RoleCapabilities/WindowsSecurityAudit.Scan.psrc'
        $parsed = Get-TestDataFile -Path $path
        $commands = @($parsed.Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true))
        $commands.Count | Should -Be 0
        $content = Get-Content -Path $path -Raw
        foreach ($forbidden in 'Add-Type', 'Invoke-Command', 'Export-MemoryDump', 'Invoke-SecurityRemediation', 'Set-SecurityBaseline', 'VisibleProviders', 'VisibleExternalCommands') {
            $content | Should -Not -Match ([regex]::Escape($forbidden))
        }
    }

    It 'sample session configuration parses with the restricted virtual-account endpoint' {
        $path = Join-Path $script:ModuleRoot 'JEA/WindowsSecurityAudit.Sample.pssc'
        $parsed = Get-TestDataFile -Path $path
        $parsed.Errors.Count | Should -Be 0
        $parsed.Data.SessionType | Should -Be 'RestrictedRemoteServer'
        $parsed.Data.RunAsVirtualAccount | Should -BeTrue
        $parsed.Data.TranscriptDirectory | Should -Be 'C:\ProgramData\JEAConfiguration\Transcripts'
        $parsed.Data.RoleDefinitions.ContainsKey('CONTOSO\WSA-Scan-Operators') | Should -BeTrue
        $parsed.Data.RoleDefinitions['CONTOSO\WSA-Scan-Operators'].RoleCapabilities | Should -Be 'WindowsSecurityAudit.Scan'
    }

    It 'publish staging includes the role and sample folders' {
        $workflow = Get-Content -Path (Join-Path $script:ModuleRoot '.github/workflows/publish.yml') -Raw
        $workflow | Should -Match "'RoleCapabilities'"
        $workflow | Should -Match "'JEA'"
    }
}

Describe 'Invoke-WsaRemoteFunctionSet' {
    It 'maps <FunctionSet> to the existing curated list and returns diagnostics' -ForEach $script:FunctionSetCases {
        $case = $_
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $case -ScriptBlock {
            param($Case)
            $allFunctions = @(
                'Get-SecurityBaseline', 'Get-DefenderStatus', 'Find-SuspiciousProcesses',
                'Find-PersistenceMechanisms', 'Get-SystemInfo', 'Get-CredentialAccessEvents',
                'Find-DefenseEvasion', 'Find-LateralMovement', 'Get-VulnerabilityAssessment'
            )
            foreach ($name in $allFunctions) {
                Mock $name { [PSCustomObject]@{ Source = 'Fixture' } }
            }
            Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }

            $output = Invoke-WsaRemoteFunctionSet -FunctionSet $Case.FunctionSet
            @($output.Results.Keys) | Should -Be $Case.Expected
            $output.Errors.Count | Should -Be 0
            $output.FunctionSet | Should -Be $Case.FunctionSet
            $output.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
            $output.DynamicCompilationExpected | Should -BeFalse
            foreach ($name in $Case.Expected) {
                Should -Invoke $name -Times 1 -Exactly
            }
        }
    }

    It 'returns per-function errors without stopping the remaining fixed set' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-SecurityBaseline { throw 'fixture failure' }
            Mock Get-DefenderStatus { [PSCustomObject]@{ Source = 'Fixture' } }
            $output = Invoke-WsaRemoteFunctionSet -FunctionSet Quick

            $output.Results.Contains('Get-DefenderStatus') | Should -BeTrue
            $output.Errors.Count | Should -Be 1
            $output.Errors[0] | Should -Match '^Get-SecurityBaseline: fixture failure'
        }
    }

    It 'rejects an arbitrary function set' {
        { Invoke-WsaRemoteFunctionSet -FunctionSet 'Get-SecurityBaseline' } | Should -Throw
    }

    It 'rejects <Name> instead of exposing an elevated primitive' -ForEach @(
        @{ Name = 'OutputPath'; Argument = 'C:\Temp' },
        @{ Name = 'ModulePath'; Argument = 'C:\Module' },
        @{ Name = 'FunctionName'; Argument = 'Get-Process' }
    ) {
        $parameters = @{ FunctionSet = 'Quick' }
        $parameters[$Name] = $Argument
        { Invoke-WsaRemoteFunctionSet @parameters } | Should -Throw
    }

    It 'rejects a ScriptBlock parameter' {
        { Invoke-WsaRemoteFunctionSet -FunctionSet Quick -ScriptBlock { Get-Process } } | Should -Throw
    }
}

Describe 'Invoke-EnterpriseSecurityScan preinstalled JEA mode' {
    It 'requires UseModuleFunctions' {
        $targetComputer = 'srv1'
        { Invoke-EnterpriseSecurityScan -ComputerName $targetComputer -ConfigurationName 'WindowsSecurityAudit' -OutputPath $TestDrive -ErrorAction Stop } |
            Should -Throw '*UseModuleFunctions*'
    }

    It 'rejects ModulePath instead of silently ignoring it' {
        $targetComputer = 'srv1'
        {
            Invoke-EnterpriseSecurityScan -ComputerName $targetComputer -UseModuleFunctions -ConfigurationName 'WindowsSecurityAudit' -ModulePath $script:ModuleRoot -OutputPath $TestDrive -ErrorAction Stop
        } | Should -Throw '*ModulePath*'
    }

    It 'propagates ConfigurationName and invokes only the literal <FunctionSet> command without deployment' -ForEach $script:FunctionSetCases {
        $case = $_
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $case, $TestDrive -ScriptBlock {
            param($Case, $TestDrive)
            $targetComputer = 'srv1'
            $sessionCapture = Join-Path $TestDrive "session-$($Case.FunctionSet).txt"
            $commandCapture = Join-Path $TestDrive "command-$($Case.FunctionSet).txt"
            $sessionCaptureLiteral = $sessionCapture.Replace("'", "''")
            $commandCaptureLiteral = $commandCapture.Replace("'", "''")

            function Test-Connection { $true }
            Set-Item -Path 'Function:\New-PSSession' -Value ([scriptblock]::Create(@"
param(`$ComputerName, `$Credential, `$ConfigurationName, `$ErrorAction)
Set-Content -LiteralPath '$sessionCaptureLiteral' -Value "`$ComputerName|`$ConfigurationName"
[PSCustomObject]@{ ComputerName = `$ComputerName; ConfigurationName = `$ConfigurationName }
"@))
            Set-Item -Path 'Function:\Invoke-Command' -Value ([scriptblock]::Create(@"
param(`$Session, `$ScriptBlock, `$ErrorAction, `$ArgumentList)
Set-Content -LiteralPath '$commandCaptureLiteral' -Value `$ScriptBlock.ToString()
[PSCustomObject]@{
    Results = [ordered]@{ 'Get-SecurityBaseline' = [PSCustomObject]@{ Findings = @() } }
    Errors = @()
    EffectiveLanguageMode = 'ConstrainedLanguage'
    DynamicCompilationExpected = `$false
}
"@))
            function Copy-Item { throw 'Copy-Item must not run in JEA mode' }
            function Remove-PSSession { }
            Mock Compress-Archive { throw 'Compress-Archive must not run in JEA mode' }

            $scan = Invoke-EnterpriseSecurityScan -ComputerName $targetComputer -UseModuleFunctions -ConfigurationName 'WindowsSecurityAudit' -RemoteFunctionSet $Case.FunctionSet -OutputPath $TestDrive -ErrorAction Stop
            $system = @($scan.SystemResults)[0]
            $system.Status | Should -Be 'Success'
            $system.Details.ExecutionMode | Should -Be 'PreinstalledJea'
            $system.Details.ConfigurationName | Should -Be 'WindowsSecurityAudit'
            $system.Details.ModuleDeployed | Should -BeFalse
            $system.Details.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
            $system.Details.DynamicCompilationExpected | Should -BeFalse

            (Get-Content -LiteralPath $sessionCapture -Raw).Trim() | Should -Be 'srv1|WindowsSecurityAudit'
            (Get-Content -LiteralPath $commandCapture -Raw).Trim() | Should -BeExactly "Invoke-WsaRemoteFunctionSet -FunctionSet $($Case.FunctionSet)"
            Should -Invoke Compress-Archive -Times 0 -Exactly
        }
    }

    It 'WhatIf creates neither a session nor a package' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($TestDrive)
            $targetComputer = 'srv1'
            Mock Test-Connection { throw 'Test-Connection must not run for WhatIf' }
            Mock New-PSSession { throw 'New-PSSession must not run for WhatIf' }
            Mock Invoke-Command { throw 'Invoke-Command must not run for WhatIf' }
            Mock Copy-Item { throw 'Copy-Item must not run for WhatIf' }
            Mock Compress-Archive { throw 'Compress-Archive must not run for WhatIf' }

            $scan = Invoke-EnterpriseSecurityScan -ComputerName $targetComputer -UseModuleFunctions -ConfigurationName 'WindowsSecurityAudit' -RemoteFunctionSet Deep -OutputPath $TestDrive -WhatIf -ErrorAction Stop
            $system = @($scan.SystemResults)[0]
            $system.Status | Should -Be 'WhatIf'
            $system.Details.ExecutionMode | Should -Be 'PreinstalledJea'
            $system.Details.ConfigurationName | Should -Be 'WindowsSecurityAudit'
            $system.Details.ModuleDeployed | Should -BeFalse
            Should -Invoke Test-Connection -Times 0 -Exactly
            Should -Invoke New-PSSession -Times 0 -Exactly
            Should -Invoke Invoke-Command -Times 0 -Exactly
            Should -Invoke Copy-Item -Times 0 -Exactly
            Should -Invoke Compress-Archive -Times 0 -Exactly
        }
    }
}
