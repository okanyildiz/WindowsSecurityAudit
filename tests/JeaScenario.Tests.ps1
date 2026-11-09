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

    It 'Export-MemoryDump skips Add-Type and fails explicitly when no external fallback applies' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($TestDrive)
            $previousOS = $env:OS
            try {
                $env:OS = 'WsaTestNonWindows'
                Mock Get-WsaEffectiveLanguageMode { 'ConstrainedLanguage' }
                Mock Add-Type { throw 'Add-Type must not be called' }
                Mock Get-Process { [PSCustomObject]@{ ProcessName = 'fixture'; Id = 123 } }
                Mock Test-Path { $true }
                Mock Write-Host { }

                $dump = Export-MemoryDump -ProcessId 123 -OutputPath (Join-Path $TestDrive 'dump') -WarningVariable warnings -WarningAction SilentlyContinue
                $dump.Success | Should -BeFalse
                $dump.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
                $dump.DynamicCompilationExpected | Should -BeFalse
                $dump.UnavailableReason | Should -Be 'ConstrainedLanguage'
                $dump.ErrorMessage | Should -Match 'dynamic compilation'
                @($warnings).Count | Should -Be 1
                Should -Invoke Add-Type -Times 0 -Exactly
            }
            finally {
                $env:OS = $previousOS
            }
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
