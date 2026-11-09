#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath 'WindowsSecurityAudit.psd1'
    $pwshCommand = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -ne $pwshCommand) {
        $script:PwshPath = $pwshCommand.Source
    }
    elseif ($PSVersionTable.PSEdition -eq 'Core') {
        $script:PwshPath = (Get-Process -Id $PID).Path
    }
    else {
        throw 'The real ConstrainedLanguage tests require pwsh.'
    }

    function Invoke-ConstrainedProbe {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet('Wrapper', 'Password', 'Audit', 'Usn', 'Dump')]
            [string]$Name
        )

        $modulePathLiteral = $script:ModulePath.Replace("'", "''")
        $probeScript = @'
$probeResult = New-Object PSObject -Property ([ordered]@{
    Returned = $false
    Value = $null
    Error = $null
    OutputDirectoryCreated = $null
})
$outputPath = Join-Path (Get-Location) ('clm-test-' + (New-Guid).Guid)
try {
    $ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
    Import-Module '__MODULE_PATH__' -Force -WarningAction SilentlyContinue -ErrorAction Stop
    $module = Get-Module WindowsSecurityAudit
    & $module {
        function script:Get-SecurityBaseline {
            New-Object PSObject -Property ([ordered]@{ Source = 'Fixture' })
        }
        function script:Get-DefenderStatus {
            New-Object PSObject -Property ([ordered]@{ Source = 'Fixture' })
        }
    }

    $value = switch ('__PROBE_NAME__') {
        'Wrapper' { Invoke-WsaRemoteFunctionSet -FunctionSet Quick }
        'Password' { & $module { Get-LocalPasswordPolicy -WarningAction SilentlyContinue } }
        'Audit' { & $module { Get-AuditPolicyTable -Subcategory 'Logon' -Force -WarningAction SilentlyContinue } }
        'Usn' { & $module { Get-UsnJournalNative -WarningAction SilentlyContinue } }
        'Dump' { Export-MemoryDump -ProcessId 123 -OutputPath $outputPath -WarningAction SilentlyContinue }
    }
    $probeResult.Value = $value
    $probeResult.Returned = $true
    if ('__PROBE_NAME__' -eq 'Dump') {
        $probeResult.OutputDirectoryCreated = Test-Path -LiteralPath $outputPath
    }
}
catch {
    $probeResult.Error = $_.Exception.Message
}
$probeResult | ConvertTo-Json -Depth 8 -Compress
'@
        $probeScript = $probeScript.Replace('__MODULE_PATH__', $modulePathLiteral).Replace('__PROBE_NAME__', $Name)
        $output = @(& $script:PwshPath -NoLogo -NoProfile -Command $probeScript 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Constrained pwsh exited with code ${LASTEXITCODE}: $($output -join [Environment]::NewLine)"
        }

        $json = ($output -join [Environment]::NewLine)
        try {
            return ($json | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            throw "Constrained probe '$Name' did not return JSON: $json"
        }
    }
}

Describe 'Real ConstrainedLanguage execution' {
    It 'runs the curated wrapper and returns both fixture results' {
        $probe = Invoke-ConstrainedProbe -Name Wrapper
        $probe.Error | Should -BeNullOrEmpty
        $probe.Returned | Should -BeTrue
        $probe.Value.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
        $probe.Value.DynamicCompilationExpected | Should -BeFalse
        @($probe.Value.Errors).Count | Should -Be 0
        @($probe.Value.Results.PSObject.Properties.Name) | Should -Be @('Get-SecurityBaseline', 'Get-DefenderStatus')
        $probe.Value.Results.'Get-SecurityBaseline'.Source | Should -Be 'Fixture'
        $probe.Value.Results.'Get-DefenderStatus'.Source | Should -Be 'Fixture'
    }

    It 'returns the local password policy diagnostic object without crashing' {
        $probe = Invoke-ConstrainedProbe -Name Password
        $probe.Error | Should -BeNullOrEmpty
        $probe.Returned | Should -BeTrue
        $probe.Value.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
        $probe.Value.DynamicCompilationExpected | Should -BeFalse
        $probe.Value.UnavailableReason | Should -Be 'ConstrainedLanguage'
        $probe.Value.Source | Should -Not -BeNullOrEmpty
    }

    It 'returns an audit policy entry without invoking prohibited bound-parameter methods' {
        $probe = Invoke-ConstrainedProbe -Name Audit
        $probe.Error | Should -BeNullOrEmpty
        $probe.Returned | Should -BeTrue
        $entry = @($probe.Value.PSObject.Properties)[0].Value
        $entry.Name | Should -Be 'Logon'
        $entry.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
        $entry.DynamicCompilationExpected | Should -BeFalse
        $entry.UnavailableReason | Should -Be 'ConstrainedLanguage'
        $entry.Source | Should -Not -BeNullOrEmpty
    }

    It 'returns the native USN unavailable result without crashing' {
        $probe = Invoke-ConstrainedProbe -Name Usn
        $probe.Error | Should -BeNullOrEmpty
        $probe.Returned | Should -BeTrue
        $probe.Value.Success | Should -BeFalse
        $probe.Value.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
        $probe.Value.DynamicCompilationExpected | Should -BeFalse
        $probe.Value.UnavailableReason | Should -Be 'ConstrainedLanguage'
        $probe.Value.Error | Should -Match 'initialization failed'
    }

    It 'degrades memory dump acquisition before creating its output directory' {
        $probe = Invoke-ConstrainedProbe -Name Dump
        $probe.Error | Should -BeNullOrEmpty
        $probe.Returned | Should -BeTrue
        $probe.Value.Success | Should -BeFalse
        $probe.Value.EffectiveLanguageMode | Should -Be 'ConstrainedLanguage'
        $probe.Value.DynamicCompilationExpected | Should -BeFalse
        $probe.Value.UnavailableReason | Should -Be 'ConstrainedLanguage'
        $probe.Value.ErrorMessage | Should -Match 'requires FullLanguage'
        $probe.OutputDirectoryCreated | Should -BeFalse
    }
}
