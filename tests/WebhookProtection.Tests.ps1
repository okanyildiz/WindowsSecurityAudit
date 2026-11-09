#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeDiscovery {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:IsWindowsHost = [bool]$IsWindows
    }
    else {
        $script:IsWindowsHost = ($env:OS -eq 'Windows_NT')
    }
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"
    $script:ModuleManifest = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psd1"
    $script:TestWebhookUrl = 'https://hooks.example.test/services/T0P-S3CR3T-0123456789'
    $script:TestProtectedValue = 'wsa-dpapi-lm-v1:Q0lQSEVSLVZFUlNJT04tMDE='

    Import-Module -Name $script:ModulePath -Force
    InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
        foreach ($commandName in @(
            'New-ScheduledTaskTrigger', 'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal',
            'New-ScheduledTaskSettingsSet', 'Register-ScheduledTask'
        )) {
            if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                Set-Item -Path "Function:\script:$commandName" -Value { }
            }
        }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'DPAPI protected-text parsing' {
    It 'parses the versioned LocalMachine marker and context without invoking DPAPI' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestProtectedValue -ScriptBlock {
            param($protectedValue)
            $parsed = ConvertFrom-WsaDpapiProtectedText -ProtectedText $protectedValue
            $parsed.Marker | Should -Be 'wsa-dpapi-lm-v1:'
            $parsed.Scope | Should -Be 'LocalMachine'
            $parsed.Version | Should -Be 1
            $parsed.Context | Should -Be 'WindowsSecurityAudit/ScheduledScan/Webhook/v1'
            [System.Convert]::ToBase64String($parsed.CipherBytes) | Should -Be 'Q0lQSEVSLVZFUlNJT04tMDE='
        }
    }

    It 'rejects a CurrentUser or otherwise wrong-scope marker' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            { ConvertFrom-WsaDpapiProtectedText -ProtectedText 'wsa-dpapi-cu-v1:QQ==' } |
                Should -Throw '*Unsupported DPAPI protection marker*'
            { ConvertFrom-WsaDpapiProtectedText -ProtectedText 'wsa-dpapi-lm-v2:QQ==' } |
                Should -Throw '*Unsupported DPAPI protection marker*'
        }
    }

    It 'rejects invalid Base64 and never treats unmarked input as plaintext' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl -ScriptBlock {
            param($plainText)
            { ConvertFrom-WsaDpapiProtectedText -ProtectedText 'wsa-dpapi-lm-v1:%%%not-base64%%%' } |
                Should -Throw '*not valid Base64*'
            { ConvertFrom-WsaDpapiProtectedText -ProtectedText $plainText } |
                Should -Throw '*Unsupported DPAPI protection marker*'
        }
    }

    It 'reports DPAPI as unavailable on non-Windows hosts' -Skip:$script:IsWindowsHost {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            { Protect-WsaDpapiData -PlainText 'not-written' } | Should -Throw '*only available on Windows*'
            { Unprotect-WsaDpapiData -ProtectedText 'wsa-dpapi-lm-v1:QQ==' } |
                Should -Throw '*only available on Windows*'
        }
    }
}

Describe 'Scheduled scan webhook protection' {
    It 'generates ciphertext-only DPAPI scripts and never emits the plaintext URL' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $script:TestProtectedValue, $TestDrive -ScriptBlock {
            param($expectedUrl, $protectedValue, $testRoot)
            Mock Protect-WsaDpapiData { $protectedValue }
            Mock New-ScheduledTaskTrigger { [PSCustomObject]@{} }
            Mock New-ScheduledTaskAction { [PSCustomObject]@{} }
            Mock New-ScheduledTaskPrincipal { [PSCustomObject]@{} }
            Mock New-ScheduledTaskSettingsSet { [PSCustomObject]@{} }
            Mock Register-ScheduledTask { }

            $outputPath = Join-Path $testRoot 'DpapiRegistration'
            $savedOs = $env:OS
            try {
                $env:OS = 'NotWindows'
                $hostOutput = @()
                $warningOutput = @()
                $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -Confirm:$false -InformationVariable +hostOutput -WarningVariable +warningOutput
            }
            finally {
                $env:OS = $savedOs
            }

            $scanContent = Get-Content -Path $result.ScriptPath -Raw
            $consoleText = (@($hostOutput) + @($warningOutput) | Out-String)
            $scanContent.Contains($expectedUrl) | Should -BeFalse
            $scanContent.Contains($protectedValue) | Should -BeTrue
            $consoleText.Contains($expectedUrl) | Should -BeFalse
            ($result | ConvertTo-Json -Depth 5).Contains($expectedUrl) | Should -BeFalse
            $result.WebhookProtection | Should -Be 'DpapiLocalMachine'
            $result.PSObject.Properties.Name | Should -Not -Contain 'WebhookUrl'
            $result.PSObject.Properties.Name | Should -Not -Contain 'WebhookSecret'
            Should -Invoke Protect-WsaDpapiData -Times 1 -Exactly -ParameterFilter { $PlainText -eq $expectedUrl }
            Get-ChildItem -Path $outputPath -Filter '*.tmp' -File | Should -BeNullOrEmpty
        }
    }

    It 'accepts WebhookSecret and converts it only for the mocked protector' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $script:TestProtectedValue, $TestDrive -ScriptBlock {
            param($expectedUrl, $protectedValue, $testRoot)
            Mock Protect-WsaDpapiData { $protectedValue }
            Mock New-ScheduledTaskTrigger { [PSCustomObject]@{} }
            Mock New-ScheduledTaskAction { [PSCustomObject]@{} }
            Mock New-ScheduledTaskPrincipal { [PSCustomObject]@{} }
            Mock New-ScheduledTaskSettingsSet { [PSCustomObject]@{} }
            Mock Register-ScheduledTask { }

            $secret = [System.Security.SecureString]::new()
            foreach ($character in $expectedUrl.ToCharArray()) {
                $secret.AppendChar($character)
            }
            $secret.MakeReadOnly()
            $outputPath = Join-Path $testRoot 'SecretRegistration'
            $savedOs = $env:OS
            try {
                $env:OS = 'NotWindows'
                $hostOutput = @()
                $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookSecret $secret -Confirm:$false -InformationVariable +hostOutput
            }
            finally {
                $env:OS = $savedOs
                $secret.Dispose()
            }

            (Get-Content -Path $result.ScriptPath -Raw).Contains($expectedUrl) | Should -BeFalse
            (@($hostOutput) | Out-String).Contains($expectedUrl) | Should -BeFalse
            $result.WebhookProtection | Should -Be 'DpapiLocalMachine'
            Should -Invoke Protect-WsaDpapiData -Times 1 -Exactly -ParameterFilter { $PlainText -eq $expectedUrl }
        }
    }

    It 'rejects WebhookUrl and WebhookSecret together' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $TestDrive -ScriptBlock {
            param($expectedUrl, $testRoot)
            $secret = [System.Security.SecureString]::new()
            foreach ($character in $expectedUrl.ToCharArray()) {
                $secret.AppendChar($character)
            }
            $secret.MakeReadOnly()
            try {
                { Register-ScheduledSecurityScan -OutputPath (Join-Path $testRoot 'Rejected') -WebhookUrl $expectedUrl -WebhookSecret $secret -WhatIf } |
                    Should -Throw '*either WebhookUrl or WebhookSecret*'
            }
            finally {
                $secret.Dispose()
            }
        }
    }

    It 'fails registration without downgrading when DPAPI protection fails' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $TestDrive -ScriptBlock {
            param($expectedUrl, $testRoot)
            Mock Protect-WsaDpapiData { throw 'Simulated DPAPI failure' }
            Mock Register-ScheduledTask { }
            $outputPath = Join-Path $testRoot 'FailedProtection'
            $savedOs = $env:OS
            try {
                $env:OS = 'NotWindows'
                { Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -Confirm:$false -ErrorAction SilentlyContinue } |
                    Should -Throw '*aborted without plaintext fallback*'
            }
            finally {
                $env:OS = $savedOs
            }

            Test-Path -Path $outputPath | Should -BeFalse
            Should -Invoke Register-ScheduledTask -Times 0 -Exactly
        }
    }

    It 'WhatIf emits no URL or ciphertext and creates no secret-bearing file' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $script:TestProtectedValue, $TestDrive -ScriptBlock {
            param($expectedUrl, $protectedValue, $testRoot)
            Mock Protect-WsaDpapiData { $protectedValue }
            $outputPath = Join-Path $testRoot 'WhatIfRegistration'
            $hostOutput = @()
            $warningOutput = @()
            $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -WhatIf -InformationVariable +hostOutput -WarningVariable +warningOutput

            $allOutput = (@($hostOutput) + @($warningOutput) + @($result) | Out-String)
            $allOutput.Contains($expectedUrl) | Should -BeFalse
            $allOutput.Contains($protectedValue) | Should -BeFalse
            $allOutput.Contains('wsa-dpapi-lm-v1:') | Should -BeFalse
            $result.Status | Should -Be 'WhatIf'
            $result.WebhookProtection | Should -Be 'DpapiLocalMachine'
            Test-Path -Path $outputPath | Should -BeFalse
            Should -Invoke Protect-WsaDpapiData -Times 0 -Exactly
        }
    }

    It 'PlainText is an explicit compatibility mode with a loud warning' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $TestDrive -ScriptBlock {
            param($expectedUrl, $testRoot)
            Mock Protect-WsaDpapiData { 'must-not-be-used' }
            Mock New-ScheduledTaskTrigger { [PSCustomObject]@{} }
            Mock New-ScheduledTaskAction { [PSCustomObject]@{} }
            Mock New-ScheduledTaskPrincipal { [PSCustomObject]@{} }
            Mock New-ScheduledTaskSettingsSet { [PSCustomObject]@{} }
            Mock Register-ScheduledTask { }

            $outputPath = Join-Path $testRoot 'PlainTextRegistration'
            $savedOs = $env:OS
            try {
                $env:OS = 'NotWindows'
                $warningOutput = @()
                $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -WebhookProtection PlainText -Confirm:$false -WarningVariable +warningOutput
            }
            finally {
                $env:OS = $savedOs
            }

            (@($warningOutput) | Out-String) | Should -Match 'SECURITY WARNING: WebhookProtection PlainText'
            (Get-Content -Path $result.ScriptPath -Raw).Contains($expectedUrl) | Should -BeTrue
            $result.WebhookProtection | Should -Be 'PlainText'
            Should -Invoke Protect-WsaDpapiData -Times 0 -Exactly
        }
    }

    It 'continues scanning after decryption failure without plaintext fallback or webhook delivery' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $script:TestProtectedValue, $script:ModuleManifest, $TestDrive -ScriptBlock {
            param($expectedUrl, $protectedValue, $moduleManifest, $testRoot)
            Mock Protect-WsaDpapiData { $protectedValue }
            Mock New-ScheduledTaskTrigger { [PSCustomObject]@{} }
            Mock New-ScheduledTaskAction { [PSCustomObject]@{} }
            Mock New-ScheduledTaskPrincipal { [PSCustomObject]@{} }
            Mock New-ScheduledTaskSettingsSet { [PSCustomObject]@{} }
            Mock Register-ScheduledTask { }

            $outputPath = Join-Path $testRoot 'DecryptionFailure'
            $savedOs = $env:OS
            try {
                $env:OS = 'NotWindows'
                $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -Confirm:$false
            }
            finally {
                $env:OS = $savedOs
            }

            $mockModulePath = Join-Path $testRoot 'WindowsSecurityAudit.psm1'
            $mockModuleContent = @'
function Invoke-SecurityAssessment {
    param($AssessmentType, $OutputPath)
    [PSCustomObject]@{
        OverallScore = 0
        Findings = @(
            [PSCustomObject]@{ Category = 'Test'; Finding = 'Synthetic critical finding'; Severity = 'Critical' }
        )
    }
}
function Unprotect-WsaDpapiData {
    param($ProtectedText)
    throw "Simulated decryption failure for $ProtectedText"
}
function Invoke-RestMethod {
    throw 'Unexpected webhook delivery after decryption failure.'
}
Export-ModuleMember -Function Invoke-SecurityAssessment, Invoke-RestMethod
'@
            Set-Content -Path $mockModulePath -Value $mockModuleContent -Encoding UTF8
            $originalModuleLine = "`$modulePath = '$($moduleManifest -replace "'", "''")'"
            $mockModuleLine = "`$modulePath = '$($mockModulePath -replace "'", "''")'"
            $scanContent = Get-Content -Path $result.ScriptPath -Raw
            $scanContent = $scanContent.Replace($originalModuleLine, $mockModuleLine)
            Set-Content -Path $result.ScriptPath -Value $scanContent -Encoding UTF8

            $powerShellPath = (Get-Process -Id $PID).Path
            $childOutput = (& $powerShellPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $result.ScriptPath 2>&1 | Out-String)
            $LASTEXITCODE | Should -Be 0 -Because $childOutput
            $childOutput | Should -Match 'Webhook decryption failed; webhook delivery is disabled for this run.'
            $childOutput.Contains($protectedValue) | Should -BeFalse
            $childOutput.Contains($expectedUrl) | Should -BeFalse
            $childOutput | Should -Not -Match 'Failed to send webhook alert'

            $summaryFile = Get-ChildItem -Path $outputPath -Filter 'RunSummary.json' -Recurse -File | Select-Object -First 1
            $summaryFile | Should -Not -BeNullOrEmpty
            $summary = Get-Content -Path $summaryFile.FullName -Raw | ConvertFrom-Json
            $summary.AlertSent | Should -BeFalse
            $summary.CriticalFindings | Should -Be 1
        }
    }
}
