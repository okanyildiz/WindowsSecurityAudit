#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeDiscovery {
    $script:IsWindowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
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
        $commandDefinitions = @{
            'New-ScheduledTaskTrigger' = { param([switch]$Daily, [switch]$Weekly, $DaysOfWeek, $At) }
            'New-ScheduledTaskAction' = { param($Execute, $Argument) }
            'New-ScheduledTaskPrincipal' = { param($UserId, $LogonType, $RunLevel) }
            'New-ScheduledTaskSettingsSet' = { param([switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries) }
            'Register-ScheduledTask' = { param($TaskName, $Action, $Trigger, $Principal, $Settings, $Description, $Force, $ErrorAction) }
        }
        foreach ($commandName in $commandDefinitions.Keys) {
            if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                Set-Item -Path "Function:\script:$commandName" -Value $commandDefinitions[$commandName]
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
            Mock Register-WsaScheduledTask { }

            $outputPath = Join-Path $testRoot 'DpapiRegistration'
            $hostOutput = @()
            $warningOutput = @()
            $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -Confirm:$false -InformationVariable +hostOutput -WarningVariable +warningOutput

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
            Mock Register-WsaScheduledTask { }

            $secret = [System.Security.SecureString]::new()
            foreach ($character in $expectedUrl.ToCharArray()) {
                $secret.AppendChar($character)
            }
            $secret.MakeReadOnly()
            $outputPath = Join-Path $testRoot 'SecretRegistration'
            $hostOutput = @()
            try {
                $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookSecret $secret -Confirm:$false -InformationVariable +hostOutput
            }
            finally {
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
            Mock Register-WsaScheduledTask { }
            $outputPath = Join-Path $testRoot 'FailedProtection'
            { Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -Confirm:$false -ErrorAction SilentlyContinue } |
                Should -Throw '*aborted without plaintext fallback*'

            Test-Path -Path $outputPath | Should -BeFalse
            Should -Invoke Register-WsaScheduledTask -Times 0 -Exactly
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
            Mock Register-WsaScheduledTask { }

            $outputPath = Join-Path $testRoot 'PlainTextRegistration'
            $warningOutput = @()
            $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -WebhookProtection PlainText -Confirm:$false -WarningVariable +warningOutput

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
            Mock Register-WsaScheduledTask { }

            $outputPath = Join-Path $testRoot 'DecryptionFailure'
            $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -Confirm:$false

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

Describe 'Scheduled scan replacement protection' {
    It 'forwards the task name, action, SYSTEM principal, settings, and description' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($testRoot)
            Mock New-ScheduledTaskTrigger {
                [PSCustomObject]@{
                    Daily = [bool]$Daily
                    Weekly = [bool]$Weekly
                    DaysOfWeek = $DaysOfWeek
                    At = $At
                }
            }
            Mock New-ScheduledTaskAction {
                [PSCustomObject]@{ Execute = $Execute; Argument = $Argument }
            }
            Mock New-ScheduledTaskPrincipal {
                [PSCustomObject]@{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel }
            }
            Mock New-ScheduledTaskSettingsSet {
                [PSCustomObject]@{
                    StartWhenAvailable = [bool]$StartWhenAvailable
                    AllowStartIfOnBatteries = [bool]$AllowStartIfOnBatteries
                    DontStopIfGoingOnBatteries = [bool]$DontStopIfGoingOnBatteries
                }
            }
            Mock Register-WsaScheduledTask { }

            $outputPath = Join-Path $testRoot 'TaskForwarding'
            $expectedScriptPath = Join-Path $outputPath 'Invoke-ScheduledSecurityScan.ps1'
            $expectedActionArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$expectedScriptPath`""
            $expectedDescription = 'WindowsSecurityAudit Full scan (Advanced) runs every day at 22:30. Alerts on Critical findings (alert dedup: on, re-alert after 14 days). Managed by Register-ScheduledSecurityScan.'
            $result = Register-ScheduledSecurityScan -OutputPath $outputPath -ScanType Full -Frequency Daily -Time '22:30' -RealertAfterDays 14 -Confirm:$false

            $result.Status | Should -Be 'Registered'
            Should -Invoke New-ScheduledTaskAction -Times 1 -Exactly -ParameterFilter {
                $Execute -eq 'powershell.exe' -and $Argument -eq $expectedActionArgs
            }
            Should -Invoke New-ScheduledTaskPrincipal -Times 1 -Exactly -ParameterFilter {
                $UserId -eq 'SYSTEM' -and $LogonType -eq 'ServiceAccount' -and $RunLevel -eq 'Highest'
            }
            Should -Invoke New-ScheduledTaskSettingsSet -Times 1 -Exactly -ParameterFilter {
                $StartWhenAvailable -and $AllowStartIfOnBatteries -and $DontStopIfGoingOnBatteries
            }
            Should -Invoke Register-WsaScheduledTask -Times 1 -Exactly -ParameterFilter {
                $TaskName -eq 'WindowsSecurityAudit-ScheduledScan' -and
                $Action.Execute -eq 'powershell.exe' -and
                $Action.Argument -eq $expectedActionArgs -and
                $Trigger.Daily -and
                $Principal.UserId -eq 'SYSTEM' -and
                $Principal.LogonType -eq 'ServiceAccount' -and
                $Principal.RunLevel -eq 'Highest' -and
                $Settings.StartWhenAvailable -and
                $Settings.AllowStartIfOnBatteries -and
                $Settings.DontStopIfGoingOnBatteries -and
                $Description -eq $expectedDescription
            }
        }
    }

    It 'restores the known-good script when the replacement move fails' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($testRoot)
            Mock Register-WsaScheduledTask { }
            Mock Move-Item {
                if ($Path -like '*.tmp') {
                    throw 'Simulated replacement move failure'
                }
            }

            $outputPath = Join-Path $testRoot 'MoveFailure'
            $null = New-Item -Path $outputPath -ItemType Directory -Force
            $scriptPath = Join-Path $outputPath 'Invoke-ScheduledSecurityScan.ps1'
            $knownGoodContent = "# Known-good scheduled scan`n"
            Set-Content -Path $scriptPath -Value $knownGoodContent -NoNewline

            { Register-ScheduledSecurityScan -OutputPath $outputPath -Confirm:$false -ErrorAction SilentlyContinue } |
                Should -Throw '*Simulated replacement move failure*'

            Get-Content -Path $scriptPath -Raw | Should -Be $knownGoodContent
            @(Get-ChildItem -Path $outputPath -Filter '*.tmp' -File).Count | Should -Be 0
            @(Get-ChildItem -Path $outputPath -Filter '*.bak' -File).Count | Should -Be 0
            Should -Invoke Move-Item -Times 1 -Exactly -ParameterFilter {
                $Path -like '*.tmp' -and $Destination -eq $scriptPath
            }
            Should -Invoke Register-WsaScheduledTask -Times 0 -Exactly
        }
    }

    It 'quarantines the replacement and restores the backup after post-rename ACL failure' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($testRoot)
            Mock Register-WsaScheduledTask { }
            Mock Write-Warning { }
            Mock Test-AdminOnlyOwnership { $true }
            $script:failScriptWriteCheck = $true
            Mock Test-NoNonAdminWriteAccess {
                if ($Path -eq $scriptPath -and $script:failScriptWriteCheck) {
                    $script:failScriptWriteCheck = $false
                    return $false
                }
                return $true
            }

            $outputPath = Join-Path $testRoot 'PostRenameAclFailure'
            $null = New-Item -Path $outputPath -ItemType Directory -Force
            $scriptPath = Join-Path $outputPath 'Invoke-ScheduledSecurityScan.ps1'
            $knownGoodContent = "# Known-good scheduled scan`n"
            Set-Content -Path $scriptPath -Value $knownGoodContent -NoNewline

            { Register-ScheduledSecurityScan -OutputPath $outputPath -Confirm:$false -ErrorAction SilentlyContinue } |
                Should -Throw '*Post-rename verification failed*'

            Get-Content -Path $scriptPath -Raw | Should -Be $knownGoodContent
            $quarantineFiles = @(Get-ChildItem -Path $outputPath -Filter '*.quarantine' -File)
            $quarantineFiles.Count | Should -Be 1
            Get-Content -Path $quarantineFiles[0].FullName -Raw | Should -Match 'Generated by Register-ScheduledSecurityScan'
            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
                $Message -like 'Unverified replacement scan script quarantined*'
            }
            @(Get-ChildItem -Path $outputPath -Filter '*.bak' -File).Count | Should -Be 0
            $script:failScriptWriteCheck | Should -BeFalse
            Should -Invoke Register-WsaScheduledTask -Times 0 -Exactly
        }
    }

    It 'warns and verifies the residual ACL when temporary-file cleanup fails' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($testRoot)
            Mock Register-WsaScheduledTask { }
            Mock Write-Warning { }
            Mock Move-Item { throw 'Simulated move failure for cleanup test' }
            Mock Remove-Item {
                if ($Path -like '*.tmp') {
                    throw 'Simulated cleanup failure'
                }
            }
            Mock Test-AdminOnlyOwnership { $true }
            Mock Test-NoNonAdminWriteAccess { $true }

            $outputPath = Join-Path $testRoot 'CleanupFailure'
            { Register-ScheduledSecurityScan -OutputPath $outputPath -Confirm:$false -ErrorAction SilentlyContinue } |
                Should -Throw '*Simulated move failure for cleanup test*'

            Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
                $Message -like 'SECURITY WARNING: Failed to remove residual protected file*'
            }
            $tempFiles = @(Get-ChildItem -Path $outputPath -Filter '*.tmp' -File)
            $tempFiles.Count | Should -Be 1
            Should -Invoke Test-AdminOnlyOwnership -Times 2 -Exactly -ParameterFilter { $Path -like '*.tmp' }
            Should -Invoke Test-NoNonAdminWriteAccess -Times 2 -Exactly -ParameterFilter { $Path -like '*.tmp' }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -like '*.tmp' }
            Should -Invoke Register-WsaScheduledTask -Times 0 -Exactly
            [System.IO.File]::Delete($tempFiles[0].FullName)
        }
    }

    It 'refuses insecure pre-existing and newly created directories before any file write' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $TestDrive -ScriptBlock {
            param($testRoot)
            Mock Test-AdminOnlyOwnership { $true }
            Mock Test-NoNonAdminWriteAccess { $false }
            Mock New-WsaPrivateFile { }
            Mock Out-File { }
            Mock Register-WsaScheduledTask { }

            foreach ($preExisting in @($false, $true)) {
                $outputPath = Join-Path $testRoot "DirectoryRefusal_$preExisting"
                if ($preExisting) {
                    $null = New-Item -Path $outputPath -ItemType Directory -Force
                }

                { Register-ScheduledSecurityScan -OutputPath $outputPath -Confirm:$false -ErrorAction SilentlyContinue } |
                    Should -Throw '*failed ownership or non-admin write-access validation*'
                Test-Path -Path $outputPath -PathType Container | Should -BeTrue
                @(Get-ChildItem -Path $outputPath -Recurse -File).Count | Should -Be 0
            }

            Should -Invoke Test-AdminOnlyOwnership -Times 2 -Exactly
            Should -Invoke Test-NoNonAdminWriteAccess -Times 2 -Exactly
            Should -Invoke New-WsaPrivateFile -Times 0 -Exactly
            Should -Invoke Out-File -Times 0 -Exactly
            Should -Invoke Register-WsaScheduledTask -Times 0 -Exactly
        }
    }

    It 'sanitizes webhook delivery errors for alarm and resolved notifications' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:TestWebhookUrl, $script:ModuleManifest, $TestDrive -ScriptBlock {
            param($expectedUrl, $moduleManifest, $testRoot)
            Mock New-ScheduledTaskTrigger { [PSCustomObject]@{} }
            Mock New-ScheduledTaskAction { [PSCustomObject]@{} }
            Mock New-ScheduledTaskPrincipal { [PSCustomObject]@{} }
            Mock New-ScheduledTaskSettingsSet { [PSCustomObject]@{} }
            Mock Register-WsaScheduledTask { }

            $outputPath = Join-Path $testRoot 'SanitizedWebhookErrors'
            $result = Register-ScheduledSecurityScan -OutputPath $outputPath -WebhookUrl $expectedUrl -WebhookProtection PlainText -Confirm:$false
            $mockModulePath = Join-Path $testRoot 'WindowsSecurityAudit.psm1'
            $mockModuleContent = @'
function Invoke-SecurityAssessment {
    param($AssessmentType, $OutputPath)
    $scenarioPath = Join-Path (Split-Path -Parent $OutputPath) 'scenario.txt'
    $resolved = (Test-Path $scenarioPath) -and ((Get-Content -Path $scenarioPath -Raw).Trim() -eq 'resolved')
    $findings = @()
    if (-not $resolved) {
        $findings = @(
            [PSCustomObject]@{ Category = 'Test'; Finding = 'Synthetic critical finding'; Severity = 'Critical' }
        )
    }
    [PSCustomObject]@{ OverallScore = 0; Findings = $findings }
}
function Invoke-RestMethod {
    param($Uri, $Method, $Body, $ContentType, $ErrorAction)
    throw "Webhook endpoint rejected $Uri"
}
Export-ModuleMember -Function Invoke-SecurityAssessment, Invoke-RestMethod
'@
            Set-Content -Path $mockModulePath -Value $mockModuleContent -Encoding UTF8
            $originalModuleLine = "`$modulePath = '$($moduleManifest -replace "'", "''")'"
            $mockModuleLine = "`$modulePath = '$($mockModulePath -replace "'", "''")'"
            $scanContent = Get-Content -Path $result.ScriptPath -Raw
            $scanContent = $scanContent.Replace($originalModuleLine, $mockModuleLine)
            Set-Content -Path $result.ScriptPath -Value $scanContent -Encoding UTF8
            $scenarioPath = Join-Path $outputPath 'scenario.txt'
            Set-Content -Path $scenarioPath -Value 'alarm'

            $powerShellPath = (Get-Process -Id $PID).Path
            $alarmOutput = (& $powerShellPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $result.ScriptPath 2>&1 | Out-String)
            $LASTEXITCODE | Should -Be 0 -Because $alarmOutput
            $alarmOutput | Should -Match 'Failed to send webhook alert\.'
            $alarmOutput | Should -Not -Match 'Webhook endpoint rejected'
            $alarmOutput.Contains($expectedUrl) | Should -BeFalse

            Set-Content -Path $scenarioPath -Value 'resolved'
            $resolvedOutput = (& $powerShellPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $result.ScriptPath 2>&1 | Out-String)
            $LASTEXITCODE | Should -Be 0 -Because $resolvedOutput
            $resolvedOutput | Should -Match 'Failed to send webhook alert\.'
            $resolvedOutput | Should -Not -Match 'Webhook endpoint rejected'
            $resolvedOutput.Contains($expectedUrl) | Should -BeFalse
        }
    }
}
