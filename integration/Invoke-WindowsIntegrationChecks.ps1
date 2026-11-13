#Requires -Version 5.1
<#
.SYNOPSIS
    Runs manual Windows integration checks for WindowsSecurityAudit.
.DESCRIPTION
    Exercises the Windows-only behavior that mocked and non-Windows CI tests
    cannot prove. Every check is isolated and returns PASS, FAIL, or UNVERIFIED
    with evidence. A required UNVERIFIED result does not count as a pass.

    The default run changes no persistent system configuration. The JEA check
    registers a temporary endpoint named WSA-IntegrationTest and unregisters it
    in finally. Its temporary configuration and transcripts are removed. The
    optional dump is written only to a temporary directory and then removed.
    Sentinel ingestion runs only when all four WSA_TEST_* variables are set.

    The DPAPI check uses the module's LocalMachine wrappers for its round-trip.
    A separate CurrentUser canary is tested under a different identity only
    when -DpapiAlternateCredential is supplied. The canary plaintext, OAuth
    client secret, access token, and credential password are never reported.
.PARAMETER ModulePath
    WindowsSecurityAudit module manifest to import. Defaults to the manifest
    beside the integration directory. JEA additionally requires the complete
    module to be discoverable by name in an admin-controlled PSModulePath.
.PARAMETER DriveLetter
    NTFS drive used by the USN and live MFT checks. Defaults to C.
.PARAMETER MftMaxRecords
    Small live MFT scan cap. A MaxRecords stop is expected and is not a failure.
.PARAMETER IncludeDump
    Creates a Mini dump of this PowerShell process, never LSASS, validates its
    MDMP signature and nonzero size, and deletes the temporary dump directory.
.PARAMETER DpapiAlternateCredential
    Credential for a different local or domain user. A short child process is
    started as that user to confirm that a CurrentUser DPAPI canary cannot be
    decrypted. Without this parameter the DPAPI boundary is UNVERIFIED.
.PARAMETER ReportPath
    JSON report path. Defaults to IntegrationReport.json beside this script.
.EXAMPLE
    .\Invoke-WindowsIntegrationChecks.ps1
    Runs the mandatory checks, plus optional checks whose prerequisites exist.
.EXAMPLE
    $credential = Get-Credential
    .\Invoke-WindowsIntegrationChecks.ps1 -DpapiAlternateCredential $credential -IncludeDump
    Runs the full local pack, including the cross-user DPAPI and dump probes.
.NOTES
    Run from an elevated Windows PowerShell 5.1 or PowerShell 7 session.
    Exit code 0 requires PASS on every required check. Optional dump and SIEM
    checks do not affect the exit code. Any report-write failure returns 1.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ModulePath = (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'WindowsSecurityAudit.psd1'),

    [Parameter()]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$DriveLetter = 'C',

    [Parameter()]
    [ValidateRange(16, 1000)]
    [int]$MftMaxRecords = 64,

    [Parameter()]
    [switch]$IncludeDump,

    [Parameter()]
    [System.Management.Automation.PSCredential]$DpapiAlternateCredential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = (Join-Path -Path $PSScriptRoot -ChildPath 'IntegrationReport.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:WsaRepositoryRoot = Split-Path -Parent $PSScriptRoot
$script:WsaModule = $null
$script:WsaModuleImportError = $null
$script:WsaCurrentIdentity = $null
$script:WsaCurrentSid = $null

function ConvertTo-WsaIntegrationSafeText {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    $secret = [Environment]::GetEnvironmentVariable('WSA_TEST_CLIENT_SECRET')
    if (-not [string]::IsNullOrEmpty($secret)) {
        $text = $text.Replace($secret, '[REDACTED]')
    }
    return ($text -replace '[\r\n]+', ' ').Trim()
}

function New-WsaIntegrationOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'UNVERIFIED')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Evidence,

        [Parameter()]
        [AllowNull()]
        [object]$Details = $null
    )

    return [PSCustomObject]@{
        Status   = $Status
        Evidence = ConvertTo-WsaIntegrationSafeText $Evidence
        Details  = $Details
    }
}

function Test-WsaIntegrationWindows {
    [CmdletBinding()]
    param()
    return ($env:OS -eq 'Windows_NT')
}

function Test-WsaIntegrationElevated {
    [CmdletBinding()]
    param()

    if (-not (Test-WsaIntegrationWindows)) { return $false }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function New-WsaIntegrationTempDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Purpose
    )

    $safePurpose = $Purpose -replace '[^A-Za-z0-9-]', '-'
    $name = 'WSA-Integration-{0}-{1}' -f $safePurpose, [Guid]::NewGuid().ToString('N')
    $path = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath $name
    $null = [IO.Directory]::CreateDirectory($path)
    return $path
}

function Get-WsaIntegrationObjectKeys {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) { return @() }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    return @($InputObject.PSObject.Properties.Name)
}

function Invoke-WsaIntegrationCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Required,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $outcome = $null
    try {
        $outcome = & $Action
        if ($null -eq $outcome -or $null -eq $outcome.PSObject.Properties['Status'] -or
            $null -eq $outcome.PSObject.Properties['Evidence'] -or
            $outcome.Status -notin @('PASS', 'FAIL', 'UNVERIFIED')) {
            throw 'The check action returned an invalid outcome.'
        }
    }
    catch {
        $message = ConvertTo-WsaIntegrationSafeText $_.Exception.Message
        $outcome = New-WsaIntegrationOutcome -Status FAIL -Evidence "Unhandled check error: $message" -Details ([ordered]@{
            ExceptionType = $_.Exception.GetType().FullName
        })
    }
    finally {
        $stopwatch.Stop()
    }

    return [PSCustomObject][ordered]@{
        Check      = $Name
        Status     = $outcome.Status
        Required   = $Required
        Evidence   = $outcome.Evidence
        Details    = $outcome.Details
        DurationMs = $stopwatch.ElapsedMilliseconds
    }
}

function Test-WsaDpapiAlternateIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CipherText,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ParentSid
    )

    $tempDirectory = $null
    $process = $null
    try {
        $executableName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $executablePath = Join-Path -Path $PSHOME -ChildPath $executableName
        if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "The current PowerShell executable was not found for the alternate-user process: $executablePath"
        }

        $tempDirectory = New-WsaIntegrationTempDirectory -Purpose 'DpapiAlternateUser'
        $stdoutPath = Join-Path -Path $tempDirectory -ChildPath 'stdout.txt'
        $stderrPath = Join-Path -Path $tempDirectory -ChildPath 'stderr.txt'
        $childTemplate = @'
$ErrorActionPreference = 'Stop'
$cipherText = '__CIPHER_TEXT__'
$parentSid = '__PARENT_SID__'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$result = [ordered]@{
    Identity = $identity.Name
    Sid = $identity.User.Value
    DifferentIdentity = ($identity.User.Value -ne $parentSid)
    DecryptSucceeded = $false
    Outcome = 'NotAttempted'
    FailureType = $null
}
$cipherBytes = $null
$plainBytes = $null
try {
    $assemblyName = if ($PSVersionTable.PSEdition -eq 'Desktop') {
        'System.Security'
    }
    else {
        'System.Security.Cryptography.ProtectedData'
    }
    $qualifiedName = "System.Security.Cryptography.ProtectedData, $assemblyName"
    $protectedDataType = [type]::GetType($qualifiedName, $false)
    if ($null -eq $protectedDataType) {
        $null = [System.Reflection.Assembly]::Load($assemblyName)
        $protectedDataType = [type]::GetType($qualifiedName, $false)
    }
    if ($null -eq $protectedDataType) {
        throw 'ProtectedData is unavailable.'
    }
    $scopeType = $protectedDataType.Assembly.GetType('System.Security.Cryptography.DataProtectionScope', $true)
    $scope = [System.Enum]::Parse($scopeType, 'CurrentUser')
    $cipherBytes = [Convert]::FromBase64String($cipherText)
    $plainBytes = $protectedDataType::Unprotect($cipherBytes, $null, $scope)
    $result.DecryptSucceeded = $true
    $result.Outcome = 'UnexpectedSuccess'
}
catch [System.Security.Cryptography.CryptographicException] {
    $result.Outcome = 'ExpectedCryptographicFailure'
    $result.FailureType = $_.Exception.GetType().FullName
}
catch {
    $result.Outcome = 'ProbeError'
    $result.FailureType = $_.Exception.GetType().FullName
}
finally {
    if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    if ($null -ne $cipherBytes) { [Array]::Clear($cipherBytes, 0, $cipherBytes.Length) }
}
[PSCustomObject]$result | ConvertTo-Json -Compress
'@
        $childScript = $childTemplate.Replace('__CIPHER_TEXT__', $CipherText).Replace('__PARENT_SID__', $ParentSid)
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
        $process = Start-Process -FilePath $executablePath -Credential $Credential -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedCommand
        ) -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop

        $childResult = $null
        if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            $stdout = [IO.File]::ReadAllText($stdoutPath).Trim()
            if ($stdout) {
                try { $childResult = $stdout | ConvertFrom-Json -ErrorAction Stop } catch { $childResult = $null }
            }
        }
        if ($null -eq $childResult) {
            $stderr = ''
            if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
                $stderr = [IO.File]::ReadAllText($stderrPath).Trim()
            }
            $detail = if ($stderr) { ConvertTo-WsaIntegrationSafeText $stderr } else { 'No child result was returned.' }
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Alternate-user DPAPI process did not produce a valid result (exit $($process.ExitCode)): $detail"
        }

        $details = [ordered]@{
            AlternateIdentity = [string]$childResult.Identity
            AlternateSid      = [string]$childResult.Sid
            DifferentIdentity = [bool]$childResult.DifferentIdentity
            DecryptSucceeded  = [bool]$childResult.DecryptSucceeded
            Outcome           = [string]$childResult.Outcome
            FailureType       = [string]$childResult.FailureType
        }
        if (-not $childResult.DifferentIdentity) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'The supplied credential resolved to the same Windows SID as the parent; choose a different identity.' -Details $details
        }
        if ($childResult.DecryptSucceeded) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence 'A different Windows identity decrypted the CurrentUser DPAPI canary unexpectedly.' -Details $details
        }
        if ($childResult.Outcome -eq 'ExpectedCryptographicFailure') {
            return New-WsaIntegrationOutcome -Status PASS -Evidence "A different Windows SID was confirmed and CurrentUser decryption failed with $($childResult.FailureType), as expected." -Details $details
        }
        return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "The alternate-user probe could not attempt a trustworthy decryption (outcome $($childResult.Outcome); type $($childResult.FailureType))." -Details $details
    }
    catch {
        return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Alternate-user process could not run: $($_.Exception.Message). Confirm logon rights and that the alternate identity differs from the elevated user."
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $tempDirectory -and (Test-Path -LiteralPath $tempDirectory)) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction Stop
        }
    }
}

$reportFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
$reportParent = Split-Path -Path $reportFullPath -Parent
if ($reportParent -and -not (Test-Path -LiteralPath $reportParent -PathType Container)) {
    throw "Report directory does not exist: $reportParent"
}

try {
    if (Test-WsaIntegrationWindows) {
        $script:WsaCurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $script:WsaCurrentSid = $script:WsaCurrentIdentity.User.Value
    }
    $script:WsaModule = Import-Module -Name $ModulePath -Force -PassThru -ErrorAction Stop
}
catch {
    $script:WsaModuleImportError = ConvertTo-WsaIntegrationSafeText $_.Exception.Message
}

$checks = @()

$checks += [PSCustomObject]@{
    Name = 'JEA temporary endpoint'
    Required = $true
    Action = {
        $endpointName = 'WSA-IntegrationTest'
        $session = $null
        $tempDirectory = $null
        $registrationAttempted = $false
        $preexistingEndpoint = $false
        try {
            if (-not (Test-WsaIntegrationWindows)) {
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'JEA requires a real Windows host.'
            }
            if (-not (Test-WsaIntegrationElevated)) {
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'JEA registration requires an elevated administrator session.'
            }
            if ($null -eq $script:WsaModule) {
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Module import is unavailable: $script:WsaModuleImportError"
            }

            $commandNames = @(
                'Get-PSSessionConfiguration', 'Test-PSSessionConfigurationFile',
                'Register-PSSessionConfiguration', 'Unregister-PSSessionConfiguration',
                'New-PSSession', 'Invoke-Command', 'Remove-PSSession'
            )
            $commands = @{}
            $missing = @()
            foreach ($commandName in $commandNames) {
                $command = Get-Command -Name $commandName -ErrorAction SilentlyContinue
                if ($null -eq $command) { $missing += $commandName } else { $commands[$commandName] = $command }
            }
            if ($missing.Count -gt 0) {
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "This PowerShell host lacks required remoting/JEA commands: $($missing -join ', ')."
            }

            $existing = @(Get-PSSessionConfiguration -Name $endpointName -ErrorAction SilentlyContinue)
            if ($existing.Count -gt 0) {
                $preexistingEndpoint = $true
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Endpoint $endpointName already exists. It was not changed. Remove a stale test endpoint only after confirming its owner, then rerun."
            }

            $availableModules = @(Get-Module -Name WindowsSecurityAudit -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending)
            if ($availableModules.Count -eq 0) {
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'JEA cannot resolve WindowsSecurityAudit by name. Install the complete module, including RoleCapabilities, in an admin-controlled PSModulePath location.'
            }
            $endpointModule = $availableModules[0]
            $rolePath = Join-Path -Path $endpointModule.ModuleBase -ChildPath 'RoleCapabilities\WindowsSecurityAudit.Scan.psrc'
            if (-not (Test-Path -LiteralPath $rolePath -PathType Leaf)) {
                return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "The module selected for JEA ($($endpointModule.ModuleBase)) lacks RoleCapabilities\WindowsSecurityAudit.Scan.psrc."
            }

            $samplePath = Join-Path -Path $script:WsaRepositoryRoot -ChildPath 'JEA\WindowsSecurityAudit.Sample.pssc'
            if (-not (Test-Path -LiteralPath $samplePath -PathType Leaf)) {
                throw "Sample JEA configuration is missing: $samplePath"
            }
            $sampleValid = Test-PSSessionConfigurationFile -Path $samplePath -ErrorAction Stop
            if (-not $sampleValid) { throw 'Test-PSSessionConfigurationFile rejected the unchanged sample configuration.' }

            $tempDirectory = New-WsaIntegrationTempDirectory -Purpose 'Jea'
            $temporaryPssc = Join-Path -Path $tempDirectory -ChildPath 'WSA-IntegrationTest.pssc'
            $transcriptDirectory = Join-Path -Path $tempDirectory -ChildPath 'Transcripts'
            $roleIdentity = $script:WsaCurrentIdentity.Name.Replace("'", "''")
            $transcriptLiteral = $transcriptDirectory.Replace("'", "''")
            $sampleText = [IO.File]::ReadAllText($samplePath)
            $roleToken = "'CONTOSO\WSA-Scan-Operators'"
            $transcriptToken = "'C:\ProgramData\JEAConfiguration\Transcripts'"
            if (-not $sampleText.Contains($roleToken) -or -not $sampleText.Contains($transcriptToken)) {
                throw 'The sample JEA file no longer contains the expected role or transcript tokens; no derived file was registered.'
            }
            $temporaryText = $sampleText.Replace($roleToken, "'$roleIdentity'").Replace($transcriptToken, "'$transcriptLiteral'")
            [IO.File]::WriteAllText($temporaryPssc, $temporaryText, (New-Object Text.UTF8Encoding($true)))
            $temporaryValid = Test-PSSessionConfigurationFile -Path $temporaryPssc -ErrorAction Stop
            if (-not $temporaryValid) { throw 'Test-PSSessionConfigurationFile rejected the temporary test-scoped configuration.' }

            $registerParameters = @{
                Name = $endpointName
                Path = $temporaryPssc
                Force = $true
                ErrorAction = 'Stop'
            }
            if ($commands['Register-PSSessionConfiguration'].Parameters.ContainsKey('NoServiceRestart')) {
                $registerParameters['NoServiceRestart'] = $true
            }
            $registrationAttempted = $true
            Register-PSSessionConfiguration @registerParameters
            $session = New-PSSession -ComputerName localhost -ConfigurationName $endpointName -ErrorAction Stop
            $remoteResult = Invoke-Command -Session $session -ScriptBlock {
                Invoke-WsaRemoteFunctionSet -FunctionSet Quick
            } -ErrorAction Stop

            $resultKeys = @(Get-WsaIntegrationObjectKeys -InputObject $remoteResult.Results)
            $expectedFunctions = @('Get-SecurityBaseline', 'Get-DefenderStatus')
            $missingResults = @($expectedFunctions | Where-Object { $resultKeys -notcontains $_ })
            if ($remoteResult.FunctionSet -ne 'Quick' -or $missingResults.Count -gt 0) {
                throw "Quick wrapper response was incomplete. Missing results: $($missingResults -join ', ')."
            }

            $arbitraryDenied = $false
            $denialMessage = $null
            try {
                $null = Invoke-Command -Session $session -ScriptBlock { Get-Process } -ErrorAction Stop
            }
            catch {
                $arbitraryDenied = $true
                $denialMessage = ConvertTo-WsaIntegrationSafeText $_.Exception.Message
            }
            if (-not $arbitraryDenied) {
                throw 'Arbitrary Get-Process script-block execution was allowed by the restricted endpoint.'
            }

            $remoteErrors = @()
            if ($null -ne $remoteResult.PSObject.Properties['Errors']) {
                $remoteErrors = @($remoteResult.Errors | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-WsaIntegrationSafeText $_ })
            }
            $details = [ordered]@{
                EndpointName = $endpointName
                SampleConfigurationValidated = [bool]$sampleValid
                TemporaryConfigurationValidated = [bool]$temporaryValid
                ScopedRoleIdentity = $script:WsaCurrentIdentity.Name
                EndpointModulePath = $endpointModule.ModuleBase
                EndpointModuleVersion = $endpointModule.Version.ToString()
                FunctionSet = [string]$remoteResult.FunctionSet
                ResultFunctions = $resultKeys
                RemoteErrorCount = $remoteErrors.Count
                RemoteErrors = $remoteErrors
                RemoteEffectiveLanguageMode = [string]$remoteResult.EffectiveLanguageMode
                RemoteDynamicCompilationExpected = [bool]$remoteResult.DynamicCompilationExpected
                ArbitraryScriptBlockDenied = $arbitraryDenied
                ArbitraryScriptBlockDenial = $denialMessage
            }
            return New-WsaIntegrationOutcome -Status PASS -Evidence "Sample and temporary PSSC validated; Quick returned both functions; arbitrary Get-Process was denied; endpoint cleanup was enforced in finally." -Details $details
        }
        finally {
            $cleanupErrors = @()
            if ($null -ne $session) {
                try { Remove-PSSession -Session $session -ErrorAction Stop } catch { $cleanupErrors += "session removal: $($_.Exception.Message)" }
            }
            if ($registrationAttempted -and -not $preexistingEndpoint) {
                try {
                    $remaining = @(Get-PSSessionConfiguration -Name $endpointName -ErrorAction SilentlyContinue)
                    if ($remaining.Count -gt 0) {
                        $unregisterParameters = @{ Name = $endpointName; Force = $true; ErrorAction = 'Stop' }
                        if ($commands['Unregister-PSSessionConfiguration'].Parameters.ContainsKey('NoServiceRestart')) {
                            $unregisterParameters['NoServiceRestart'] = $true
                        }
                        Unregister-PSSessionConfiguration @unregisterParameters
                    }
                    $remaining = @(Get-PSSessionConfiguration -Name $endpointName -ErrorAction SilentlyContinue)
                    if ($remaining.Count -gt 0) { throw 'endpoint still exists after unregister' }
                }
                catch {
                    $cleanupErrors += "endpoint removal: $($_.Exception.Message)"
                }
            }
            if ($null -ne $tempDirectory -and (Test-Path -LiteralPath $tempDirectory)) {
                try { Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction Stop } catch { $cleanupErrors += "temporary files: $($_.Exception.Message)" }
            }
            if ($cleanupErrors.Count -gt 0) {
                throw "JEA cleanup failed: $($cleanupErrors -join '; ')"
            }
        }
    }
}

$checks += [PSCustomObject]@{
    Name = 'DPAPI protection and identity boundary'
    Required = $true
    Action = {
        if (-not (Test-WsaIntegrationWindows)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'DPAPI requires Windows.'
        }
        if ($null -eq $script:WsaModule) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Module import is unavailable: $script:WsaModuleImportError"
        }

        $canary = 'WSA-Integration-Canary-' + [Guid]::NewGuid().ToString('N')
        $probe = & $script:WsaModule {
            param($PlainText, $TypeSuffix)

            $languageMode = Get-WsaEffectiveLanguageMode
            $compilationExpected = Test-WsaDynamicCompilationExpected
            $compilationSucceeded = $false
            $compilationError = $null
            $probeTypeName = 'WSAIntegrationCompilationProbe' + $TypeSuffix
            try {
                $compiledType = Add-Type -TypeDefinition "public static class $probeTypeName { public static int GetValue() { return 42; } }" -PassThru -ErrorAction Stop
                $compilationSucceeded = ($compiledType::GetValue() -eq 42)
            }
            catch {
                $compilationError = $_.Exception.GetType().FullName
            }

            $protectedText = Protect-WsaDpapiData -PlainText $PlainText -ErrorAction Stop
            $roundTrip = Unprotect-WsaDpapiData -ProtectedText $protectedText -ErrorAction Stop
            $roundTripSucceeded = ($roundTrip -ceq $PlainText)
            $markerValid = $protectedText.StartsWith('wsa-dpapi-lm-v1:', [StringComparison]::Ordinal)

            $protectedDataType = Get-WsaDpapiProtectedDataType
            $scopeType = $protectedDataType.Assembly.GetType('System.Security.Cryptography.DataProtectionScope', $true)
            $currentUserScope = [System.Enum]::Parse($scopeType, 'CurrentUser')
            $plainBytes = $null
            $currentUserCipherBytes = $null
            try {
                $plainBytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
                $currentUserCipherBytes = $protectedDataType::Protect($plainBytes, $null, $currentUserScope)
                $currentUserCipherText = [Convert]::ToBase64String($currentUserCipherBytes)
            }
            finally {
                if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
                if ($null -ne $currentUserCipherBytes) { [Array]::Clear($currentUserCipherBytes, 0, $currentUserCipherBytes.Length) }
            }

            return [PSCustomObject]@{
                LanguageMode = [string]$languageMode
                DynamicCompilationExpected = [bool]$compilationExpected
                DynamicCompilationSucceeded = [bool]$compilationSucceeded
                CompilationError = $compilationError
                RoundTripSucceeded = $roundTripSucceeded
                MarkerValid = $markerValid
                CurrentUserCipherText = $currentUserCipherText
            }
        } $canary ([Guid]::NewGuid().ToString('N'))

        $details = [ordered]@{
            LocalMachineRoundTrip = [bool]$probe.RoundTripSucceeded
            LocalMachineMarkerValid = [bool]$probe.MarkerValid
            LanguageMode = [string]$probe.LanguageMode
            DynamicCompilationExpected = [bool]$probe.DynamicCompilationExpected
            DynamicCompilationSucceeded = [bool]$probe.DynamicCompilationSucceeded
            CompilationError = $probe.CompilationError
            CrossUserStatus = 'NOT_RUN'
            CrossUserDetails = $null
        }
        if (-not $probe.RoundTripSucceeded -or -not $probe.MarkerValid) {
            throw 'The module LocalMachine DPAPI wrapper did not round-trip the canary with the expected marker.'
        }

        $capabilityEvidence = "LanguageMode=$($probe.LanguageMode); compilation expected=$($probe.DynamicCompilationExpected); actual compilation=$($probe.DynamicCompilationSucceeded)"
        if ($null -eq $DpapiAlternateCredential) {
            $details.CrossUserStatus = 'UNVERIFIED'
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "LocalMachine wrapper round-trip passed; $capabilityEvidence. Cross-user CurrentUser boundary not run: supply -DpapiAlternateCredential (Get-Credential) for a different identity." -Details $details
        }

        $crossUser = Test-WsaDpapiAlternateIdentity -CipherText $probe.CurrentUserCipherText -Credential $DpapiAlternateCredential -ParentSid $script:WsaCurrentSid
        $details.CrossUserStatus = $crossUser.Status
        $details.CrossUserDetails = $crossUser.Details
        return New-WsaIntegrationOutcome -Status $crossUser.Status -Evidence "LocalMachine wrapper round-trip passed; $capabilityEvidence. Cross-user: $($crossUser.Evidence)" -Details $details
    }
}

$checks += [PSCustomObject]@{
    Name = 'Native FSCTL USN journal'
    Required = $true
    Action = {
        if (-not (Test-WsaIntegrationWindows)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'Native USN journal access requires Windows and NTFS.'
        }
        if (-not (Test-WsaIntegrationElevated)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'Native USN journal access requires elevation.'
        }
        if ($null -eq $script:WsaModule) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Module import is unavailable: $script:WsaModuleImportError"
        }

        $journal = Get-FileSystemJournal -DriveLetter $DriveLetter -Mode USNJournal -MaxRecords 100 -ErrorAction Stop
        $source = [string]$journal.Summary.Source
        $recordCount = @($journal.Records).Count
        $notes = @($journal.Notes | ForEach-Object { ConvertTo-WsaIntegrationSafeText $_ })
        $summaryKeys = @(Get-WsaIntegrationObjectKeys -InputObject $journal.Summary)
        $journalReadable = ($summaryKeys -contains 'TotalRecords')
        $details = [ordered]@{
            DriveLetter = $DriveLetter.ToUpperInvariant()
            Source = $source
            RecordCount = $recordCount
            JournalReadable = $journalReadable
            IsElevated = [bool]$journal.IsElevated
            Notes = $notes
        }
        if ($source -eq 'Native') {
            return New-WsaIntegrationOutcome -Status PASS -Evidence "Summary.Source=Native; $recordCount record(s) returned. Zero records is valid for an inactive journal." -Details $details
        }
        if ($journalReadable) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "The journal was readable but Summary.Source=$source instead of Native; record count=$recordCount." -Details $details
        }
        return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "The journal could not be read on $($DriveLetter):; source=$source. Confirm an NTFS volume and an accessible USN journal; no activity is not itself a failure." -Details $details
    }
}

$checks += [PSCustomObject]@{
    Name = 'Native live MFT and sector-tail parsing'
    Required = $true
    Action = {
        if (-not (Test-WsaIntegrationWindows)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'Live MFT FSCTL access requires Windows and NTFS.'
        }
        if (-not (Test-WsaIntegrationElevated)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'Live MFT FSCTL access requires elevation.'
        }
        if ($null -eq $script:WsaModule) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Module import is unavailable: $script:WsaModuleImportError"
        }

        $mft = Get-FileSystemJournal -DriveLetter $DriveLetter -Mode MftTimestompScan -MaxRecords $MftMaxRecords -MaxSeconds 120 -IncludeAll -ErrorAction Stop
        $summary = $mft.Summary
        $records = @($mft.Records)
        $invalidRecords = @()
        $validSiTimestampCount = 0
        $validFnTimestampCount = 0
        $completeAttributeCount = 0
        $timestampNames = @('SiCreated', 'SiModified', 'SiMftChanged', 'SiAccessed', 'FnCreated', 'FnModified', 'FnMftChanged', 'FnAccessed')
        $nestedTimestampNames = @('Created', 'Modified', 'MftChanged', 'Accessed')

        foreach ($record in $records) {
            if ($null -eq $record) {
                $invalidRecords += 'Null record emitted.'
                continue
            }
            $requiredProperties = @(
                'RecordNumber', 'FileReferenceNumber', 'FileReference', 'SequenceNumber', 'InUse',
                'HasStandardInformation', 'HasFileName', 'NameNamespace', 'FileNames', 'Source'
            ) + $timestampNames
            $missingProperties = @($requiredProperties | Where-Object { $null -eq $record.PSObject.Properties[$_] })
            if ($missingProperties.Count -gt 0) {
                $invalidRecords += "Record is missing properties: $($missingProperties -join ', ')."
                continue
            }
            if ([long]$record.RecordNumber -lt 0 -or [int]$record.SequenceNumber -lt 1) {
                $invalidRecords += "Invalid record identity at record $($record.RecordNumber)."
            }
            if (-not $record.InUse -or $record.Source -ne 'FSCTL_GET_NTFS_FILE_RECORD') {
                $invalidRecords += "Invalid source/in-use flags at record $($record.RecordNumber)."
            }
            if ($record.FileReferenceNumber -cnotmatch '^0x[0-9a-f]{12}$' -or $record.FileReference -cnotmatch '^0x[0-9a-f]{16}$') {
                $invalidRecords += "Invalid file-reference format at record $($record.RecordNumber)."
            }
            if ($record.HasFileName -and ([byte]$record.NameNamespace -gt 3 -or [string]::IsNullOrWhiteSpace([string]$record.FileName))) {
                $invalidRecords += "Invalid FILE_NAME attributes at record $($record.RecordNumber)."
            }
            if ($record.HasStandardInformation -and $record.HasFileName) { $completeAttributeCount++ }

            foreach ($timestampName in $timestampNames) {
                $timestamp = $record.$timestampName
                if ($null -ne $timestamp) {
                    if ($timestamp -isnot [DateTime] -or $timestamp.Year -lt 1601) {
                        $invalidRecords += "Garbage $timestampName at record $($record.RecordNumber)."
                    }
                    elseif ($timestampName -eq 'SiCreated') { $validSiTimestampCount++ }
                    elseif ($timestampName -eq 'FnCreated') { $validFnTimestampCount++ }
                }
            }
            foreach ($nameInfo in @($record.FileNames)) {
                if ($null -eq $nameInfo) {
                    $invalidRecords += "Null FILE_NAME attribute at record $($record.RecordNumber)."
                    continue
                }
                foreach ($timestampName in $nestedTimestampNames) {
                    $validName = 'Fn' + $timestampName + 'Valid'
                    if ($null -eq $nameInfo.PSObject.Properties[$timestampName] -or $null -eq $nameInfo.PSObject.Properties[$validName]) {
                        $invalidRecords += "Incomplete FILE_NAME timestamp shape at record $($record.RecordNumber)."
                        continue
                    }
                    $timestamp = $nameInfo.$timestampName
                    $valid = [bool]$nameInfo.$validName
                    if (($valid -and $null -eq $timestamp) -or (-not $valid -and $null -ne $timestamp)) {
                        $invalidRecords += "Inconsistent $validName at record $($record.RecordNumber)."
                    }
                    elseif ($null -ne $timestamp -and ($timestamp -isnot [DateTime] -or $timestamp.Year -lt 1601)) {
                        $invalidRecords += "Garbage FILE_NAME $timestampName at record $($record.RecordNumber)."
                    }
                }
            }
        }

        if ($summary.MalformedRecords -ne 0) { $invalidRecords += "Summary reports $($summary.MalformedRecords) malformed record(s)." }
        if ($summary.BytesPerSector -le 0 -or $summary.BytesPerFileRecord -le 0 -or
            ($summary.BytesPerFileRecord % $summary.BytesPerSector) -ne 0) {
            $invalidRecords += 'Invalid sector/file-record geometry.'
        }
        if ($records.Count -eq 0 -or $validSiTimestampCount -eq 0 -or $validFnTimestampCount -eq 0 -or $completeAttributeCount -eq 0) {
            $invalidRecords += 'The capped scan did not emit enough valid SI/FN records to validate parsing.'
        }

        $details = [ordered]@{
            DriveLetter = $DriveLetter.ToUpperInvariant()
            Source = [string]$summary.Source
            Success = [bool]$summary.Success
            StopReason = [string]$summary.StopReason
            RecordsScanned = [long]$summary.RecordsScanned
            ReturnedRecords = $records.Count
            MalformedRecords = [int]$summary.MalformedRecords
            BytesPerSector = [int]$summary.BytesPerSector
            BytesPerFileRecord = [int]$summary.BytesPerFileRecord
            ValidSiCreatedCount = $validSiTimestampCount
            ValidFnCreatedCount = $validFnTimestampCount
            CompleteAttributeRecordCount = $completeAttributeCount
            InvalidRecordEvidence = @($invalidRecords | Select-Object -First 20)
        }
        if ($summary.Source -ne 'NativeMft' -or -not $summary.Success -or $summary.RecordsScanned -le 0) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Native MFT scan did not complete successfully: Source=$($summary.Source); Success=$($summary.Success); StopReason=$($summary.StopReason); scanned=$($summary.RecordsScanned)." -Details $details
        }
        if ($summary.StopReason -notin @('MaxRecords', 'Complete')) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Native MFT scan ended unexpectedly with StopReason=$($summary.StopReason)." -Details $details
        }
        if ($invalidRecords.Count -gt 0) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Native MFT returned invalid record/sector-tail evidence: $(($invalidRecords | Select-Object -First 3) -join '; ')" -Details $details
        }
        return New-WsaIntegrationOutcome -Status PASS -Evidence "Source=NativeMft; scanned=$($summary.RecordsScanned); returned=$($records.Count); StopReason=$($summary.StopReason); malformed=0; valid SI/FN and sector geometry confirmed." -Details $details
    }
}

$checks += [PSCustomObject]@{
    Name = 'Optional self-process memory dump'
    Required = $false
    Action = {
        if (-not $IncludeDump) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'Not requested. Rerun with -IncludeDump to create and delete a Mini dump of this PowerShell process (never LSASS).'
        }
        if (-not (Test-WsaIntegrationWindows)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'The dump integration probe requires Windows.'
        }
        if (-not (Test-WsaIntegrationElevated)) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'The dump integration probe requires elevation.'
        }
        if ($null -eq $script:WsaModule) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Module import is unavailable: $script:WsaModuleImportError"
        }

        $tempDirectory = $null
        try {
            $tempDirectory = New-WsaIntegrationTempDirectory -Purpose 'SelfDump'
            $targetPid = $PID
            $dump = Export-MemoryDump -ProcessId $targetPid -DumpType Mini -OutputPath $tempDirectory -Confirm:$false -ErrorAction Stop
            $fileValid = $false
            $fileSize = [long]0
            $signatureValid = $false
            $pathContained = $false
            $dumpPath = $null
            if ($null -ne $dump.PSObject.Properties['DumpFile']) { $dumpPath = [string]$dump.DumpFile }
            if ($dumpPath -and (Test-Path -LiteralPath $dumpPath -PathType Leaf)) {
                $tempFull = [IO.Path]::GetFullPath($tempDirectory).TrimEnd('\') + '\'
                $dumpFull = [IO.Path]::GetFullPath($dumpPath)
                $pathContained = $dumpFull.StartsWith($tempFull, [StringComparison]::OrdinalIgnoreCase)
                $item = Get-Item -LiteralPath $dumpPath -ErrorAction Stop
                $fileSize = [long]$item.Length
                if ($pathContained -and $fileSize -gt 0) {
                    $stream = $null
                    $signature = [byte[]]@(0, 0, 0, 0)
                    try {
                        $stream = [IO.File]::Open($dumpFull, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                        $bytesRead = $stream.Read($signature, 0, 4)
                        $signatureValid = ($bytesRead -eq 4 -and $signature[0] -eq 0x4D -and $signature[1] -eq 0x44 -and
                            $signature[2] -eq 0x4D -and $signature[3] -eq 0x50)
                    }
                    finally {
                        if ($null -ne $stream) { $stream.Dispose() }
                    }
                }
                $fileValid = ($pathContained -and $fileSize -gt 0 -and $signatureValid)
            }
            $details = [ordered]@{
                TargetProcessId = $targetPid
                TargetWasLsass = $false
                ReportedSuccess = [bool]$dump.Success
                Method = [string]$dump.Method
                FileSize = $fileSize
                MdmpSignatureValid = $signatureValid
                FileInsideTemporaryDirectory = $pathContained
                ErrorMessage = ConvertTo-WsaIntegrationSafeText $dump.ErrorMessage
            }
            if ($dump.Success -and $fileValid) {
                return New-WsaIntegrationOutcome -Status PASS -Evidence "Self-process Mini dump succeeded; nonempty MDMP validated ($fileSize bytes) via $($dump.Method); temporary directory removal enforced in finally." -Details $details
            }
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Dump proof failed: reported Success=$($dump.Success); valid nonempty MDMP=$fileValid; size=$fileSize; error=$($dump.ErrorMessage)." -Details $details
        }
        finally {
            if ($null -ne $tempDirectory -and (Test-Path -LiteralPath $tempDirectory)) {
                Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction Stop
            }
        }
    }
}

$checks += [PSCustomObject]@{
    Name = 'Optional Sentinel OAuth and ingestion'
    Required = $false
    Action = {
        $variableNames = @('WSA_TEST_TENANT_ID', 'WSA_TEST_CLIENT_ID', 'WSA_TEST_CLIENT_SECRET', 'WSA_TEST_DCR_URI')
        $missing = @($variableNames | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
        if ($missing.Count -eq $variableNames.Count) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence 'Not configured. Set WSA_TEST_TENANT_ID, WSA_TEST_CLIENT_ID, WSA_TEST_CLIENT_SECRET, and WSA_TEST_DCR_URI to run a real token acquisition and one-event ingestion probe.'
        }
        if ($missing.Count -gt 0) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "SIEM test configuration is incomplete; missing environment variables: $($missing -join ', '). No secret values were read into the report."
        }
        if ($null -eq $script:WsaModule) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Module import is unavailable: $script:WsaModuleImportError"
        }

        $tenantId = $env:WSA_TEST_TENANT_ID
        $clientId = $env:WSA_TEST_CLIENT_ID
        $dcrUri = $env:WSA_TEST_DCR_URI
        $secureSecret = $null
        $secretCharacters = $null
        $tokenAcquired = $false
        $ingestionSucceeded = $false
        $probeId = [Guid]::NewGuid().ToString('N')
        try {
            $secureSecret = New-Object Security.SecureString
            $secretCharacters = $env:WSA_TEST_CLIENT_SECRET.ToCharArray()
            foreach ($character in $secretCharacters) { $secureSecret.AppendChar($character) }
            $secureSecret.MakeReadOnly()

            $tokenAcquired = & $script:WsaModule {
                param($Tenant, $Client, $Secret)
                $accessToken = $null
                try {
                    $accessToken = Get-SiemAccessToken -TenantId $Tenant -ClientId $Client -ClientSecret $Secret -MonitorScope 'https://monitor.azure.com/.default' -MaxRetries 1 -ThrottleMs 0 -ErrorAction Stop
                    return (-not [string]::IsNullOrWhiteSpace($accessToken))
                }
                finally {
                    $accessToken = $null
                }
            } $tenantId $clientId $secureSecret

            if (-not $tokenAcquired) { throw 'The module token path returned no access token.' }
            $probeEvent = [PSCustomObject]@{
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                ComputerName = $env:COMPUTERNAME
                EventType = 'WindowsSecurityAuditIntegrationProbe'
                Message = 'WindowsSecurityAudit SentinelLogsIngestion integration probe'
                ProbeId = $probeId
            }
            $sendResult = Send-SiemEvent -InputObject $probeEvent -Destination SentinelLogsIngestion -Uri $dcrUri -TenantId $tenantId -ClientId $clientId -ClientSecret $secureSecret -MaxRetries 1 -ThrottleMs 0 -ErrorAction Stop
            $ingestionSucceeded = ($sendResult.EventsSent -eq 1 -and $sendResult.BatchesSent -eq 1 -and $sendResult.Failed -eq 0)
            $parsedUri = [Uri]$dcrUri
            $safeEndpoint = '{0}://{1}:{2}' -f $parsedUri.Scheme, $parsedUri.Host, $parsedUri.Port
            $details = [ordered]@{
                TokenAcquired = $tokenAcquired
                IngestionSucceeded = $ingestionSucceeded
                EventsSent = [int]$sendResult.EventsSent
                BatchesSent = [int]$sendResult.BatchesSent
                FailedEvents = [int]$sendResult.Failed
                ProbeId = $probeId
                EndpointOriginOnly = $safeEndpoint
                SecretOrTokenIncluded = $false
            }
            if ($ingestionSucceeded) {
                return New-WsaIntegrationOutcome -Status PASS -Evidence "Module OAuth path acquired a nonempty token and Sentinel ingestion accepted one event in one batch. ProbeId=$probeId. Token and secret were not reported." -Details $details
            }
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Token acquired=True; ingestion succeeded=False; EventsSent=$($sendResult.EventsSent); BatchesSent=$($sendResult.BatchesSent); Failed=$($sendResult.Failed)." -Details $details
        }
        catch {
            $details = [ordered]@{
                TokenAcquired = $tokenAcquired
                IngestionSucceeded = $ingestionSucceeded
                ProbeId = $probeId
                ExceptionType = $_.Exception.GetType().FullName
                SecretOrTokenIncluded = $false
            }
            $errorType = $_.Exception.GetType().FullName
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Token acquired=$tokenAcquired; ingestion succeeded=$ingestionSucceeded; error type=$errorType. Error text is suppressed to prevent credential or token reflection." -Details $details
        }
        finally {
            if ($null -ne $secureSecret) { $secureSecret.Dispose() }
            if ($null -ne $secretCharacters) { [Array]::Clear($secretCharacters, 0, $secretCharacters.Length) }
        }
    }
}

$checks += [PSCustomObject]@{
    Name = 'Module import and AMSI/Defender history'
    Required = $true
    Action = {
        if ($null -eq $script:WsaModule) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Module import failed: $script:WsaModuleImportError"
        }
        $functionCount = $script:WsaModule.ExportedFunctions.Count
        $moduleRoot = $script:WsaModule.ModuleBase
        $importDetails = [ordered]@{
            ModulePath = $script:WsaModule.Path
            ModuleVersion = $script:WsaModule.Version.ToString()
            ExportedFunctionCount = $functionCount
            ModuleRoot = $moduleRoot
        }
        if ($functionCount -lt 76) {
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Only $functionCount functions were exported; at least 76 are required." -Details $importDetails
        }

        $threatCommand = Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($null -eq $threatCommand) {
            return New-WsaIntegrationOutcome -Status UNVERIFIED -Evidence "Imported all $functionCount functions, but Get-MpThreatDetection is unavailable; AMSI/Defender history cannot be verified on this host." -Details $importDetails
        }

        $detections = @(Get-MpThreatDetection -ErrorAction Stop)
        $moduleRootPrefix = $moduleRoot.TrimEnd('\') + '\'
        $matchingDetections = @()
        foreach ($detection in $detections) {
            if ($null -eq $detection) { continue }
            $resources = @()
            if ($null -ne $detection.PSObject.Properties['Resources']) {
                $resources = @($detection.Resources | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
            }
            $matchedResources = @($resources | Where-Object { $_.IndexOf($moduleRootPrefix, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
            if ($matchedResources.Count -gt 0) {
                $matchingDetections += [PSCustomObject]@{
                    ThreatName = [string]$detection.ThreatName
                    InitialDetectionTime = $detection.InitialDetectionTime
                    Resources = $matchedResources
                }
            }
        }
        $details = [ordered]@{
            ModulePath = $script:WsaModule.Path
            ModuleVersion = $script:WsaModule.Version.ToString()
            ExportedFunctionCount = $functionCount
            ModuleRoot = $moduleRoot
            DefenderHistoryAvailable = $true
            TotalHistoryDetections = $detections.Count
            ModuleFileDetectionCount = $matchingDetections.Count
            ModuleFileDetections = @($matchingDetections | Select-Object -First 25)
        }
        if ($matchingDetections.Count -gt 0) {
            $threatNames = @($matchingDetections.ThreatName | Sort-Object -Unique)
            return New-WsaIntegrationOutcome -Status FAIL -Evidence "Imported $functionCount functions, but Defender history references module files in $($matchingDetections.Count) detection(s): $($threatNames -join ', ')." -Details $details
        }
        return New-WsaIntegrationOutcome -Status PASS -Evidence "Imported all $functionCount functions; Get-MpThreatDetection returned $($detections.Count) historical detection(s), none referencing the module root." -Details $details
    }
}

$results = @()
foreach ($check in $checks) {
    $results += Invoke-WsaIntegrationCheck -Name $check.Name -Required $check.Required -Action $check.Action
}

$requiredFailures = @($results | Where-Object { $_.Required -and $_.Status -ne 'PASS' })
$requiredPassed = ($requiredFailures.Count -eq 0)
$exitCode = if ($requiredPassed) { 0 } else { 1 }
$report = [PSCustomObject][ordered]@{
    SchemaVersion = '1.0'
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    PSEdition = $PSVersionTable.PSEdition
    OSVersion = [Environment]::OSVersion.VersionString
    Elevated = Test-WsaIntegrationElevated
    DriveLetter = $DriveLetter.ToUpperInvariant()
    IncludeDump = [bool]$IncludeDump
    AlternateDpapiCredentialSupplied = ($null -ne $DpapiAlternateCredential)
    RequiredChecksPassed = $requiredPassed
    ExitCode = $exitCode
    Summary = [PSCustomObject][ordered]@{
        Total = $results.Count
        Passed = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
        Failed = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
        Unverified = @($results | Where-Object { $_.Status -eq 'UNVERIFIED' }).Count
        RequiredTotal = @($results | Where-Object { $_.Required }).Count
        RequiredPassed = @($results | Where-Object { $_.Required -and $_.Status -eq 'PASS' }).Count
        RequiredNotPassed = $requiredFailures.Count
    }
    Checks = $results
}

try {
    $json = $report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($reportFullPath, $json, (New-Object Text.UTF8Encoding($true)))
}
catch {
    $exitCode = 1
    Write-Error "Could not write integration report '$reportFullPath': $($_.Exception.Message)"
}

Write-Host ''
Write-Host 'WindowsSecurityAudit Windows integration verification' -ForegroundColor Cyan
$results | Select-Object Check, Status, Evidence | Format-Table -AutoSize -Wrap | Out-Host
Write-Host "Required checks passed: $requiredPassed" -ForegroundColor $(if ($requiredPassed) { 'Green' } else { 'Red' })
Write-Host "Report: $reportFullPath"
Write-Host "Exit code: $exitCode"
exit $exitCode
