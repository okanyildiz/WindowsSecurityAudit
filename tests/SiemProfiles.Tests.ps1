#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path $script:ModuleRoot -ChildPath 'WindowsSecurityAudit.psd1'
    $script:OriginalProfileRoot = $env:WSA_SIEM_PROFILE_ROOT
    $script:IngestionUri = 'https://example.ingest.monitor.azure.com/dataCollectionRules/dcr-test/streams/Custom-Wsa?api-version=2023-03-01'
    $script:TenantId = '11111111-1111-1111-1111-111111111111'
    $script:ClientId = '22222222-2222-2222-2222-222222222222'
    Import-Module -Name $script:ModulePath -Force

    function New-TestFinding {
        param([string]$Message = 'Test finding')
        [PSCustomObject]@{
            Severity       = 'High'
            Category       = 'Test'
            Finding        = $Message
            Impact         = 'Test impact'
            Recommendation = 'Test recommendation'
        }
    }

    function New-TestSecret {
        param([string]$Value = 'oauth-secret-value')
        $secure = New-Object System.Security.SecureString
        foreach ($character in $Value.ToCharArray()) { $secure.AppendChar($character) }
        $secure.MakeReadOnly()
        return $secure
    }
}

Describe 'SIEM auth profiles and Logs Ingestion' {
BeforeEach {
    $script:ProfileTestRoot = Join-Path $TestDrive ('profiles-' + [Guid]::NewGuid().ToString('N'))
    $env:WSA_SIEM_PROFILE_ROOT = $script:ProfileTestRoot
    $script:TestTokenRequests = @()
    $script:TestIngestionRequests = @()
    $script:TestTokenStatusSequence = @()
    $script:TestIngestionStatusSequence = @()
    InModuleScope -ModuleName 'WindowsSecurityAudit' {
        $script:SiemTokenCache.Clear()
    }

    Mock -ModuleName 'WindowsSecurityAudit' Protect-SiemSecret {
        param($Secret, $Name, $Scope, $Purpose)
        $bstr = [IntPtr]::Zero
        try {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        $prefix = $(if ($Scope -eq 'LocalMachine') { 'wsa-dpapi-lm-v1:' } else { 'wsa-dpapi-cu-v1:' })
        $prefix + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain))
    }
    Mock -ModuleName 'WindowsSecurityAudit' Unprotect-SiemSecret {
        param($SecretRef, $Name, $Scope, $Purpose)
        $prefix = $(if ($Scope -eq 'LocalMachine') { 'wsa-dpapi-lm-v1:' } else { 'wsa-dpapi-cu-v1:' })
        if (-not $SecretRef.StartsWith($prefix, [StringComparison]::Ordinal)) { throw 'Wrong test DPAPI scope.' }
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SecretRef.Substring($prefix.Length)))
    }
    Mock -ModuleName 'WindowsSecurityAudit' Protect-SiemProfileAcl { }
    Mock -ModuleName 'WindowsSecurityAudit' Start-Sleep { }

    Mock -ModuleName 'WindowsSecurityAudit' Invoke-RestMethod {
        if ($Uri -like 'https://login.microsoftonline.com/*') {
            $requestNumber = $script:TestTokenRequests.Count + 1
            $script:TestTokenRequests += [PSCustomObject]@{
                Uri         = [string]$Uri
                Method      = $Method
                ContentType = $ContentType
                Body        = @{
                    grant_type    = $Body['grant_type']
                    client_id     = $Body['client_id']
                    client_secret = $Body['client_secret']
                    scope         = $Body['scope']
                }
            }
            $status = 200
            if ($script:TestTokenStatusSequence.Count -ge $requestNumber) {
                $status = [int]$script:TestTokenStatusSequence[$requestNumber - 1]
            }
            if ($status -ne 200) {
                $httpException = [Exception]::new("Simulated HTTP $status")
                $httpResponse = [PSCustomObject]@{ StatusCode = [Net.HttpStatusCode]$status }
                $httpException = Add-Member -InputObject $httpException -NotePropertyName Response -NotePropertyValue $httpResponse -PassThru
                throw $httpException
            }
            return [PSCustomObject]@{
                access_token = "test-token-$requestNumber"
                expires_in   = 3600
                token_type   = 'Bearer'
            }
        }

        $requestNumber = $script:TestIngestionRequests.Count + 1
        $headerCopy = @{}
        if ($null -ne $Headers) {
            foreach ($key in $Headers.Keys) { $headerCopy[$key] = $Headers[$key] }
        }
        if ($Body -is [byte[]]) {
            $bodyText = [Text.Encoding]::UTF8.GetString($Body)
            $bodyBytes = $Body.Length
        }
        else {
            $bodyText = [string]$Body
            $bodyBytes = [Text.Encoding]::UTF8.GetByteCount($bodyText)
        }
        $script:TestIngestionRequests += [PSCustomObject]@{
            Uri       = [string]$Uri
            Method    = $Method
            Headers   = $headerCopy
            BodyText  = $bodyText
            ByteCount = $bodyBytes
        }
        $status = 200
        if ($script:TestIngestionStatusSequence.Count -ge $requestNumber) {
            $status = [int]$script:TestIngestionStatusSequence[$requestNumber - 1]
        }
        if ($status -ne 200) {
            $httpException = [Exception]::new("Simulated HTTP $status")
            $httpResponse = [PSCustomObject]@{ StatusCode = [Net.HttpStatusCode]$status }
            $httpException = Add-Member -InputObject $httpException -NotePropertyName Response -NotePropertyValue $httpResponse -PassThru
            throw $httpException
        }
        return $null
    }
}

AfterEach {
    if ($null -eq $script:OriginalProfileRoot) {
        Remove-Item Env:WSA_SIEM_PROFILE_ROOT -ErrorAction SilentlyContinue
    }
    else {
        $env:WSA_SIEM_PROFILE_ROOT = $script:OriginalProfileRoot
    }
    if (Test-Path -LiteralPath $script:ProfileTestRoot) {
        Remove-Item -LiteralPath $script:ProfileTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

AfterAll {
    if ($null -eq $script:OriginalProfileRoot) {
        Remove-Item Env:WSA_SIEM_PROFILE_ROOT -ErrorAction SilentlyContinue
    }
    else {
        $env:WSA_SIEM_PROFILE_ROOT = $script:OriginalProfileRoot
    }
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'SIEM profile store' {
    It 'round trips a Logs Ingestion profile without plaintext or secret metadata' {
        $result = Set-SiemProfile -Name sentinel-prod -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -Secret (New-TestSecret) -Scope CurrentUser -Confirm:$false
        $path = Join-Path $script:ProfileTestRoot 'CurrentUser/sentinel-prod.json'
        Test-Path -LiteralPath $path | Should -BeTrue
        $json = [IO.File]::ReadAllText($path)
        $json | Should -Not -Match 'oauth-secret-value'
        $json | Should -Match 'wsa-dpapi-cu-v1:'

        $result.HasSecret | Should -BeTrue
        $result.Destination | Should -Be 'SentinelLogsIngestion'
        $metadata = Get-SiemProfile -Name sentinel-prod
        $metadata.Count | Should -Be 1
        $metadata[0].PSObject.Properties.Name | Should -Not -Contain 'secretRef'
        $metadata[0].PSObject.Properties.Name | Should -Not -Contain 'uriRef'
        ($metadata | ConvertTo-Json -Depth 5) | Should -Not -Match 'oauth-secret-value|wsa-dpapi'

        Remove-SiemProfile -Name sentinel-prod -Confirm:$false
        Test-Path -LiteralPath $path | Should -BeFalse
        @(Get-SiemProfile).Count | Should -Be 0
    }

    It 'protects a generic webhook URI and suppresses it in metadata' {
        $secretUri = 'https://example.invalid/ingest?api_key=uri-secret-value'
        $profile = Set-SiemProfile -Name webhook -Destination GenericWebhook -Uri $secretUri -ProtectUri -Confirm:$false
        $path = Join-Path $script:ProfileTestRoot 'CurrentUser/webhook.json'
        [IO.File]::ReadAllText($path) | Should -Not -Match 'uri-secret-value'
        $profile.Uri | Should -BeNullOrEmpty
        $profile.IsUriProtected | Should -BeTrue
        $profile.HasSecret | Should -BeFalse
        $profile.PSObject.Properties.Name | Should -Not -Contain 'uriRef'
    }

    It 'rejects invalid profile names: <_>' -ForEach @('', '.hidden', 'bad/name', '../evil', 'bad name', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') {
        {
            Set-SiemProfile -Name $_ -Destination GenericWebhook -Uri 'https://example.invalid/ingest' -Confirm:$false
        } | Should -Throw
        Test-Path -LiteralPath $script:ProfileTestRoot | Should -BeFalse
    }

    It 'enforces destination-specific validation before writing' {
        $secret = New-TestSecret
        { Set-SiemProfile -Name invalid -Destination SentinelLogsIngestion -Uri $script:IngestionUri -Secret $secret -Confirm:$false } | Should -Throw
        { Set-SiemProfile -Name invalid -Destination SplunkHEC -Uri 'https://splunk.invalid/collector' -Confirm:$false } | Should -Throw
        { Set-SiemProfile -Name invalid -Destination GenericWebhook -Uri 'https://example.invalid' -Secret $secret -Confirm:$false } | Should -Throw
        { Set-SiemProfile -Name invalid -Destination Sentinel -Uri 'https://example.invalid/api/logs?api-version=2016-04-01' -Secret $secret -Confirm:$false } | Should -Throw
        Test-Path -LiteralPath $script:ProfileTestRoot | Should -BeFalse
    }

    It 'rejects ambiguous duplicate names in Auto scope' {
        Set-SiemProfile -Name duplicate -Destination GenericWebhook -Uri 'https://user.invalid' -Scope CurrentUser -Confirm:$false | Out-Null
        Set-SiemProfile -Name duplicate -Destination GenericWebhook -Uri 'https://machine.invalid' -Scope LocalMachine -Confirm:$false | Out-Null
        { Get-SiemProfile -Name duplicate } | Should -Throw '*both CurrentUser and LocalMachine*'
        (Get-SiemProfile -Name duplicate -Scope CurrentUser).Uri | Should -Be 'https://user.invalid'
        (Get-SiemProfile -Name duplicate -Scope LocalMachine).Uri | Should -Be 'https://machine.invalid'
        { Remove-SiemProfile -Name duplicate -Confirm:$false } | Should -Throw '*both CurrentUser and LocalMachine*'
        @(Get-SiemProfile).Count | Should -Be 2
    }

    It 'rejects malformed schemas without reflecting secret values' {
        Set-SiemProfile -Name malformed -Destination GenericWebhook -Uri 'https://example.invalid' -Confirm:$false | Out-Null
        $path = Join-Path $script:ProfileTestRoot 'CurrentUser/malformed.json'
        $record = [IO.File]::ReadAllText($path) | ConvertFrom-Json
        $record | Add-Member -NotePropertyName unexpectedSecret -NotePropertyValue 'must-not-leak'
        [IO.File]::WriteAllText($path, ($record | ConvertTo-Json -Depth 5))
        $caught = $null
        try { Get-SiemProfile -Name malformed -ErrorAction Stop } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Match 'unsupported field'
        $caught.Exception.Message | Should -Not -Match 'must-not-leak'
    }

    It 'rejects a stored OAuth profile with missing required fields' {
        Set-SiemProfile -Name incomplete -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -Secret (New-TestSecret) -Confirm:$false | Out-Null
        $path = Join-Path $script:ProfileTestRoot 'CurrentUser/incomplete.json'
        $record = [IO.File]::ReadAllText($path) | ConvertFrom-Json
        $record.PSObject.Properties.Remove('tenantId')
        [IO.File]::WriteAllText($path, ($record | ConvertTo-Json -Depth 5))
        { Get-SiemProfile -Name incomplete } | Should -Throw '*missing tenantId*'
    }

    It 'requires Force for replacement and honors WhatIf without protecting a secret' {
        Set-SiemProfile -Name replace-me -Destination GenericWebhook -Uri 'https://old.invalid' -Confirm:$false | Out-Null
        { Set-SiemProfile -Name replace-me -Destination GenericWebhook -Uri 'https://new.invalid' -Confirm:$false } | Should -Throw '*Use -Force*'
        (Set-SiemProfile -Name replace-me -Destination GenericWebhook -Uri 'https://new.invalid' -Force -Confirm:$false).Uri | Should -Be 'https://new.invalid'

        Set-SiemProfile -Name what-if -Destination SplunkHEC -Uri 'https://splunk.invalid/collector' -Secret (New-TestSecret) -WhatIf
        Test-Path -LiteralPath (Join-Path $script:ProfileTestRoot 'CurrentUser/what-if.json') | Should -BeFalse
        Should -Invoke Protect-SiemSecret -ModuleName 'WindowsSecurityAudit' -Times 0 -Exactly
    }

    It 'does not remove a profile under WhatIf' {
        Set-SiemProfile -Name keep-me -Destination GenericWebhook -Uri 'https://example.invalid' -Confirm:$false | Out-Null
        Remove-SiemProfile -Name keep-me -WhatIf
        Test-Path -LiteralPath (Join-Path $script:ProfileTestRoot 'CurrentUser/keep-me.json') | Should -BeTrue
    }
}

Describe 'Sentinel Logs Ingestion authentication and transport' {
    It 'uses the exact Entra token endpoint, form body, scope, and Bearer ingestion request' {
        $result = New-TestFinding | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -ThrottleMs 0
        $result.EventsSent | Should -Be 1
        $result.Failed | Should -Be 0

        $tokens = @($script:TestTokenRequests)
        $ingestion = @($script:TestIngestionRequests)
        $tokens.Count | Should -Be 1
        $tokens[0].Uri | Should -Be "https://login.microsoftonline.com/$script:TenantId/oauth2/v2.0/token"
        $tokens[0].Method | Should -Be 'Post'
        $tokens[0].ContentType | Should -Be 'application/x-www-form-urlencoded'
        $tokens[0].Body.grant_type | Should -Be 'client_credentials'
        $tokens[0].Body.client_id | Should -Be $script:ClientId
        $tokens[0].Body.client_secret | Should -Be 'oauth-secret-value'
        $tokens[0].Body.scope | Should -Be 'https://monitor.azure.com/.default'
        $ingestion.Count | Should -Be 1
        $ingestion[0].Headers.Authorization | Should -Be 'Bearer test-token-1'
        $ingestion[0].Headers.ContainsKey('SharedKey') | Should -BeFalse
        $ingestion[0].Headers.ContainsKey('Log-Type') | Should -BeFalse
        $ingestion[0].Headers.ContainsKey('x-ms-date') | Should -BeFalse
        $ingestion[0].BodyText | Should -Match '^\[.*\]$'
    }

    It 'sends from a stored OAuth profile' {
        Set-SiemProfile -Name oauth-profile -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -Secret (New-TestSecret) -Confirm:$false | Out-Null
        $result = New-TestFinding | Send-SiemEvent -ProfileName oauth-profile -ProfileScope CurrentUser -ThrottleMs 0
        $result.EventsSent | Should -Be 1
        $tokens = @($script:TestTokenRequests)
        $tokens.Count | Should -Be 1
        $tokens[0].Body.client_secret | Should -Be 'oauth-secret-value'
    }

    It 'reuses a cached unexpired token across calls' {
        $secret = New-TestSecret
        New-TestFinding -Message first | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $secret -ThrottleMs 0 | Out-Null
        New-TestFinding -Message second | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $secret -ThrottleMs 0 | Out-Null
        @($script:TestTokenRequests).Count | Should -Be 1
        @($script:TestIngestionRequests).Count | Should -Be 2
    }

    It 'refreshes a token inside the five-minute expiry margin' {
        InModuleScope -ModuleName 'WindowsSecurityAudit' {
            $key = '11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|https://monitor.azure.com/.default'
            $script:SiemTokenCache[$key] = [PSCustomObject]@{
                AccessToken = 'stale-token'
                ExpiresAt   = [DateTimeOffset]::UtcNow.AddSeconds(-1)
            }
        }
        New-TestFinding | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -ThrottleMs 0 | Out-Null
        $ingestion = @($script:TestIngestionRequests)
        $ingestion[0].Headers.Authorization | Should -Be 'Bearer test-token-1'
        @($script:TestTokenRequests).Count | Should -Be 1
    }

    It 're-authenticates once and retries the first ingestion HTTP 401' {
        $script:TestIngestionStatusSequence = @(401, 200)
        $result = New-TestFinding | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -ThrottleMs 0 -WarningAction SilentlyContinue
        $result.EventsSent | Should -Be 1
        $result.Failed | Should -Be 0
        $tokens = @($script:TestTokenRequests)
        $ingestion = @($script:TestIngestionRequests)
        $tokens.Count | Should -Be 2
        $ingestion.Count | Should -Be 2
        $ingestion[0].Headers.Authorization | Should -Be 'Bearer test-token-1'
        $ingestion[1].Headers.Authorization | Should -Be 'Bearer test-token-2'
    }

    It 'does not retry ingestion HTTP 403' {
        $script:TestIngestionStatusSequence = @(403)
        $result = New-TestFinding | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -ThrottleMs 0 -WarningAction SilentlyContinue
        $result.EventsSent | Should -Be 0
        $result.Failed | Should -Be 1
        @($script:TestTokenRequests).Count | Should -Be 1
        @($script:TestIngestionRequests).Count | Should -Be 1
    }

    It 'backs off and retries transient ingestion failures' {
        $script:TestIngestionStatusSequence = @(429, 200)
        $result = New-TestFinding | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -MaxRetries 1 -ThrottleMs 10 -WarningAction SilentlyContinue
        $result.EventsSent | Should -Be 1
        @($script:TestIngestionRequests).Count | Should -Be 2
        Should -Invoke Start-Sleep -ModuleName 'WindowsSecurityAudit' -Times 1 -Exactly
    }

    It 'backs off and retries transient token failures' {
        $script:TestTokenStatusSequence = @(429, 200)
        $result = New-TestFinding | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -MaxRetries 1 -ThrottleMs 10 -WarningAction SilentlyContinue
        $result.EventsSent | Should -Be 1
        @($script:TestTokenRequests).Count | Should -Be 2
        Should -Invoke Start-Sleep -ModuleName 'WindowsSecurityAudit' -Times 1 -Exactly
    }

    It 'keeps every request within the UTF-8 byte budget and delivers each event once' {
        $expected = @()
        $findings = @()
        for ($index = 0; $index -lt 12; $index++) {
            $message = 'event-{0:D2}-{1}' -f $index, ('x' * 120)
            $expected += $message
            $findings += New-TestFinding -Message $message
        }
        $result = $findings | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -MaxBatchBytes 1000 -ThrottleMs 0
        $result.EventsSent | Should -Be 12
        $result.Failed | Should -Be 0
        $requests = @($script:TestIngestionRequests)
        $requests.Count | Should -BeGreaterThan 1
        $actual = @()
        $batchEventCounts = @()
        foreach ($request in $requests) {
            $request.ByteCount | Should -BeLessOrEqual 1000
            $events = @($request.BodyText | ConvertFrom-Json)
            $batchEventCounts += $events.Count
            $actual += @($events | ForEach-Object { $_.message })
        }
        @($batchEventCounts | Where-Object { $_ -gt 1 }).Count | Should -BeGreaterThan 0
        $actual.Count | Should -Be 12
        @($actual | Sort-Object) | Should -Be @($expected | Sort-Object)
    }

    It 'counts a single oversized event as failed without sending it' {
        $result = New-TestFinding -Message ('x' * 500) | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $script:IngestionUri -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret (New-TestSecret) -MaxBatchBytes 100 -ThrottleMs 0 -WarningAction SilentlyContinue
        $result.EventsSent | Should -Be 0
        $result.Failed | Should -Be 1
        @($script:TestIngestionRequests).Count | Should -Be 0
    }

    It 'warns for legacy Sentinel while retaining SharedKey headers' {
        $sharedKey = [Convert]::ToBase64String([byte[]](1..32))
        $legacyUri = 'https://33333333-3333-3333-3333-333333333333.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'
        $result = New-TestFinding | Send-SiemEvent -Destination Sentinel -Uri $legacyUri -Token $sharedKey -WorkspaceId '33333333-3333-3333-3333-333333333333' -ThrottleMs 0 -WarningVariable legacyWarnings -WarningAction SilentlyContinue
        $result.EventsSent | Should -Be 1
        @($legacyWarnings | Where-Object { $_ -match 'deprecated.*September 14, 2026' }).Count | Should -Be 1
        $requests = @($script:TestIngestionRequests)
        $requests[0].Headers.Authorization | Should -Match '^SharedKey '
        $requests[0].Headers['Log-Type'] | Should -Be 'WindowsSecurityAudit'
        $requests[0].Headers.ContainsKey('x-ms-date') | Should -BeTrue
    }

    It 'rejects mixed Profile and Direct parameters' {
        { New-TestFinding | Send-SiemEvent -ProfileName oauth -Destination SentinelLogsIngestion -Uri $script:IngestionUri } | Should -Throw
    }
}

Describe 'Export-SecurityReport SIEM profile integration' {
    BeforeEach {
        Mock -ModuleName 'WindowsSecurityAudit' Get-SecurityBaseline { [PSCustomObject]@{ SecurityScore = 10 } }
        Mock -ModuleName 'WindowsSecurityAudit' Get-SystemInfo { $null }
        Mock -ModuleName 'WindowsSecurityAudit' Find-PersistenceMechanisms { $null }
        Mock -ModuleName 'WindowsSecurityAudit' Find-SuspiciousProcesses { $null }
        Mock -ModuleName 'WindowsSecurityAudit' Find-NetworkAnomalies { $null }
        Mock -ModuleName 'WindowsSecurityAudit' Find-SuspiciousAuthentication { $null }
        Mock -ModuleName 'WindowsSecurityAudit' Get-EventLogAnalysis { $null }
        Mock -ModuleName 'WindowsSecurityAudit' Get-RegistryAnalysis { $null }
    }

    It 'passes the profile name and scope to Send-SiemEvent' {
        Mock -ModuleName 'WindowsSecurityAudit' Send-SiemEvent {
            [PSCustomObject]@{ BatchesSent = 0; EventsSent = 0; Failed = 0; DurationSec = 0 }
        }
        $outputPath = Join-Path $TestDrive 'profile-report'
        $result = Export-SecurityReport -ReportType Technical -Format JSON -OutputPath $outputPath -NoAutoOpen -StreamProfileName oauth -StreamProfileScope CurrentUser
        $result.StreamResult | Should -Not -BeNullOrEmpty
        Should -Invoke Send-SiemEvent -ModuleName 'WindowsSecurityAudit' -Times 1 -Exactly -ParameterFilter {
            $ProfileName -eq 'oauth' -and
            $ProfileScope -eq 'CurrentUser' -and
            -not $PSBoundParameters.ContainsKey('Destination') -and
            -not $PSBoundParameters.ContainsKey('Uri')
        }
    }

    It 'rejects ambiguous direct and profile streaming parameters' {
        {
            Export-SecurityReport -ReportType Technical -Format JSON -OutputPath (Join-Path $TestDrive 'invalid-report') -NoAutoOpen -StreamProfileName oauth -StreamTo SplunkHEC
        } | Should -Throw '*cannot be combined*'
    }

    It 'documents profiles as the only report route for direct OAuth ingestion' {
        {
            Export-SecurityReport -ReportType Technical -Format JSON -OutputPath (Join-Path $TestDrive 'invalid-oauth-report') -NoAutoOpen -StreamTo SentinelLogsIngestion -StreamUri $script:IngestionUri
        } | Should -Throw '*Use -StreamProfileName*'
    }
}
}
