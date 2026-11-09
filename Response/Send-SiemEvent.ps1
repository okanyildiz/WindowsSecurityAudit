function Send-SiemEvent {
    <#
    .SYNOPSIS
        Streams security findings to SIEM HTTP endpoints or a stored SIEM profile.
    .DESCRIPTION
        Converts findings to NDJSON or CEF and sends them in batches. Direct parameter
        calls preserve Splunk HEC, legacy Microsoft Sentinel, and generic webhook behavior.
        SentinelLogsIngestion uses Entra OAuth2 client credentials and the Azure Monitor
        Logs Ingestion API. Profile calls resolve connection metadata and DPAPI secrets
        without returning or logging secret material.

        Legacy Sentinel uses the deprecated Log Analytics HTTP Data Collector API, whose
        support ended September 14, 2026. It remains only as a compatibility path and emits
        a warning. SentinelLogsIngestion requires a configured Entra application, DCR,
        ingestion endpoint, table/schema, and Monitoring Metrics Publisher access on the DCR.
        DCR schema changes can require downstream KQL and parser migration.

        Logs Ingestion requests are JSON arrays limited by both BatchSize and actual UTF-8
        byte count. MaxBatchBytes defaults to 900000, below the service 1 MB request limit.
        OAuth tokens are cached in module memory with a five-minute expiry margin. The first
        ingestion HTTP 401 causes one token refresh and retry; HTTP 429/5xx use exponential
        backoff. HTTP 400/403 configuration failures are not retried.
    .PARAMETER InputObject
        Finding object(s) to stream. Accepts pipeline input.
    .PARAMETER Format
        Event format: NDJSON (one compact JSON object per line) or CEF (CEF:0 string).
    .PARAMETER Destination
        Direct target type: SplunkHEC, Sentinel, SentinelLogsIngestion, or GenericWebhook.
    .PARAMETER Uri
        Direct endpoint URL. Logs Ingestion requires
        /dataCollectionRules/{dcrId}/streams/{stream}?api-version={version}.
    .PARAMETER Token
        Splunk HEC token or legacy Sentinel shared key. Not used for OAuth ingestion.
    .PARAMETER Headers
        Additional HTTP headers (hashtable), intended for GenericWebhook endpoints.
    .PARAMETER WorkspaceId
        Legacy Log Analytics workspace ID. Optional when it can be parsed from the Sentinel URI.
    .PARAMETER LogType
        Legacy Log Analytics custom log type. Defaults to WindowsSecurityAudit.
    .PARAMETER ProfileName
        Stored profile name. Cannot be combined with direct destination, URI, or credentials.
    .PARAMETER ProfileScope
        Profile lookup scope. Auto checks CurrentUser then LocalMachine and rejects duplicates.
    .PARAMETER TenantId
        Entra tenant GUID or domain for direct SentinelLogsIngestion calls.
    .PARAMETER ClientId
        Entra application client ID for direct SentinelLogsIngestion calls.
    .PARAMETER ClientSecret
        Entra client secret as a SecureString for direct SentinelLogsIngestion calls.
    .PARAMETER MonitorScope
        Entra resource scope. Defaults to https://monitor.azure.com/.default.
    .PARAMETER MaxBatchBytes
        Maximum UTF-8 JSON-array bytes per Logs Ingestion request. Defaults to 900000.
    .PARAMETER HostName
        Host value embedded in each event. Defaults to the local machine name.
    .PARAMETER BatchSize
        Maximum number of events per HTTP POST. Defaults to 100.
    .PARAMETER MaxRetries
        Maximum transient-failure retries per batch or token request. Defaults to 3.
    .PARAMETER ThrottleMs
        Base delay in milliseconds between batches and exponential retry backoff.
    .EXAMPLE
        $report.Findings | Send-SiemEvent -Destination SplunkHEC -Uri 'https://splunk.contoso.com:8088/services/collector' -Token $hecToken
    .EXAMPLE
        $findings | Send-SiemEvent -ProfileName sentinel-prod -ProfileScope LocalMachine
    .EXAMPLE
        $findings | Send-SiemEvent -Destination SentinelLogsIngestion -Uri $ingestionUri -TenantId $tenantId -ClientId $clientId -ClientSecret $secureSecret
    .EXAMPLE
        $findings | Send-SiemEvent -Destination GenericWebhook -Uri 'https://siem.contoso.com/ingest' -Format CEF -Headers @{ 'X-Api-Key' = $apiKey }
    .OUTPUTS
        PSCustomObject with BatchesSent, EventsSent, Failed, and DurationSec properties.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter()]
        [ValidateSet('NDJSON', 'CEF')]
        [string]$Format = 'NDJSON',

        [Parameter(ParameterSetName = 'Direct', Mandatory = $true)]
        [ValidateSet('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion', 'GenericWebhook')]
        [string]$Destination,

        [Parameter(ParameterSetName = 'Direct', Mandatory = $true)]
        [string]$Uri,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$Token,

        [Parameter(ParameterSetName = 'Direct')]
        [hashtable]$Headers,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$WorkspaceId,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$LogType = 'WindowsSecurityAudit',

        [Parameter(ParameterSetName = 'Profile', Mandatory = $true)]
        [string]$ProfileName,

        [Parameter(ParameterSetName = 'Profile')]
        [ValidateSet('Auto', 'CurrentUser', 'LocalMachine')]
        [string]$ProfileScope = 'Auto',

        [Parameter(ParameterSetName = 'Direct')]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Direct')]
        [SecureString]$ClientSecret,

        [Parameter(ParameterSetName = 'Direct')]
        [string]$MonitorScope = 'https://monitor.azure.com/.default',

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxBatchBytes = 900000,

        [Parameter()]
        [string]$HostName = [Environment]::MachineName,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$BatchSize = 100,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [Parameter()]
        [ValidateRange(0, 60000)]
        [int]$ThrottleMs = 250
    )

    begin {
        function Get-UnixEpochSeconds {
            param([AllowNull()][object]$Timestamp)
            $unixEpoch = [DateTimeOffset]'1970-01-01T00:00:00Z'
            $parsed = $null
            if ($null -ne $Timestamp) {
                try {
                    $parsed = [DateTimeOffset]::Parse([string]$Timestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
                }
                catch {
                    $parsed = $null
                }
            }
            if ($null -eq $parsed) { $parsed = [DateTimeOffset]::UtcNow }
            return [long][math]::Floor(($parsed.ToUniversalTime() - $unixEpoch).TotalSeconds)
        }

        function New-SentinelSharedKeySignature {
            param(
                [Parameter(Mandatory = $true)][string]$WorkspaceId,
                [Parameter(Mandatory = $true)][string]$SharedKey,
                [Parameter(Mandatory = $true)][int]$ContentLength,
                [Parameter(Mandatory = $true)][string]$Rfc1123Date
            )
            $stringToSign = "POST`n$ContentLength`napplication/json`nx-ms-date:$Rfc1123Date`n/api/logs"
            $keyBytes = $null
            $hmac = $null
            try {
                $keyBytes = [Convert]::FromBase64String($SharedKey)
                $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $keyBytes)
                $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
            }
            finally {
                if ($null -ne $hmac) { $hmac.Dispose() }
                if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
            }
            $signature = [Convert]::ToBase64String($signatureBytes)
            return "SharedKey ${WorkspaceId}:$signature"
        }

        $uriWasProtected = $false
        if ($PSCmdlet.ParameterSetName -eq 'Profile') {
            $resolved = Resolve-SiemProfile -Name $ProfileName -Scope $ProfileScope
            $profile = $resolved.Profile
            $Destination = [string](Get-SiemObjectProperty $profile 'type')
            $TenantId = [string](Get-SiemObjectProperty $profile 'tenantId')
            $ClientId = [string](Get-SiemObjectProperty $profile 'clientId')
            $MonitorScope = [string](Get-SiemObjectProperty $profile 'monitorScope')
            $WorkspaceId = [string](Get-SiemObjectProperty $profile 'workspaceId')
            $LogType = [string](Get-SiemObjectProperty $profile 'logType')
            if ($Destination -eq 'Sentinel' -and [string]::IsNullOrWhiteSpace($LogType)) {
                $LogType = 'WindowsSecurityAudit'
            }

            $uriRef = [string](Get-SiemObjectProperty $profile 'uriRef')
            if (-not [string]::IsNullOrWhiteSpace($uriRef)) {
                $Uri = Unprotect-SiemSecret -SecretRef $uriRef -Name $ProfileName -Scope $resolved.Scope -Purpose Uri
                $uriWasProtected = $true
            }
            else {
                $Uri = [string](Get-SiemObjectProperty $profile 'uri')
            }
            $secretRef = [string](Get-SiemObjectProperty $profile 'secretRef')
            if (-not [string]::IsNullOrWhiteSpace($secretRef)) {
                $plainSecret = Unprotect-SiemSecret -SecretRef $secretRef -Name $ProfileName -Scope $resolved.Scope -Purpose Secret
                if ($Destination -eq 'SentinelLogsIngestion') {
                    $ClientSecret = ConvertTo-SiemSecureString -PlainText $plainSecret
                }
                else {
                    $Token = $plainSecret
                }
                $plainSecret = $null
            }
        }

        if ($Destination -eq 'Sentinel') {
            Write-Warning "The 'Sentinel' destination uses the deprecated Log Analytics HTTP Data Collector API (support ended September 14, 2026). Migrate to 'SentinelLogsIngestion'."
        }

        try {
            $tls12 = [Net.SecurityProtocolType]::Tls12
            $lowerProtocols = [Net.SecurityProtocolType]::Ssl3 -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11
            $protocol = [Net.ServicePointManager]::SecurityProtocol
            $protocol = ($protocol -band (-bnot $lowerProtocols)) -bor $tls12
            try {
                $protocol = $protocol -bor [Net.SecurityProtocolType]::Tls13
            }
            catch {
                Write-Verbose 'TLS 1.3 is unavailable; retaining TLS 1.2 as the minimum.'
            }
            [Net.ServicePointManager]::SecurityProtocol = $protocol
            $appliedProtocol = [Net.ServicePointManager]::SecurityProtocol
            if (($appliedProtocol -band $lowerProtocols) -ne 0 -or ($appliedProtocol -band $tls12) -ne [int]$tls12) {
                throw 'Transport security policy verification failed.'
            }
        }
        catch {
            throw "Could not enforce TLS 1.2 or newer: $($_.Exception.GetType().Name)"
        }

        $requireHttps = $Destination -in @('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion') -or
            ($Destination -eq 'GenericWebhook' -and (-not [string]::IsNullOrWhiteSpace($Token) -or $uriWasProtected))
        $validatedUri = Assert-SiemEndpointUri -Uri $Uri -Destination $Destination -RequireHttps:$requireHttps
        $safeEndpoint = Get-SiemSafeEndpoint -Uri $validatedUri

        if ($validatedUri.Scheme -eq 'http') {
            Write-Warning "Endpoint $safeEndpoint uses cleartext HTTP; event data and custom headers will be sent unencrypted."
        }
        if ($Destination -eq 'SplunkHEC' -and [string]::IsNullOrWhiteSpace($Token)) {
            throw 'SplunkHEC requires -Token for the Authorization header.'
        }
        if ($Destination -eq 'Sentinel') {
            if ([string]::IsNullOrWhiteSpace($Token)) {
                throw 'Sentinel requires -Token containing the Log Analytics shared key.'
            }
            if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
                $workspaceMatch = [regex]::Match($Uri, '^https?://([A-Za-z0-9-]+)\.ods\.opinsights\.azure\.')
                if ($workspaceMatch.Success) { $WorkspaceId = $workspaceMatch.Groups[1].Value }
            }
            if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
                throw 'Sentinel requires -WorkspaceId or a workspace data collector URI.'
            }
        }
        if ($Destination -eq 'SentinelLogsIngestion') {
            if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or $null -eq $ClientSecret) {
                throw 'SentinelLogsIngestion requires TenantId, ClientId, and ClientSecret, either directly or from a profile.'
            }
            if ($ClientSecret.Length -eq 0) { throw 'ClientSecret cannot be empty.' }
            if (-not [string]::IsNullOrWhiteSpace($Token)) {
                throw 'SentinelLogsIngestion uses ClientSecret for OAuth, not the legacy Token parameter.'
            }
            Assert-SiemTenantId -TenantId $TenantId
            Assert-SiemMonitorScope -MonitorScope $MonitorScope
        }

        Write-Host "Streaming findings to $Destination endpoint..." -ForegroundColor Cyan
        Write-Host "  Endpoint: $safeEndpoint" -ForegroundColor Yellow
        Write-Host "  Format: $Format | Batch size: $BatchSize | Max retries: $MaxRetries" -ForegroundColor Yellow
        if (-not [string]::IsNullOrWhiteSpace($Token) -or $null -ne $ClientSecret) {
            Write-Host '  Credential: provided (not logged)' -ForegroundColor Yellow
        }

        if ([string]::IsNullOrWhiteSpace($HostName)) { $HostName = 'unknown-host' }
        $staticHeaders = @{}
        if ($null -ne $Headers) {
            foreach ($headerName in @($Headers.Keys)) { $staticHeaders[$headerName] = $Headers[$headerName] }
        }
        if ($Destination -eq 'SplunkHEC') { $staticHeaders['Authorization'] = "Splunk $Token" }

        $contentType = 'application/x-ndjson; charset=utf-8'
        if ($Destination -in @('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion')) {
            $contentType = 'application/json'
        }
        elseif ($Destination -eq 'GenericWebhook' -and $Format -eq 'CEF') {
            $contentType = 'text/plain; charset=utf-8'
        }

        $pending = @()
        $batchesSent = 0
        $eventsSent = 0
        $failedEvents = 0
        $startTime = Get-Date
    }

    process {
        $pending += $InputObject
    }

    end {
        if (@($pending).Count -eq 0) {
            Write-Warning 'No findings received; nothing to stream.'
            return [PSCustomObject]@{ BatchesSent = 0; EventsSent = 0; Failed = 0; DurationSec = 0 }
        }

        $eventLines = @($pending | ConvertTo-SiemEvent -Format $Format -HostName $HostName)
        $totalEvents = @($eventLines).Count
        if ($totalEvents -eq 0) {
            Write-Warning "No findings could be converted to $Format events; nothing to stream."
            return [PSCustomObject]@{ BatchesSent = 0; EventsSent = 0; Failed = 0; DurationSec = 0 }
        }

        if ($Destination -eq 'SentinelLogsIngestion' -and $Format -eq 'CEF') {
            $jsonLines = @()
            foreach ($line in $eventLines) {
                $jsonLines += ([ordered]@{
                    timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    host      = $HostName
                    message   = $line
                } | ConvertTo-Json -Compress -Depth 5)
            }
            $eventLines = @($jsonLines)
        }

        $batches = New-Object 'System.Collections.Generic.List[object]'
        if ($Destination -eq 'SentinelLogsIngestion') {
            $currentLines = New-Object 'System.Collections.Generic.List[string]'
            $currentBytes = 2
            foreach ($line in $eventLines) {
                $lineBytes = [Text.Encoding]::UTF8.GetByteCount([string]$line)
                $commaBytes = $(if ($currentLines.Count -gt 0) { 1 } else { 0 })
                $wouldExceed = $currentBytes + $lineBytes + $commaBytes -gt $MaxBatchBytes
                if ($currentLines.Count -gt 0 -and ($currentLines.Count -ge $BatchSize -or $wouldExceed)) {
                    $batches.Add([object]$currentLines.ToArray())
                    $currentLines = New-Object 'System.Collections.Generic.List[string]'
                    $currentBytes = 2
                    $commaBytes = 0
                }
                if ($currentLines.Count -eq 0 -and 2 + $lineBytes -gt $MaxBatchBytes) {
                    $failedEvents++
                    Write-Warning "One event exceeds the $MaxBatchBytes-byte Logs Ingestion budget and was skipped."
                    continue
                }
                $commaBytes = $(if ($currentLines.Count -gt 0) { 1 } else { 0 })
                $currentLines.Add([string]$line)
                $currentBytes += $lineBytes + $commaBytes
            }
            if ($currentLines.Count -gt 0) { $batches.Add([object]$currentLines.ToArray()) }
        }
        else {
            for ($rangeStart = 0; $rangeStart -lt $totalEvents; $rangeStart += $BatchSize) {
                $rangeEnd = [math]::Min($rangeStart + $BatchSize, $totalEvents) - 1
                $batches.Add([object]@($eventLines[$rangeStart..$rangeEnd]))
            }
        }

        $totalBatches = $batches.Count
        Write-Host "Sending $totalEvents event(s) in $totalBatches batch(es)..." -ForegroundColor Yellow
        for ($batchIndex = 0; $batchIndex -lt $totalBatches; $batchIndex++) {
            $batchNumber = $batchIndex + 1
            $batchLines = @($batches[$batchIndex])
            $batchCount = $batchLines.Count
            $body = $null
            $bodyBytes = $null
            $requestHeaders = @{}
            foreach ($headerName in @($staticHeaders.Keys)) { $requestHeaders[$headerName] = $staticHeaders[$headerName] }

            try {
                switch ($Destination) {
                    'SplunkHEC' {
                        $hecLines = @()
                        foreach ($line in $batchLines) {
                            $eventObject = $null
                            $eventTime = $null
                            $eventHost = $HostName
                            if ($Format -eq 'NDJSON') {
                                try { $eventObject = ($line | ConvertFrom-Json -ErrorAction Stop) }
                                catch { $eventObject = $null }
                            }
                            if ($null -ne $eventObject) {
                                $timestampProperty = $eventObject.PSObject.Properties['timestamp']
                                if ($null -ne $timestampProperty -and $null -ne $timestampProperty.Value) { $eventTime = $timestampProperty.Value }
                                $hostProperty = $eventObject.PSObject.Properties['host']
                                if ($null -ne $hostProperty -and -not [string]::IsNullOrWhiteSpace([string]$hostProperty.Value)) {
                                    $eventHost = [string]$hostProperty.Value
                                }
                                $hecLines += ([ordered]@{
                                    time        = (Get-UnixEpochSeconds -Timestamp $eventTime)
                                    host        = $eventHost
                                    sourcetype  = 'windowsecurityaudit:finding'
                                    event       = $eventObject
                                } | ConvertTo-Json -Compress -Depth 10)
                            }
                            else {
                                $hecLines += ([ordered]@{
                                    time        = (Get-UnixEpochSeconds -Timestamp $null)
                                    host        = $eventHost
                                    sourcetype  = 'windowsecurityaudit:finding'
                                    event       = $line
                                } | ConvertTo-Json -Compress -Depth 10)
                            }
                        }
                        $body = ($hecLines -join "`n")
                    }
                    'Sentinel' {
                        if ($Format -eq 'NDJSON') {
                            $body = '[' + ($batchLines -join ',') + ']'
                        }
                        else {
                            $cefObjects = @()
                            foreach ($line in $batchLines) {
                                $cefObjects += ([ordered]@{
                                    timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                                    host      = $HostName
                                    message   = $line
                                } | ConvertTo-Json -Compress -Depth 5)
                            }
                            $body = '[' + ($cefObjects -join ',') + ']'
                        }
                        $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
                        $rfc1123Date = [DateTime]::UtcNow.ToString('r', [Globalization.CultureInfo]::InvariantCulture)
                        $requestHeaders['Authorization'] = New-SentinelSharedKeySignature -WorkspaceId $WorkspaceId -SharedKey $Token -ContentLength $bodyBytes.Length -Rfc1123Date $rfc1123Date
                        $requestHeaders['x-ms-date'] = $rfc1123Date
                        $requestHeaders['Log-Type'] = $LogType
                    }
                    'SentinelLogsIngestion' {
                        $body = '[' + ($batchLines -join ',') + ']'
                        $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
                    }
                    'GenericWebhook' {
                        $body = ($batchLines -join "`n")
                    }
                }
            }
            catch {
                Write-Error "Failed to build $Destination request payload ($($_.Exception.GetType().Name))."
                throw "Failed to build $Destination request payload."
            }

            $accessToken = $null
            if ($Destination -eq 'SentinelLogsIngestion') {
                try {
                    $accessToken = Get-SiemAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -MonitorScope $MonitorScope -MaxRetries $MaxRetries -ThrottleMs $ThrottleMs
                    $requestHeaders['Authorization'] = "Bearer $accessToken"
                }
                catch {
                    $failedEvents += $batchCount
                    Write-Warning "Batch $batchNumber of $totalBatches could not acquire an Entra token and was skipped."
                    continue
                }
            }

            $requestParams = @{
                Uri             = $Uri
                Method          = 'Post'
                ContentType     = $contentType
                TimeoutSec      = 100
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if ($null -ne $bodyBytes) { $requestParams['Body'] = $bodyBytes } else { $requestParams['Body'] = $body }
            if ($requestHeaders.Count -gt 0) { $requestParams['Headers'] = $requestHeaders }
            if ($requestHeaders.ContainsKey('Content-Type')) { $requestParams.Remove('ContentType') }

            $requestAttempts = 0
            $transientRetries = 0
            $reauthenticated = $false
            $delivered = $false
            $lastFailure = 'Unknown transport error.'
            while (-not $delivered) {
                $requestAttempts++
                try {
                    $null = Invoke-RestMethod @requestParams
                    $delivered = $true
                }
                catch {
                    $statusCode = Get-SiemHttpStatusCode -Exception $_.Exception
                    $lastFailure = $(if ($null -ne $statusCode) { "HTTP $statusCode" } else { "Transport exception: $($_.Exception.GetType().Name)" })
                    if ($Destination -eq 'SentinelLogsIngestion' -and $statusCode -eq 401 -and -not $reauthenticated) {
                        $reauthenticated = $true
                        Write-Warning "Batch $batchNumber received HTTP 401; refreshing the Entra token and retrying once."
                        try {
                            $accessToken = Get-SiemAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -MonitorScope $MonitorScope -MaxRetries $MaxRetries -ThrottleMs $ThrottleMs -ForceRefresh
                            $requestHeaders['Authorization'] = "Bearer $accessToken"
                        }
                        catch {
                            $lastFailure = 'Entra token refresh failed.'
                            break
                        }
                        continue
                    }

                    $isTransient = ($null -ne $statusCode) -and (($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -le 599))
                    if ($isTransient -and $transientRetries -lt $MaxRetries) {
                        $transientRetries++
                        $backoffMs = $ThrottleMs * [int][math]::Pow(2, $transientRetries)
                        Write-Warning "Batch $batchNumber transient failure (HTTP $statusCode); retry $transientRetries of $MaxRetries in $backoffMs ms."
                        if ($backoffMs -gt 0) { Start-Sleep -Milliseconds $backoffMs }
                        continue
                    }
                    break
                }
            }

            if ($delivered) {
                $batchesSent++
                $eventsSent += $batchCount
                Write-Verbose "Batch $batchNumber of $totalBatches delivered ($batchCount event(s))."
            }
            else {
                $failedEvents += $batchCount
                Write-Warning "Batch $batchNumber of $totalBatches failed after $requestAttempts attempt(s) and was skipped: $lastFailure"
            }
            $accessToken = $null

            if ($batchIndex -lt ($totalBatches - 1) -and $ThrottleMs -gt 0) {
                Start-Sleep -Milliseconds $ThrottleMs
            }
        }

        $durationSec = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
        Write-Host "SIEM stream complete: $eventsSent event(s) sent in $batchesSent batch(es); $failedEvents event(s) failed ($durationSec s)." -ForegroundColor Green
        return [PSCustomObject]@{
            BatchesSent = $batchesSent
            EventsSent  = $eventsSent
            Failed      = $failedEvents
            DurationSec = $durationSec
        }
    }
}
