function Send-SiemEvent {
    <#
    .SYNOPSIS
        Streams security findings directly to SIEM HTTP endpoints
    .DESCRIPTION
        Converts finding objects to NDJSON or CEF via ConvertTo-SiemEvent and streams them
        in batches to a SIEM HTTP endpoint: Splunk HTTP Event Collector (HEC), Microsoft
        Sentinel (Log Analytics Data Collector API), or a generic webhook.

        SplunkHEC wraps each NDJSON event one JSON object per line with
        {"time":<epoch>,"host":<host>,"sourcetype":"windowsecurityaudit:finding","event":{...}}
        and authenticates with the 'Splunk <token>' Authorization header. CEF events are
        delivered as the raw string value of the 'event' field.

        Sentinel posts a JSON array to the Log Analytics Data Collector API and builds the
        documented HMAC-SHA256 SharedKey signature from the string-to-sign
        "POST\n<contentLength>\napplication/json\nx-ms-date:<rfc1123date>\n/api/logs".
        -Token supplies the shared key; the workspace ID comes from -WorkspaceId or is
        parsed from the data collector endpoint in -Uri.

        GenericWebhook posts the raw NDJSON/CEF body with optional custom -Headers.

        Transient failures (HTTP 429 or 5xx) are retried per batch with exponential
        backoff up to -MaxRetries times; a batch that still fails is counted in Failed and
        streaming continues with the next batch. Tokens are never written to output in
        full: console output shows only the first four characters followed by '...'.
        Cleartext http:// endpoints are rejected when -Token is supplied, and warned
        about otherwise, so credentials are never sent unencrypted.

        Event timestamps reflect the UTC time of conversion (produced by
        ConvertTo-SiemEvent), not the time the finding was originally detected.
    .PARAMETER InputObject
        Finding object(s) to stream. Accepts pipeline input.
    .PARAMETER Format
        Event format: NDJSON (one compact JSON object per line) or CEF (CEF:0 string).
    .PARAMETER Destination
        Target endpoint type: SplunkHEC, Sentinel, or GenericWebhook.
    .PARAMETER Uri
        Endpoint URL. For Sentinel, either the full data collector URL
        (https://<workspaceId>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01)
        or use -WorkspaceId with the same base URL.
    .PARAMETER Token
        Credential for the endpoint: the HEC token for SplunkHEC, the shared key for
        Sentinel. Sent only in request headers, never logged in full.
    .PARAMETER Headers
        Additional HTTP headers (hashtable), intended for GenericWebhook endpoints.
    .PARAMETER WorkspaceId
        Log Analytics workspace ID for Sentinel. Optional when the workspace ID can be
        parsed from -Uri.
    .PARAMETER LogType
        Log Analytics custom log type (Log-Type header) for Sentinel. Defaults to
        'WindowsSecurityAudit'.
    .PARAMETER HostName
        Host value embedded in each event. Defaults to the local machine name.
    .PARAMETER BatchSize
        Number of events per HTTP POST. Defaults to 100.
    .PARAMETER MaxRetries
        Maximum retries per batch on transient errors (HTTP 429/5xx) with exponential
        backoff. Defaults to 3.
    .PARAMETER ThrottleMs
        Base delay in milliseconds between batches; also the base of the exponential
        retry backoff (ThrottleMs * 2^attempt). Defaults to 250.
    .EXAMPLE
        $report.Findings | Send-SiemEvent -Destination SplunkHEC -Uri "https://splunk.contoso.com:8088/services/collector" -Token $hecToken
    .EXAMPLE
        Find-SuspiciousProcesses | Send-SiemEvent -Destination Sentinel -Uri "https://<workspaceId>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" -Token $sharedKey
    .EXAMPLE
        $findings | Send-SiemEvent -Destination GenericWebhook -Uri "https://siem.contoso.com/ingest" -Format CEF -Headers @{ 'X-Api-Key' = $apiKey }
    .OUTPUTS
        PSCustomObject with BatchesSent, EventsSent, Failed, and DurationSec properties.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter()]
        [ValidateSet('NDJSON', 'CEF')]
        [string]$Format = 'NDJSON',

        [Parameter(Mandatory = $true)]
        [ValidateSet('SplunkHEC', 'Sentinel', 'GenericWebhook')]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [string]$Token,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [string]$WorkspaceId,

        [Parameter()]
        [string]$LogType = 'WindowsSecurityAudit',

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
        function ConvertTo-MaskedToken {
            param([AllowNull()][string]$Secret)
            if ([string]::IsNullOrEmpty($Secret)) { return '(not provided)' }
            if ($Secret.Length -le 4) { return '****' }
            return ($Secret.Substring(0, 4) + '...')
        }

        function Get-UnixEpochSeconds {
            param([AllowNull()][object]$Timestamp)
            $unixEpoch = [DateTimeOffset]'1970-01-01T00:00:00Z'
            $parsed = $null
            if ($null -ne $Timestamp) {
                try {
                    $parsed = [DateTimeOffset]::Parse([string]$Timestamp, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
                }
                catch {
                    $parsed = $null
                }
            }
            if ($null -eq $parsed) { $parsed = [DateTimeOffset]::UtcNow }
            return [long][math]::Floor(($parsed.ToUniversalTime() - $unixEpoch).TotalSeconds)
        }

        function Get-HttpStatusCodeFromException {
            param([AllowNull()][object]$Exception)
            if ($null -eq $Exception) { return $null }
            $responseProp = $Exception.PSObject.Properties['Response']
            if ($null -eq $responseProp -or $null -eq $responseProp.Value) { return $null }
            $statusProp = $responseProp.Value.PSObject.Properties['StatusCode']
            if ($null -eq $statusProp -or $null -eq $statusProp.Value) { return $null }
            try {
                return [int]$statusProp.Value
            }
            catch {
                return $null
            }
        }

        function New-SentinelSharedKeySignature {
            param(
                [Parameter(Mandatory = $true)]
                [string]$WorkspaceId,
                [Parameter(Mandatory = $true)]
                [string]$SharedKey,
                [Parameter(Mandatory = $true)]
                [int]$ContentLength,
                [Parameter(Mandatory = $true)]
                [string]$Rfc1123Date
            )
            $stringToSign = "POST`n$ContentLength`napplication/json`nx-ms-date:$Rfc1123Date`n/api/logs"
            $keyBytes = [Convert]::FromBase64String($SharedKey)
            $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $keyBytes)
            try {
                $signatureBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToSign))
            }
            finally {
                $hmac.Dispose()
            }
            $signature = [Convert]::ToBase64String($signatureBytes)
            return "SharedKey ${WorkspaceId}:$signature"
        }

        Write-Host "Streaming findings to $Destination endpoint..." -ForegroundColor Cyan
        Write-Host "  Endpoint: $Uri" -ForegroundColor Yellow
        Write-Host "  Format: $Format | Batch size: $BatchSize | Max retries: $MaxRetries" -ForegroundColor Yellow
        if (-not [string]::IsNullOrWhiteSpace($Token)) {
            Write-Host "  Token: $(ConvertTo-MaskedToken -Secret $Token)" -ForegroundColor Yellow
        }

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        catch {
            Write-Verbose "Could not enforce TLS 1.2: $_"
        }

        $validatedUri = $null
        if (-not [System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$validatedUri) -or ($validatedUri.Scheme -ne 'https' -and $validatedUri.Scheme -ne 'http')) {
            Write-Error "Uri '$Uri' is not a valid absolute HTTP(S) endpoint."
            throw "Invalid SIEM endpoint Uri."
        }

        if ($validatedUri.Scheme -eq 'http') {
            if (-not [string]::IsNullOrWhiteSpace($Token)) {
                Write-Error "Refusing to send -Token credentials to the cleartext HTTP endpoint '$Uri'. Use HTTPS."
                throw "Cleartext HTTP endpoint rejected."
            }
            Write-Warning "Endpoint '$Uri' uses cleartext HTTP; event data and any custom headers (including API keys) will be sent unencrypted."
        }

        if ($Destination -eq 'SplunkHEC' -and [string]::IsNullOrWhiteSpace($Token)) {
            Write-Error "SplunkHEC requires -Token (HEC token) for the 'Splunk <token>' Authorization header."
            throw "Missing Splunk HEC token."
        }

        if ($Destination -eq 'Sentinel') {
            if ([string]::IsNullOrWhiteSpace($Token)) {
                Write-Error "Sentinel requires -Token containing the Log Analytics shared key."
                throw "Missing Sentinel shared key."
            }
            if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
                $workspaceMatch = [regex]::Match($Uri, '^https?://([A-Za-z0-9-]+)\.ods\.opinsights\.azure\.')
                if ($workspaceMatch.Success) {
                    $WorkspaceId = $workspaceMatch.Groups[1].Value
                }
            }
            if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
                Write-Error "Sentinel requires -WorkspaceId or a -Uri of the form https://<workspaceId>.ods.opinsights.azure.com/api/logs."
                throw "Missing Sentinel workspace ID."
            }
        }

        if ([string]::IsNullOrWhiteSpace($HostName)) {
            $HostName = 'unknown-host'
        }

        $staticHeaders = @{}
        if ($null -ne $Headers) {
            foreach ($headerName in @($Headers.Keys)) {
                $staticHeaders[$headerName] = $Headers[$headerName]
            }
        }
        if ($Destination -eq 'SplunkHEC') {
            $staticHeaders['Authorization'] = "Splunk $Token"
        }

        $contentType = 'application/x-ndjson; charset=utf-8'
        if ($Destination -eq 'SplunkHEC' -or $Destination -eq 'Sentinel') {
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
            Write-Warning "No findings received; nothing to stream."
            return [PSCustomObject]@{
                BatchesSent = 0
                EventsSent  = 0
                Failed      = 0
                DurationSec = 0
            }
        }

        $eventLines = @($pending | ConvertTo-SiemEvent -Format $Format -HostName $HostName)
        $totalEvents = @($eventLines).Count

        if ($totalEvents -eq 0) {
            Write-Warning "No findings could be converted to $Format events; nothing to stream."
            return [PSCustomObject]@{
                BatchesSent = 0
                EventsSent  = 0
                Failed      = 0
                DurationSec = 0
            }
        }

        $totalBatches = [int][math]::Ceiling($totalEvents / $BatchSize)
        Write-Host "Sending $totalEvents event(s) in $totalBatches batch(es)..." -ForegroundColor Yellow

        for ($batchIndex = 0; $batchIndex -lt $totalBatches; $batchIndex++) {
            $batchNumber = $batchIndex + 1
            $rangeStart = $batchIndex * $BatchSize
            $rangeEnd = [math]::Min($rangeStart + $BatchSize, $totalEvents) - 1
            $batchLines = @($eventLines[$rangeStart..$rangeEnd])
            $batchCount = @($batchLines).Count

            $body = $null
            $bodyBytes = $null
            $requestHeaders = @{}
            foreach ($headerName in @($staticHeaders.Keys)) {
                $requestHeaders[$headerName] = $staticHeaders[$headerName]
            }

            try {
                switch ($Destination) {
                    'SplunkHEC' {
                        $hecLines = @()
                        foreach ($line in $batchLines) {
                            $eventObject = $null
                            $eventTime = $null
                            $eventHost = $HostName
                            if ($Format -eq 'NDJSON') {
                                try {
                                    $eventObject = ($line | ConvertFrom-Json -ErrorAction Stop)
                                }
                                catch {
                                    $eventObject = $null
                                }
                            }
                            if ($null -ne $eventObject) {
                                $timestampProp = $eventObject.PSObject.Properties['timestamp']
                                if ($null -ne $timestampProp -and $null -ne $timestampProp.Value) {
                                    $eventTime = $timestampProp.Value
                                }
                                $hostProp = $eventObject.PSObject.Properties['host']
                                if ($null -ne $hostProp -and -not [string]::IsNullOrWhiteSpace([string]$hostProp.Value)) {
                                    $eventHost = [string]$hostProp.Value
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
                        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $rfc1123Date = [DateTime]::UtcNow.ToString('r', [System.Globalization.CultureInfo]::InvariantCulture)
                        $requestHeaders['Authorization'] = New-SentinelSharedKeySignature -WorkspaceId $WorkspaceId -SharedKey $Token -ContentLength $bodyBytes.Length -Rfc1123Date $rfc1123Date
                        $requestHeaders['x-ms-date'] = $rfc1123Date
                        $requestHeaders['Log-Type'] = $LogType
                    }
                    'GenericWebhook' {
                        $body = ($batchLines -join "`n")
                    }
                }
            }
            catch {
                Write-Error "Failed to build $Destination request payload: $_"
                throw
            }

            $requestParams = @{
                Uri             = $Uri
                Method          = 'Post'
                ContentType     = $contentType
                TimeoutSec      = 100
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if ($null -ne $bodyBytes) {
                $requestParams['Body'] = $bodyBytes
            }
            else {
                $requestParams['Body'] = $body
            }
            if ($requestHeaders.Count -gt 0) {
                $requestParams['Headers'] = $requestHeaders
            }
            if ($requestHeaders.ContainsKey('Content-Type')) {
                $requestParams.Remove('ContentType')
            }

            $attempt = 0
            $delivered = $false
            $lastErrorMessage = ''
            while (-not $delivered -and $attempt -le $MaxRetries) {
                $attempt++
                try {
                    $null = Invoke-RestMethod @requestParams
                    $delivered = $true
                }
                catch {
                    $lastErrorMessage = $_.Exception.Message
                    $statusCode = Get-HttpStatusCodeFromException -Exception $_.Exception
                    $isTransient = ($null -ne $statusCode) -and (($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -le 599))
                    if ($isTransient -and $attempt -le $MaxRetries) {
                        $backoffMs = $ThrottleMs * [int][math]::Pow(2, $attempt)
                        Write-Warning "Batch $batchNumber transient failure (HTTP $statusCode); retry $attempt of $MaxRetries in $backoffMs ms."
                        if ($backoffMs -gt 0) {
                            Start-Sleep -Milliseconds $backoffMs
                        }
                    }
                    else {
                        break
                    }
                }
            }

            if ($delivered) {
                $batchesSent++
                $eventsSent += $batchCount
                Write-Verbose "Batch $batchNumber of $totalBatches delivered ($batchCount event(s))."
            }
            else {
                $failedEvents += $batchCount
                Write-Warning "Batch $batchNumber of $totalBatches failed after $attempt attempt(s) and was skipped: $lastErrorMessage"
            }

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
