$script:SiemTokenCache = @{}

function ConvertFrom-SiemSecureString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$SecureString
    )

    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function ConvertTo-SiemSecureString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PlainText
    )

    $secure = New-Object System.Security.SecureString
    $characters = $null
    try {
        $characters = $PlainText.ToCharArray()
        foreach ($character in $characters) {
            $secure.AppendChar($character)
        }
        $secure.MakeReadOnly()
        return $secure
    }
    finally {
        if ($null -ne $characters) {
            [Array]::Clear($characters, 0, $characters.Length)
        }
    }
}

function Get-SiemHttpStatusCode {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Exception
    )

    if ($null -eq $Exception) { return $null }
    $responseProperty = $Exception.PSObject.Properties['Response']
    if ($null -eq $responseProperty -or $null -eq $responseProperty.Value) { return $null }
    $statusProperty = $responseProperty.Value.PSObject.Properties['StatusCode']
    if ($null -eq $statusProperty -or $null -eq $statusProperty.Value) { return $null }
    try {
        return [int]$statusProperty.Value
    }
    catch {
        return $null
    }
}

function Assert-SiemTenantId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    if ($TenantId -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,255}$' -or $TenantId.Contains('..')) {
        throw 'TenantId must be a tenant GUID or domain name without path separators.'
    }
}

function Assert-SiemMonitorScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MonitorScope
    )

    $parsed = $null
    if (-not [Uri]::TryCreate($MonitorScope, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or
        -not $parsed.AbsolutePath.EndsWith('/.default', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::IsNullOrEmpty($parsed.Query) -or
        -not [string]::IsNullOrEmpty($parsed.Fragment) -or
        -not [string]::IsNullOrEmpty($parsed.UserInfo)) {
        throw 'MonitorScope must be an HTTPS resource scope ending in /.default, without a query or fragment.'
    }
}

function Assert-SiemEndpointUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion', 'GenericWebhook')]
        [string]$Destination = 'GenericWebhook',

        [Parameter()]
        [switch]$RequireHttps
    )

    $parsed = $null
    if (-not [Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        ($parsed.Scheme -ne 'https' -and $parsed.Scheme -ne 'http') -or
        -not [string]::IsNullOrEmpty($parsed.UserInfo)) {
        throw 'The SIEM endpoint must be an absolute HTTP(S) URI without embedded user information.'
    }
    if (($RequireHttps.IsPresent -or $Destination -eq 'SentinelLogsIngestion') -and $parsed.Scheme -ne 'https') {
        throw 'This SIEM destination requires an HTTPS endpoint.'
    }

    if ($Destination -eq 'SentinelLogsIngestion') {
        if ($parsed.AbsolutePath -notmatch '^/dataCollectionRules/[^/]+/streams/[^/]+/?$' -or
            $parsed.Query -notmatch '^\?api-version=[A-Za-z0-9._-]+$' -or
            -not [string]::IsNullOrEmpty($parsed.Fragment)) {
            throw 'The Logs Ingestion URI must use /dataCollectionRules/{dcrId}/streams/{stream}?api-version={version}.'
        }
    }

    return $parsed
}

function Get-SiemSafeEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Uri]$Uri
    )

    $port = $Uri.Port
    if ($port -lt 0) {
        $port = $(if ($Uri.Scheme -eq 'https') { 443 } else { 80 })
    }
    return ('{0}://{1}:{2}' -f $Uri.Scheme, $Uri.Host, $port)
}

function Get-SiemAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$MonitorScope,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [Parameter()]
        [ValidateRange(0, 60000)]
        [int]$ThrottleMs = 250,

        [Parameter()]
        [switch]$ForceRefresh
    )

    Assert-SiemTenantId -TenantId $TenantId
    Assert-SiemMonitorScope -MonitorScope $MonitorScope
    if ([string]::IsNullOrWhiteSpace($ClientId)) {
        throw 'ClientId is required for Entra client-credentials authentication.'
    }
    if ($ClientSecret.Length -eq 0) {
        throw 'ClientSecret cannot be empty.'
    }

    $cacheKey = '{0}|{1}|{2}' -f $TenantId.ToLowerInvariant(), $ClientId.ToLowerInvariant(), $MonitorScope
    if ($ForceRefresh.IsPresent -and $script:SiemTokenCache.ContainsKey($cacheKey)) {
        $script:SiemTokenCache.Remove($cacheKey)
    }

    if ($script:SiemTokenCache.ContainsKey($cacheKey)) {
        $cached = $script:SiemTokenCache[$cacheKey]
        if ([DateTimeOffset]::UtcNow -lt $cached.ExpiresAt) {
            return [string]$cached.AccessToken
        }
        $script:SiemTokenCache.Remove($cacheKey)
    }

    $tokenEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
    $plainSecret = $null
    $requestBody = $null
    $response = $null
    try {
        $plainSecret = ConvertFrom-SiemSecureString -SecureString $ClientSecret
        $requestBody = @{
            grant_type    = 'client_credentials'
            client_id     = $ClientId
            client_secret = $plainSecret
            scope         = $MonitorScope
        }

        $attempt = 0
        while ($true) {
            $attempt++
            try {
                $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -ContentType 'application/x-www-form-urlencoded' -Body $requestBody -TimeoutSec 100 -UseBasicParsing -ErrorAction Stop
                break
            }
            catch {
                $statusCode = Get-SiemHttpStatusCode -Exception $_.Exception
                $isTransient = ($null -ne $statusCode) -and (($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -le 599))
                if ($isTransient -and $attempt -le $MaxRetries) {
                    $backoffMs = $ThrottleMs * [int][math]::Pow(2, $attempt)
                    Write-Warning "Entra token request transient failure (HTTP $statusCode); retry $attempt of $MaxRetries in $backoffMs ms."
                    if ($backoffMs -gt 0) {
                        Start-Sleep -Milliseconds $backoffMs
                    }
                    continue
                }

                $statusText = $(if ($null -ne $statusCode) { " (HTTP $statusCode)" } else { '' })
                throw "Entra token request failed after $attempt attempt(s)$statusText."
            }
        }

        $accessTokenProperty = $response.PSObject.Properties['access_token']
        $expiresProperty = $response.PSObject.Properties['expires_in']
        if ($null -eq $accessTokenProperty -or [string]::IsNullOrWhiteSpace([string]$accessTokenProperty.Value) -or $null -eq $expiresProperty) {
            throw 'Entra token response did not contain access_token and expires_in.'
        }
        $expiresIn = 0.0
        if (-not [double]::TryParse([string]$expiresProperty.Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$expiresIn) -or $expiresIn -le 0) {
            throw 'Entra token response contained an invalid expires_in value.'
        }

        $script:SiemTokenCache[$cacheKey] = [PSCustomObject]@{
            AccessToken = [string]$accessTokenProperty.Value
            ExpiresAt   = [DateTimeOffset]::UtcNow.AddSeconds($expiresIn - 300)
        }
        return [string]$accessTokenProperty.Value
    }
    finally {
        if ($null -ne $requestBody) {
            $requestBody['client_secret'] = $null
        }
        $plainSecret = $null
        $response = $null
    }
}
