function ConvertTo-SiemEvent {
    <#
    .SYNOPSIS
        Converts security findings into SIEM-ready event strings
    .DESCRIPTION
        Transforms finding objects (Severity/Category/Finding/Impact/Recommendation) or any
        PSCustomObject into newline-delimited JSON (NDJSON) or Common Event Format (CEF)
        strings suitable for ingestion by SIEM platforms (Splunk, Microsoft Sentinel,
        QRadar, ArcSight). One line is emitted per input object, so the output can be
        written directly to a .ndjson or .cef file or streamed to a collector.

        Objects that do not match the expected finding shape degrade to a generic
        informational event instead of throwing. Technique ID discovery (MITRE ATT&CK)
        is a heuristic: technique_id is populated only when the input object exposes a
        recognizable technique property (TechniqueId, Technique, MitreTechnique, etc.).
        The CEF 'act' field is also heuristic: 'Remediate' for High/Critical severity,
        'Review' otherwise. Timestamps reflect the UTC time of conversion, not the time
        the finding was originally detected.
    .PARAMETER InputObject
        Finding object(s) to convert. Accepts pipeline input.
    .PARAMETER Format
        Output format: NDJSON (one compact JSON object per line) or CEF (CEF:0 string).
    .PARAMETER HostName
        Host value embedded in each event. Defaults to the local machine name.
    .PARAMETER ProductVersion
        Product version string embedded in each event. Defaults to '1.4.0'.
    .EXAMPLE
        $report.Findings | ConvertTo-SiemEvent -Format NDJSON | Out-File findings.ndjson -Encoding UTF8
    .EXAMPLE
        ConvertTo-SiemEvent -InputObject $finding -Format CEF -HostName "WS01.contoso.com"
    .OUTPUTS
        String. One NDJSON line or CEF string per input object.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateSet('NDJSON', 'CEF')]
        [string]$Format,

        [Parameter()]
        [string]$HostName = [Environment]::MachineName,

        [Parameter()]
        [string]$ProductVersion = '1.4.0'
    )

    begin {
        Write-Host "Converting findings to $Format events (host: $HostName)..." -ForegroundColor Cyan

        if ([string]::IsNullOrWhiteSpace($HostName)) {
            $HostName = 'unknown-host'
        }

        $severityMap = @{
            'Critical' = 10
            'High'     = 7
            'Medium'   = 5
            'Low'      = 3
            'Info'     = 1
        }

        function Get-ObjectPropertyValue {
            param(
                [object]$Object,
                [string[]]$Names
            )
            if ($null -eq $Object) { return $null }
            foreach ($name in $Names) {
                $prop = $Object.PSObject.Properties[$name]
                if ($null -ne $prop -and $null -ne $prop.Value) {
                    return $prop.Value
                }
            }
            return $null
        }

        function Get-SeverityNumber {
            param(
                [string]$SeverityName,
                [hashtable]$Map
            )
            foreach ($key in @($Map.Keys)) {
                if ($key -ieq $SeverityName) { return $Map[$key] }
            }
            return 1
        }

        function ConvertTo-CefHeaderEscaped {
            param([AllowNull()][object]$Value)
            if ($null -eq $Value) { return '' }
            $text = [string]$Value
            $text = $text -replace '\\', '\\' -replace '\|', '\|'
            return ($text -replace "[`r`n]", ' ')
        }

        function ConvertTo-CefExtensionEscaped {
            param([AllowNull()][object]$Value)
            if ($null -eq $Value) { return '' }
            $text = [string]$Value
            $text = $text -replace '\\', '\\' -replace '=', '\='
            return ($text -replace "`r", '\r' -replace "`n", '\n')
        }
    }

    process {
        try {
            $severity = Get-ObjectPropertyValue -Object $InputObject -Names @('Severity')
            $category = Get-ObjectPropertyValue -Object $InputObject -Names @('Category')
            $message = Get-ObjectPropertyValue -Object $InputObject -Names @('Finding', 'Message', 'Description', 'Name', 'Title')
            $impact = Get-ObjectPropertyValue -Object $InputObject -Names @('Impact')
            $recommendation = Get-ObjectPropertyValue -Object $InputObject -Names @('Recommendation', 'Remediation')
            $techniqueId = Get-ObjectPropertyValue -Object $InputObject -Names @('TechniqueId', 'TechniqueID', 'Technique', 'MitreTechnique', 'MITRETechnique', 'AttackTechnique')

            if ($null -eq $InputObject) {
                Write-Warning "Null input object received; emitting generic event."
            }

            if ($null -eq $severity) { $severity = 'Info' }
            if ($null -eq $category) { $category = 'Generic' }
            if ($null -eq $message) {
                if ($null -ne $InputObject) {
                    $message = "$InputObject"
                    if ([string]::IsNullOrWhiteSpace($message)) {
                        $message = ($InputObject | ConvertTo-Json -Compress -Depth 3)
                    }
                }
                if ([string]::IsNullOrWhiteSpace([string]$message) -or $message -eq '{}') {
                    $message = 'Unspecified event'
                }
            }

            $severityNumber = Get-SeverityNumber -SeverityName ([string]$severity) -Map $severityMap

            $action = 'Review'
            if ($severityNumber -ge 7) { $action = 'Remediate' }

            $timestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

            if ($Format -eq 'NDJSON') {
                $eventData = [ordered]@{
                    timestamp      = $timestampUtc
                    host           = $HostName
                    product        = 'WindowsSecurityAudit'
                    severity       = [string]$severity
                    category       = [string]$category
                    message        = [string]$message
                    impact         = $(if ($null -ne $impact) { [string]$impact } else { '' })
                    recommendation = $(if ($null -ne $recommendation) { [string]$recommendation } else { '' })
                }
                if ($null -ne $techniqueId) {
                    $eventData['technique_id'] = [string]$techniqueId
                }

                Write-Output ($eventData | ConvertTo-Json -Compress)
            }
            else {
                $header = 'CEF:0|{0}|{1}|{2}|{3}|{4}|{5}' -f `
                    'okanyildiz', `
                    'WindowsSecurityAudit', `
                    (ConvertTo-CefHeaderEscaped $ProductVersion), `
                    (ConvertTo-CefHeaderEscaped $category), `
                    (ConvertTo-CefHeaderEscaped $message), `
                    $severityNumber

                $extension = 'rt={0} shost={1} act={2} cs1={3} cs1Label=Impact cs2={4} cs2Label=Recommendation' -f `
                    $timestampUtc, `
                    (ConvertTo-CefExtensionEscaped $HostName), `
                    (ConvertTo-CefExtensionEscaped $action), `
                    (ConvertTo-CefExtensionEscaped $impact), `
                    (ConvertTo-CefExtensionEscaped $recommendation)

                if ($null -ne $techniqueId) {
                    $extension += ' cs3={0} cs3Label=TechniqueId' -f (ConvertTo-CefExtensionEscaped $techniqueId)
                }

                Write-Output ($header + '| ' + $extension)
            }
        }
        catch {
            Write-Warning "Failed to convert object to $Format event: $_"
        }
    }

    end {
    }
}
