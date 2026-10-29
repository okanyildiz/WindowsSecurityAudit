#requires -Version 5.1

<#
.SYNOPSIS
    Shared output-safety helpers (CSV formula-injection escaping, HTML encoding).
.DESCRIPTION
    Internal helpers used by export/report functions. CSV escaping follows the
    spreadsheet formula-injection convention: any value starting with =, +, -, @
    (or tab/CR/LF) is prefixed with a single quote. HTML encoding uses
    System.Net.WebUtility.HtmlEncode (available on .NET Framework 4.x / PS 5.1).
#>

function Protect-CsvField {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ($text.Length -eq 0) { return '' }
    if ($text -match '^[=+\-@\t\r\n]') {
        return "'$text"
    }
    return $text
}

function ConvertTo-CsvSafeObject {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)][AllowNull()][object]$InputObject)
    process {
        if ($null -eq $InputObject) { return }
        $row = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            $row[$property.Name] = if ($value -is [string]) { Protect-CsvField $value } else { $value }
        }
        [PSCustomObject]$row
    }
}

function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
