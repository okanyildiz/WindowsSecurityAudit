function Get-SiemProfile {
    <#
    .SYNOPSIS
        Gets SIEM profile metadata without exposing secret material.
    .DESCRIPTION
        Reads one profile or lists profiles from both scopes. With -Name and Auto scope,
        CurrentUser is checked before LocalMachine and duplicate names are rejected as
        ambiguous. The output never contains plaintext secrets, secretRef, or uriRef.
    .PARAMETER Name
        Optional profile name. If omitted, all valid profile files are listed.
    .PARAMETER Scope
        CurrentUser, LocalMachine, or Auto. Auto is the default.
    .EXAMPLE
        Get-SiemProfile
    .EXAMPLE
        Get-SiemProfile -Name sentinel-prod -Scope LocalMachine
    .OUTPUTS
        PSCustomObject metadata including HasSecret and IsUriProtected.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name,

        [Parameter()]
        [ValidateSet('Auto', 'CurrentUser', 'LocalMachine')]
        [string]$Scope = 'Auto'
    )

    if ($PSBoundParameters.ContainsKey('Name')) {
        $resolved = Resolve-SiemProfile -Name $Name -Scope $Scope
        return ConvertTo-SiemProfileMetadata -Profile $resolved.Profile -Path $resolved.Path
    }

    $scopes = $(if ($Scope -eq 'Auto') { @('CurrentUser', 'LocalMachine') } else { @($Scope) })
    foreach ($candidateScope in $scopes) {
        $directory = Get-SiemProfileDirectory -Scope $candidateScope
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
        $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File | Sort-Object Name)
        foreach ($file in $files) {
            if ($file.BaseName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { continue }
            $profile = Read-SiemProfileRecord -Path $file.FullName -ExpectedName $file.BaseName -ExpectedScope $candidateScope
            ConvertTo-SiemProfileMetadata -Profile $profile -Path $file.FullName
        }
    }
}
