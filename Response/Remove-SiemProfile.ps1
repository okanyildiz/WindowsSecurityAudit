function Remove-SiemProfile {
    <#
    .SYNOPSIS
        Removes a stored SIEM authentication profile.
    .DESCRIPTION
        Deletes the selected profile JSON file. Auto scope checks CurrentUser before
        LocalMachine and rejects duplicate names instead of choosing one silently.
    .PARAMETER Name
        Name of the profile to remove.
    .PARAMETER Scope
        CurrentUser, LocalMachine, or Auto. Auto is the default.
    .EXAMPLE
        Remove-SiemProfile -Name sentinel-prod -Scope LocalMachine
    .EXAMPLE
        Remove-SiemProfile -Name old-siem -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [ValidateSet('Auto', 'CurrentUser', 'LocalMachine')]
        [string]$Scope = 'Auto'
    )

    $resolved = Resolve-SiemProfile -Name $Name -Scope $Scope
    if ($PSCmdlet.ShouldProcess("$($resolved.Scope)/$Name", 'Remove SIEM profile')) {
        Remove-Item -LiteralPath $resolved.Path -Force -ErrorAction Stop
    }
}
