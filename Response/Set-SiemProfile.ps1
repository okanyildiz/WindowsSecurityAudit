function Set-SiemProfile {
    <#
    .SYNOPSIS
        Creates or replaces a DPAPI-protected SIEM authentication profile.
    .DESCRIPTION
        Stores SIEM connection metadata in the CurrentUser or LocalMachine profile store.
        Secrets are protected with the matching Windows DPAPI scope and are never written
        as plaintext. Generic webhook URLs can be protected with -ProtectUri. Existing
        profiles require -Force. LocalMachine use normally requires elevation.
    .PARAMETER Name
        Profile name matching ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.
    .PARAMETER Destination
        SIEM destination type.
    .PARAMETER Uri
        Endpoint URI. SentinelLogsIngestion requires the full DCR stream URI with api-version.
    .PARAMETER Secret
        Splunk HEC token, legacy Sentinel shared key, or Entra client secret.
    .PARAMETER Scope
        Profile and DPAPI scope. Defaults to CurrentUser. Service-account CurrentUser
        profiles must be created while running as that service account.
    .PARAMETER ProtectUri
        Protects a GenericWebhook full URI with DPAPI instead of storing it as plaintext.
    .PARAMETER TenantId
        Entra tenant GUID or domain for SentinelLogsIngestion.
    .PARAMETER ClientId
        Entra application client ID for SentinelLogsIngestion.
    .PARAMETER MonitorScope
        Entra resource scope. Defaults to https://monitor.azure.com/.default.
    .PARAMETER WorkspaceId
        Log Analytics workspace ID for legacy Sentinel.
    .PARAMETER LogType
        Log Analytics custom log type for legacy Sentinel.
    .PARAMETER Force
        Replaces an existing profile in the same scope.
    .EXAMPLE
        Set-SiemProfile -Name sentinel-prod -Destination SentinelLogsIngestion -Uri $ingestionUri -TenantId $tenantId -ClientId $clientId -Secret (Read-Host -AsSecureString) -Scope LocalMachine
    .EXAMPLE
        Set-SiemProfile -Name splunk-prod -Destination SplunkHEC -Uri 'https://splunk.contoso.com:8088/services/collector' -Secret (Read-Host -AsSecureString)
    .OUTPUTS
        PSCustomObject profile metadata. Secret references and plaintext secrets are not returned.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion', 'GenericWebhook')]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [SecureString]$Secret,

        [Parameter()]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope = 'CurrentUser',

        [Parameter()]
        [switch]$ProtectUri,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [string]$MonitorScope,

        [Parameter()]
        [string]$WorkspaceId,

        [Parameter()]
        [string]$LogType,

        [Parameter()]
        [switch]$Force
    )

    if ($Destination -eq 'SentinelLogsIngestion' -and [string]::IsNullOrWhiteSpace($MonitorScope)) {
        $MonitorScope = 'https://monitor.azure.com/.default'
    }
    $values = @{
        Name         = $Name
        Destination  = $Destination
        Uri          = $Uri
        Secret       = $Secret
        ProtectUri   = $ProtectUri.IsPresent
        TenantId     = $TenantId
        ClientId     = $ClientId
        MonitorScope = $MonitorScope
        WorkspaceId  = $WorkspaceId
        LogType      = $LogType
    }
    Assert-SiemNewProfile -Values $values

    $path = Get-SiemProfilePath -Name $Name -Scope $Scope
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and -not $Force.IsPresent) {
        throw "SIEM profile '$Name' already exists in $Scope scope. Use -Force to replace it."
    }
    if (-not $PSCmdlet.ShouldProcess("$Scope/$Name", "Store $Destination SIEM profile with DPAPI-protected secrets")) {
        return
    }

    $secretRef = $null
    $uriRef = $null
    $storedUri = $Uri
    if ($null -ne $Secret) {
        $secretRef = Protect-SiemSecret -Secret $Secret -Name $Name -Scope $Scope -Purpose Secret
    }
    if ($ProtectUri.IsPresent) {
        $secureUri = ConvertTo-SiemSecureString -PlainText $Uri
        try {
            $uriRef = Protect-SiemSecret -Secret $secureUri -Name $Name -Scope $Scope -Purpose Uri
            $storedUri = $null
        }
        finally {
            $secureUri.Dispose()
        }
    }

    $profile = [ordered]@{
        schemaVersion = 1
        name          = $Name
        type          = $Destination
        uri           = $storedUri
        scope         = $Scope
        tenantId      = $(if ($Destination -eq 'SentinelLogsIngestion') { $TenantId } else { $null })
        clientId      = $(if ($Destination -eq 'SentinelLogsIngestion') { $ClientId } else { $null })
        monitorScope  = $(if ($Destination -eq 'SentinelLogsIngestion') { $MonitorScope } else { $null })
        workspaceId   = $(if ($Destination -eq 'Sentinel') { $WorkspaceId } else { $null })
        logType       = $(if ($Destination -eq 'Sentinel') { $LogType } else { $null })
        secretRef     = $secretRef
        uriRef        = $uriRef
    }
    Write-SiemProfileJson -Profile $profile -Path $path -Scope $Scope -Replace:$Force
    Get-SiemProfile -Name $Name -Scope $Scope
}
