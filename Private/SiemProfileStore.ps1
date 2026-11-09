$script:SiemProfileStoreRoot = $null

function Assert-SiemProfileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw 'Profile name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.'
    }
}

function Get-SiemProfileDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope
    )

    $override = $script:SiemProfileStoreRoot
    if ([string]::IsNullOrWhiteSpace($override)) {
        $override = $env:WSA_SIEM_PROFILE_ROOT
    }
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        return (Join-Path -Path $override -ChildPath $Scope)
    }

    if ($Scope -eq 'LocalMachine') {
        $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        if ([string]::IsNullOrWhiteSpace($base)) { $base = $env:ProgramData }
    }
    else {
        $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
        if ([string]::IsNullOrWhiteSpace($base)) { $base = $env:APPDATA }
    }
    if ([string]::IsNullOrWhiteSpace($base)) {
        throw 'The profile storage root is unavailable on this platform. Set WSA_SIEM_PROFILE_ROOT for testing.'
    }
    return (Join-Path -Path (Join-Path -Path $base -ChildPath 'WindowsSecurityAudit') -ChildPath 'SiemProfiles')
}

function Get-SiemProfilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope
    )

    Assert-SiemProfileName -Name $Name
    return (Join-Path -Path (Get-SiemProfileDirectory -Scope $Scope) -ChildPath ($Name + '.json'))
}

function Protect-SiemDpapiText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PlainText,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($null -eq ('System.Security.Cryptography.ProtectedData' -as [type])) {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
    }

    $plain = $null
    $entropy = $null
    $cipher = $null
    try {
        $plain = [Text.Encoding]::UTF8.GetBytes($PlainText)
        $entropy = [Text.Encoding]::UTF8.GetBytes($Context)
        $protectionScope = [Enum]::Parse([Security.Cryptography.DataProtectionScope], $Scope)
        $cipher = [Security.Cryptography.ProtectedData]::Protect($plain, $entropy, $protectionScope)
        $prefix = $(if ($Scope -eq 'LocalMachine') { 'wsa-dpapi-lm-v1:' } else { 'wsa-dpapi-cu-v1:' })
        return ($prefix + [Convert]::ToBase64String($cipher))
    }
    catch {
        throw 'DPAPI protection failed. Profiles require Windows DPAPI and cannot fall back to plaintext.'
    }
    finally {
        if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($null -ne $entropy) { [Array]::Clear($entropy, 0, $entropy.Length) }
        if ($null -ne $cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    }
}

function Protect-SiemSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Secret,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope,

        [Parameter()]
        [ValidateSet('Secret', 'Uri')]
        [string]$Purpose = 'Secret'
    )

    Assert-SiemProfileName -Name $Name
    $plainText = $null
    try {
        $plainText = ConvertFrom-SiemSecureString -SecureString $Secret
        $context = 'WindowsSecurityAudit/SiemProfile/{0}/{1}/{2}/v1' -f $Scope, $Name, $Purpose
        return Protect-SiemDpapiText -PlainText $plainText -Scope $Scope -Context $context
    }
    finally {
        $plainText = $null
    }
}

function Unprotect-SiemSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SecretRef,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope,

        [Parameter()]
        [ValidateSet('Secret', 'Uri')]
        [string]$Purpose = 'Secret'
    )

    Assert-SiemProfileName -Name $Name
    $prefix = $(if ($Scope -eq 'LocalMachine') { 'wsa-dpapi-lm-v1:' } else { 'wsa-dpapi-cu-v1:' })
    if (-not $SecretRef.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw 'The protected value has an invalid marker or belongs to a different DPAPI scope.'
    }
    if ($null -eq ('System.Security.Cryptography.ProtectedData' -as [type])) {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
    }

    $plain = $null
    $entropy = $null
    $cipher = $null
    try {
        $cipher = [Convert]::FromBase64String($SecretRef.Substring($prefix.Length))
        $context = 'WindowsSecurityAudit/SiemProfile/{0}/{1}/{2}/v1' -f $Scope, $Name, $Purpose
        $entropy = [Text.Encoding]::UTF8.GetBytes($context)
        $protectionScope = [Enum]::Parse([Security.Cryptography.DataProtectionScope], $Scope)
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $entropy, $protectionScope)
        return [Text.Encoding]::UTF8.GetString($plain)
    }
    catch {
        throw 'DPAPI unprotection failed. Verify the profile scope, profile name, machine, and service account.'
    }
    finally {
        if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($null -ne $entropy) { [Array]::Clear($entropy, 0, $entropy.Length) }
        if ($null -ne $cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    }
}

function ConvertTo-SiemSidString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($Identity)
        return $sid.Value
    }
    catch {
        $account = New-Object System.Security.Principal.NTAccount($Identity)
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
}

function Protect-SiemProfileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope
    )

    if ($env:OS -ne 'Windows_NT') {
        Write-Verbose "Non-Windows host: skipping profile ACL lockdown for '$Path'."
        return
    }

    $identities = @()
    $ownerSid = $null
    if ($Scope -eq 'LocalMachine') {
        $identities = @('S-1-5-18', 'S-1-5-32-544')
        $ownerSid = 'S-1-5-32-544'
    }
    else {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $identities = @($currentSid)
        $ownerSid = $currentSid
    }

    $acl = Get-Acl -Path $Path -ErrorAction Stop
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        $null = $acl.RemoveAccessRule($existingRule)
    }
    foreach ($identity in $identities) {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($identity)),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($accessRule)
    }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($ownerSid)))
    Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop

    $applied = Get-Acl -Path $Path -ErrorAction Stop
    if (-not $applied.AreAccessRulesProtected) {
        throw 'Profile ACL verification failed: inheritance is still enabled.'
    }
    if ((ConvertTo-SiemSidString -Identity $applied.Owner) -ne $ownerSid) {
        throw 'Profile ACL verification failed: unexpected file owner.'
    }
    $rules = @($applied.Access)
    if ($rules.Count -ne $identities.Count) {
        throw 'Profile ACL verification failed: unexpected access rules remain.'
    }
    foreach ($rule in $rules) {
        $ruleSid = ConvertTo-SiemSidString -Identity $rule.IdentityReference.Value
        if ($identities -notcontains $ruleSid -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw 'Profile ACL verification failed: an access rule is not restricted to the required identity.'
        }
    }
}

function Initialize-SiemProfileDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope
    )

    $directory = Get-SiemProfileDirectory -Scope $Scope
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    Protect-SiemProfileAcl -Path $directory -Scope $Scope
    return $directory
}

function Write-SiemProfileJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Profile,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope,

        [Parameter()]
        [switch]$Replace
    )

    $directory = Initialize-SiemProfileDirectory -Scope $Scope
    $targetExists = Test-Path -LiteralPath $Path -PathType Leaf
    if ($targetExists -and -not $Replace.IsPresent) {
        throw "SIEM profile already exists. Use -Force to replace it."
    }
    if ($targetExists) {
        Protect-SiemProfileAcl -Path $Path -Scope $Scope
    }

    $temporaryPath = Join-Path -Path $directory -ChildPath ('.' + $Profile.name + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = $null
    try {
        $stream = New-Object System.IO.FileStream($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Close()
        $stream = $null
        Protect-SiemProfileAcl -Path $temporaryPath -Scope $Scope

        $json = $Profile | ConvertTo-Json -Depth 5
        $encoding = New-Object System.Text.UTF8Encoding($true)
        [IO.File]::WriteAllText($temporaryPath, $json, $encoding)

        $targetExists = Test-Path -LiteralPath $Path -PathType Leaf
        if ($targetExists) {
            if (-not $Replace.IsPresent) {
                throw 'SIEM profile was created by another process. Use -Force to replace it.'
            }
            Protect-SiemProfileAcl -Path $Path -Scope $Scope
            # Remove+move instead of [IO.File]::Replace (which fails with
            # 'path is empty' on some .NET/PS combinations in CI)
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            [IO.File]::Move($temporaryPath, $Path)
        }
        else {
            [IO.File]::Move($temporaryPath, $Path)
        }
        Protect-SiemProfileAcl -Path $Path -Scope $Scope
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-SiemObjectProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-SiemNewProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Values
    )

    Assert-SiemProfileName -Name $Values.Name
    $destination = $Values.Destination
    $hasSecret = $null -ne $Values.Secret
    if ($hasSecret -and $Values.Secret.Length -eq 0) {
        throw 'Secret cannot be empty.'
    }

    $requireHttps = $destination -in @('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion') -or $Values.ProtectUri
    $null = Assert-SiemEndpointUri -Uri $Values.Uri -Destination $destination -RequireHttps:$requireHttps

    if ($destination -eq 'GenericWebhook') {
        if ($hasSecret) {
            throw 'GenericWebhook profiles do not store arbitrary authorization headers or secrets. Use -ProtectUri for a secret URL.'
        }
        foreach ($field in @('TenantId', 'ClientId', 'MonitorScope', 'WorkspaceId', 'LogType')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$Values[$field])) {
                throw "$field is not valid for GenericWebhook profiles."
            }
        }
        return
    }

    if ($Values.ProtectUri) {
        throw 'ProtectUri is supported only for GenericWebhook profiles.'
    }
    if (-not $hasSecret) {
        throw "$destination profiles require -Secret."
    }

    if ($destination -eq 'SentinelLogsIngestion') {
        if ([string]::IsNullOrWhiteSpace($Values.TenantId) -or [string]::IsNullOrWhiteSpace($Values.ClientId)) {
            throw 'SentinelLogsIngestion profiles require -TenantId and -ClientId.'
        }
        Assert-SiemTenantId -TenantId $Values.TenantId
        Assert-SiemMonitorScope -MonitorScope $Values.MonitorScope
        if (-not [string]::IsNullOrWhiteSpace($Values.WorkspaceId) -or -not [string]::IsNullOrWhiteSpace($Values.LogType)) {
            throw 'WorkspaceId and LogType belong only to the legacy Sentinel destination.'
        }
        return
    }

    foreach ($field in @('TenantId', 'ClientId', 'MonitorScope')) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Values[$field])) {
            throw "$field is valid only for SentinelLogsIngestion profiles."
        }
    }
    if ($destination -eq 'SplunkHEC') {
        if (-not [string]::IsNullOrWhiteSpace($Values.WorkspaceId) -or -not [string]::IsNullOrWhiteSpace($Values.LogType)) {
            throw 'WorkspaceId and LogType are valid only for legacy Sentinel profiles.'
        }
    }
    elseif ($destination -eq 'Sentinel' -and [string]::IsNullOrWhiteSpace($Values.WorkspaceId)) {
        if ($Values.Uri -notmatch '^https://([A-Za-z0-9-]+)\.ods\.opinsights\.azure\.') {
            throw 'Sentinel requires -WorkspaceId or a workspace data collector URI.'
        }
    }
}

function Assert-SiemStoredProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Profile,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$ExpectedScope
    )

    $allowedProperties = @('schemaVersion', 'name', 'type', 'uri', 'scope', 'tenantId', 'clientId', 'monitorScope', 'workspaceId', 'logType', 'secretRef', 'uriRef')
    foreach ($property in @($Profile.PSObject.Properties)) {
        if ($allowedProperties -notcontains $property.Name) {
            throw "Stored profile contains unsupported field '$($property.Name)'."
        }
    }
    if ([string](Get-SiemObjectProperty $Profile 'schemaVersion') -ne '1') {
        throw 'Stored profile has an unsupported or missing schemaVersion.'
    }

    $name = [string](Get-SiemObjectProperty $Profile 'name')
    $type = [string](Get-SiemObjectProperty $Profile 'type')
    $scope = [string](Get-SiemObjectProperty $Profile 'scope')
    Assert-SiemProfileName -Name $name
    if ($name -cne $ExpectedName -or $scope -cne $ExpectedScope) {
        throw 'Stored profile identity does not match its file name or scope.'
    }
    if ($type -notin @('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion', 'GenericWebhook')) {
        throw 'Stored profile has an invalid destination type.'
    }

    $uri = [string](Get-SiemObjectProperty $Profile 'uri')
    $uriRef = [string](Get-SiemObjectProperty $Profile 'uriRef')
    $secretRef = [string](Get-SiemObjectProperty $Profile 'secretRef')
    $tenantId = [string](Get-SiemObjectProperty $Profile 'tenantId')
    $clientId = [string](Get-SiemObjectProperty $Profile 'clientId')
    $monitorScope = [string](Get-SiemObjectProperty $Profile 'monitorScope')
    $workspaceId = [string](Get-SiemObjectProperty $Profile 'workspaceId')
    $logType = [string](Get-SiemObjectProperty $Profile 'logType')
    $expectedPrefix = $(if ($ExpectedScope -eq 'LocalMachine') { 'wsa-dpapi-lm-v1:' } else { 'wsa-dpapi-cu-v1:' })

    if ([string]::IsNullOrWhiteSpace($uriRef)) {
        if ([string]::IsNullOrWhiteSpace($uri)) { throw 'Stored profile has no endpoint URI.' }
        $requireHttps = $type -in @('SplunkHEC', 'Sentinel', 'SentinelLogsIngestion')
        $null = Assert-SiemEndpointUri -Uri $uri -Destination $type -RequireHttps:$requireHttps
    }
    else {
        if ($type -ne 'GenericWebhook' -or -not [string]::IsNullOrWhiteSpace($uri) -or -not $uriRef.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
            throw 'Stored profile has an invalid protected URI reference.'
        }
    }

    if ($type -eq 'GenericWebhook') {
        if (-not [string]::IsNullOrWhiteSpace($secretRef)) { throw 'GenericWebhook profiles cannot contain secretRef.' }
        foreach ($value in @($tenantId, $clientId, $monitorScope, $workspaceId, $logType)) {
            if (-not [string]::IsNullOrWhiteSpace($value)) { throw 'GenericWebhook profile contains destination-specific fields.' }
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($secretRef) -or -not $secretRef.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
        throw 'Stored profile is missing a secretRef for the correct DPAPI scope.'
    }
    if (-not [string]::IsNullOrWhiteSpace($uriRef)) { throw 'Only GenericWebhook profiles can contain uriRef.' }

    if ($type -eq 'SentinelLogsIngestion') {
        if ([string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($monitorScope)) {
            throw 'SentinelLogsIngestion profile is missing tenantId, clientId, or monitorScope.'
        }
        Assert-SiemTenantId -TenantId $tenantId
        Assert-SiemMonitorScope -MonitorScope $monitorScope
        if (-not [string]::IsNullOrWhiteSpace($workspaceId) -or -not [string]::IsNullOrWhiteSpace($logType)) {
            throw 'SentinelLogsIngestion profile contains legacy Sentinel fields.'
        }
    }
    else {
        foreach ($value in @($tenantId, $clientId, $monitorScope)) {
            if (-not [string]::IsNullOrWhiteSpace($value)) { throw 'Legacy profile contains OAuth-only fields.' }
        }
        if ($type -eq 'SplunkHEC' -and (-not [string]::IsNullOrWhiteSpace($workspaceId) -or -not [string]::IsNullOrWhiteSpace($logType))) {
            throw 'SplunkHEC profile contains Sentinel-only fields.'
        }
        if ($type -eq 'Sentinel' -and [string]::IsNullOrWhiteSpace($workspaceId) -and $uri -notmatch '^https://([A-Za-z0-9-]+)\.ods\.opinsights\.azure\.') {
            throw 'Sentinel profile is missing workspaceId.'
        }
    }
}

function Read-SiemProfileRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$ExpectedScope
    )

    try {
        $json = [IO.File]::ReadAllText($Path)
        $profile = $json | ConvertFrom-Json -ErrorAction Stop
        if ($profile -is [Array]) { throw 'Stored profile JSON must contain one object.' }
        Assert-SiemStoredProfile -Profile $profile -ExpectedName $ExpectedName -ExpectedScope $ExpectedScope
        return $profile
    }
    catch {
        throw "Could not read SIEM profile '$ExpectedName' ($ExpectedScope): $($_.Exception.Message)"
    }
}

function Resolve-SiemProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [ValidateSet('Auto', 'CurrentUser', 'LocalMachine')]
        [string]$Scope = 'Auto'
    )

    Assert-SiemProfileName -Name $Name
    $scopes = $(if ($Scope -eq 'Auto') { @('CurrentUser', 'LocalMachine') } else { @($Scope) })
    $matches = @()
    foreach ($candidateScope in $scopes) {
        $path = Get-SiemProfilePath -Name $Name -Scope $candidateScope
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $matches += [PSCustomObject]@{
                Name    = $Name
                Scope   = $candidateScope
                Path    = $path
                Profile = (Read-SiemProfileRecord -Path $path -ExpectedName $Name -ExpectedScope $candidateScope)
            }
        }
    }
    if ($matches.Count -eq 0) {
        throw "SIEM profile '$Name' was not found in the requested scope."
    }
    if ($matches.Count -gt 1) {
        throw "SIEM profile '$Name' exists in both CurrentUser and LocalMachine scopes. Specify the scope explicitly."
    }
    return $matches[0]
}

function ConvertTo-SiemProfileMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Profile,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $uriRef = [string](Get-SiemObjectProperty $Profile 'uriRef')
    $secretRef = [string](Get-SiemObjectProperty $Profile 'secretRef')
    $isUriProtected = -not [string]::IsNullOrWhiteSpace($uriRef)
    return [PSCustomObject]@{
        PSTypeName      = 'WindowsSecurityAudit.SiemProfile'
        SchemaVersion   = [int](Get-SiemObjectProperty $Profile 'schemaVersion')
        Name            = [string](Get-SiemObjectProperty $Profile 'name')
        Destination     = [string](Get-SiemObjectProperty $Profile 'type')
        Scope           = [string](Get-SiemObjectProperty $Profile 'scope')
        Uri             = $(if ($isUriProtected) { $null } else { [string](Get-SiemObjectProperty $Profile 'uri') })
        HasUri          = $true
        IsUriProtected  = $isUriProtected
        HasSecret       = (-not [string]::IsNullOrWhiteSpace($secretRef))
        TenantId        = [string](Get-SiemObjectProperty $Profile 'tenantId')
        ClientId        = [string](Get-SiemObjectProperty $Profile 'clientId')
        MonitorScope    = [string](Get-SiemObjectProperty $Profile 'monitorScope')
        WorkspaceId     = [string](Get-SiemObjectProperty $Profile 'workspaceId')
        LogType         = [string](Get-SiemObjectProperty $Profile 'logType')
        Path            = $Path
    }
}
