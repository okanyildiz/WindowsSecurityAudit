$script:WsaDpapiWebhookMarker = 'wsa-dpapi-lm-v1:'
$script:WsaDpapiWebhookContext = 'WindowsSecurityAudit/ScheduledScan/Webhook/v1'

function ConvertFrom-WsaDpapiProtectedText {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ProtectedText
    )

    if (-not $ProtectedText.StartsWith($script:WsaDpapiWebhookMarker, [System.StringComparison]::Ordinal)) {
        throw [System.ArgumentException]::new("Unsupported DPAPI protection marker. Expected '$script:WsaDpapiWebhookMarker'.")
    }

    $encodedCipherText = $ProtectedText.Substring($script:WsaDpapiWebhookMarker.Length)
    if ([string]::IsNullOrWhiteSpace($encodedCipherText)) {
        throw [System.FormatException]::new('The DPAPI ciphertext is empty.')
    }

    try {
        $cipherBytes = [System.Convert]::FromBase64String($encodedCipherText)
    }
    catch {
        throw [System.FormatException]::new('The DPAPI ciphertext is not valid Base64.')
    }

    if ($cipherBytes.Length -eq 0) {
        throw [System.FormatException]::new('The DPAPI ciphertext is empty.')
    }

    return [PSCustomObject]@{
        Marker = $script:WsaDpapiWebhookMarker
        Scope = 'LocalMachine'
        Version = 1
        Context = $script:WsaDpapiWebhookContext
        CipherBytes = $cipherBytes
    }
}

function Get-WsaDpapiProtectedDataType {
    [CmdletBinding()]
    [OutputType([type])]
    param()

    $assemblyName = if ($PSVersionTable.PSEdition -eq 'Desktop') {
        'System.Security'
    }
    else {
        'System.Security.Cryptography.ProtectedData'
    }
    $qualifiedName = "System.Security.Cryptography.ProtectedData, $assemblyName"
    $protectedDataType = [type]::GetType($qualifiedName, $false)

    if ($null -eq $protectedDataType) {
        try {
            $null = [System.Reflection.Assembly]::Load($assemblyName)
        }
        catch {
            throw [System.PlatformNotSupportedException]::new(
                "Windows DPAPI ProtectedData is unavailable because assembly '$assemblyName' could not be loaded.",
                $_.Exception)
        }
        $protectedDataType = [type]::GetType($qualifiedName, $false)
    }

    if ($null -eq $protectedDataType) {
        throw [System.PlatformNotSupportedException]::new(
            "Windows DPAPI ProtectedData is unavailable in assembly '$assemblyName'.")
    }

    return $protectedDataType
}

function Protect-WsaDpapiData {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PlainText
    )

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw [System.PlatformNotSupportedException]::new('Windows DPAPI LocalMachine protection is only available on Windows.')
    }

    $protectedDataType = Get-WsaDpapiProtectedDataType
    $scopeType = $protectedDataType.Assembly.GetType('System.Security.Cryptography.DataProtectionScope', $true)
    $scope = [System.Enum]::Parse($scopeType, 'LocalMachine')
    $plainBytes = $null
    $entropyBytes = $null
    $cipherBytes = $null

    try {
        $entropyBytes = [System.Text.Encoding]::UTF8.GetBytes($script:WsaDpapiWebhookContext)
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $cipherBytes = $protectedDataType::Protect($plainBytes, $entropyBytes, $scope)
        return $script:WsaDpapiWebhookMarker + [System.Convert]::ToBase64String($cipherBytes)
    }
    finally {
        if ($null -ne $plainBytes) {
            [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        if ($null -ne $entropyBytes) {
            [System.Array]::Clear($entropyBytes, 0, $entropyBytes.Length)
        }
        if ($null -ne $cipherBytes) {
            [System.Array]::Clear($cipherBytes, 0, $cipherBytes.Length)
        }
    }
}

function Unprotect-WsaDpapiData {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ProtectedText
    )

    $parsedProtectedText = $null
    $plainBytes = $null
    $entropyBytes = $null
    $cipherBytes = $null

    try {
        $parsedProtectedText = ConvertFrom-WsaDpapiProtectedText -ProtectedText $ProtectedText
        $cipherBytes = $parsedProtectedText.CipherBytes

        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            throw [System.PlatformNotSupportedException]::new('Windows DPAPI LocalMachine unprotection is only available on Windows.')
        }

        $protectedDataType = Get-WsaDpapiProtectedDataType
        $scopeType = $protectedDataType.Assembly.GetType('System.Security.Cryptography.DataProtectionScope', $true)
        $scope = [System.Enum]::Parse($scopeType, 'LocalMachine')
        $entropyBytes = [System.Text.Encoding]::UTF8.GetBytes($script:WsaDpapiWebhookContext)
        $plainBytes = $protectedDataType::Unprotect($cipherBytes, $entropyBytes, $scope)
        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    finally {
        if ($null -ne $plainBytes) {
            [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        if ($null -ne $entropyBytes) {
            [System.Array]::Clear($entropyBytes, 0, $entropyBytes.Length)
        }
        if ($null -ne $cipherBytes) {
            [System.Array]::Clear($cipherBytes, 0, $cipherBytes.Length)
        }
    }
}
