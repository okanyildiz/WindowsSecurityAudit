#requires -Version 5.1

function Resolve-WsaBinaryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CommandLine,

        [Parameter()]
        [switch]$AppendDll
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $normalizeWindowsPath = {
        param([AllowNull()][AllowEmptyString()][string]$Path)

        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        $Path = $Path.Replace('/', '\')
        $isUnc = $Path.StartsWith('\\', [StringComparison]::Ordinal)
        $isDrivePath = $Path -match '^[A-Za-z]:\\'
        if (-not $isUnc -and -not $isDrivePath) { return $null }

        $prefix = $null
        $remainder = $null
        $minimumSegments = 0
        if ($isUnc) {
            $prefix = '\\'
            $remainder = $Path.Substring(2)
            $minimumSegments = 2
        }
        else {
            $prefix = $Path.Substring(0, 2) + '\'
            $remainder = $Path.Substring(3)
        }

        $segments = @()
        foreach ($segment in $remainder.Split([char]'\')) {
            if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.') { continue }
            if ($segment -eq '..') {
                if ($segments.Count -gt $minimumSegments) {
                    if ($segments.Count -eq 1) {
                        $segments = @()
                    }
                    else {
                        $segments = @($segments[0..($segments.Count - 2)])
                    }
                }
                elseif ($isUnc -and $segments.Count -lt $minimumSegments) {
                    return $null
                }
                continue
            }
            $segments += $segment
        }

        if ($isUnc) {
            if ($segments.Count -lt 2) { return $null }
            return $prefix + ($segments -join '\')
        }
        if ($segments.Count -eq 0) { return $prefix }
        return $prefix + ($segments -join '\')
    }

    $text = $CommandLine.Trim().Replace('/', '\')
    $candidate = $null
    $wasQuoted = $false
    if ($text.StartsWith('"', [StringComparison]::Ordinal)) {
        $closingQuote = $text.IndexOf('"', 1)
        if ($closingQuote -lt 0) { return $null }
        $candidate = $text.Substring(1, $closingQuote - 1)
        $wasQuoted = $true
    }
    else {
        $extensionPattern = '\.(?:exe|dll|sys|com|scr|cpl|ocx|bat|cmd|ps1|vbs|js|jse|wsf|hta)(?=$|\s)'
        $regexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
        $extensionMatch = [Text.RegularExpressions.Regex]::Match($text, $extensionPattern, $regexOptions)
        if ($extensionMatch.Success) {
            $candidate = $text.Substring(0, $extensionMatch.Index + $extensionMatch.Length)
        }
        elseif ($AppendDll -and $text -notmatch '\s') {
            $candidate = $text
        }
        else {
            return $null
        }
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }
    $candidate = $candidate.Trim().Replace('/', '\')
    if ($candidate.StartsWith('\\?\', [StringComparison]::Ordinal) -or
        $candidate.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = $candidate.Substring(4)
        if ($candidate.StartsWith('UNC\', [StringComparison]::OrdinalIgnoreCase)) {
            $candidate = '\\' + $candidate.Substring(4)
        }
    }

    $regexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
    $candidate = [Text.RegularExpressions.Regex]::Replace($candidate, '%([^%]+)%', {
        param($match)
        $value = [Environment]::GetEnvironmentVariable($match.Groups[1].Value)
        if ($null -eq $value) { return $match.Value }
        return $value.Replace('/', '\')
    })

    $getSystemRoot = {
        $root = [Environment]::GetEnvironmentVariable('SystemRoot')
        if ([string]::IsNullOrWhiteSpace($root)) {
            $root = [Environment]::GetEnvironmentVariable('windir')
        }
        if ([string]::IsNullOrWhiteSpace($root)) { $root = 'C:\Windows' }
        return (& $normalizeWindowsPath $root)
    }

    if ($candidate.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $systemRoot = & $getSystemRoot
        if ($null -eq $systemRoot) { return $null }
        $candidate = $systemRoot.TrimEnd('\') + '\' + $candidate.Substring(12)
    }
    elseif ($candidate.StartsWith('system32\', [StringComparison]::OrdinalIgnoreCase)) {
        $systemRoot = & $getSystemRoot
        if ($null -eq $systemRoot) { return $null }
        $candidate = $systemRoot.TrimEnd('\') + '\System32\' + $candidate.Substring(9)
    }

    $isBareName = $candidate.IndexOf('\') -lt 0 -and $candidate.IndexOf(':') -lt 0
    if ($isBareName) {
        $hasExtension = $candidate -match '\.[^.\\]+$'
        if ($AppendDll -and -not $hasExtension) {
            $candidate += '.dll'
            $hasExtension = $true
        }
        $knownExtension = $candidate -match '\.(?:exe|dll|sys|com|scr|cpl|ocx|bat|cmd|ps1|vbs|js|jse|wsf|hta)$'
        if (-not $knownExtension) {
            if ($wasQuoted -and -not $hasExtension) { return $null }
            if (-not $AppendDll) { return $null }
        }
        $systemRoot = & $getSystemRoot
        if ($null -eq $systemRoot) { return $null }
        $candidate = $systemRoot.TrimEnd('\') + '\System32\' + $candidate
    }

    return (& $normalizeWindowsPath $candidate)
}

function Test-WsaTrustedBinary {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CommandLine,

        [Parameter()]
        [AllowNull()]
        [hashtable]$SignatureCache,

        [Parameter()]
        [switch]$AppendDll
    )

    if ($null -eq $SignatureCache) { $SignatureCache = @{} }

    $resolvedPath = Resolve-WsaBinaryPath -CommandLine $CommandLine -AppendDll:$AppendDll
    $exists = $false
    $signatureStatus = 'Unknown'
    $signer = 'N/A'
    $userWritable = $false
    $trusted = $false
    $reasons = @()

    if ([string]::IsNullOrEmpty($resolvedPath)) {
        return [PSCustomObject][ordered]@{
            ResolvedPath = $resolvedPath
            Exists = $false
            SignatureStatus = $signatureStatus
            Signer = $signer
            UserWritable = $false
            Trusted = $false
            Reasons = @('Unable to resolve binary path')
        }
    }

    $isUserProfilePath = $resolvedPath -match '^[A-Za-z]:\\Users\\'
    $profileRoot = [Environment]::GetEnvironmentVariable('USERPROFILE')
    if (-not [string]::IsNullOrWhiteSpace($profileRoot)) {
        $profileRoot = $profileRoot.Replace('/', '\').TrimEnd('\')
        if ($resolvedPath.Equals($profileRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $resolvedPath.StartsWith($profileRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $isUserProfilePath = $true
        }
    }
    if ($isUserProfilePath -or
        $resolvedPath.IndexOf('\AppData\', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $resolvedPath.IndexOf('\Windows\Temp\', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $userWritable = $true
        $reasons += 'User-writable location'
    }

    $lastSeparator = $resolvedPath.LastIndexOf('\')
    $baseName = if ($lastSeparator -ge 0) { $resolvedPath.Substring($lastSeparator + 1) } else { $resolvedPath }
    $lolBins = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')
    $isLolBin = $false
    foreach ($lolBin in $lolBins) {
        if ($baseName.Equals($lolBin, [StringComparison]::OrdinalIgnoreCase)) {
            $isLolBin = $true
            break
        }
    }
    if ($isLolBin) {
        $reasons += 'Script host or LOLBin; review the supplied arguments'
    }

    try {
        $exists = Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction Stop
    }
    catch {
        Write-Verbose "Could not test binary path '$resolvedPath': $($_.Exception.Message)"
        $exists = $false
    }

    if (-not $exists) {
        $reasons += 'Target file not found'
    }
    else {
        $signature = $null
        if ($SignatureCache.ContainsKey($resolvedPath)) {
            $signature = $SignatureCache[$resolvedPath]
        }
        else {
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $resolvedPath -ErrorAction Stop
            }
            catch {
                Write-Verbose "Could not read Authenticode signature for '$resolvedPath': $($_.Exception.Message)"
                $signatureStatus = 'Unavailable'
                $signature = [PSCustomObject]@{
                    Status = 'Unavailable'
                    SignerCertificate = $null
                }
            }
            $SignatureCache[$resolvedPath] = $signature
        }

        if ($null -ne $signature -and $signature.PSObject.Properties['Status'] -and $null -ne $signature.Status) {
            $statusText = $signature.Status.ToString()
            if (-not [string]::IsNullOrWhiteSpace($statusText)) { $signatureStatus = $statusText }
        }

        if ($null -ne $signature -and $signature.PSObject.Properties['SignerCertificate'] -and $null -ne $signature.SignerCertificate) {
            $certificate = $signature.SignerCertificate
            try {
                $simpleName = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                if (-not [string]::IsNullOrWhiteSpace($simpleName)) { $signer = $simpleName }
            }
            catch {
                Write-Verbose 'Could not read the simple signer name; using the certificate subject.'
            }

            if ($signer -eq 'N/A' -and $certificate.PSObject.Properties['Subject'] -and $null -ne $certificate.Subject) {
                $subject = $certificate.Subject.ToString()
                $commonName = [Text.RegularExpressions.Regex]::Match($subject, '(?:^|,)\s*CN\s*=\s*([^,]+)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($commonName.Success) {
                    $signer = $commonName.Groups[1].Value.Trim()
                }
                elseif (-not [string]::IsNullOrWhiteSpace($subject)) {
                    $signer = $subject
                }
            }
        }

        if ($signatureStatus -eq 'Valid') {
            $trusted = -not $userWritable -and -not $isLolBin
        }
        elseif ($signatureStatus -eq 'Unavailable') {
            $reasons += 'Unavailable'
        }
        else {
            $reasons += $signatureStatus
        }
    }

    return [PSCustomObject][ordered]@{
        ResolvedPath = $resolvedPath
        Exists = $exists
        SignatureStatus = $signatureStatus
        Signer = $signer
        UserWritable = $userWritable
        Trusted = $trusted
        Reasons = @($reasons)
    }
}
