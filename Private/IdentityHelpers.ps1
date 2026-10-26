<#
.SYNOPSIS
    Locale-invariant identity helpers (private).
.DESCRIPTION
    SID-based lookups that survive non-English Windows, 32-bit PowerShell on
    64-bit Windows (LocalAccounts module missing), domain controllers (no local
    SAM), and unresolvable SIDs (AzureAD-joined machines, PowerShell#2996).
    All functions degrade to empty/$null/$false instead of throwing.
#>

# False = last admin-group lookup failed (unknown), NOT 'zero admins'
$script:AdminGroupLookupSucceeded = $false

function Get-WellKnownSid {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        Administrators     = 'S-1-5-32-544'
        Users              = 'S-1-5-32-545'
        Guests             = 'S-1-5-32-546'
        BackupOperators    = 'S-1-5-32-551'
        RemoteDesktopUsers = 'S-1-5-32-555'
        System             = 'S-1-5-18'
        LocalService       = 'S-1-5-19'
        NetworkService     = 'S-1-5-20'
        Everyone           = 'S-1-1-0'
        AuthenticatedUsers = 'S-1-5-11'
    }
}

function Get-AdminGroupMembers {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string]$Sid = 'S-1-5-32-544'
    )

    $script:AdminGroupLookupSucceeded = $false
    $members = @()

    # Preferred: LocalAccounts module, addressed by SID (locale-invariant).
    # NOTE: module is missing in 32-bit PowerShell on 64-bit Windows.
    if (Get-Command 'Get-LocalGroupMember' -ErrorAction SilentlyContinue) {
        try {
            $sidObject = [Security.Principal.SecurityIdentifier]$Sid
            $raw = @(Get-LocalGroupMember -SID $sidObject -ErrorAction Stop)
            foreach ($member in $raw) {
                $memberName = $null
                $memberSid = $null
                $memberClass = $null
                if ($null -ne $member) {
                    if ($member.PSObject.Properties['Name']) { $memberName = $member.Name }
                    if ($member.PSObject.Properties['SID'] -and $null -ne $member.SID) {
                        $memberSid = $member.SID.Value
                    }
                    if ($member.PSObject.Properties['ObjectClass']) { $memberClass = $member.ObjectClass }
                }
                $members += [PSCustomObject]@{
                    Name        = $memberName
                    SID         = $memberSid
                    ObjectClass = $memberClass
                }
            }
            $script:AdminGroupLookupSucceeded = $true
            return $members
        }
        catch {
            # Includes the known 'Failed to compare two elements' bug on
            # unresolvable SIDs (AzureAD-joined machines, PowerShell#2996)
            Write-Verbose "Get-AdminGroupMembers: Get-LocalGroupMember failed, trying ADSI: $($_.Exception.Message)"
        }
    }

    # Fallback: ADSI WinNT provider. SID -> localized group name, then enumerate.
    try {
        $groupName = ([Security.Principal.SecurityIdentifier]$Sid).Translate(
            [Security.Principal.NTAccount]).Value.Split('\')[-1]
    }
    catch {
        Write-Verbose "Get-AdminGroupMembers: cannot translate SID $Sid : $($_.Exception.Message)"
        return $members
    }

    try {
        $group = ([ADSI]"WinNT://./$groupName,group")
        $rawMembers = @($group.psbase.Invoke('Members'))
        foreach ($member in $rawMembers) {
            $memberName = $null
            $memberSid = $null
            $memberClass = $null
            try {
                $memberName = $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
            }
            catch {
                Write-Verbose "Get-AdminGroupMembers: member Name unreadable: $($_.Exception.Message)"
            }
            try {
                $memberClass = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
            }
            catch {
                Write-Verbose "Get-AdminGroupMembers: member Class unreadable: $($_.Exception.Message)"
            }
            $members += [PSCustomObject]@{
                Name        = $memberName
                SID         = $memberSid
                ObjectClass = $memberClass
            }
        }
        $script:AdminGroupLookupSucceeded = $true
    }
    catch {
        Write-Verbose "Get-AdminGroupMembers: ADSI enumeration failed: $($_.Exception.Message)"
        $members = @()
    }

    return $members
}

function Get-LocalUserByRid {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Rid
    )

    $suffix = "-$Rid"

    # Preferred: LocalAccounts module (missing in 32-bit PowerShell on 64-bit Windows)
    if (Get-Command 'Get-LocalUser' -ErrorAction SilentlyContinue) {
        try {
            $user = @(Get-LocalUser -ErrorAction Stop |
                Where-Object { $null -ne $_.SID -and $_.SID.Value.EndsWith($suffix) } |
                Select-Object -First 1)
            if ($user.Count -gt 0 -and $null -ne $user[0]) {
                return [PSCustomObject]@{
                    Name        = $user[0].Name
                    SID         = $user[0].SID.Value
                    Enabled     = $user[0].Enabled
                    Description = $user[0].Description
                }
            }
        }
        catch {
            Write-Verbose "Get-LocalUserByRid: Get-LocalUser failed: $($_.Exception.Message)"
        }
    }

    # Fallback: CIM Win32_UserAccount (SID values are locale-invariant)
    if (Get-Command 'Get-CimInstance' -ErrorAction SilentlyContinue) {
        try {
            $account = @(Get-CimInstance -ClassName 'Win32_UserAccount' -Filter 'LocalAccount=True' -ErrorAction Stop |
                Where-Object { $null -ne $_.SID -and $_.SID.EndsWith($suffix) } |
                Select-Object -First 1)
            if ($account.Count -gt 0 -and $null -ne $account[0]) {
                $enabled = $null
                if ($account[0].PSObject.Properties['Disabled'] -and $null -ne $account[0].Disabled) {
                    $enabled = (-not $account[0].Disabled)
                }
                return [PSCustomObject]@{
                    Name        = $account[0].Name
                    SID         = $account[0].SID
                    Enabled     = $enabled
                    Description = $account[0].Description
                }
            }
        }
        catch {
            Write-Verbose "Get-LocalUserByRid: CIM query failed: $($_.Exception.Message)"
        }
    }

    # Last resort: ADSI WinNT provider, RID extracted from objectSID bytes
    try {
        $computer = [ADSI]'WinNT://.'
        foreach ($child in @($computer.psbase.Children)) {
            $schemaClass = $null
            try {
                $schemaClass = $child.GetType().InvokeMember('SchemaClassName', 'GetProperty', $null, $child, $null)
            }
            catch {
                continue
            }
            if ($schemaClass -ne 'User') { continue }
            try {
                $sidBytes = [byte[]]($child.GetType().InvokeMember('objectSID', 'GetProperty', $null, $child, $null))
                $userSid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                if ($userSid.EndsWith($suffix)) {
                    $userName = $child.GetType().InvokeMember('Name', 'GetProperty', $null, $child, $null)
                    $userFlags = 0
                    $description = $null
                    try {
                        $userFlags = [int]($child.GetType().InvokeMember('UserFlags', 'GetProperty', $null, $child, $null))
                    }
                    catch {
                        Write-Verbose "Get-LocalUserByRid: UserFlags unreadable: $($_.Exception.Message)"
                    }
                    try {
                        $description = $child.GetType().InvokeMember('Description', 'GetProperty', $null, $child, $null)
                    }
                    catch {
                        Write-Verbose "Get-LocalUserByRid: Description unreadable: $($_.Exception.Message)"
                    }
                    # ADS_UF_ACCOUNTDISABLE = 0x2
                    return [PSCustomObject]@{
                        Name        = $userName
                        SID         = $userSid
                        Enabled     = (-not [bool]($userFlags -band 0x2))
                        Description = $description
                    }
                }
            }
            catch {
                Write-Verbose "Get-LocalUserByRid: ADSI user unreadable: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Verbose "Get-LocalUserByRid: ADSI enumeration failed: $($_.Exception.Message)"
    }

    return $null
}

function Test-IdentityReferenceIsSid {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        $IdentityReference,

        [Parameter()]
        [string]$Sid
    )

    if ($null -eq $IdentityReference -or [string]::IsNullOrEmpty($Sid)) { return $false }

    try {
        if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) {
            return ($IdentityReference.Value -eq $Sid)
        }

        $ntAccount = $null
        if ($IdentityReference -is [Security.Principal.NTAccount]) {
            $ntAccount = $IdentityReference
        }
        elseif ($IdentityReference -is [string]) {
            # Some ACLs carry unresolved SIDs as plain strings
            if ($IdentityReference -eq $Sid) { return $true }
            try {
                $ntAccount = New-Object Security.Principal.NTAccount($IdentityReference)
            }
            catch {
                $ntAccount = $null
            }
        }

        if ($null -ne $ntAccount) {
            try {
                return ($ntAccount.Translate([Security.Principal.SecurityIdentifier]).Value -eq $Sid)
            }
            catch {
                # Untranslatable name; fall through to raw string equality
            }
        }

        return ([string]$IdentityReference -eq $Sid)
    }
    catch {
        return $false
    }
}
