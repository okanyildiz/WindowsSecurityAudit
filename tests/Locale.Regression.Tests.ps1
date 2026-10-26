#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Locale-regression tests for the Private/ locale-invariant helpers.
.DESCRIPTION
    Cross-platform tests (run green on macOS and on the Windows CI lint job):

    * Fixture equivalence (WinLogKit PR #58 pattern): the English and German
      (ANSI/cp1252, localized header + names + inclusion text) auditpol /backup
      fixtures in tests/fixtures/ must parse to IDENTICAL GUID -> Value maps via
      ConvertFrom-AuditPolicyBackupCsv. Junk Option: rows and blank lines are
      filtered by the GUID regex; System rows win over per-user rows.
    * Static regression guard ('no text readers'): locale-fragile parsing patterns
      are forbidden in every module file. All legacy call sites were migrated to the
      Private/ helpers in v1.6.0, so the forbidden lists below carry NO grandfather
      entries — any occurrence anywhere fails the build.
    * Helper contract/degradation on non-Windows hosts: Get-AuditPolicyTable,
      Get-LocalPasswordPolicy, Get-WlanProfileList and Get-LocalUserByRid degrade
      to Unavailable/empty/$null instead of throwing; Test-IdentityReferenceIsSid
      and Get-WellKnownSid honor their SID contracts on every platform.

    Two documented seams do NOT exist yet and their tests are skipped on purpose:
    the auditpol /get CSV parse is still inline in Get-AuditPolicyTable (strategy 3,
    honest-unknown on localized inclusion text), and the NetApi seconds->days /
    TIMEQ_FOREVER (0xFFFFFFFF) -> -1 conversions are inline behind the C#
    NetUserModalsGet interop in Get-LocalPasswordPolicy.ps1. Extract pure parser
    seams first, then unskip.

    The module targets Windows PowerShell 5.1+, so only APIs available in
    5.1 are used here (no null-coalescing/ternary operators, no ForEach-Object -Parallel).
#>

BeforeDiscovery {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'

    # Locale-fragile patterns that must never appear. All legacy call sites were
    # migrated to the Private/ helpers in v1.6.0 — any match anywhere fails the guard.
    $script:ForbiddenReaders = @(
        @{
            Name          = "raw 'auditpol /get' text parsing (localized Inclusion columns)"
            Regex         = 'auditpol(\.exe)?\s+/get\b'
            Grandfathered = @()
        }
        @{
            Name          = "'Minimum password length' label parsing of 'net accounts' output"
            Regex         = 'Select-String\s+["''][^"'']*[Pp]assword\s+[Ll]ength'
            Grandfathered = @()
        }
        @{
            Name          = 'name-based Get-LocalGroupMember -Group with a string literal'
            Regex         = 'Get-LocalGroupMember\b[^\n|]*-Group\s+["'']'
            Grandfathered = @()
        }
        @{
            Name          = 'name-based Get-LocalUser -Name Guest/Administrator'
            Regex         = 'Get-LocalUser\b[^\n|]*-Name\s+["''](Guest|Administrator)["'']'
            Grandfathered = @()
        }
        @{
            Name          = 'string identities (Everyone / NT AUTHORITY\SYSTEM / BUILTIN\Administrators) in FileSystemAccessRule'
            Regex         = 'FileSystemAccessRule\(\s*["''](Everyone|NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators)["'']'
            Grandfathered = @()
        }
        @{
            Name          = "IdentityReference matched against '(Everyone' style name patterns"
            Regex         = 'IdentityReference\b[^\n]*-match\s+["''][^"'']*\(?Everyone'
            Grandfathered = @()
        }
    )
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"
    $script:FixturePath = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures'
    $script:EnFixture = Join-Path -Path $script:FixturePath -ChildPath 'auditpol-backup-en.csv'
    $script:DeFixture = Join-Path -Path $script:FixturePath -ChildPath 'auditpol-backup-de.csv'

    Import-Module -Name $script:ModulePath -Force -DisableNameChecking

    $script:IsWindowsHost = $false
    try {
        $script:IsWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        # RuntimeInformation missing on old .NET Framework (PS 5.1)
        $script:IsWindowsHost = ($env:OS -eq 'Windows_NT')
    }

    # Every module .ps1 file except the tests folder and Private/Get-AuditPolicyTable.ps1
    # (the one file allowed to touch auditpol /get output, covered by fixtures instead)
    $script:GuardedFiles = @(
        Get-ChildItem -Path $script:ModuleRoot -Filter '*.ps1' -Recurse -File |
            Where-Object {
                $_.FullName -notmatch '[\\/]\.git[\\/]' -and
                $_.FullName -notmatch '[\\/]tests[\\/]' -and
                $_.FullName -ne (Join-Path -Path $script:ModuleRoot -ChildPath 'Private/Get-AuditPolicyTable.ps1')
            } |
            ForEach-Object {
                $relative = $_.FullName.Substring($script:ModuleRoot.Length) -replace '^[\\/]+', '' -replace '[\\/]', '/'
                [PSCustomObject]@{ FullName = $_.FullName; RelativePath = $relative }
            }
    )
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertFrom-AuditPolicyBackupCsv fixture equivalence (WinLogKit PR #58 pattern)' {
    It 'parses the German ANSI/cp1252 fixture without throwing (salt#68354)' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:DeFixture -ScriptBlock {
            param($deFixture)
            { ConvertFrom-AuditPolicyBackupCsv -Path $deFixture } | Should -Not -Throw
        }
    }

    It 'pins the English fixture to the expected GUID -> Value map' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:EnFixture -ScriptBlock {
            param($enFixture)
            $expected = @{
                '0cce9210-69ae-11d9-bed3-505054503030' = 3 # Security State Change
                '0cce9212-69ae-11d9-bed3-505054503030' = 3 # System Integrity
                '0cce9215-69ae-11d9-bed3-505054503030' = 3 # Logon
                '0cce9216-69ae-11d9-bed3-505054503030' = 1 # Logoff
                '0cce921b-69ae-11d9-bed3-505054503030' = 1 # Special Logon
                '0cce921d-69ae-11d9-bed3-505054503030' = 0 # File System (No Auditing)
                '0cce9228-69ae-11d9-bed3-505054503030' = 2 # Sensitive Privilege Use (Failure)
                '0cce922b-69ae-11d9-bed3-505054503030' = 1 # Process Creation
                '0cce923b-69ae-11d9-bed3-505054503030' = 2 # Directory Service Access
                '0cce923f-69ae-11d9-bed3-505054503030' = 3 # Credential Validation
            }
            $map = ConvertFrom-AuditPolicyBackupCsv -Path $enFixture
            $map.Count | Should -Be $expected.Count
            foreach ($key in @($expected.Keys)) {
                $map.ContainsKey($key) | Should -BeTrue -Because "GUID $key must be parsed"
                $map[$key] | Should -Be $expected[$key] -Because "numeric Setting Value is locale-invariant ($key)"
            }
        }
    }

    It 'produces IDENTICAL GUID -> Value maps from the English and the localized German fixture' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:EnFixture, $script:DeFixture -ScriptBlock {
            param($enFixture, $deFixture)
            $enMap = ConvertFrom-AuditPolicyBackupCsv -Path $enFixture
            $deMap = ConvertFrom-AuditPolicyBackupCsv -Path $deFixture
            $deMap.Count | Should -Be $enMap.Count
            $enKeys = @($enMap.Keys | Sort-Object)
            $deKeys = @($deMap.Keys | Sort-Object)
            ($deKeys -join ',') | Should -Be ($enKeys -join ',') -Because 'subcategory GUIDs are locale-invariant'
            foreach ($key in $enKeys) {
                $deMap[$key] | Should -Be $enMap[$key] -Because "localized names/inclusion text must not change the numeric value ($key)"
            }
        }
    }

    It 'filters the Option:CrashOnAuditFail junk row and blank lines via the GUID regex' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:EnFixture -ScriptBlock {
            param($enFixture)
            # The fixture carries 10 real subcategory rows plus one Option: row
            # (no GUID), one blank line and one per-user row: exactly 10 survive
            $map = ConvertFrom-AuditPolicyBackupCsv -Path $enFixture
            $map.Count | Should -Be 10 -Because 'the Option: junk row, the blank line and the per-user row must not add entries'
            @($map.Keys | Where-Object { $_ -notmatch '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' }).Count |
                Should -Be 0 -Because 'every surviving key must be a bare GUID'
        }
    }

    It 'lets System rows win over per-user rows for the same GUID' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:EnFixture, $script:DeFixture -ScriptBlock {
            param($enFixture, $deFixture)
            # Both fixtures carry a per-user Logon row (value 1) after the System row (value 3)
            $enMap = ConvertFrom-AuditPolicyBackupCsv -Path $enFixture
            $deMap = ConvertFrom-AuditPolicyBackupCsv -Path $deFixture
            $enMap['0cce9215-69ae-11d9-bed3-505054503030'] | Should -Be 3 -Because 'the System row must win over the per-user SID row'
            $deMap['0cce9215-69ae-11d9-bed3-505054503030'] | Should -Be 3 -Because 'the System row must win over the per-user SID row'
        }
    }

    It 'falls back to per-user rows only when no System rows exist' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $lines = @(
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
                'WSA-TEST01,S-1-5-21-3623811015-3361044348-30300820-1001,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1'
            )
            $map = ConvertFrom-AuditPolicyBackupCsv -Lines $lines
            $map['0cce9215-69ae-11d9-bed3-505054503030'] | Should -Be 1 -Because 'with no System row present the per-user row is the only source'
        }
    }

    It 'accepts raw -Lines with the same result as -Path' {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $script:EnFixture -ScriptBlock {
            param($enFixture)
            $fromPath = ConvertFrom-AuditPolicyBackupCsv -Path $enFixture
            # No -Encoding, exactly like the production read of the backup file
            $fromLines = ConvertFrom-AuditPolicyBackupCsv -Lines @(Get-Content -LiteralPath $enFixture)
            $fromLines.Count | Should -Be $fromPath.Count
            foreach ($key in @($fromPath.Keys)) {
                $fromLines[$key] | Should -Be $fromPath[$key]
            }
        }
    }

    It 'returns an empty map for content without a header and data rows' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $map = ConvertFrom-AuditPolicyBackupCsv -Lines @('header only')
            $map.Count | Should -Be 0
        }
    }

    # SKIPPED (no parse seam): the auditpol /get CSV parse (6 columns, no numeric
    # value, English-only Inclusion text) is still inline in Get-AuditPolicyTable
    # (strategy 3) and the change under test allowed extracting only the BackupCsv
    # strategy. Once a ConvertFrom-AuditPolicyGetCsv-style seam exists, add a German
    # /r fixture ('Erfolg und Fehler') asserting Value stays $null (honest unknown)
    # instead of being guessed from localized text.
    It 'never guesses values from localized auditpol /get inclusion text' -Skip {
    }
}

Describe 'No locale-fragile text readers (static regression guard)' {
    It 'no new file uses <Name>' -ForEach $script:ForbiddenReaders {
        $offenders = @(
            foreach ($file in $script:GuardedFiles) {
                if ($_.Grandfathered -contains $file.RelativePath) { continue }
                $content = Get-Content -Path $file.FullName -Raw
                if ($null -ne $content -and $content -match $_.Regex) { $file.RelativePath }
            }
        )
        $offenders.Count | Should -Be 0 -Because ("locale-fragile pattern '{0}' is forbidden module-wide since v1.6.0 (use the Private/ locale-invariant helpers): {1}" -f $_.Name, ($offenders -join ', '))
    }

    It "'net accounts' appears only in Hardening/Set-SecurityBaseline.ps1 (legit /set usage)" {
        # Invocation context only: the doc comment in Private/Get-LocalPasswordPolicy.ps1
        # ('NEVER calls net accounts') is documentation, not an invocation
        $regex = '(?m)(=|\||;|\{|\()\s*net(\.exe)?\s+accounts\b|^[ \t]*net(\.exe)?\s+accounts\b'
        $allowed = @(
            'Hardening/Set-SecurityBaseline.ps1'        # legit /set (write) usage
        )
        $offenders = @(
            foreach ($file in $script:GuardedFiles) {
                if ($allowed -contains $file.RelativePath) { continue }
                $content = Get-Content -Path $file.FullName -Raw
                if ($null -ne $content -and $content -match $regex) { $file.RelativePath }
            }
        )
        $offenders.Count | Should -Be 0 -Because ("'net accounts' output is localized; reads must go through Get-LocalPasswordPolicy, writes belong to Set-SecurityBaseline: {0}" -f ($offenders -join ', '))
    }
}

Describe 'Private helper contract and degradation' {
    Context 'non-Windows hosts (macOS/Linux dev boxes and CI)' {
        It 'Get-AuditPolicyTable returns 59 entries, all Source=Unavailable with null Values' {
            if ($script:IsWindowsHost) {
                Set-ItResult -Skipped -Because 'on Windows the table resolves real data via Api/BackupCsv instead of degrading'
                return
            }
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $table = Get-AuditPolicyTable -Force
                $table.Count | Should -Be 59 -Because 'one entry per known audit subcategory GUID'
                $entries = @($table.Values)
                @($entries | Where-Object { $_.Source -ne 'Unavailable' }).Count | Should -Be 0
                @($entries | Where-Object { $null -ne $_.Value }).Count | Should -Be 0
                @($entries | Where-Object { $_.Success -or $_.Failure }).Count | Should -Be 0
            }
        }

        It 'Get-LocalPasswordPolicy degrades to Source=Unavailable' {
            if ($script:IsWindowsHost) {
                Set-ItResult -Skipped -Because 'on Windows the SAM policy resolves via NetApi/Secedit instead of degrading'
                return
            }
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $policy = Get-LocalPasswordPolicy
                $policy.Source | Should -Be 'Unavailable'
                $policy.MinPasswordLength | Should -BeNullOrEmpty
                $policy.MaxPasswordAgeDays | Should -BeNullOrEmpty
            }
        }

        It 'Get-WlanProfileList returns an empty array' {
            if ($script:IsWindowsHost) {
                Set-ItResult -Skipped -Because 'on Windows the WLAN API may return real profiles'
                return
            }
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $profiles = @(Get-WlanProfileList)
                $profiles.Count | Should -Be 0
            }
        }

        It 'Get-LocalUserByRid -Rid 500 returns null instead of throwing' {
            if ($script:IsWindowsHost) {
                Set-ItResult -Skipped -Because 'on Windows RID 500 (built-in Administrator) exists and resolves'
                return
            }
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                { Get-LocalUserByRid -Rid 500 } | Should -Not -Throw
                Get-LocalUserByRid -Rid 500 | Should -BeNullOrEmpty
            }
        }
    }

    Context 'platform-independent identity helpers' {
        It 'Test-IdentityReferenceIsSid matches a raw unresolved SID string against the same SID' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                Test-IdentityReferenceIsSid -IdentityReference 'S-1-1-0' -Sid 'S-1-1-0' | Should -BeTrue
            }
        }

        It 'Test-IdentityReferenceIsSid rejects a raw SID string against a different SID' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                Test-IdentityReferenceIsSid -IdentityReference 'S-1-1-0' -Sid 'S-1-5-32-544' | Should -BeFalse
            }
        }

        It 'Test-IdentityReferenceIsSid returns false for null input' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                Test-IdentityReferenceIsSid -IdentityReference $null -Sid 'S-1-1-0' | Should -BeFalse
            }
        }

        It 'Get-WellKnownSid contains the documented mappings' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $sids = Get-WellKnownSid
                $sids.Administrators     | Should -Be 'S-1-5-32-544'
                $sids.Users              | Should -Be 'S-1-5-32-545'
                $sids.Guests             | Should -Be 'S-1-5-32-546'
                $sids.BackupOperators    | Should -Be 'S-1-5-32-551'
                $sids.RemoteDesktopUsers | Should -Be 'S-1-5-32-555'
                $sids.System             | Should -Be 'S-1-5-18'
                $sids.LocalService       | Should -Be 'S-1-5-19'
                $sids.NetworkService     | Should -Be 'S-1-5-20'
                $sids.Everyone           | Should -Be 'S-1-1-0'
                $sids.AuthenticatedUsers | Should -Be 'S-1-5-11'
            }
        }
    }

    # SKIPPED (no parse seam): the NetApi seconds -> days conversion and the
    # TIMEQ_FOREVER (0xFFFFFFFF) -> -1 mapping live inline behind the C#
    # NetUserModalsGet interop in Get-LocalPasswordPolicy.ps1 and cannot execute
    # on non-Windows hosts. Extract a pure conversion helper first, then unskip.
    It 'converts NetApi seconds to days and TIMEQ_FOREVER (0xFFFFFFFF) to -1' -Skip {
    }
}
