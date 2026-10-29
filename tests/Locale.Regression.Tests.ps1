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

    One documented seam does NOT exist yet and its test is skipped on purpose:
    the auditpol /get CSV parse is still inline in Get-AuditPolicyTable (strategy 3,
    honest-unknown on localized inclusion text). The NetApi seconds->days /
    TIMEQ_FOREVER (0xFFFFFFFF) -> -1 conversion seam now EXISTS as the pure
    ConvertTo-PolicyFromModals helper in Private/Get-LocalPasswordPolicy.ps1 and
    is covered by the tests below.

    The module targets Windows PowerShell 5.1+, so only APIs available in
    5.1 are used here (no null-coalescing/ternary operators, no ForEach-Object -Parallel).
#>

BeforeDiscovery {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'

    # Locale-fragile patterns that must never appear. All legacy call sites were
    # migrated to the Private/ helpers in v1.6.0 — any match anywhere fails the guard.
    # Every regex carries BadSamples: representative offending snippets the regex
    # MUST match, pinned by the guard self-test below so a regex can never
    # silently rot into a dead guard.
    $script:ForbiddenReaders = @(
        @{
            Name          = "raw 'auditpol /get' text parsing (localized Inclusion columns)"
            Regex         = 'auditpol(\.exe)?\s+/get\b'
            Grandfathered = @()
            BadSamples    = @(
                '$output = auditpol /get /category:* /r'
                '$output = auditpol.exe /get /subcategory:"Logon"'
            )
        }
        @{
            Name          = "'Minimum password length' label parsing of 'net accounts' output"
            Regex         = 'Select-String\b(\s+-Pattern)?\s+["''][^"'']*[Pp]assword\s+[Ll]ength'
            Grandfathered = @()
            BadSamples    = @(
                'Select-String ''Minimum password length'''
                'Select-String -Pattern ''Minimum password length'''
            )
        }
        @{
            Name          = 'name-based Get-LocalGroupMember -Group with a string literal'
            Regex         = 'Get-LocalGroupMember\b[^\n|]*-Group\s+["'']'
            Grandfathered = @()
            BadSamples    = @('Get-LocalGroupMember -Group ''Administrators''')
        }
        @{
            Name          = 'name-based Get-LocalUser -Name Guest/Administrator'
            Regex         = 'Get-LocalUser\b[^\n|]*-Name\s+["''](Guest|Administrator)["'']'
            Grandfathered = @()
            BadSamples    = @('Get-LocalUser -Name ''Guest''')
        }
        @{
            Name          = 'string identities (Everyone / NT AUTHORITY\SYSTEM / BUILTIN\Administrators) in FileSystemAccessRule'
            Regex         = 'FileSystemAccessRule\(\s*["''](Everyone|NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators)["'']'
            Grandfathered = @()
            BadSamples    = @('New-Object System.Security.AccessControl.FileSystemAccessRule(''Everyone'', ''FullControl'', ''Allow'')')
        }
        @{
            Name          = "IdentityReference matched against '(Everyone' style name patterns"
            Regex         = 'IdentityReference\b[^\n]*-match\s+["''][^"'']*\(?Everyone'
            Grandfathered = @()
            BadSamples    = @('$rule.IdentityReference -match ''^(Everyone|BUILTIN)''')
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

    Import-Module -Name $script:ModulePath -Force

    # Invocation-context guard for 'net accounts' reads (leading = | ; { ( & or
    # line start). Hardening/Set-SecurityBaseline.ps1 is allowed (legit /set writes).
    # Defined in BeforeAll (not BeforeDiscovery): run-phase script state is fresh,
    # so runtime references from It blocks need run-phase initialization.
    $script:NetAccountsGuard = @{
        Name       = "'net accounts' invocation outside Hardening/Set-SecurityBaseline.ps1"
        Regex      = '(?m)(=|\||;|\{|\(|&)\s*net(\.exe)?\s+accounts\b|^[ \t]*net(\.exe)?\s+accounts\b'
        Allowed    = @('Hardening/Set-SecurityBaseline.ps1')
        BadSamples = @(
            '$x = net accounts'
            '$x = & net accounts'
        )
    }

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

    It 'merges per-GUID: a per-user-only GUID survives next to a GUID where the System row wins' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $lines = @(
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
                'WSA-TEST01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3'
                'WSA-TEST01,S-1-5-21-3623811015-3361044348-30300820-1001,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1'
            )
            $map = ConvertFrom-AuditPolicyBackupCsv -Lines $lines
            $map.Count | Should -Be 2 -Because 'a GUID with only per-user rows must not be dropped just because another GUID has a System row'
            $map['0cce9215-69ae-11d9-bed3-505054503030'] | Should -Be 3 -Because 'the System row wins for Logon'
            $map['0cce9216-69ae-11d9-bed3-505054503030'] | Should -Be 1 -Because 'Logoff has only the per-user row, so it is the source'
        }
    }

    It 'lets the System row win even when the per-user row comes first (reordered rows)' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $lines = @(
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
                'WSA-TEST01,S-1-5-21-3623811015-3361044348-30300820-1001,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1'
                'WSA-TEST01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3'
            )
            $map = ConvertFrom-AuditPolicyBackupCsv -Lines $lines
            $map.Count | Should -Be 1
            $map['0cce9215-69ae-11d9-bed3-505054503030'] | Should -Be 3 -Because 'row order must not matter: System wins regardless of position'
        }
    }

    It 'drops rows whose Setting Value is outside the 0-3 range' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $lines = @(
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
                'WSA-TEST01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,5'
                'WSA-TEST01,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1'
            )
            $map = ConvertFrom-AuditPolicyBackupCsv -Lines $lines
            $map.Count | Should -Be 1 -Because "'5' is not a valid audit setting value (0-3) and the row must be rejected"
            $map.ContainsKey('0cce9215-69ae-11d9-bed3-505054503030') | Should -BeFalse
            $map['0cce9216-69ae-11d9-bed3-505054503030'] | Should -Be 1
        }
    }

    It 'lets the first System row win when duplicate System rows exist for one GUID' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $lines = @(
                'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
                'WSA-TEST01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3'
                'WSA-TEST01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1'
            )
            $map = ConvertFrom-AuditPolicyBackupCsv -Lines $lines
            $map.Count | Should -Be 1
            $map['0cce9215-69ae-11d9-bed3-505054503030'] | Should -Be 3 -Because 'the first System row for a GUID wins'
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
        $regex = $script:NetAccountsGuard.Regex
        $allowed = $script:NetAccountsGuard.Allowed
        $offenders = @(
            foreach ($file in $script:GuardedFiles) {
                if ($allowed -contains $file.RelativePath) { continue }
                $content = Get-Content -Path $file.FullName -Raw
                if ($null -ne $content -and $content -match $regex) { $file.RelativePath }
            }
        )
        $offenders.Count | Should -Be 0 -Because ("'net accounts' output is localized; reads must go through Get-LocalPasswordPolicy, writes belong to Set-SecurityBaseline: {0}" -f ($offenders -join ', '))
    }

    It 'guard regex still matches its representative bad samples: <Name>' -ForEach $script:ForbiddenReaders {
        foreach ($sample in $_.BadSamples) {
            $sample -match $_.Regex | Should -BeTrue -Because "a guard regex that no longer matches its own bad sample is a dead guard (sample: $sample)"
        }
    }

    It "guard regex still matches its representative bad samples: net accounts invocation" {
        foreach ($sample in $script:NetAccountsGuard.BadSamples) {
            $sample -match $script:NetAccountsGuard.Regex | Should -BeTrue -Because "a guard regex that no longer matches its own bad sample is a dead guard (sample: $sample)"
        }
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

        It 'Test-IdentityReferenceIsSid matches a SecurityIdentifier object input against its SID string' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                # On non-Windows .NET the whole System.Security.Principal.Windows
                # surface (including every SecurityIdentifier constructor) throws
                # PlatformNotSupportedException, so the object cannot be built there;
                # the assertion itself runs wherever the type is constructible.
                $sidObject = $null
                try {
                    $sidObject = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
                }
                catch {
                    Set-ItResult -Skipped -Because 'SecurityIdentifier cannot be constructed on this platform (Windows Principal functionality is not supported)'
                    return
                }
                Test-IdentityReferenceIsSid -IdentityReference $sidObject -Sid 'S-1-5-32-544' | Should -BeTrue
                Test-IdentityReferenceIsSid -IdentityReference $sidObject -Sid 'S-1-1-0' | Should -BeFalse
            }
        }
    }

    Context 'Get-AuditSubcategoryGuid name resolution' {
        It 'resolves subcategory names case-insensitively' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                Get-AuditSubcategoryGuid -Name 'logon' | Should -Be '{0CCE9215-69AE-11D9-BED3-505054503030}'
                Get-AuditSubcategoryGuid -Name 'Logon' | Should -Be '{0CCE9215-69AE-11D9-BED3-505054503030}'
            }
        }

        It 'returns null for an unknown subcategory name' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                Get-AuditSubcategoryGuid -Name 'Not A Real Subcategory' | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Get-AuditPolicyTable subset selection and cache behavior' {
        It 'returns exactly the requested subcategories' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $table = Get-AuditPolicyTable -Subcategory 'Logon', 'Logoff'
                $table.Count | Should -Be 2
                $table.ContainsKey('0cce9215-69ae-11d9-bed3-505054503030') | Should -BeTrue
                $table.ContainsKey('0cce9216-69ae-11d9-bed3-505054503030') | Should -BeTrue
            }
        }

        It 'skips unknown names in -Subcategory' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $table = Get-AuditPolicyTable -Subcategory 'Logon', 'Logoff', 'Not A Real Subcategory'
                $table.Count | Should -Be 2 -Because 'unknown subcategory names are skipped, not fatal'
            }
        }

        It 'serves equivalent content from the cache on repeated calls without -Force' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $first = Get-AuditPolicyTable
                $second = Get-AuditPolicyTable
                $second.Count | Should -Be $first.Count
                $firstKeys = @($first.Keys | Sort-Object)
                (@($second.Keys | Sort-Object) -join ',') | Should -Be ($firstKeys -join ',')
                foreach ($key in $firstKeys) {
                    $second[$key].Value | Should -Be $first[$key].Value
                    $second[$key].Success | Should -Be $first[$key].Success
                    $second[$key].Failure | Should -Be $first[$key].Failure
                    $second[$key].Source | Should -Be $first[$key].Source
                }
            }
        }

        It 'never lets callers corrupt the cache (clone-on-read)' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $table = Get-AuditPolicyTable
                $entry = $table['0cce9215-69ae-11d9-bed3-505054503030']
                $originalValue = $entry.Value
                $entry.Value = 999
                $fresh = Get-AuditPolicyTable
                $fresh['0cce9215-69ae-11d9-bed3-505054503030'].Value |
                    Should -Be $originalValue -Because 'mutating a returned table must not corrupt the cached table'
                # Hygiene: rebuild the cache so no later test inherits state from this one
                $null = Get-AuditPolicyTable -Force
            }
        }
    }

    Context 'Get-LocalUserByRid RID suffix matching' {
        It 'does not match a user whose SID merely ends with the RID digits (RID 500 vs ...-1500)' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                # Get-LocalUser does not exist on non-Windows hosts and Pester can
                # only mock existing commands, so define a stub first. The SID is a
                # duck-typed .Value holder because SecurityIdentifier constructors
                # throw PlatformNotSupportedException off Windows; the code under
                # test only ever touches $_.SID.Value.
                function Get-LocalUser { }
                Mock Get-LocalUser {
                    @(
                        [PSCustomObject]@{
                            Name        = 'Rid1500User'
                            SID         = [PSCustomObject]@{ Value = 'S-1-5-21-3623811015-3361044348-30300820-1500' }
                            Enabled     = $true
                            Description = ''
                        }
                    )
                }
                # On Windows the CIM fallback would find the REAL RID-500 account
                # (e.g. the CI runner's administrator) when the mocked Get-LocalUser
                # returns no match — neutralize the fallback inside this test.
                if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                    Mock Get-CimInstance { @() }
                }
                Get-LocalUserByRid -Rid 500 | Should -BeNullOrEmpty -Because 'SID ...-1500 must not match RID 500 (suffix match includes the dash)'
                $hit = Get-LocalUserByRid -Rid 1500
                $hit.Name | Should -Be 'Rid1500User' -Because 'the mock wiring must actually be exercised (positive control)'
            }
        }
    }

    Context 'ConvertTo-PolicyFromModals pure conversion seam' {
        It 'converts NetApi seconds to days/hours/minutes and TIMEQ_FOREVER (0xFFFFFFFF) to -1' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $modals0 = @{
                    usrmod0_min_passwd_len    = [uint32]7
                    usrmod0_max_passwd_age    = [uint32]3628800    # 42 days, in seconds
                    usrmod0_min_passwd_age    = [uint32]86400      # 1 day, in seconds
                    usrmod0_force_logoff      = [uint32]::MaxValue # TIMEQ_FOREVER
                    usrmod0_password_hist_len = [uint32]5
                }
                $modals3 = @{
                    usrmod3_lockout_duration           = [uint32]1800 # 30 minutes, in seconds
                    usrmod3_lockout_observation_window = [uint32]600  # 10 minutes, in seconds
                    usrmod3_lockout_threshold          = [uint32]5
                }
                $policy = ConvertTo-PolicyFromModals -Modals0 $modals0 -Modals3 $modals3
                $policy.MinPasswordLength | Should -Be 7
                $policy.MaxPasswordAgeDays | Should -Be 42
                $policy.MinPasswordAgeDays | Should -Be 1
                $policy.PasswordHistoryLength | Should -Be 5
                $policy.ForceLogoffHours | Should -Be -1 -Because 'TIMEQ_FOREVER (0xFFFFFFFF) maps to -1'
                $policy.LockoutThreshold | Should -Be 5
                $policy.LockoutDurationMinutes | Should -Be 30
                $policy.LockoutObservationWindowMinutes | Should -Be 10
            }
        }

        It 'maps a TIMEQ_FOREVER lockout duration to -1 and null Modals0 to null fields' {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                $modals3 = @{
                    usrmod3_lockout_duration           = [uint32]::MaxValue # TIMEQ_FOREVER: until admin unlocks
                    usrmod3_lockout_observation_window = [uint32]600
                    usrmod3_lockout_threshold          = [uint32]0
                }
                $policy = ConvertTo-PolicyFromModals -Modals0 $null -Modals3 $modals3
                $policy.LockoutDurationMinutes | Should -Be -1
                $policy.LockoutObservationWindowMinutes | Should -Be 10
                $policy.LockoutThreshold | Should -Be 0
                $policy.MinPasswordLength | Should -BeNullOrEmpty
                $policy.MaxPasswordAgeDays | Should -BeNullOrEmpty
                $policy.MinPasswordAgeDays | Should -BeNullOrEmpty
                $policy.PasswordHistoryLength | Should -BeNullOrEmpty
                $policy.ForceLogoffHours | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'PS 5.1 encoding safety (BOM guard)' {
    # Windows PowerShell 5.1 reads BOM-less files as ANSI: any non-ASCII content
    # (em dashes, accented chars) corrupts parsing. Every script with non-ASCII
    # bytes must be UTF-8 with BOM.
    It 'every .ps1/.psm1/.psd1 with non-ASCII content is UTF-8 with BOM' {
        $offenders = @(
            Get-ChildItem -Path $script:ModuleRoot -Include '*.ps1','*.psm1','*.psd1' -Recurse -File |
                Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
                Where-Object {
                    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
                    $hasNonAscii = $false
                    foreach ($byte in $bytes) { if ($byte -gt 0x7F) { $hasNonAscii = $true; break } }
                    $hasNonAscii -and -not $hasBom
                } |
                ForEach-Object { $_.FullName.Substring($script:ModuleRoot.Length) }
        )
        $offenders.Count | Should -Be 0 -Because ("PS 5.1 misreads BOM-less non-ASCII files as ANSI: {0}" -f ($offenders -join ', '))
    }
}
