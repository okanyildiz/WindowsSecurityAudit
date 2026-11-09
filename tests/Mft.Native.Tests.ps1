#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Cross-platform synthetic fixtures for native MFT SI/FN parsing.
.DESCRIPTION
    FILE records and FSCTL output buffers are synthetic. The parser and
    enumeration seams perform no operating system calls. Live DeviceIoControl
    integration and FSCTL sector-tail restoration remain Windows-only checks.
#>

BeforeDiscovery {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"
    Import-Module -Name $script:ModulePath -Force

    $typeReady = InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
        Initialize-MftNativeType
    }
    if (-not $typeReady) {
        throw 'MftNative could not be compiled; fixture tests cannot run.'
    }

    function Set-MftFixtureUInt16 {
        param([byte[]]$Buffer, [int]$Offset, [uint16]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 2)
    }

    function Set-MftFixtureUInt32 {
        param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 4)
    }

    function Set-MftFixtureUInt64 {
        param([byte[]]$Buffer, [int]$Offset, [uint64]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 8)
    }

    function Set-MftFixtureInt64 {
        param([byte[]]$Buffer, [int]$Offset, [long]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 8)
    }

    function Set-MftFixtureFileTime {
        param([byte[]]$Buffer, [int]$Offset, [datetime]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value.ToFileTimeUtc()), 0, $Buffer, $Offset, 8)
    }

    function New-MftFileRecord {
        param(
            [uint32]$RecordNumber = 42,
            [string]$FileName = 'timestomp.exe',
            [datetime]$SiCreated = [datetime]::SpecifyKind([datetime]'2024-01-01T03:04:05', [DateTimeKind]::Utc),
            [datetime]$FnCreated = $SiCreated,
            [datetime]$SiModified = [datetime]::SpecifyKind([datetime]'2024-01-03T03:04:05', [DateTimeKind]::Utc),
            [datetime]$FnModified = $SiModified,
            [switch]$RawFixup,
            [switch]$IncludeAttributeList,
            [switch]$IncludeNonResidentData,
            [switch]$FreeRecord
        )

        [byte[]]$record = @(0) * 1024
        $record[0] = 0x46
        $record[1] = 0x49
        $record[2] = 0x4C
        $record[3] = 0x45
        Set-MftFixtureUInt16 -Buffer $record -Offset 4 -Value 0x30
        Set-MftFixtureUInt16 -Buffer $record -Offset 6 -Value 3
        Set-MftFixtureUInt64 -Buffer $record -Offset 8 -Value 0x1122334455667788
        Set-MftFixtureUInt16 -Buffer $record -Offset 16 -Value 1
        Set-MftFixtureUInt16 -Buffer $record -Offset 18 -Value 1
        Set-MftFixtureUInt16 -Buffer $record -Offset 20 -Value 0x38
        $flags = if ($FreeRecord) { [uint16]0 } else { [uint16]1 }
        Set-MftFixtureUInt16 -Buffer $record -Offset 22 -Value $flags
        Set-MftFixtureUInt32 -Buffer $record -Offset 28 -Value 1024
        Set-MftFixtureUInt16 -Buffer $record -Offset 40 -Value 4
        Set-MftFixtureUInt32 -Buffer $record -Offset 44 -Value $RecordNumber
        Set-MftFixtureUInt16 -Buffer $record -Offset 48 -Value 0xAABB
        Set-MftFixtureUInt16 -Buffer $record -Offset 50 -Value 0x1111
        Set-MftFixtureUInt16 -Buffer $record -Offset 52 -Value 0x2222

        $siOffset = 0x38
        $siLength = 0x60
        Set-MftFixtureUInt32 -Buffer $record -Offset $siOffset -Value 0x10
        Set-MftFixtureUInt32 -Buffer $record -Offset ($siOffset + 4) -Value $siLength
        Set-MftFixtureUInt16 -Buffer $record -Offset ($siOffset + 14) -Value 0
        Set-MftFixtureUInt32 -Buffer $record -Offset ($siOffset + 16) -Value 72
        Set-MftFixtureUInt16 -Buffer $record -Offset ($siOffset + 20) -Value 24
        $siValue = $siOffset + 24
        Set-MftFixtureFileTime -Buffer $record -Offset $siValue -Value $SiCreated
        Set-MftFixtureFileTime -Buffer $record -Offset ($siValue + 8) -Value $SiModified
        $mftChanged = [datetime]::SpecifyKind([datetime]'2024-01-04T03:04:05', [DateTimeKind]::Utc)
        $accessed = [datetime]::SpecifyKind([datetime]'2024-01-05T03:04:05', [DateTimeKind]::Utc)
        Set-MftFixtureFileTime -Buffer $record -Offset ($siValue + 16) -Value $mftChanged
        Set-MftFixtureFileTime -Buffer $record -Offset ($siValue + 24) -Value $accessed
        Set-MftFixtureUInt32 -Buffer $record -Offset ($siValue + 32) -Value 0x20

        $offset = $siOffset + $siLength
        if ($IncludeAttributeList) {
            Set-MftFixtureUInt32 -Buffer $record -Offset $offset -Value 0x20
            Set-MftFixtureUInt32 -Buffer $record -Offset ($offset + 4) -Value 0x20
            Set-MftFixtureUInt16 -Buffer $record -Offset ($offset + 14) -Value 1
            Set-MftFixtureUInt32 -Buffer $record -Offset ($offset + 16) -Value 0
            Set-MftFixtureUInt16 -Buffer $record -Offset ($offset + 20) -Value 24
            $offset += 0x20
        }

        [byte[]]$nameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $fnLength = (24 + 66 + $nameBytes.Length + 7) -band (-bnot 7)
        $fnOffset = $offset
        Set-MftFixtureUInt32 -Buffer $record -Offset $fnOffset -Value 0x30
        Set-MftFixtureUInt32 -Buffer $record -Offset ($fnOffset + 4) -Value $fnLength
        Set-MftFixtureUInt16 -Buffer $record -Offset ($fnOffset + 14) -Value 2
        Set-MftFixtureUInt32 -Buffer $record -Offset ($fnOffset + 16) -Value (66 + $nameBytes.Length)
        Set-MftFixtureUInt16 -Buffer $record -Offset ($fnOffset + 20) -Value 24
        $fnValue = $fnOffset + 24
        Set-MftFixtureUInt64 -Buffer $record -Offset $fnValue -Value 0x0005000000000005
        Set-MftFixtureFileTime -Buffer $record -Offset ($fnValue + 8) -Value $FnCreated
        Set-MftFixtureFileTime -Buffer $record -Offset ($fnValue + 16) -Value $FnModified
        Set-MftFixtureFileTime -Buffer $record -Offset ($fnValue + 24) -Value $mftChanged
        Set-MftFixtureFileTime -Buffer $record -Offset ($fnValue + 32) -Value $accessed
        Set-MftFixtureUInt64 -Buffer $record -Offset ($fnValue + 40) -Value 0x1000
        Set-MftFixtureUInt64 -Buffer $record -Offset ($fnValue + 48) -Value 0x200
        Set-MftFixtureUInt32 -Buffer $record -Offset ($fnValue + 56) -Value 0x20
        $record[$fnValue + 64] = [byte]$FileName.Length
        $record[$fnValue + 65] = 1
        [Array]::Copy($nameBytes, 0, $record, $fnValue + 66, $nameBytes.Length)
        $offset = $fnOffset + $fnLength

        if ($IncludeNonResidentData) {
            Set-MftFixtureUInt32 -Buffer $record -Offset $offset -Value 0x80
            Set-MftFixtureUInt32 -Buffer $record -Offset ($offset + 4) -Value 0x40
            $record[$offset + 8] = 1
            Set-MftFixtureUInt16 -Buffer $record -Offset ($offset + 14) -Value 3
            Set-MftFixtureUInt16 -Buffer $record -Offset ($offset + 32) -Value 0x40
            Set-MftFixtureUInt64 -Buffer $record -Offset ($offset + 40) -Value 0x1000
            Set-MftFixtureUInt64 -Buffer $record -Offset ($offset + 48) -Value 0x200
            Set-MftFixtureUInt64 -Buffer $record -Offset ($offset + 56) -Value 0x200
            $offset += 0x40
        }

        Set-MftFixtureUInt32 -Buffer $record -Offset $offset -Value ([uint32]::MaxValue)
        Set-MftFixtureUInt32 -Buffer $record -Offset ($offset + 4) -Value 0
        Set-MftFixtureUInt32 -Buffer $record -Offset 24 -Value ($offset + 8)

        if ($RawFixup) {
            Set-MftFixtureUInt16 -Buffer $record -Offset 0x1FE -Value 0xAABB
            Set-MftFixtureUInt16 -Buffer $record -Offset 0x3FE -Value 0xAABB
        }
        else {
            Set-MftFixtureUInt16 -Buffer $record -Offset 0x1FE -Value 0x1111
            Set-MftFixtureUInt16 -Buffer $record -Offset 0x3FE -Value 0x2222
        }
        return ,$record
    }

    function Add-MftAlternateFileName {
        param(
            [byte[]]$Record,
            [string]$FileName = 'hardlink.exe',
            [datetime]$Created = [datetime]::SpecifyKind([datetime]'2025-01-01T03:04:05', [DateTimeKind]::Utc),
            [datetime]$Modified = [datetime]::SpecifyKind([datetime]'2024-01-03T03:04:05', [DateTimeKind]::Utc),
            [uint64]$Parent = 0x0006000000000006,
            [uint16]$AttributeId = 7,
            [byte]$NameNamespace = 0
        )

        $fnOffset = [int]([BitConverter]::ToUInt32($Record, 24) - 8)
        [byte[]]$nameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $fnLength = (24 + 66 + $nameBytes.Length + 7) -band (-bnot 7)
        Set-MftFixtureUInt32 -Buffer $Record -Offset $fnOffset -Value 0x30
        Set-MftFixtureUInt32 -Buffer $Record -Offset ($fnOffset + 4) -Value $fnLength
        Set-MftFixtureUInt16 -Buffer $Record -Offset ($fnOffset + 14) -Value $AttributeId
        Set-MftFixtureUInt32 -Buffer $Record -Offset ($fnOffset + 16) -Value (66 + $nameBytes.Length)
        Set-MftFixtureUInt16 -Buffer $Record -Offset ($fnOffset + 20) -Value 24
        $fnValue = $fnOffset + 24
        Set-MftFixtureUInt64 -Buffer $Record -Offset $fnValue -Value $Parent
        Set-MftFixtureFileTime -Buffer $Record -Offset ($fnValue + 8) -Value $Created
        Set-MftFixtureFileTime -Buffer $Record -Offset ($fnValue + 16) -Value $Modified
        $mftChanged = [datetime]::SpecifyKind([datetime]'2024-01-04T03:04:05', [DateTimeKind]::Utc)
        $accessed = [datetime]::SpecifyKind([datetime]'2024-01-05T03:04:05', [DateTimeKind]::Utc)
        Set-MftFixtureFileTime -Buffer $Record -Offset ($fnValue + 24) -Value $mftChanged
        Set-MftFixtureFileTime -Buffer $Record -Offset ($fnValue + 32) -Value $accessed
        Set-MftFixtureUInt64 -Buffer $Record -Offset ($fnValue + 40) -Value 0x1000
        Set-MftFixtureUInt64 -Buffer $Record -Offset ($fnValue + 48) -Value 0x200
        Set-MftFixtureUInt32 -Buffer $Record -Offset ($fnValue + 56) -Value 0x20
        $Record[$fnValue + 64] = [byte]$FileName.Length
        $Record[$fnValue + 65] = $NameNamespace
        [Array]::Copy($nameBytes, 0, $Record, $fnValue + 66, $nameBytes.Length)

        $offset = $fnOffset + $fnLength
        Set-MftFixtureUInt32 -Buffer $Record -Offset $offset -Value ([uint32]::MaxValue)
        Set-MftFixtureUInt32 -Buffer $Record -Offset ($offset + 4) -Value 0
        Set-MftFixtureUInt32 -Buffer $Record -Offset 24 -Value ($offset + 8)
        return ,$Record
    }

    function New-MftOutputBuffer {
        param(
            [byte[]]$Record,
            [long]$Actual,
            [uint32]$ReportedRecordLength = 1024
        )

        [byte[]]$output = @(0) * (12 + $Record.Length)
        Set-MftFixtureUInt64 -Buffer $output -Offset 0 -Value ([uint64]$Actual)
        Set-MftFixtureUInt32 -Buffer $output -Offset 8 -Value $ReportedRecordLength
        [Array]::Copy($Record, 0, $output, 12, $Record.Length)
        return ,$output
    }

    function Invoke-MftParse {
        param(
            [byte[]]$Record,
            [bool]$ApplyFixups = $false,
            [int]$BytesPerSector = 512
        )

        return InModuleScope -ModuleName $script:ModuleName `
            -ArgumentList $Record, $ApplyFixups, $BytesPerSector -ScriptBlock {
                param([byte[]]$record, [bool]$applyFixups, [int]$bytesPerSector)
                [MftNative]::ParseFileRecord($record, $applyFixups, $bytesPerSector)
            }
    }

    function Invoke-MftOutputParse {
        param(
            [byte[]]$Output,
            [long]$Requested,
            [int]$BytesReturned = -1,
            [int]$RecordSize = 1024
        )

        if ($BytesReturned -lt 0) {
            $BytesReturned = $Output.Length
        }
        return InModuleScope -ModuleName $script:ModuleName `
            -ArgumentList $Output, $BytesReturned, $Requested, $RecordSize -ScriptBlock {
                param([byte[]]$output, [int]$bytesReturned, [long]$requested, [int]$recordSize)
                [MftNative]::ParseFileRecordOutputBuffer($output, $bytesReturned, $requested, $recordSize, $false, 512)
            }
    }

    function Invoke-MftEnumerate {
        param(
            [scriptblock]$Reader,
            [scriptblock]$Clock,
            [long]$EstimatedCount = 6,
            [int]$MaxRecords = 100,
            [int]$MaxSeconds = 300,
            [bool]$IncludeAll = $true
        )

        $nativeReader = [MftNative+MftRecordReader]$Reader
        $nativeClock = [MftNative+MftElapsedClock]$Clock
        return InModuleScope -ModuleName $script:ModuleName `
            -ArgumentList $EstimatedCount, $MaxRecords, $MaxSeconds, $IncludeAll, $nativeReader, $nativeClock -ScriptBlock {
                param($estimatedCount, $maxRecords, $maxSeconds, $includeAll, $reader, $clock)
                [MftNative]::EnumerateRecords($estimatedCount, 1024, 512, $maxRecords, $maxSeconds, $includeAll, $reader, $clock)
            }
    }

    function ConvertTo-PublicMftFixtureRecord {
        param([object]$NativeRecord)
        return InModuleScope -ModuleName $script:ModuleName -ArgumentList $NativeRecord -ScriptBlock {
            param($record)
            ConvertTo-MftNativeRecord -NativeRecord $record
        }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'MFT synthetic FILE record parsing' {
    It 'decodes a clean in-use timestomp.exe record exactly without applying fixups' {
        $record = New-MftFileRecord
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Error | Should -BeNullOrEmpty
        $parsed.Record.FileReferenceNumber | Should -Be 42
        $parsed.Record.HeaderRecordNumber | Should -Be 42
        $parsed.Record.SequenceNumber | Should -Be 1
        $parsed.Record.LinkCount | Should -Be 1
        $parsed.Record.InUse | Should -BeTrue
        $parsed.Record.IsDirectory | Should -BeFalse
        $parsed.Record.FileName | Should -Be 'timestomp.exe'
        $parsed.Record.ParentFileReferenceNumber | Should -Be 0x0005000000000005
        $parsed.Record.NameNamespace | Should -Be 1
        $parsed.Record.FnAttributeId | Should -Be 2
        $parsed.Record.SiCreated.Kind | Should -Be ([DateTimeKind]::Utc)
        $parsed.Record.SiCreated.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-01 03:04:05'
        $parsed.Record.FnCreated.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-01 03:04:05'
        $parsed.Record.SiModified.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-03 03:04:05'
        $parsed.Record.FnModified.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-03 03:04:05'
        $parsed.Record.SiMftChanged.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-04 03:04:05'
        $parsed.Record.SiAccessed.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-05 03:04:05'
        $parsed.Record.TimestompSuspect | Should -BeFalse
        $parsed.Record.SuspicionReason | Should -BeNullOrEmpty
        $parsed.RecordBytes[0x1FE] | Should -Be 0x11
        $parsed.RecordBytes[0x1FF] | Should -Be 0x11
        $parsed.RecordBytes[0x3FE] | Should -Be 0x22
        $parsed.RecordBytes[0x3FF] | Should -Be 0x22
        $record[0x1FE] | Should -Be 0x11
        $record[0x3FF] | Should -Be 0x22
    }

    It 'flags SI creation in 2020 against FN creation in 2024 and preserves the public UTC contract' {
        $siCreated = [datetime]::SpecifyKind([datetime]'2020-01-01T03:04:05', [DateTimeKind]::Utc)
        $fnCreated = [datetime]::SpecifyKind([datetime]'2024-01-01T03:04:05', [DateTimeKind]::Utc)
        $record = New-MftFileRecord -SiCreated $siCreated -FnCreated $fnCreated
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.SiCreated.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2020-01-01 03:04:05'
        $parsed.Record.FnCreated.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-01 03:04:05'
        $parsed.Record.TimestompSuspect | Should -BeTrue
        $parsed.Record.SuspicionReason | Should -Be 'SI_CREATED_LT_FN_CREATED'

        $public = ConvertTo-PublicMftFixtureRecord -NativeRecord $parsed.Record
        $public.FileReferenceNumber | Should -Be '0x00000000002a'
        $public.FileReference | Should -Be '0x000100000000002a'
        $public.ParentFileReferenceNumber | Should -Be '0x0005000000000005'
        $public.FileName | Should -Be 'timestomp.exe'
        $public.SiCreated.Kind | Should -Be ([DateTimeKind]::Utc)
        $public.FnCreated.Kind | Should -Be ([DateTimeKind]::Utc)
        $public.SiCreated | Should -Be $siCreated
        $public.FnCreated | Should -Be $fnCreated
        $public.CreatedDeltaTicks | Should -Be ($fnCreated.ToFileTimeUtc() - $siCreated.ToFileTimeUtc())
        $public.TimestompSuspect | Should -BeTrue
        $public.SuspicionReason | Should -Be 'SI_CREATED_LT_FN_CREATED'
        $public.Source | Should -Be 'FSCTL_GET_NTFS_FILE_RECORD'
    }

    It 'retains a modified-time mismatch as supporting evidence without raising an alert' {
        $siModified = [datetime]::SpecifyKind([datetime]'2019-02-03T04:05:06', [DateTimeKind]::Utc)
        $fnModified = [datetime]::SpecifyKind([datetime]'2024-01-03T03:04:05', [DateTimeKind]::Utc)
        $record = New-MftFileRecord -SiModified $siModified -FnModified $fnModified
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.SiCreatedFileTime | Should -Be $parsed.Record.FnCreatedFileTime
        $parsed.Record.TimestompSuspect | Should -BeFalse
        $parsed.Record.SuspicionReason | Should -Be 'SI_MODIFIED_LT_FN_MODIFIED'
        $parsed.Record.FileNameFindings.Count | Should -Be 0
        $public = ConvertTo-PublicMftFixtureRecord -NativeRecord $parsed.Record
        $public.ModifiedDeltaTicks | Should -Be ($fnModified.ToFileTimeUtc() - $siModified.ToFileTimeUtc())
    }

    It 'does not flag SI creation later than FN creation' {
        $siCreated = [datetime]::SpecifyKind([datetime]'2025-01-01T03:04:05', [DateTimeKind]::Utc)
        $fnCreated = [datetime]::SpecifyKind([datetime]'2024-01-01T03:04:05', [DateTimeKind]::Utc)
        $record = New-MftFileRecord -SiCreated $siCreated -FnCreated $fnCreated
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.TimestompSuspect | Should -BeFalse
        $parsed.Record.SuspicionReason | Should -Be 'SI_CREATED_GT_FN_CREATED'
        $parsed.Record.FileNameFindings.Count | Should -Be 0
        $public = ConvertTo-PublicMftFixtureRecord -NativeRecord $parsed.Record
        $public.TimestompSuspect | Should -BeFalse
        $public.CreatedDeltaTicks | Should -Be ($fnCreated.ToFileTimeUtc() - $siCreated.ToFileTimeUtc())
    }

    It 'does not flag SI modified later than FN modified' {
        $siModified = [datetime]::SpecifyKind([datetime]'2025-01-03T03:04:05', [DateTimeKind]::Utc)
        $fnModified = [datetime]::SpecifyKind([datetime]'2024-01-03T03:04:05', [DateTimeKind]::Utc)
        $record = New-MftFileRecord -SiModified $siModified -FnModified $fnModified
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.TimestompSuspect | Should -BeFalse
        $parsed.Record.SuspicionReason | Should -Be 'SI_MODIFIED_GT_FN_MODIFIED'
        $parsed.Record.FileNameFindings.Count | Should -Be 0
        $public = ConvertTo-PublicMftFixtureRecord -NativeRecord $parsed.Record
        $public.TimestompSuspect | Should -BeFalse
        $public.ModifiedDeltaTicks | Should -Be ($fnModified.ToFileTimeUtc() - $siModified.ToFileTimeUtc())
    }

    It 'evaluates every FN and emits a candidate for a suspicious alternate hard link' {
        $record = New-MftFileRecord
        $record = Add-MftAlternateFileName -Record $record
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.FileNames.Count | Should -Be 2
        $parsed.Record.FileName | Should -Be 'timestomp.exe'
        $parsed.Record.FnAttributeId | Should -Be 2
        $parsed.Record.ParentFileReferenceNumber | Should -Be 0x0005000000000005
        $parsed.Record.TimestompSuspect | Should -BeTrue
        $parsed.Record.SuspicionReason | Should -BeNullOrEmpty
        $parsed.Record.FileNameFindings.Count | Should -Be 1
        $parsed.Record.FileNameFindings[0].Name | Should -Be 'hardlink.exe'
        $parsed.Record.FileNameFindings[0].AttributeId | Should -Be 7
        $parsed.Record.FileNameFindings[0].ParentFileReferenceNumber | Should -Be 0x0006000000000006
        $parsed.Record.FileNameFindings[0].SuspicionReason | Should -Be 'SI_CREATED_LT_FN_CREATED'

        $public = ConvertTo-PublicMftFixtureRecord -NativeRecord $parsed.Record
        $public.FileName | Should -Be 'timestomp.exe'
        $public.FileNameFindings.Count | Should -Be 1
        $public.FileNameFindings[0].FileName | Should -Be 'hardlink.exe'
        $public.FileNameFindings[0].FnAttributeId | Should -Be 7
        $public.FileNameFindings[0].ParentFileReferenceNumber | Should -Be '0x0006000000000006'
        $public.FileNames[0].TimestompSuspect | Should -BeFalse
        $public.FileNames[1].TimestompSuspect | Should -BeTrue
    }

    It 'compares raw extreme FILETIME values even when UTC display is invalid' {
        $record = New-MftFileRecord
        Set-MftFixtureInt64 -Buffer $record -Offset 0x50 -Value -1
        Set-MftFixtureInt64 -Buffer $record -Offset 0xB8 -Value 0
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.SiCreatedFileTime | Should -Be -1
        $parsed.Record.FnCreatedFileTime | Should -Be 0
        $parsed.Record.SiCreatedValid | Should -BeFalse
        $parsed.Record.FnCreatedValid | Should -BeTrue
        $parsed.Record.SiCreated | Should -BeNullOrEmpty
        $parsed.Record.TimestompSuspect | Should -BeTrue
        $parsed.Record.SuspicionReason | Should -Be 'SI_CREATED_LT_FN_CREATED'
        $public = ConvertTo-PublicMftFixtureRecord -NativeRecord $parsed.Record
        $public.SiCreated | Should -BeNullOrEmpty
        $public.CreatedDeltaTicks | Should -BeNullOrEmpty
        $public.TimestompSuspect | Should -BeTrue
        $public.FileNameFindings.Count | Should -Be 1
    }

    It 'preserves a free-record flag in the pure parser without treating it as deleted evidence' {
        $record = New-MftFileRecord -FreeRecord
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.InUse | Should -BeFalse
        $parsed.Record.PSObject.Properties.Name | Should -Not -Contain 'Deleted'
    }

    It 'skips a non-resident DATA attribute and still parses SI/FN' {
        $record = New-MftFileRecord -IncludeNonResidentData
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.FileName | Should -Be 'timestomp.exe'
        $parsed.Record.HasStandardInformation | Should -BeTrue
        $parsed.Record.HasFileName | Should -BeTrue
    }

    It 'marks attribute-list coverage in record notes' {
        $record = New-MftFileRecord -IncludeAttributeList
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeTrue
        $parsed.Record.HasAttributeList | Should -BeTrue
        @($parsed.Record.Notes | Where-Object { $_ -match 'extension attributes were not resolved' }).Count | Should -Be 1
    }
}

Describe 'MFT raw fixup handling' {
    It 'verifies and restores both sector tails only when applyFixups is true' {
        $raw = New-MftFileRecord -RawFixup
        $parsed = Invoke-MftParse -Record $raw -ApplyFixups $true

        $parsed.Success | Should -BeTrue
        $parsed.RecordBytes[0x1FE] | Should -Be 0x11
        $parsed.RecordBytes[0x1FF] | Should -Be 0x11
        $parsed.RecordBytes[0x3FE] | Should -Be 0x22
        $parsed.RecordBytes[0x3FF] | Should -Be 0x22
        $raw[0x1FE] | Should -Be 0xBB
        $raw[0x1FF] | Should -Be 0xAA
        $raw[0x3FE] | Should -Be 0xBB
        $raw[0x3FF] | Should -Be 0xAA
    }

    It 'does not verify or modify sector tails when applyFixups is false' {
        $raw = New-MftFileRecord -RawFixup
        $parsed = Invoke-MftParse -Record $raw -ApplyFixups $false

        $parsed.Success | Should -BeTrue
        $parsed.RecordBytes[0x1FE] | Should -Be 0xBB
        $parsed.RecordBytes[0x1FF] | Should -Be 0xAA
        $parsed.RecordBytes[0x3FE] | Should -Be 0xBB
        $parsed.RecordBytes[0x3FF] | Should -Be 0xAA
        $raw[0x1FE] | Should -Be 0xBB
        $raw[0x3FE] | Should -Be 0xBB
    }

    It 'rejects a fixup mismatch without returning a partially repaired record' {
        $raw = New-MftFileRecord -RawFixup
        Set-MftFixtureUInt16 -Buffer $raw -Offset 0x3FE -Value 0xCCCC
        $parsed = Invoke-MftParse -Record $raw -ApplyFixups $true

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'Update sequence mismatch at sector 2'
        $parsed.Record | Should -BeNullOrEmpty
        $parsed.RecordBytes | Should -BeNullOrEmpty
        $raw[0x1FE] | Should -Be 0xBB
    }
}

Describe 'MFT malformed record bounds checks' {
    It 'rejects a bad FILE signature' {
        $record = New-MftFileRecord
        $record[0] = 0
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'signature is not FILE'
    }

    It 'rejects a truncated attribute header' {
        $record = New-MftFileRecord
        Set-MftFixtureUInt32 -Buffer $record -Offset 24 -Value 0x40
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'Truncated attribute header'
    }

    It 'rejects an attribute length beyond the record' {
        $record = New-MftFileRecord
        Set-MftFixtureUInt32 -Buffer $record -Offset 0x3C -Value 0x600
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'extends beyond the record'
    }

    It 'rejects an FN name extending beyond its resident value' {
        $record = New-MftFileRecord
        $record[0x98 + 24 + 64] = 100
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'Unicode name extends beyond'
    }

    It 'rejects used size greater than allocated size' {
        $record = New-MftFileRecord
        Set-MftFixtureUInt32 -Buffer $record -Offset 24 -Value 2048
        $parsed = Invoke-MftParse -Record $record

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'used size exceeds its allocated size'
    }

    It 'does not throw for deterministic mutations of a valid record' {
        $random = [Random]::new(42)
        for ($case = 0; $case -lt 30; $case++) {
            $record = New-MftFileRecord
            for ($change = 0; $change -lt 6; $change++) {
                $record[$random.Next($record.Length)] = [byte]$random.Next(256)
            }
            { Invoke-MftParse -Record $record -ApplyFixups ($case % 2 -eq 0) } | Should -Not -Throw
        }
    }
}

Describe 'MFT FSCTL output-buffer seam' {
    It 'accepts a lower returned ordinal and strips the 12-byte prefix' {
        $record = New-MftFileRecord -RecordNumber 42
        $output = New-MftOutputBuffer -Record $record -Actual 42
        $parsed = Invoke-MftOutputParse -Output $output -Requested 50

        $parsed.PrefixValid | Should -BeTrue
        $parsed.Success | Should -BeTrue
        $parsed.ActualFileReferenceNumber | Should -Be 42
        $parsed.ParseResult.Record.FileReferenceNumber | Should -Be 42
        $parsed.ParseResult.Record.FileName | Should -Be 'timestomp.exe'
    }

    It 'rejects a returned ordinal greater than requested' {
        $record = New-MftFileRecord -RecordNumber 51
        $output = New-MftOutputBuffer -Record $record -Actual 51
        $parsed = Invoke-MftOutputParse -Output $output -Requested 50

        $parsed.PrefixValid | Should -BeFalse
        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'exceeds the requested ordinal'
    }

    It 'rejects a FileRecordLength different from the volume record size' {
        $record = New-MftFileRecord -RecordNumber 42
        $output = New-MftOutputBuffer -Record $record -Actual 42 -ReportedRecordLength 512
        $parsed = Invoke-MftOutputParse -Output $output -Requested 50

        $parsed.PrefixValid | Should -BeFalse
        $parsed.Error | Should -Match 'does not equal the volume record size'
    }

    It 'accepts an exact NTFS 3.1 header entry-number match including zero' {
        $record = New-MftFileRecord -RecordNumber 0
        $output = New-MftOutputBuffer -Record $record -Actual 0
        $parsed = Invoke-MftOutputParse -Output $output -Requested 0

        $parsed.Success | Should -BeTrue
        $parsed.ParseResult.Record.HeaderRecordNumberPresent | Should -BeTrue
        $parsed.ParseResult.Record.HeaderRecordNumber | Should -Be 0
        $parsed.ParseResult.Record.FileReferenceNumber | Should -Be 0
    }

    It 'rejects a nonzero ordinal when the NTFS 3.1 header entry number is zero' {
        $record = New-MftFileRecord -RecordNumber 0
        $output = New-MftOutputBuffer -Record $record -Actual 42
        $parsed = Invoke-MftOutputParse -Output $output -Requested 50

        $parsed.PrefixValid | Should -BeTrue
        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'entry number 0 does not match.*42'
    }

    It 'rejects an ordinal above the NTFS 3.1 header range before casting' {
        $actual = [long]([uint32]::MaxValue) + 1
        $record = New-MftFileRecord -RecordNumber 0
        $output = New-MftOutputBuffer -Record $record -Actual $actual
        $parsed = Invoke-MftOutputParse -Output $output -Requested $actual

        $parsed.PrefixValid | Should -BeTrue
        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'exceeds the NTFS 3.1 header entry-number range'
    }

    It 'uses the ordinal fallback only for an NTFS 3.0 header' {
        $record = New-MftFileRecord -RecordNumber 42
        Set-MftFixtureUInt16 -Buffer $record -Offset 4 -Value 0x2A
        $output = New-MftOutputBuffer -Record $record -Actual 42
        $parsed = Invoke-MftOutputParse -Output $output -Requested 50

        $parsed.Success | Should -BeTrue
        $parsed.ParseResult.Record.HeaderRecordNumberPresent | Should -BeFalse
        $parsed.ParseResult.Record.FileReferenceNumber | Should -Be 42
        @($parsed.ParseResult.Record.Notes | Where-Object { $_ -match 'NTFS 3.0.*fallback' }).Count | Should -Be 1
    }
}

Describe 'MFT scripted downward enumeration' {
    It 'follows decreasing actuals, stops at zero, and labels gaps as non-deletion evidence' {
        $outputs = @{
            5 = New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 5) -Actual 5
            3 = New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 3) -Actual 3
            0 = New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 0) -Actual 0
        }
        $requests = [System.Collections.Generic.List[long]]::new()
        $reader = {
            param($context)
            $requests.Add($context.RequestedFileReferenceNumber)
            $actual = switch ($context.RequestedFileReferenceNumber) {
                5 { 5 }
                4 { 3 }
                2 { 0 }
                default { throw "Unexpected request $($context.RequestedFileReferenceNumber)" }
            }
            $buffer = $outputs[$actual]
            [Array]::Copy($buffer, 0, $context.OutputBuffer, 0, $buffer.Length)
            [MftNative+MftRecordReadResult]@{ Success = $true; BytesReturned = [uint32]$buffer.Length; Win32Error = 0 }
        }
        $clock = { [long]0 }
        $scan = Invoke-MftEnumerate -Reader $reader -Clock $clock

        $scan.Success | Should -BeTrue
        $scan.StopReason | Should -Be 'Complete'
        $scan.Incomplete | Should -BeFalse
        $scan.RecordsScanned | Should -Be 3
        $scan.Records.Count | Should -Be 3
        @($scan.Records | ForEach-Object { $_.FileReferenceNumber }) -join ',' | Should -Be '5,3,0'
        ($requests -join ',') | Should -Be '5,4,2'
        $scan.SkippedOrdinalCount | Should -Be 3
        @($scan.Notes | Where-Object { $_ -match 'not deleted-file evidence' }).Count | Should -BeGreaterThan 0
    }

    It 'adds an explicit note for a large ordinal gap' {
        $record = New-MftFileRecord -RecordNumber 0
        $output = New-MftOutputBuffer -Record $record -Actual 0
        $reader = {
            param($context)
            [Array]::Copy($output, 0, $context.OutputBuffer, 0, $output.Length)
            [MftNative+MftRecordReadResult]@{ Success = $true; BytesReturned = [uint32]$output.Length; Win32Error = 0 }
        }
        $scan = Invoke-MftEnumerate -Reader $reader -Clock { [long]0 } -EstimatedCount 2000

        $scan.Success | Should -BeTrue
        $scan.SkippedOrdinalCount | Should -Be 1999
        @($scan.Notes | Where-Object { $_ -match 'Skipped 1999 ordinals' }).Count | Should -Be 1
    }

    It 'truncates honestly at MaxRecords without issuing another native call' {
        $outputs = @(
            (New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 2) -Actual 2),
            (New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 1) -Actual 1),
            (New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 0) -Actual 0)
        )
        $readCount = [ref]0
        $reader = {
            param($context)
            $buffer = $outputs[$readCount.Value]
            $readCount.Value++
            [Array]::Copy($buffer, 0, $context.OutputBuffer, 0, $buffer.Length)
            [MftNative+MftRecordReadResult]@{ Success = $true; BytesReturned = [uint32]$buffer.Length; Win32Error = 0 }
        }
        $scan = Invoke-MftEnumerate -Reader $reader -Clock { [long]0 } -EstimatedCount 3 -MaxRecords 2

        $scan.Success | Should -BeTrue
        $scan.Truncated | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'MaxRecords'
        $scan.RecordsScanned | Should -Be 2
        $scan.Records.Count | Should -Be 2
        $readCount.Value | Should -Be 2
        @($scan.Notes | Where-Object { $_ -match 'MaxRecords cap of 2' }).Count | Should -Be 1
    }

    It 'uses the injectable clock to stop at the time budget with partial evidence' {
        $output = New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 2) -Actual 2
        $elapsed = [ref][long]0
        $readCount = [ref]0
        $reader = {
            param($context)
            $readCount.Value++
            [Array]::Copy($output, 0, $context.OutputBuffer, 0, $output.Length)
            $elapsed.Value = 300000
            [MftNative+MftRecordReadResult]@{ Success = $true; BytesReturned = [uint32]$output.Length; Win32Error = 0 }
        }
        $clock = { [long]$elapsed.Value }
        $scan = Invoke-MftEnumerate -Reader $reader -Clock $clock -EstimatedCount 3 -MaxSeconds 300

        $scan.Success | Should -BeTrue
        $scan.Truncated | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'MaxSeconds'
        $scan.RecordsScanned | Should -Be 1
        $scan.Records.Count | Should -Be 1
        $readCount.Value | Should -Be 1
        @($scan.Notes | Where-Object { $_ -match '300-second time budget' }).Count | Should -Be 1
    }

    It 'preserves earlier records after a native error' {
        $output = New-MftOutputBuffer -Record (New-MftFileRecord -RecordNumber 1) -Actual 1
        $readCount = [ref]0
        $reader = {
            param($context)
            if ($readCount.Value -eq 0) {
                $readCount.Value++
                [Array]::Copy($output, 0, $context.OutputBuffer, 0, $output.Length)
                return [MftNative+MftRecordReadResult]@{ Success = $true; BytesReturned = [uint32]$output.Length; Win32Error = 0 }
            }
            [MftNative+MftRecordReadResult]@{ Success = $false; BytesReturned = [uint32]0; Win32Error = 5 }
        }
        $scan = Invoke-MftEnumerate -Reader $reader -Clock { [long]0 } -EstimatedCount 2

        $scan.Success | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'NativeError'
        $scan.Error | Should -Match 'access denied'
        $scan.RecordsScanned | Should -Be 1
        $scan.Records.Count | Should -Be 1
        @($scan.Notes | Where-Object { $_ -match 'partial evidence' }).Count | Should -Be 1
    }
}

Describe 'Get-FileSystemJournal MftTimestompScan integration' {
    It 'returns suspects by default and exposes native summary fields' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Test-JournalElevation { $true }
            $clean = [PSCustomObject]@{ FileName = 'clean.exe'; TimestompSuspect = $false }
            $suspect = [PSCustomObject]@{ FileName = 'timestomp.exe'; TimestompSuspect = $true }
            Mock Get-MftNative {
                [PSCustomObject]@{
                    Records = @($clean, $suspect)
                    Success = $true
                    Error = $null
                    Notes = @('synthetic native note')
                    RecordsScanned = [long]2
                    SuspectCount = 1
                    MalformedRecords = 0
                    AttributeListRecords = 0
                    MissingStandardInformation = 0
                    MissingFileName = 0
                    ExtensionRecordsSkipped = 0
                    NotInUseRecordsSkipped = 0
                    SkippedOrdinalCount = [long]0
                    EstimatedMftRecords = [long]2
                    BytesPerSector = 512
                    BytesPerFileRecord = 1024
                    ElapsedMilliseconds = [long]25
                    Truncated = $false
                    Incomplete = $false
                    StopReason = 'Complete'
                }
            }
            $originalOs = $env:OS
            try {
                $env:OS = 'Windows_NT'
                $result = Get-FileSystemJournal -Mode MftTimestompScan -MaxRecords 50000 -MaxSeconds 12 -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Records.Count | Should -Be 1
            $result.Records[0].FileName | Should -Be 'timestomp.exe'
            $result.Summary.Source | Should -Be 'NativeMft'
            $result.Summary.RecordsScanned | Should -Be 2
            $result.Summary.SuspectCount | Should -Be 1
            $result.Summary.Truncated | Should -BeFalse
            $result.Summary.Incomplete | Should -BeFalse
            $result.Summary.StopReason | Should -Be 'Complete'
            $result.Summary.MaxSeconds | Should -Be 12
            $result.Summary.Success | Should -BeTrue
            $expectedKeys = @(
                'RecordsScanned', 'NativeRecordsReturned', 'ReturnedRecords', 'SuspectCount',
                'MalformedRecords', 'AttributeListRecords', 'MissingStandardInformation', 'MissingFileName',
                'ExtensionRecordsSkipped', 'NotInUseRecordsSkipped', 'SkippedOrdinalCount', 'EstimatedMftRecords',
                'BytesPerSector', 'BytesPerFileRecord', 'ElapsedMilliseconds', 'MaxRecords', 'MaxSeconds',
                'IncludeAll', 'Success', 'Truncated', 'Incomplete', 'StopReason', 'Source'
            )
            @($expectedKeys | Where-Object { $_ -notin @($result.Summary.Keys) }).Count | Should -Be 0
            $result.Notes | Should -Contain 'synthetic native note'
            Should -Invoke Get-MftNative -Times 1 -Exactly -ParameterFilter {
                $MaxRecords -eq 50000 -and $MaxSeconds -eq 12 -and -not $IncludeAll
            }
        }
    }

    It 'returns every mocked native record with IncludeAll' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Test-JournalElevation { $true }
            Mock Get-MftNative {
                [PSCustomObject]@{
                    Records = @(
                        [PSCustomObject]@{ FileName = 'clean.exe'; TimestompSuspect = $false },
                        [PSCustomObject]@{ FileName = 'suspect.exe'; TimestompSuspect = $true }
                    )
                    Success = $true; Error = $null; Notes = @(); RecordsScanned = [long]2; SuspectCount = 1
                    MalformedRecords = 0; AttributeListRecords = 0; MissingStandardInformation = 0; MissingFileName = 0
                    ExtensionRecordsSkipped = 0; NotInUseRecordsSkipped = 0; SkippedOrdinalCount = [long]0
                    EstimatedMftRecords = [long]2; BytesPerSector = 512; BytesPerFileRecord = 1024; ElapsedMilliseconds = [long]1
                    Truncated = $false; Incomplete = $false; StopReason = 'Complete'
                }
            }
            $originalOs = $env:OS
            try {
                $env:OS = 'Windows_NT'
                $result = Get-FileSystemJournal -Mode MftTimestompScan -IncludeAll -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Records.Count | Should -Be 2
            $result.Summary.ReturnedRecords | Should -Be 2
            $result.Summary.IncludeAll | Should -BeTrue
            Should -Invoke Get-MftNative -Times 1 -Exactly -ParameterFilter { $IncludeAll }
        }
    }

    It 'returns an honest non-Windows note without invoking the native collector' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-MftNative { throw 'native collector must not run on non-Windows' }
            $originalOs = $env:OS
            try {
                $env:OS = 'Unix'
                $result = Get-FileSystemJournal -Mode MftTimestompScan -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Records.Count | Should -Be 0
            $result.Summary.Source | Should -Be 'Unavailable'
            $result.Summary.StopReason | Should -Be 'UnsupportedPlatform'
            @($result.Notes | Where-Object { $_ -match 'FSCTL_GET_NTFS_FILE_RECORD is only available on Windows' }).Count | Should -Be 1
            Should -Invoke Get-MftNative -Times 0 -Exactly
        }
    }

    It 'returns an elevation note without invoking the native collector' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Test-JournalElevation { $false }
            Mock Get-MftNative { throw 'native collector must not run without elevation' }
            $originalOs = $env:OS
            try {
                $env:OS = 'Windows_NT'
                $result = Get-FileSystemJournal -Mode MftTimestompScan -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Records.Count | Should -Be 0
            $result.Summary.Source | Should -Be 'Unavailable'
            $result.Summary.StopReason | Should -Be 'ElevationRequired'
            @($result.Notes | Where-Object { $_ -match 'administrator elevation is required' }).Count | Should -Be 1
            Should -Invoke Get-MftNative -Times 0 -Exactly
        }
    }

    It 'returns the complete zeroed summary schema on every degraded MFT path' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Test-JournalElevation { $false }
            Mock Get-MftNative { throw 'synthetic native invocation failure' }
            $originalOs = $env:OS
            $results = @()
            try {
                $env:OS = 'Windows_NT'
                $results += Get-FileSystemJournal -Mode MftTimestompScan -DriveLetter '!!' -WarningAction SilentlyContinue
                $env:OS = 'Unix'
                $results += Get-FileSystemJournal -Mode MftTimestompScan -WarningAction SilentlyContinue
                $env:OS = 'Windows_NT'
                $results += Get-FileSystemJournal -Mode MftTimestompScan -WarningAction SilentlyContinue
                Mock Test-JournalElevation { $true }
                $results += Get-FileSystemJournal -Mode MftTimestompScan -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $expectedKeys = @(
                'RecordsScanned', 'NativeRecordsReturned', 'ReturnedRecords', 'SuspectCount',
                'MalformedRecords', 'AttributeListRecords', 'MissingStandardInformation', 'MissingFileName',
                'ExtensionRecordsSkipped', 'NotInUseRecordsSkipped', 'SkippedOrdinalCount', 'EstimatedMftRecords',
                'BytesPerSector', 'BytesPerFileRecord', 'ElapsedMilliseconds', 'MaxRecords', 'MaxSeconds',
                'IncludeAll', 'Success', 'Truncated', 'Incomplete', 'StopReason', 'Source'
            )
            $expectedReasons = @('InvalidDriveLetter', 'UnsupportedPlatform', 'ElevationRequired', 'InvocationFailed')
            $results.Count | Should -Be 4
            for ($index = 0; $index -lt $results.Count; $index++) {
                $summary = $results[$index].Summary
                $reason = $expectedReasons[$index]
                @($expectedKeys | Where-Object { $_ -notin @($summary.Keys) }).Count | Should -Be 0 -Because "$reason must preserve the complete schema"
                $summary.RecordsScanned | Should -Be 0
                $summary.SuspectCount | Should -Be 0
                $summary.Success | Should -BeFalse
                $summary.Truncated | Should -BeFalse
                $summary.Incomplete | Should -BeFalse
                $summary.StopReason | Should -Be $reason
                $summary.Source | Should -Be 'Unavailable'
            }
            Should -Invoke Get-MftNative -Times 1 -Exactly
        }
    }
}
