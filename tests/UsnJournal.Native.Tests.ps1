#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Cross-platform fixtures for binary USN journal parsing.
.DESCRIPTION
    Every journal buffer is synthetic. ParseBuffer and ReadJournalChunks perform
    no direct operating system calls, so these tests exercise V2/V3 decoding,
    bounds checks, and read-loop policy on macOS, Linux, and Windows. Native
    DeviceIoControl integration remains a Windows-only verification item.
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
        Initialize-UsnJournalNativeType
    }
    if (-not $typeReady) {
        throw 'UsnJournalNative could not be compiled; fixture tests cannot run.'
    }

    function Set-UsnFixtureUInt16 {
        param([byte[]]$Buffer, [int]$Offset, [uint16]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 2)
    }

    function Set-UsnFixtureUInt32 {
        param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 4)
    }

    function Set-UsnFixtureUInt64 {
        param([byte[]]$Buffer, [int]$Offset, [uint64]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 8)
    }

    function Set-UsnFixtureInt64 {
        param([byte[]]$Buffer, [int]$Offset, [long]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 8)
    }

    function New-ExactUsnFixtureBuffer {
        [byte[]]$buffer = @(
            0x50, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, 0xc0, 0x48, 0x58, 0x28, 0x3d, 0xda, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x3c, 0x00, 0x65, 0x00, 0x76, 0x00,
            0x69, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x65, 0x00,
            0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        return ,$buffer
    }

    function New-UsnV2FixtureRecord {
        param(
            [string]$FileName = 'a.txt',
            [long]$Usn = 0x1000,
            [long]$FileTime = 133486382450000000,
            [uint32]$ReasonMask = 0x100,
            [uint64]$FileReference = 0x0005000000001234,
            [uint64]$ParentReference = 0x0005000000000005,
            [int]$FileNameOffset = 60
        )

        if ($FileNameOffset -lt 60) {
            throw 'A valid V2 fixture FileNameOffset must be at least 60.'
        }

        [byte[]]$nameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $unalignedLength = $FileNameOffset + $nameBytes.Length
        $recordLength = ($unalignedLength + 7) -band (-bnot 7)
        [byte[]]$record = @(0) * $recordLength

        Set-UsnFixtureUInt32 -Buffer $record -Offset 0 -Value ([uint32]$recordLength)
        Set-UsnFixtureUInt16 -Buffer $record -Offset 4 -Value 2
        Set-UsnFixtureUInt16 -Buffer $record -Offset 6 -Value 0
        Set-UsnFixtureUInt64 -Buffer $record -Offset 8 -Value $FileReference
        Set-UsnFixtureUInt64 -Buffer $record -Offset 16 -Value $ParentReference
        Set-UsnFixtureInt64 -Buffer $record -Offset 24 -Value $Usn
        Set-UsnFixtureInt64 -Buffer $record -Offset 32 -Value $FileTime
        Set-UsnFixtureUInt32 -Buffer $record -Offset 40 -Value $ReasonMask
        Set-UsnFixtureUInt32 -Buffer $record -Offset 52 -Value 0x20
        Set-UsnFixtureUInt16 -Buffer $record -Offset 56 -Value ([uint16]$nameBytes.Length)
        Set-UsnFixtureUInt16 -Buffer $record -Offset 58 -Value ([uint16]$FileNameOffset)
        [Array]::Copy($nameBytes, 0, $record, $FileNameOffset, $nameBytes.Length)

        return ,$record
    }

    function New-UsnV3FixtureRecord {
        param(
            [string]$FileName = 'refs.txt',
            [long]$Usn = 0x2000,
            [long]$FileTime = 133486382450000000,
            [uint32]$ReasonMask = 0x8000,
            [byte[]]$FileReference = [byte[]](0..15),
            [byte[]]$ParentReference = [byte[]](16..31),
            [int]$FileNameOffset = 76
        )

        if ($FileReference.Length -ne 16 -or $ParentReference.Length -ne 16) {
            throw 'V3 fixture identifiers must each contain exactly 16 bytes.'
        }
        if ($FileNameOffset -lt 76) {
            throw 'A valid V3 fixture FileNameOffset must be at least 76.'
        }

        [byte[]]$nameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $unalignedLength = $FileNameOffset + $nameBytes.Length
        $recordLength = ($unalignedLength + 7) -band (-bnot 7)
        [byte[]]$record = @(0) * $recordLength

        Set-UsnFixtureUInt32 -Buffer $record -Offset 0 -Value ([uint32]$recordLength)
        Set-UsnFixtureUInt16 -Buffer $record -Offset 4 -Value 3
        Set-UsnFixtureUInt16 -Buffer $record -Offset 6 -Value 0
        [Array]::Copy($FileReference, 0, $record, 8, 16)
        [Array]::Copy($ParentReference, 0, $record, 24, 16)
        Set-UsnFixtureInt64 -Buffer $record -Offset 40 -Value $Usn
        Set-UsnFixtureInt64 -Buffer $record -Offset 48 -Value $FileTime
        Set-UsnFixtureUInt32 -Buffer $record -Offset 56 -Value $ReasonMask
        Set-UsnFixtureUInt32 -Buffer $record -Offset 68 -Value 0x20
        Set-UsnFixtureUInt16 -Buffer $record -Offset 72 -Value ([uint16]$nameBytes.Length)
        Set-UsnFixtureUInt16 -Buffer $record -Offset 74 -Value ([uint16]$FileNameOffset)
        [Array]::Copy($nameBytes, 0, $record, $FileNameOffset, $nameBytes.Length)

        return ,$record
    }

    function New-UsnUnknownVersionFixtureRecord {
        param([uint16]$MajorVersion = 4)
        [byte[]]$record = @(0) * 16
        Set-UsnFixtureUInt32 -Buffer $record -Offset 0 -Value 16
        Set-UsnFixtureUInt16 -Buffer $record -Offset 4 -Value $MajorVersion
        Set-UsnFixtureUInt16 -Buffer $record -Offset 6 -Value 0
        return ,$record
    }

    function New-UsnFixtureBuffer {
        param(
            [Parameter()]
            [AllowEmptyCollection()]
            [object[]]$Records = @(),
            [long]$NextUsn = 0x3000
        )

        $bufferLength = 8
        foreach ($record in $Records) {
            $bufferLength += $record.Length
        }

        [byte[]]$buffer = @(0) * $bufferLength
        Set-UsnFixtureInt64 -Buffer $buffer -Offset 0 -Value $NextUsn
        $offset = 8
        foreach ($record in $Records) {
            [Array]::Copy($record, 0, $buffer, $offset, $record.Length)
            $offset += $record.Length
        }
        return ,$buffer
    }

    function Invoke-UsnParse {
        param(
            [byte[]]$Buffer,
            [int]$BytesReturned = -1,
            [int]$MaxRecords = 10000
        )

        if ($BytesReturned -lt 0) {
            $BytesReturned = $Buffer.Length
        }

        return InModuleScope -ModuleName $script:ModuleName `
            -ArgumentList $Buffer, $BytesReturned, $MaxRecords -ScriptBlock {
                param([byte[]]$buffer, [int]$bytesReturned, [int]$maxRecords)
                [UsnJournalNative]::ParseBuffer($buffer, $bytesReturned, $maxRecords)
            }
    }

    function Invoke-UsnReadChunks {
        param(
            [scriptblock]$ChunkReader,
            [long]$StartUsn = 0x1000,
            [long]$TargetNextUsn = 0x9000,
            [int]$MaxRecords = 10000,
            [bool]$UseVersion1 = $false,
            [uint16]$MinMajorVersion = 2,
            [uint16]$MaxMajorVersion = 3
        )

        $reader = [UsnJournalNative+UsnChunkReader]$ChunkReader
        return InModuleScope -ModuleName $script:ModuleName `
            -ArgumentList $StartUsn, $TargetNextUsn, $MaxRecords, $UseVersion1, $MinMajorVersion, $MaxMajorVersion, $reader -ScriptBlock {
                param($startUsn, $targetNextUsn, $maxRecords, $useVersion1, $minMajorVersion, $maxMajorVersion, $chunkReader)
                [UsnJournalNative]::ReadJournalChunks(
                    $startUsn,
                    $targetNextUsn,
                    $maxRecords,
                    $useVersion1,
                    $minMajorVersion,
                    $maxMajorVersion,
                    $chunkReader)
            }
    }

    function ConvertTo-PublicUsnFixtureRecord {
        param([object]$NativeRecord)
        return InModuleScope -ModuleName $script:ModuleName -ArgumentList $NativeRecord -ScriptBlock {
            param($record)
            ConvertTo-UsnJournalNativeRecord -NativeRecord $record
        }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'USN exact synthetic buffer and public mapping' {
    It 'parses the specified evil.exe fixture and preserves the public contract' {
        $buffer = New-ExactUsnFixtureBuffer
        $buffer.Length | Should -Be 88

        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeTrue
        $parsed.Error | Should -BeNullOrEmpty
        $parsed.NextUsn | Should -Be 0x1050
        $parsed.Records.Count | Should -Be 1
        $parsed.Records[0].FileName | Should -Be 'evil.exe'
        $parsed.Records[0].Usn | Should -Be 0x1000
        $parsed.Records[0].ReasonMask | Should -Be 0x100

        $record = ConvertTo-PublicUsnFixtureRecord -NativeRecord $parsed.Records[0]
        $record.FileName | Should -Be 'evil.exe'
        $record.FullPath | Should -BeNullOrEmpty
        $record.Reason | Should -Be '0x00000100: FILE_CREATE'
        $record.ReasonMask | Should -BeOfType [uint32]
        @($record.ReasonFlags).Count | Should -Be 1
        $record.ReasonFlags[0] | Should -Be 'FILE_CREATE'
        $record.TimeStamp.Kind | Should -Be ([DateTimeKind]::Utc)
        $record.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-02 03:04:05'
        $record.TimeStampText | Should -Be '2024-01-02T03:04:05.0000000Z'
        $record.Usn | Should -Be '0x1000'
        $record.Usn | Should -BeOfType [string]
        $record.FileReferenceNumber | Should -Be '0x5000000001234'
        $record.FileReferenceNumber | Should -BeOfType [string]
        $record.ParentFileReferenceNumber | Should -Be '0x5000000000005'
    }
}

Describe 'USN valid record fixtures' {
    It 'walks multiple records with nontrivial padding and honors FileNameOffset' {
        $first = New-UsnV2FixtureRecord -FileName 'a.bin' -Usn 0x1000 -FileNameOffset 64
        $second = New-UsnV2FixtureRecord -FileName 'second.txt' -Usn 0x1010 -FileNameOffset 68
        ($first.Length % 8) | Should -Be 0
        ($second.Length % 8) | Should -Be 0

        $buffer = New-UsnFixtureBuffer -Records @($first, $second) -NextUsn 0x4000
        $parsed = Invoke-UsnParse -Buffer $buffer

        $parsed.Success | Should -BeTrue
        $parsed.NextUsn | Should -Be 0x4000
        $parsed.Records.Count | Should -Be 2
        $parsed.Records[0].FileName | Should -Be 'a.bin'
        $parsed.Records[1].FileName | Should -Be 'second.txt'
        $parsed.Records[1].Usn | Should -Be 0x1010
    }

    It 'keeps all 16 bytes of V3 file and parent identifiers' {
        $v3 = New-UsnV3FixtureRecord -FileName 'refs.txt'
        $buffer = New-UsnFixtureBuffer -Records @($v3) -NextUsn 0x5000
        $parsed = Invoke-UsnParse -Buffer $buffer

        $parsed.Success | Should -BeTrue
        $parsed.Records.Count | Should -Be 1
        $parsed.Records[0].MajorVersion | Should -Be 3
        $parsed.Records[0].FileName | Should -Be 'refs.txt'
        $parsed.Records[0].Usn | Should -Be 0x2000
        $parsed.Records[0].ReasonMask | Should -Be 0x8000
        $parsed.Records[0].FileAttributes | Should -Be 0x20
        $parsed.Records[0].TimeStamp.Kind | Should -Be ([DateTimeKind]::Utc)
        $parsed.Records[0].TimeStamp.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2024-01-02 03:04:05'
        $parsed.Records[0].FileReferenceNumber128.Length | Should -Be 16
        $parsed.Records[0].ParentFileReferenceNumber128.Length | Should -Be 16
        ($parsed.Records[0].FileReferenceNumber128 -join ',') | Should -Be (([byte[]](0..15)) -join ',')
        ($parsed.Records[0].ParentFileReferenceNumber128 -join ',') | Should -Be (([byte[]](16..31)) -join ',')

        $record = ConvertTo-PublicUsnFixtureRecord -NativeRecord $parsed.Records[0]
        $record.Reason | Should -Be '0x00008000: BASIC_INFO_CHANGE'
        $record.ReasonFlags | Should -Contain 'BASIC_INFO_CHANGE'
        $record.Usn | Should -Be '0x2000'
        $record.TimeStampText | Should -Be '2024-01-02T03:04:05.0000000Z'
        $record.FileReferenceNumber | Should -Be '0x000102030405060708090a0b0c0d0e0f'
        $record.ParentFileReferenceNumber | Should -Be '0x101112131415161718191a1b1c1d1e1f'
        $record.FullPath | Should -BeNullOrEmpty
    }

    It 'decodes a non-ASCII UTF-16 name without a null terminator' {
        $name = ([char]0x00E9).ToString() + ([char]0x96EA).ToString()
        $v2 = New-UsnV2FixtureRecord -FileName $name
        $v2.Length | Should -Be 64
        $v2[$v2.Length - 2] | Should -Not -Be 0
        $v2[$v2.Length - 1] | Should -Not -Be 0

        $buffer = New-UsnFixtureBuffer -Records @($v2)
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeTrue
        $parsed.Records.Count | Should -Be 1
        $parsed.Records[0].FileName | Should -Be $name
        $parsed.Records[0].FileName.Length | Should -Be 2
    }

    It 'caps a multi-record buffer at MaxRecords 1' {
        $first = New-UsnV2FixtureRecord -FileName 'first.txt' -Usn 0x1000
        $second = New-UsnV2FixtureRecord -FileName 'second.txt' -Usn 0x1010
        $buffer = New-UsnFixtureBuffer -Records @($first, $second) -NextUsn 0x6000
        $parsed = Invoke-UsnParse -Buffer $buffer -MaxRecords 1

        $parsed.Success | Should -BeTrue
        $parsed.Records.Count | Should -Be 1
        $parsed.Records[0].FileName | Should -Be 'first.txt'
        $parsed.NextUsn | Should -Be 0x6000
    }

    It 'skips an unknown major version with a diagnostic and continues by RecordLength' {
        $unknown = New-UsnUnknownVersionFixtureRecord -MajorVersion 4
        $valid = New-UsnV2FixtureRecord -FileName 'after-v4.txt'
        $buffer = New-UsnFixtureBuffer -Records @($unknown, $valid)
        $parsed = Invoke-UsnParse -Buffer $buffer

        $parsed.Success | Should -BeTrue
        $parsed.Records.Count | Should -Be 1
        $parsed.Records[0].FileName | Should -Be 'after-v4.txt'
        $parsed.Diagnostics.Count | Should -Be 1
        $parsed.Diagnostics[0] | Should -Match 'major version 4'
    }

    It 'sets an invalid FILETIME to null without losing the buffer' {
        $invalid = New-UsnV2FixtureRecord -FileName 'invalid-time.txt' -FileTime -1
        $valid = New-UsnV2FixtureRecord -FileName 'valid-time.txt' -Usn 0x1010
        $buffer = New-UsnFixtureBuffer -Records @($invalid, $valid)
        $parsed = Invoke-UsnParse -Buffer $buffer

        $parsed.Success | Should -BeTrue
        $parsed.Records.Count | Should -Be 2
        $parsed.Records[0].TimeStamp | Should -BeNullOrEmpty
        $parsed.Records[1].TimeStamp | Should -Not -BeNullOrEmpty
        @($parsed.Diagnostics | Where-Object { $_ -match 'Invalid FILETIME' }).Count | Should -Be 1

        $record = ConvertTo-PublicUsnFixtureRecord -NativeRecord $parsed.Records[0]
        $record.TimeStamp | Should -BeNullOrEmpty
        $record.TimeStampText | Should -BeNullOrEmpty
    }

    It 'accepts a USN-only buffer with an advancing continuation value' {
        $buffer = New-UsnFixtureBuffer -Records @() -NextUsn 0x7000
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeTrue
        $parsed.NextUsn | Should -Be 0x7000
        $parsed.Records.Count | Should -Be 0
    }

    It 'accepts a USN-only buffer with a non-advancing continuation value' {
        $buffer = New-UsnFixtureBuffer -Records @() -NextUsn 0x1000
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeTrue
        $parsed.NextUsn | Should -Be 0x1000
        $parsed.Records.Count | Should -Be 0
    }
}

Describe 'USN malformed buffer bounds checks' {
    It 'rejects a zero RecordLength' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt32 -Buffer $buffer -Offset 8 -Value 0
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'RecordLength 0'
    }

    It 'rejects a V2 RecordLength shorter than the fixed prefix' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt32 -Buffer $buffer -Offset 8 -Value 56
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'shorter than its 60-byte fixed prefix'
    }

    It 'rejects a RecordLength larger than the remaining buffer' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt32 -Buffer $buffer -Offset 8 -Value 88
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'only 80 bytes remain'
    }

    It 'rejects an unaligned RecordLength' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt32 -Buffer $buffer -Offset 8 -Value 76
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match '8-byte aligned'
    }

    It 'rejects a truncated continuation USN' {
        $buffer = New-ExactUsnFixtureBuffer
        $parsed = Invoke-UsnParse -Buffer $buffer -BytesReturned 4
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match '8-byte continuation USN'
    }

    It 'rejects a truncated common record header' {
        $buffer = New-ExactUsnFixtureBuffer
        $parsed = Invoke-UsnParse -Buffer $buffer -BytesReturned 12
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'Trailing partial USN record header'
    }

    It 'retains prior records but rejects a trailing partial record' {
        $exact = New-ExactUsnFixtureBuffer
        [byte[]]$buffer = @(0) * ($exact.Length + 4)
        [Array]::Copy($exact, 0, $buffer, 0, $exact.Length)
        $parsed = Invoke-UsnParse -Buffer $buffer

        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 1
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'only 4 bytes remain'
    }

    It 'rejects a filename extending beyond its record' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt16 -Buffer $buffer -Offset 64 -Value 32
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'extends beyond RecordLength'
    }

    It 'rejects an odd filename byte count' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt16 -Buffer $buffer -Offset 64 -Value 15
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'even byte count'
    }

    It 'rejects a filename offset inside the fixed prefix' {
        $buffer = New-ExactUsnFixtureBuffer
        Set-UsnFixtureUInt16 -Buffer $buffer -Offset 66 -Value 58
        $parsed = Invoke-UsnParse -Buffer $buffer
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'overlaps the 60-byte fixed prefix'
    }

    It 'rejects a returned byte count larger than the supplied buffer' {
        $buffer = New-ExactUsnFixtureBuffer
        $parsed = Invoke-UsnParse -Buffer $buffer -BytesReturned ($buffer.Length + 8)
        $parsed.Success | Should -BeFalse
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
        $parsed.Error | Should -Match 'exceeds the USN journal buffer length'
    }
}

Describe 'USN ParseBuffer edge inputs' {
    It 'returns no records and does not throw for a null buffer' {
        { Invoke-UsnParse -Buffer $null -BytesReturned 0 } | Should -Not -Throw
        $parsed = Invoke-UsnParse -Buffer $null -BytesReturned 0

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'buffer is null'
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
    }

    It 'returns no records and does not throw when MaxRecords is zero' {
        $buffer = New-ExactUsnFixtureBuffer
        { Invoke-UsnParse -Buffer $buffer -MaxRecords 0 } | Should -Not -Throw
        $parsed = Invoke-UsnParse -Buffer $buffer -MaxRecords 0

        $parsed.Success | Should -BeFalse
        $parsed.Error | Should -Match 'MaxRecords must be greater than zero'
        $parsed.Records.Count | Should -Be 0
        $parsed.Diagnostics.Count | Should -Be 0
    }
}

Describe 'USN scripted chunk read loop' {
    It 'stops at MaxRecords 3 after two advancing buffers without a third read' {
        $firstBuffer = New-UsnFixtureBuffer -Records @(
            (New-UsnV2FixtureRecord -FileName 'first.txt' -Usn 0x1000),
            (New-UsnV2FixtureRecord -FileName 'second.txt' -Usn 0x1010)
        ) -NextUsn 0x2000
        $secondBuffer = New-UsnFixtureBuffer -Records @(
            (New-UsnV2FixtureRecord -FileName 'third.txt' -Usn 0x2000),
            (New-UsnV2FixtureRecord -FileName 'fourth.txt' -Usn 0x2010)
        ) -NextUsn 0x3000
        $buffers = @($firstBuffer, $secondBuffer)
        $readCount = [ref]0
        $reader = {
            param($context)
            $buffer = $buffers[$readCount.Value]
            $readCount.Value++
            [Array]::Copy($buffer, 0, $context.OutputBuffer, 0, $buffer.Length)
            [UsnJournalNative+UsnChunkReadResult]@{
                Success = $true
                BytesReturned = [uint32]$buffer.Length
                Win32Error = 0
            }
        }

        $readResult = Invoke-UsnReadChunks -ChunkReader $reader -StartUsn 0x1000 -TargetNextUsn 0x5000 -MaxRecords 3

        $readResult.Success | Should -BeTrue
        $readResult.Error | Should -BeNullOrEmpty
        $readResult.Records.Count | Should -Be 3
        $readResult.Records[0].FileName | Should -Be 'first.txt'
        $readResult.Records[1].FileName | Should -Be 'second.txt'
        $readResult.Records[2].FileName | Should -Be 'third.txt'
        $readCount.Value | Should -Be 2
    }

    It 'stops successfully after one read with a non-advancing continuation' {
        $buffer = New-UsnFixtureBuffer -Records @() -NextUsn 0x1000
        $readCount = [ref]0
        $reader = {
            param($context)
            $readCount.Value++
            [Array]::Copy($buffer, 0, $context.OutputBuffer, 0, $buffer.Length)
            [UsnJournalNative+UsnChunkReadResult]@{
                Success = $true
                BytesReturned = [uint32]$buffer.Length
                Win32Error = 0
            }
        }

        $readResult = Invoke-UsnReadChunks -ChunkReader $reader -StartUsn 0x1000 -TargetNextUsn 0x5000

        $readResult.Success | Should -BeTrue
        $readResult.Error | Should -BeNullOrEmpty
        $readResult.Records.Count | Should -Be 0
        $readCount.Value | Should -Be 1
        $readResult.Notes.Count | Should -Be 1
        $readResult.Notes[0] | Should -Match 'infinite loop'
    }

    It 'reports a regressing continuation and retains prior records' {
        $record = New-UsnV2FixtureRecord -FileName 'retained.txt' -Usn 0x1000
        $buffer = New-UsnFixtureBuffer -Records @($record) -NextUsn 0x500
        $readCount = [ref]0
        $reader = {
            param($context)
            $readCount.Value++
            [Array]::Copy($buffer, 0, $context.OutputBuffer, 0, $buffer.Length)
            [UsnJournalNative+UsnChunkReadResult]@{
                Success = $true
                BytesReturned = [uint32]$buffer.Length
                Win32Error = 0
            }
        }

        $readResult = Invoke-UsnReadChunks -ChunkReader $reader -StartUsn 0x1000 -TargetNextUsn 0x5000

        $readResult.Success | Should -BeFalse
        $readResult.Error | Should -Match 'next USN 1280 is below start USN 4096'
        $readResult.Records.Count | Should -Be 1
        $readResult.Records[0].FileName | Should -Be 'retained.txt'
        $readCount.Value | Should -Be 1
    }

    It 'retries ERROR_MORE_DATA with a larger buffer' {
        $record = New-UsnV2FixtureRecord -FileName 'retry.txt' -Usn 0x1000
        $buffer = New-UsnFixtureBuffer -Records @($record) -NextUsn 0x2000
        $readCount = [ref]0
        $bufferSizes = [System.Collections.Generic.List[int]]::new()
        $reader = {
            param($context)
            $bufferSizes.Add($context.OutputBuffer.Length)
            if ($readCount.Value -eq 0) {
                $readCount.Value++
                return [UsnJournalNative+UsnChunkReadResult]@{
                    Success = $false
                    BytesReturned = [uint32]0
                    Win32Error = 234
                }
            }
            $readCount.Value++
            [Array]::Copy($buffer, 0, $context.OutputBuffer, 0, $buffer.Length)
            [UsnJournalNative+UsnChunkReadResult]@{
                Success = $true
                BytesReturned = [uint32]$buffer.Length
                Win32Error = 0
            }
        }

        $readResult = Invoke-UsnReadChunks -ChunkReader $reader -StartUsn 0x1000 -TargetNextUsn 0x5000 -MaxRecords 1

        $readResult.Success | Should -BeTrue
        $readResult.Error | Should -BeNullOrEmpty
        $readResult.Records.Count | Should -Be 1
        $readResult.Records[0].FileName | Should -Be 'retry.txt'
        $readCount.Value | Should -Be 2
        $bufferSizes.Count | Should -Be 2
        $bufferSizes[0] | Should -Be 65536
        $bufferSizes[1] | Should -Be 131072
    }
}

Describe 'USN collection policy and reason compatibility' {
    It 'adds TRANSACTED_CHANGE and INTEGRITY_CHANGE to the reason map' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $flags = @(Get-UsnReasonFlagNames -Mask ([uint32]0x00C00000))
            ($flags -join ',') | Should -Be 'TRANSACTED_CHANGE,INTEGRITY_CHANGE'
        }
    }

    It 'adds a null ParentFileReferenceNumber on the fsutil path' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $record = New-UsnJournalRecord -Fields @{ FileName = 'legacy.txt'; Reason = '0x00000100' }
            $record.PSObject.Properties.Name | Should -Contain 'ParentFileReferenceNumber'
            $record.ParentFileReferenceNumber | Should -BeNullOrEmpty
        }
    }

    It 'uses native records first without calling fsutil' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock ConvertTo-UsnJournalNativeRecord { [PSCustomObject]@{ FileName = 'native.txt' } }
            Mock Get-UsnJournalNative {
                [PSCustomObject]@{
                    Records = @([PSCustomObject]@{ FileName = 'raw.txt' })
                    Success = $true
                    Error = $null
                    Source = 'Native'
                    NextUsn = [long]0x1050
                    Notes = @()
                    Incomplete = $false
                }
            }
            Mock Get-FsutilOutput { throw 'fsutil must not be called on native success' }

            $collection = Get-UsnJournalCollection -DriveLetter C -Elevated
            $collection.Success | Should -BeTrue
            $collection.Source | Should -Be 'Native'
            $collection.Records[0].FileName | Should -Be 'native.txt'
            Should -Invoke Get-UsnJournalNative -Times 1 -Exactly
            Should -Invoke Get-FsutilOutput -Times 0 -Exactly
        }
    }

    It 'falls back to fsutil with the capability note after a zero-record native failure' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Get-UsnJournalNative {
                [PSCustomObject]@{
                    Records = @()
                    Success = $false
                    Error = 'synthetic native failure'
                    Source = 'Native'
                    NextUsn = [long]0
                    Notes = @()
                    Incomplete = $false
                }
            }
            Mock Get-FsutilOutput { $script:FsutilLastExitCode = 0; return @() }
            Mock ConvertFrom-UsnJournalOutput { return @() }

            $collection = Get-UsnJournalCollection -DriveLetter C -Elevated
            $collection.Success | Should -BeTrue
            $collection.Source | Should -Be 'Fsutil'
            $collection.Notes | Should -Contain 'native journal read unavailable; using fsutil (English-locale output required)'
            Should -Invoke Get-UsnJournalNative -Times 1 -Exactly
            Should -Invoke Get-FsutilOutput -Times 1 -Exactly
        }
    }

    It 'returns partial native evidence without appending fsutil records' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock ConvertTo-UsnJournalNativeRecord { [PSCustomObject]@{ FileName = 'partial.txt' } }
            Mock Get-UsnJournalNative {
                [PSCustomObject]@{
                    Records = @([PSCustomObject]@{ FileName = 'raw.txt' })
                    Success = $false
                    Error = 'synthetic read interruption'
                    Source = 'Native'
                    NextUsn = [long]0x2000
                    Notes = @('Native USN journal collection is incomplete: synthetic read interruption')
                    Incomplete = $true
                }
            }
            Mock Get-FsutilOutput { throw 'fsutil must not be called for partial native evidence' }

            $collection = Get-UsnJournalCollection -DriveLetter C -Elevated
            $collection.Success | Should -BeTrue
            $collection.Incomplete | Should -BeTrue
            $collection.Source | Should -Be 'Native'
            $collection.Records.Count | Should -Be 1
            $collection.Notes | Should -Contain 'Native USN journal collection is incomplete: synthetic read interruption'
            Should -Invoke Get-FsutilOutput -Times 0 -Exactly
        }
    }
}

Describe 'USN native reason formatting' {
    It 'matches the fsutil hex mask and pipe-delimited flag format' {
        $native = New-UsnV2FixtureRecord -FileName 'reasons.txt' -ReasonMask ([uint32]0x00C00100)
        $buffer = New-UsnFixtureBuffer -Records @($native)
        $parsed = Invoke-UsnParse -Buffer $buffer
        $record = ConvertTo-PublicUsnFixtureRecord -NativeRecord $parsed.Records[0]

        $record.Reason | Should -Be '0x00c00100: FILE_CREATE | TRANSACTED_CHANGE | INTEGRITY_CHANGE'
        $record.ReasonMask | Should -Be ([uint32]0x00C00100)
        ($record.ReasonFlags -join ',') | Should -Be 'FILE_CREATE,TRANSACTED_CHANGE,INTEGRITY_CHANGE'
    }
}

Describe 'USN timestomp UTC comparison' {
    It 'does not flag a same-instant native pair displayed at UTC <Offset> hours' -ForEach @(
        @{ Offset = -5 },
        @{ Offset = 3 }
    ) {
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $Offset -ScriptBlock {
            param($offset)
            $instantUtc = [datetime]::SpecifyKind([datetime]'2024-01-02T03:04:05', [DateTimeKind]::Utc)
            $file = [PSCustomObject]@{
                Name = 'same.txt'
                FullName = 'C:\cases\same.txt'
                LastWriteTime = [datetime]::SpecifyKind($instantUtc.AddHours($offset), [DateTimeKind]::Unspecified)
                LastWriteTimeUtc = $instantUtc
            }
            $journal = [PSCustomObject]@{
                FileName = 'same.txt'
                FullPath = $null
                TimeStamp = $instantUtc
            }

            $evaluation = Test-TimestompSignature -FileInfo $file -CreationRecords @($journal)

            @($evaluation.Indicators).Count | Should -Be 0
            $evaluation.JournalCreationTime.Kind | Should -Be ([DateTimeKind]::Utc)
        }
    }

    It 'treats an unspecified legacy journal timestamp as local wall clock' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $instantUtc = [datetime]::SpecifyKind([datetime]'2024-01-02T03:04:05', [DateTimeKind]::Utc)
            $localTime = $instantUtc.ToLocalTime()
            $legacyTime = [datetime]::SpecifyKind($localTime, [DateTimeKind]::Unspecified)
            $file = [PSCustomObject]@{
                Name = 'legacy.txt'
                FullName = 'C:\cases\legacy.txt'
                LastWriteTime = $localTime
                LastWriteTimeUtc = $instantUtc
            }
            $journal = [PSCustomObject]@{
                FileName = 'legacy.txt'
                FullPath = $null
                TimeStamp = $legacyTime
            }

            $evaluation = Test-TimestompSignature -FileInfo $file -CreationRecords @($journal)

            @($evaluation.Indicators).Count | Should -Be 0
            $evaluation.JournalCreationTime.Kind | Should -Be ([DateTimeKind]::Unspecified)
        }
    }

    It 'still flags a genuinely backdated file in UTC' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $journalTimeUtc = [datetime]::SpecifyKind([datetime]'2024-01-02T03:04:05', [DateTimeKind]::Utc)
            $fileTimeUtc = $journalTimeUtc.AddHours(-1)
            $file = [PSCustomObject]@{
                Name = 'backdated.txt'
                FullName = 'C:\cases\backdated.txt'
                LastWriteTime = [datetime]::SpecifyKind($fileTimeUtc.AddHours(3), [DateTimeKind]::Unspecified)
                LastWriteTimeUtc = $fileTimeUtc
            }
            $journal = [PSCustomObject]@{
                FileName = 'backdated.txt'
                FullPath = $null
                TimeStamp = $journalTimeUtc
            }

            $evaluation = Test-TimestompSignature -FileInfo $file -CreationRecords @($journal)

            @($evaluation.Indicators).Count | Should -Be 1
            $evaluation.Indicators | Should -Contain 'BACKDATED_SI_TIMESTAMP'
        }
    }
}

Describe 'Get-FileSystemJournal collection contracts' {
    It 'always exposes Summary.Source as Unavailable on non-Windows in <_> mode' -ForEach @(
        'USNJournal',
        'MFTSummary',
        'TimestompScan'
    ) {
        $mode = $_
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $mode -ScriptBlock {
            param($mode)
            $originalOs = $env:OS
            try {
                $env:OS = 'Unix'
                $result = Get-FileSystemJournal -Mode $mode -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Summary.ContainsKey('Source') | Should -BeTrue
            $result.Summary.Source | Should -Be 'Unavailable'
        }
    }

    It 'keeps Summary.Source Unavailable when journal collection fails' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            Mock Test-JournalElevation { $true }
            Mock Get-UsnJournalCollection {
                [PSCustomObject]@{
                    Records = @()
                    Success = $false
                    Error = 'synthetic access denied'
                    Source = 'Fsutil'
                    NextUsn = [long]0
                    FsutilExitCode = 5
                    AccessDenied = $true
                    NativeAttempted = $true
                    Incomplete = $false
                    Notes = @()
                }
            }
            $originalOs = $env:OS
            try {
                $env:OS = 'Windows_NT'
                $result = Get-FileSystemJournal -Mode USNJournal -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Summary.ContainsKey('Source') | Should -BeTrue
            $result.Summary.Source | Should -Be 'Unavailable'
            @($result.Notes | Where-Object { $_ -match 'USN journal read failed' }).Count | Should -Be 1
        }
    }

    It 'rejects invalid drive <_> before native and fsutil collectors' -ForEach @(
        '1',
        'CC',
        ':',
        '/',
        ([char]0x00E9)
    ) {
        $driveValue = $_
        InModuleScope -ModuleName $script:ModuleName -ArgumentList $driveValue -ScriptBlock {
            param($drive)
            Mock Get-UsnJournalNative { throw 'native collector must not run' }
            Mock Get-FsutilOutput { throw 'fsutil collector must not run' }

            $collection = Get-UsnJournalCollection -DriveLetter $drive -Elevated -WarningAction SilentlyContinue

            $collection.Success | Should -BeFalse
            $collection.Source | Should -Be 'Unavailable'
            $collection.Error | Should -Match 'exactly one ASCII letter'
            @($collection.Notes | Where-Object { $_ -match 'Collection was skipped' }).Count | Should -Be 1
            Should -Invoke Get-UsnJournalNative -Times 0 -Exactly
            Should -Invoke Get-FsutilOutput -Times 0 -Exactly

            $native = [UsnJournalNative]::ReadJournal($drive, 10, [uint32]::MaxValue)
            $native.Success | Should -BeFalse
            $native.Error | Should -Match 'exactly one ASCII letter'
            $native.Records.Count | Should -Be 0
        }
    }

    It 'does not emit the path cap note when all 251 records are V3' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $records = @(1..251 | ForEach-Object {
                [PSCustomObject]@{
                    FileName = "v3-$_.txt"
                    FullPath = $null
                    ReasonFlags = @()
                    TimeStamp = $null
                    TimeStampText = $null
                    FileReferenceNumber = '0x' + $_.ToString('x32')
                }
            })
            Mock Test-JournalElevation { $true }
            Mock Get-UsnJournalCollection {
                [PSCustomObject]@{
                    Records = $records
                    Success = $true
                    Error = $null
                    Source = 'Native'
                    NextUsn = [long]0
                    FsutilExitCode = $null
                    AccessDenied = $false
                    NativeAttempted = $true
                    Incomplete = $false
                    Notes = @()
                }
            }
            Mock Resolve-UsnJournalPath { $null }
            $originalOs = $env:OS
            try {
                $env:OS = 'Windows_NT'
                $result = Get-FileSystemJournal -Mode USNJournal -MaxRecords 300 -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Summary.Source | Should -Be 'Native'
            @($result.Notes | Where-Object { $_ -match '128-bit file identifiers' }).Count | Should -Be 1
            @($result.Notes | Where-Object { $_ -match 'Full-path resolution was capped' }).Count | Should -Be 0
            Should -Invoke Resolve-UsnJournalPath -Times 0 -Exactly
        }
    }

    It 'emits the path cap note only after an eligible 64-bit record is skipped' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            $records = @(1..251 | ForEach-Object {
                [PSCustomObject]@{
                    FileName = "v2-$_.txt"
                    FullPath = $null
                    ReasonFlags = @()
                    TimeStamp = $null
                    TimeStampText = $null
                    FileReferenceNumber = '0x' + $_.ToString('x')
                }
            })
            Mock Test-JournalElevation { $true }
            Mock Get-UsnJournalCollection {
                [PSCustomObject]@{
                    Records = $records
                    Success = $true
                    Error = $null
                    Source = 'Native'
                    NextUsn = [long]0
                    FsutilExitCode = $null
                    AccessDenied = $false
                    NativeAttempted = $true
                    Incomplete = $false
                    Notes = @()
                }
            }
            Mock Resolve-UsnJournalPath { $null }
            $originalOs = $env:OS
            try {
                $env:OS = 'Windows_NT'
                $result = Get-FileSystemJournal -Mode USNJournal -MaxRecords 300 -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }

            $result.Summary.Source | Should -Be 'Native'
            @($result.Notes | Where-Object { $_ -match 'Full-path resolution was capped' }).Count | Should -Be 1
            Should -Invoke Resolve-UsnJournalPath -Times 250 -Exactly
        }
    }
}
