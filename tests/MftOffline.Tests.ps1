#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Cross-platform synthetic fixtures for offline acquired-MFT analysis.
.DESCRIPTION
    Builds raw FILE records with update sequence arrays and sector tails. Tests
    exercise both real temporary files and an injected record-source delegate.
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
        throw 'MftNative could not be compiled; offline fixture tests cannot run.'
    }

    function Set-OfflineFixtureUInt16 {
        param([byte[]]$Buffer, [int]$Offset, [uint16]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 2)
    }

    function Set-OfflineFixtureUInt32 {
        param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 4)
    }

    function Set-OfflineFixtureUInt64 {
        param([byte[]]$Buffer, [int]$Offset, [uint64]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 8)
    }

    function Set-OfflineFixtureFileTime {
        param([byte[]]$Buffer, [int]$Offset, [datetime]$Value)
        [Array]::Copy([BitConverter]::GetBytes($Value.ToFileTimeUtc()), 0, $Buffer, $Offset, 8)
    }

    function New-OfflineFileRecord {
        param(
            [uint32]$RecordNumber,
            [string]$FileName,
            [uint64]$ParentRecordNumber = 0,
            [uint16]$ParentSequence = 1,
            [uint16]$SequenceNumber = 1,
            [datetime]$BaseTime,
            [switch]$Directory,
            [switch]$Free
        )

        [byte[]]$record = @(0) * 1024
        $record[0] = 0x46
        $record[1] = 0x49
        $record[2] = 0x4C
        $record[3] = 0x45
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 4 -Value 0x30
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 6 -Value 3
        Set-OfflineFixtureUInt64 -Buffer $record -Offset 8 -Value 0x1122334455667788
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 16 -Value $SequenceNumber
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 18 -Value 1
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 20 -Value 0x38
        $flags = [uint16]0
        if (-not $Free) { $flags = $flags -bor 1 }
        if ($Directory) { $flags = $flags -bor 2 }
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 22 -Value $flags
        Set-OfflineFixtureUInt32 -Buffer $record -Offset 28 -Value 1024
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 40 -Value 4
        Set-OfflineFixtureUInt32 -Buffer $record -Offset 44 -Value $RecordNumber
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 48 -Value 0xAABB
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 50 -Value 0x1111
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 52 -Value 0x2222

        $siOffset = 0x38
        $siLength = 0x60
        Set-OfflineFixtureUInt32 -Buffer $record -Offset $siOffset -Value 0x10
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($siOffset + 4) -Value $siLength
        Set-OfflineFixtureUInt16 -Buffer $record -Offset ($siOffset + 14) -Value 0
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($siOffset + 16) -Value 72
        Set-OfflineFixtureUInt16 -Buffer $record -Offset ($siOffset + 20) -Value 24
        $siValue = $siOffset + 24
        $created = [datetime]::SpecifyKind($BaseTime, [DateTimeKind]::Utc)
        $modified = $created.AddHours(1)
        $mftChanged = $created.AddHours(2)
        $accessed = $created.AddHours(3)
        Set-OfflineFixtureFileTime -Buffer $record -Offset $siValue -Value $created
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($siValue + 8) -Value $modified
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($siValue + 16) -Value $mftChanged
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($siValue + 24) -Value $accessed
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($siValue + 32) -Value 0x20

        [byte[]]$nameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $fnLength = (24 + 66 + $nameBytes.Length + 7) -band (-bnot 7)
        $fnOffset = $siOffset + $siLength
        Set-OfflineFixtureUInt32 -Buffer $record -Offset $fnOffset -Value 0x30
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($fnOffset + 4) -Value $fnLength
        Set-OfflineFixtureUInt16 -Buffer $record -Offset ($fnOffset + 14) -Value 2
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($fnOffset + 16) -Value (66 + $nameBytes.Length)
        Set-OfflineFixtureUInt16 -Buffer $record -Offset ($fnOffset + 20) -Value 24
        $fnValue = $fnOffset + 24
        $parentReference = ([uint64]$ParentSequence -shl 48) -bor $ParentRecordNumber
        Set-OfflineFixtureUInt64 -Buffer $record -Offset $fnValue -Value $parentReference
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($fnValue + 8) -Value $created
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($fnValue + 16) -Value $modified
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($fnValue + 24) -Value $mftChanged
        Set-OfflineFixtureFileTime -Buffer $record -Offset ($fnValue + 32) -Value $accessed
        Set-OfflineFixtureUInt64 -Buffer $record -Offset ($fnValue + 40) -Value 0x1000
        Set-OfflineFixtureUInt64 -Buffer $record -Offset ($fnValue + 48) -Value 0x200
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($fnValue + 56) -Value 0x20
        $record[$fnValue + 64] = [byte]$FileName.Length
        $record[$fnValue + 65] = 1
        [Array]::Copy($nameBytes, 0, $record, $fnValue + 66, $nameBytes.Length)
        $offset = $fnOffset + $fnLength
        Set-OfflineFixtureUInt32 -Buffer $record -Offset $offset -Value ([uint32]::MaxValue)
        Set-OfflineFixtureUInt32 -Buffer $record -Offset ($offset + 4) -Value 0
        Set-OfflineFixtureUInt32 -Buffer $record -Offset 24 -Value ($offset + 8)

        Set-OfflineFixtureUInt16 -Buffer $record -Offset 0x1FE -Value 0xAABB
        Set-OfflineFixtureUInt16 -Buffer $record -Offset 0x3FE -Value 0xAABB
        return ,$record
    }

    function Add-OfflineAlternateFileName {
        param(
            [byte[]]$Record,
            [string]$FileName,
            [uint64]$ParentRecordNumber,
            [uint16]$ParentSequence = 1,
            [datetime]$BaseTime,
            [uint16]$AttributeId = 7,
            [byte]$NameNamespace = 0
        )

        $fnOffset = [int]([BitConverter]::ToUInt32($Record, 24) - 8)
        [byte[]]$nameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $fnLength = (24 + 66 + $nameBytes.Length + 7) -band (-bnot 7)
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset $fnOffset -Value 0x30
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset ($fnOffset + 4) -Value $fnLength
        Set-OfflineFixtureUInt16 -Buffer $Record -Offset ($fnOffset + 14) -Value $AttributeId
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset ($fnOffset + 16) -Value (66 + $nameBytes.Length)
        Set-OfflineFixtureUInt16 -Buffer $Record -Offset ($fnOffset + 20) -Value 24
        $fnValue = $fnOffset + 24
        $parentReference = ([uint64]$ParentSequence -shl 48) -bor $ParentRecordNumber
        Set-OfflineFixtureUInt64 -Buffer $Record -Offset $fnValue -Value $parentReference
        $created = [datetime]::SpecifyKind($BaseTime, [DateTimeKind]::Utc)
        Set-OfflineFixtureFileTime -Buffer $Record -Offset ($fnValue + 8) -Value $created
        Set-OfflineFixtureFileTime -Buffer $Record -Offset ($fnValue + 16) -Value $created.AddHours(1)
        Set-OfflineFixtureFileTime -Buffer $Record -Offset ($fnValue + 24) -Value $created.AddHours(2)
        Set-OfflineFixtureFileTime -Buffer $Record -Offset ($fnValue + 32) -Value $created.AddHours(3)
        Set-OfflineFixtureUInt64 -Buffer $Record -Offset ($fnValue + 40) -Value 0x1000
        Set-OfflineFixtureUInt64 -Buffer $Record -Offset ($fnValue + 48) -Value 0x200
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset ($fnValue + 56) -Value 0x20
        $Record[$fnValue + 64] = [byte]$FileName.Length
        $Record[$fnValue + 65] = $NameNamespace
        [Array]::Copy($nameBytes, 0, $Record, $fnValue + 66, $nameBytes.Length)

        $offset = $fnOffset + $fnLength
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset $offset -Value ([uint32]::MaxValue)
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset ($offset + 4) -Value 0
        Set-OfflineFixtureUInt32 -Buffer $Record -Offset 24 -Value ($offset + 8)
        return ,$Record
    }

    function New-OfflineHardLinkFixtureBytes {
        param(
            [datetime]$PrimaryTime,
            [datetime]$AlternateTime
        )

        $rootTime = [datetime]::SpecifyKind([datetime]'2024-06-01T00:00:00', [DateTimeKind]::Utc)
        $primaryLink = New-OfflineFileRecord -RecordNumber 3 -FileName 'primary.txt' -ParentRecordNumber 1 -BaseTime $PrimaryTime
        $primaryLink = Add-OfflineAlternateFileName -Record $primaryLink -FileName 'alternate.txt' -ParentRecordNumber 2 -BaseTime $AlternateTime
        Set-OfflineFixtureUInt16 -Buffer $primaryLink -Offset 18 -Value 2
        $unresolvedLink = New-OfflineFileRecord -RecordNumber 4 -FileName 'other-primary.txt' -ParentRecordNumber 1 -BaseTime $PrimaryTime.AddDays(1)
        $unresolvedLink = Add-OfflineAlternateFileName -Record $unresolvedLink -FileName 'unresolved.txt' -ParentRecordNumber 99 -ParentSequence 7 -BaseTime $AlternateTime.AddDays(1)
        Set-OfflineFixtureUInt16 -Buffer $unresolvedLink -Offset 18 -Value 2
        $records = @(
            (New-OfflineFileRecord -RecordNumber 0 -FileName '.' -ParentRecordNumber 0 -Directory -BaseTime $rootTime),
            (New-OfflineFileRecord -RecordNumber 1 -FileName 'primary-dir' -ParentRecordNumber 0 -Directory -BaseTime $rootTime.AddMonths(-1)),
            (New-OfflineFileRecord -RecordNumber 2 -FileName 'alternate-dir' -ParentRecordNumber 0 -Directory -BaseTime $rootTime.AddMonths(-2)),
            $primaryLink,
            $unresolvedLink
        )
        [byte[]]$bytes = @(0) * ($records.Count * 1024)
        for ($index = 0; $index -lt $records.Count; $index++) {
            [Array]::Copy($records[$index], 0, $bytes, $index * 1024, 1024)
        }
        return ,$bytes
    }

    function New-OfflineFixtureBytes {
        $rootTime = [datetime]::SpecifyKind([datetime]'2024-06-01T00:00:00', [DateTimeKind]::Utc)
        $records = @(
            (New-OfflineFileRecord -RecordNumber 0 -FileName '.' -ParentRecordNumber 0 -Directory -BaseTime $rootTime),
            (New-OfflineFileRecord -RecordNumber 1 -FileName 'valid.txt' -BaseTime $rootTime.AddMonths(-5)),
            (New-OfflineFileRecord -RecordNumber 2 -FileName 'deleted.txt' -Free -BaseTime $rootTime.AddMonths(-3)),
            (New-OfflineFileRecord -RecordNumber 3 -FileName 'cycle-a' -ParentRecordNumber 4 -Directory -BaseTime $rootTime.AddMonths(-4)),
            (New-OfflineFileRecord -RecordNumber 4 -FileName 'cycle-b' -ParentRecordNumber 3 -Directory -BaseTime $rootTime.AddMonths(-2)),
            (New-OfflineFileRecord -RecordNumber 5 -FileName 'orphan.txt' -ParentRecordNumber 99 -ParentSequence 7 -BaseTime $rootTime.AddMonths(-1))
        )
        [byte[]]$bytes = @(0) * ($records.Count * 1024)
        for ($index = 0; $index -lt $records.Count; $index++) {
            [Array]::Copy($records[$index], 0, $bytes, $index * 1024, 1024)
        }
        return ,$bytes
    }

    function New-OfflineFixtureFile {
        param([string]$Path)
        $bytes = New-OfflineFixtureBytes
        [IO.File]::WriteAllBytes($Path, $bytes)
        return $bytes
    }

    function Invoke-OfflineFile {
        param(
            [string]$Path,
            [int]$RecordSize = 1024,
            [int]$MaxRecords = 100,
            [int]$MaxSeconds = 300,
            [bool]$IncludeDeleted = $true,
            [bool]$IncludeAll = $true,
            [switch]$SuppressRecordOutput,
            [string]$TimelineCsvPath
        )

        $parameters = @{
            MftPath         = $Path
            RecordSizeBytes = $RecordSize
            MaxRecords      = $MaxRecords
            MaxSeconds      = $MaxSeconds
            IncludeDeleted  = $IncludeDeleted
            IncludeAll      = $IncludeAll
        }
        if ($PSBoundParameters.ContainsKey('SuppressRecordOutput')) {
            $parameters.SuppressRecordOutput = $true
        }
        if ($PSBoundParameters.ContainsKey('TimelineCsvPath')) {
            $parameters.TimelineCsvPath = $TimelineCsvPath
        }
        return InModuleScope -ModuleName $script:ModuleName -ArgumentList $parameters -ScriptBlock {
            param($offlineParameters)
            Get-MftOffline @offlineParameters
        }
    }

    function New-OfflineDelegate {
        param([byte[]]$Bytes, [scriptblock]$AfterRead)
        $reader = {
            param($context)
            $remaining = [long]$Bytes.Length - [long]$context.Offset
            $count = 0
            if ($remaining -gt 0) {
                $count = [int][Math]::Min([long]$context.ByteCount, $remaining)
                [Array]::Copy($Bytes, [int]$context.Offset, $context.Buffer, 0, $count)
            }
            if ($null -ne $AfterRead) {
                & $AfterRead $context $count
            }
            [MftNative+MftOfflineReadResult]@{ Success = $true; BytesRead = $count; Error = $null }
        }.GetNewClosure()
        return $reader
    }

    function Invoke-OfflineDelegate {
        param(
            [scriptblock]$Reader,
            [long]$SourceLength,
            [scriptblock]$Clock = { [long]0 },
            [int]$RecordSize = 1024,
            [int]$MaxRecords = 100,
            [int]$MaxSeconds = 300,
            [bool]$IncludeDeleted = $true,
            [switch]$SuppressRecordOutput,
            [string]$TimelineCsvPath
        )

        $parameters = @{
            RecordSource    = $Reader
            SourceLength    = $SourceLength
            ElapsedClock    = $Clock
            RecordSizeBytes = $RecordSize
            MaxRecords      = $MaxRecords
            MaxSeconds      = $MaxSeconds
            IncludeDeleted  = $IncludeDeleted
            IncludeAll      = $true
        }
        if ($PSBoundParameters.ContainsKey('SuppressRecordOutput')) {
            $parameters.SuppressRecordOutput = $true
        }
        if ($PSBoundParameters.ContainsKey('TimelineCsvPath')) {
            $parameters.TimelineCsvPath = $TimelineCsvPath
        }
        return InModuleScope -ModuleName $script:ModuleName -ArgumentList $parameters -ScriptBlock {
            param($offlineParameters)
            Get-MftOffline @offlineParameters
        }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'Offline MFT streaming file analysis' {
    It 'detects record size at 0x1C and repairs sector tails without modifying evidence' {
        $path = Join-Path $TestDrive 'detect.mft'
        $original = New-OfflineFixtureFile -Path $path
        $scan = Invoke-OfflineFile -Path $path -RecordSize 0

        $scan.Success | Should -BeTrue
        $scan.StopReason | Should -Be 'Complete'
        $scan.RecordSizeBytes | Should -Be 1024
        $scan.BytesPerFileRecord | Should -Be 1024
        $scan.RecordsScanned | Should -Be 6
        $scan.Records.Count | Should -Be 5
        @($scan.Notes | Where-Object { $_ -match 'allocated size at offset 0x1C' }).Count | Should -Be 1

        $valid = @($scan.Records | Where-Object { $_.RecordNumber -eq 1 })[0]
        $valid.RecordBytes[0x1FE] | Should -Be 0x11
        $valid.RecordBytes[0x1FF] | Should -Be 0x11
        $valid.RecordBytes[0x3FE] | Should -Be 0x22
        $valid.RecordBytes[0x3FF] | Should -Be 0x22
        $original[1024 + 0x1FE] | Should -Be 0xBB
        $original[1024 + 0x1FF] | Should -Be 0xAA
        $onDisk = [IO.File]::ReadAllBytes($path)
        $onDisk[1024 + 0x1FE] | Should -Be 0xBB
        $onDisk[1024 + 0x3FF] | Should -Be 0xAA
    }

    It 'marks both record-size detection truncation branches as truncated' {
        [byte[]]$headerBytes = @(0) * 20
        $headerReader = New-OfflineDelegate -Bytes $headerBytes
        $headerScan = Invoke-OfflineDelegate -Reader $headerReader -SourceLength $headerBytes.Length -RecordSize 0

        $fixture = New-OfflineFixtureBytes
        [byte[]]$candidateBytes = @(0) * 100
        [Array]::Copy($fixture, 0, $candidateBytes, 0, $candidateBytes.Length)
        $candidateReader = New-OfflineDelegate -Bytes $candidateBytes
        $candidateScan = Invoke-OfflineDelegate -Reader $candidateReader -SourceLength $candidateBytes.Length -RecordSize 0

        foreach ($scan in @($headerScan, $candidateScan)) {
            $scan.Success | Should -BeFalse
            $scan.Incomplete | Should -BeTrue
            $scan.Truncated | Should -BeTrue
            $scan.StopReason | Should -Be 'TruncatedRecord'
            $scan.RecordsScanned | Should -Be 0
        }
        $headerScan.PartialTrailingBytes | Should -Be 20
        $candidateScan.PartialTrailingBytes | Should -Be 100
        $headerScan.Error | Should -Match 'inside a 48-byte FILE header'
        $candidateScan.Error | Should -Match 'inside a FILE record'
    }

    It 'separates not-in-use previous records and states their evidentiary limit' {
        $path = Join-Path $TestDrive 'deleted.mft'
        New-OfflineFixtureFile -Path $path | Out-Null
        $scan = Invoke-OfflineFile -Path $path

        $scan.DeletedCount | Should -Be 1
        $scan.PreviousRecords.Count | Should -Be 1
        @($scan.Records | Where-Object { -not $_.InUse }).Count | Should -Be 0
        $previous = $scan.PreviousRecords[0]
        $previous.RecordNumber | Should -Be 2
        $previous.FileName | Should -Be 'deleted.txt'
        $previous.InUse | Should -BeFalse
        $previous.EvidenceType | Should -Be 'PreviousExistence'
        $previous.EvidenceNote | Should -Match 'does not prove deletion time'
        $previous.EvidenceNote | Should -Match 'reuse'
        $previous.BestEffortPath | Should -Be '\deleted.txt'
        @($previous.Notes | Where-Object { $_ -match 'does not prove deletion time' }).Count | Should -Be 1
    }

    It 'honors IncludeDeleted false in records and timeline output' {
        $path = Join-Path $TestDrive 'excluded-deleted.mft'
        $timeline = Join-Path $TestDrive 'excluded-deleted.csv'
        New-OfflineFixtureFile -Path $path | Out-Null
        $scan = Invoke-OfflineFile -Path $path -IncludeDeleted $false -TimelineCsvPath $timeline

        $scan.DeletedCount | Should -Be 1
        $scan.PreviousRecords.Count | Should -Be 0
        $rows = @(Import-Csv -Path $timeline)
        $rows.Count | Should -Be 40
        @($rows | Where-Object { $_.InUse -eq 'false' }).Count | Should -Be 0
    }

    It 'stops cyclic parent walks and counts every unresolved path without partial output' {
        $path = Join-Path $TestDrive 'paths.mft'
        New-OfflineFixtureFile -Path $path | Out-Null
        $scan = Invoke-OfflineFile -Path $path

        $scan.UnresolvedPathCount | Should -Be 3
        $valid = @($scan.Records | Where-Object { $_.RecordNumber -eq 1 })[0]
        $valid.BestEffortPath | Should -Be '\valid.txt'
        $valid.PathStatus | Should -Be 'Resolved'
        foreach ($number in 3, 4) {
            $cycle = @($scan.Records | Where-Object { $_.RecordNumber -eq $number })[0]
            $cycle.PathStatus | Should -Be 'CycleDetected'
            $cycle.BestEffortPath | Should -BeNullOrEmpty
        }
        $orphan = @($scan.Records | Where-Object { $_.RecordNumber -eq 5 })[0]
        $orphan.PathStatus | Should -Be 'MissingParent'
        $orphan.BestEffortPath | Should -BeNullOrEmpty
        @($scan.Notes | Where-Object { $_ -match 'CycleDetected.*no partial path' }).Count | Should -Be 2
    }

    It 'rejects a reused parent sequence number instead of constructing a stale path' {
        $bytes = New-OfflineFixtureBytes
        $recordOne = New-OfflineFileRecord -RecordNumber 1 -FileName 'valid.txt' -ParentSequence 2 -BaseTime ([datetime]'2024-01-01T00:00:00Z')
        [Array]::Copy($recordOne, 0, $bytes, 1024, 1024)
        $reader = New-OfflineDelegate -Bytes $bytes
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length

        $record = @($scan.Records | Where-Object { $_.RecordNumber -eq 1 })[0]
        $record.PathStatus | Should -Be 'ParentSequenceMismatch'
        $record.BestEffortPath | Should -BeNullOrEmpty
        $scan.UnresolvedPathCount | Should -Be 4
    }

    It 'excludes a record with a fixup mismatch and never emits repaired partial bytes' {
        $bytes = New-OfflineFixtureBytes
        Set-OfflineFixtureUInt16 -Buffer $bytes -Offset (1024 + 0x3FE) -Value 0xCCCC
        $reader = New-OfflineDelegate -Bytes $bytes
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length

        $scan.MalformedRecords | Should -Be 1
        @($scan.Records | Where-Object { $_.RecordNumber -eq 1 }).Count | Should -Be 0
        @($scan.Notes | Where-Object { $_ -match 'Update sequence mismatch at sector 2' }).Count | Should -Be 1
        $bytes[1024 + 0x1FE] | Should -Be 0xBB
        $bytes[1024 + 0x3FE] | Should -Be 0xCC
    }

    It 'preserves complete records and reports a truncated trailing record honestly' {
        $fixture = New-OfflineFixtureBytes
        [byte[]]$bytes = @(0) * ($fixture.Length + 100)
        [Array]::Copy($fixture, 0, $bytes, 0, $fixture.Length)
        [Array]::Copy($fixture, 0, $bytes, $fixture.Length, 100)
        $reader = New-OfflineDelegate -Bytes $bytes
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length

        $scan.Success | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.Truncated | Should -BeTrue
        $scan.StopReason | Should -Be 'TruncatedRecord'
        $scan.RecordsScanned | Should -Be 6
        $scan.PartialTrailingBytes | Should -Be 100
        $scan.MalformedRecords | Should -Be 1
        $scan.Error | Should -Match 'truncated trailing record'
        @($scan.Notes | Where-Object { $_ -match 'partial bytes were not parsed.*partial evidence' }).Count | Should -Be 1
    }
}

Describe 'Offline MFT timeline and scan caps' {
    It 'streams a globally timestamp-sorted CSV with all SI/FN timestamp types' {
        $path = Join-Path $TestDrive 'timeline.mft'
        $timeline = Join-Path $TestDrive 'timeline.csv'
        New-OfflineFixtureFile -Path $path | Out-Null
        $scan = Invoke-OfflineFile -Path $path -TimelineCsvPath $timeline

        $scan.Success | Should -BeTrue
        $scan.TimelineRowCount | Should -Be 48
        $rows = @(Import-Csv -Path $timeline)
        $rows.Count | Should -Be 48
        @($rows[0].PSObject.Properties.Name) -join ',' | Should -Be 'TimestampUtc,Source,Type,BestEffortPath,FileName,ParentFileReferenceNumber,NameNamespace,FnAttributeId,FileReferenceNumber,InUse,RecordNumber'
        for ($index = 1; $index -lt $rows.Count; $index++) {
            $previous = [datetime]::Parse($rows[$index - 1].TimestampUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
            $current = [datetime]::Parse($rows[$index].TimestampUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
            $current | Should -BeGreaterOrEqual $previous
        }
        @($rows.Source | Sort-Object -Unique) -join ',' | Should -Be 'FN,SI'
        @($rows.Type | Sort-Object -Unique) -join ',' | Should -Be 'Accessed,Created,MftChanged,Modified'
        foreach ($type in 'Created', 'Modified', 'MftChanged', 'Accessed') {
            @($rows | Where-Object { $_.Type -eq $type }).Count | Should -Be 12
        }
        $rows[0].Type | Should -Be 'Created'
        $rows[0].TimestampUtc | Should -Match '^2024-01-01T00:00:00\.0000000Z$'
        @($rows | Where-Object { $_.RecordNumber -eq '1' -and $_.BestEffortPath -eq '\valid.txt' }).Count | Should -Be 8
        @($rows | Where-Object { $_.RecordNumber -eq '1' })[0].FileReferenceNumber | Should -Be '0x000000000001'
        @($rows | Where-Object { $_.RecordNumber -eq '2' -and $_.InUse -eq 'false' }).Count | Should -Be 8
        @($rows | Where-Object { $_.RecordNumber -eq '3' -and $_.BestEffortPath }).Count | Should -Be 0
    }

    It 'attributes each hard-link FN timeline row to its own resolved parent' {
        $primaryTime = [datetime]'2024-01-02T03:04:05Z'
        $alternateTime = [datetime]'2025-02-03T04:05:06Z'
        $bytes = New-OfflineHardLinkFixtureBytes -PrimaryTime $primaryTime -AlternateTime $alternateTime
        $timeline = Join-Path $TestDrive 'hard-links.csv'
        $reader = New-OfflineDelegate -Bytes $bytes
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length -TimelineCsvPath $timeline

        $scan.Success | Should -BeTrue
        $scan.UnresolvedPathCount | Should -Be 0
        $scan.TimelineRowCount | Should -Be 48
        $rows = @(Import-Csv -Path $timeline)
        $siRows = @($rows | Where-Object { $_.RecordNumber -eq '3' -and $_.Source -eq 'SI' })
        $siRows.Count | Should -Be 4
        @($siRows | Where-Object { $_.BestEffortPath -ne '\primary-dir\primary.txt' }).Count | Should -Be 0
        @($siRows | Where-Object { $_.FileName }).Count | Should -Be 0

        $primaryFn = @($rows | Where-Object { $_.RecordNumber -eq '3' -and $_.FileName -eq 'primary.txt' })
        $primaryFn.Count | Should -Be 4
        @($primaryFn | Where-Object { $_.BestEffortPath -ne '\primary-dir\primary.txt' }).Count | Should -Be 0
        $primaryFn[0].ParentFileReferenceNumber | Should -Be '0x0001000000000001'
        $primaryFn[0].NameNamespace | Should -Be '1'
        $primaryFn[0].FnAttributeId | Should -Be '2'

        $alternateFn = @($rows | Where-Object { $_.RecordNumber -eq '3' -and $_.FileName -eq 'alternate.txt' })
        $alternateFn.Count | Should -Be 4
        @($alternateFn | Where-Object { $_.BestEffortPath -ne '\alternate-dir\alternate.txt' }).Count | Should -Be 0
        $alternateFn[0].ParentFileReferenceNumber | Should -Be '0x0001000000000002'
        $alternateFn[0].NameNamespace | Should -Be '0'
        $alternateFn[0].FnAttributeId | Should -Be '7'
        $primaryCreated = @($primaryFn | Where-Object { $_.Type -eq 'Created' })[0]
        $alternateCreated = @($alternateFn | Where-Object { $_.Type -eq 'Created' })[0]
        $alternateCreated.TimestampUtc | Should -Not -Be $primaryCreated.TimestampUtc
        $alternateCreated.TimestampUtc | Should -Be $alternateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)

        $unresolvedFn = @($rows | Where-Object { $_.RecordNumber -eq '4' -and $_.FileName -eq 'unresolved.txt' })
        $unresolvedFn.Count | Should -Be 4
        @($unresolvedFn | Where-Object { $_.BestEffortPath }).Count | Should -Be 0
        $otherPrimaryFn = @($rows | Where-Object { $_.RecordNumber -eq '4' -and $_.FileName -eq 'other-primary.txt' })
        @($otherPrimaryFn | Where-Object { $_.BestEffortPath -ne '\primary-dir\other-primary.txt' }).Count | Should -Be 0
    }

    It 'can suppress retained record objects without suppressing timeline evidence' {
        $path = Join-Path $TestDrive 'suppressed.mft'
        $timeline = Join-Path $TestDrive 'suppressed.csv'
        New-OfflineFixtureFile -Path $path | Out-Null
        $scan = Invoke-OfflineFile -Path $path -TimelineCsvPath $timeline -SuppressRecordOutput

        $scan.Success | Should -BeTrue
        $scan.SuppressRecordOutput | Should -BeTrue
        $scan.Records.Count | Should -Be 0
        $scan.PreviousRecords.Count | Should -Be 0
        $scan.RecordsScanned | Should -Be 6
        $scan.DeletedCount | Should -Be 1
        $scan.TimelineRowCount | Should -Be 48
        @(Import-Csv -Path $timeline).Count | Should -Be 48
        @($scan.Notes | Where-Object { $_ -match 'retention is suppressed.*counters and timeline' }).Count | Should -Be 1
    }

    It 'stops at MaxRecords with a truncated sorted partial timeline' {
        $bytes = New-OfflineFixtureBytes
        $timeline = Join-Path $TestDrive 'max-records.csv'
        $reader = New-OfflineDelegate -Bytes $bytes
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length -MaxRecords 2 -TimelineCsvPath $timeline

        $scan.Success | Should -BeTrue
        $scan.Truncated | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'MaxRecords'
        $scan.RecordsScanned | Should -Be 2
        $scan.TimelineRowCount | Should -Be 16
        @($scan.Notes | Where-Object { $_ -match 'MaxRecords cap of 2.*incomplete' }).Count | Should -Be 1
        @(Import-Csv -Path $timeline).Count | Should -Be 16
    }

    It 'uses the injected clock to stop at MaxSeconds with partial evidence' {
        $bytes = New-OfflineFixtureBytes
        $elapsed = [ref][long]0
        $afterRead = {
            param($context, $count)
            if ($context.Offset -eq 0) {
                $elapsed.Value = 1000
            }
        }.GetNewClosure()
        $reader = New-OfflineDelegate -Bytes $bytes -AfterRead $afterRead
        $clock = { [long]$elapsed.Value }.GetNewClosure()
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length -Clock $clock -MaxSeconds 1

        $scan.Success | Should -BeTrue
        $scan.Truncated | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'MaxSeconds'
        $scan.RecordsScanned | Should -Be 1
        @($scan.Notes | Where-Object { $_ -match '1-second time budget.*incomplete' }).Count | Should -Be 1
    }

    It 'enforces MaxSeconds during record-size detection and finalizes an empty timeline' {
        $bytes = New-OfflineFixtureBytes
        $elapsed = [ref][long]0
        $readCount = [ref][int]0
        $afterRead = {
            param($context, $count)
            $readCount.Value++
            if ($context.ByteCount -eq 48) {
                $elapsed.Value = 1000
            }
        }.GetNewClosure()
        $reader = New-OfflineDelegate -Bytes $bytes -AfterRead $afterRead
        $clock = { [long]$elapsed.Value }.GetNewClosure()
        $timeline = Join-Path $TestDrive 'detection-max-seconds.csv'
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length -RecordSize 0 -Clock $clock -MaxSeconds 1 -TimelineCsvPath $timeline

        $scan.Success | Should -BeFalse
        $scan.Error | Should -BeNullOrEmpty
        $scan.Truncated | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'MaxSeconds'
        $scan.RecordsScanned | Should -Be 0
        $scan.RecordSizeBytes | Should -Be 0
        $scan.TimelineRowCount | Should -Be 0
        $readCount.Value | Should -Be 1
        @(Import-Csv -Path $timeline).Count | Should -Be 0
        @($scan.Notes | Where-Object { $_ -match 'record-size detection stopped at the 1-second time budget' }).Count | Should -Be 1
    }

    It 'enforces MaxSeconds during a parent walk and preserves the partial timeline' {
        $bytes = New-OfflineFixtureBytes
        $elapsed = [ref][long]0
        $readCount = [ref][int]0
        $afterRead = {
            param($context, $count)
            $readCount.Value++
            if ($readCount.Value -eq 3) {
                $elapsed.Value = 1000
            }
        }.GetNewClosure()
        $reader = New-OfflineDelegate -Bytes $bytes -AfterRead $afterRead
        $clock = { [long]$elapsed.Value }.GetNewClosure()
        $timeline = Join-Path $TestDrive 'parent-max-seconds.csv'
        $scan = Invoke-OfflineDelegate -Reader $reader -SourceLength $bytes.Length -Clock $clock -MaxSeconds 1 -TimelineCsvPath $timeline

        $scan.Success | Should -BeTrue
        $scan.Error | Should -BeNullOrEmpty
        $scan.Truncated | Should -BeTrue
        $scan.Incomplete | Should -BeTrue
        $scan.StopReason | Should -Be 'MaxSeconds'
        $scan.RecordsScanned | Should -Be 2
        $scan.Records.Count | Should -Be 1
        $scan.Records[0].RecordNumber | Should -Be 0
        $scan.UnresolvedPathCount | Should -Be 0
        $scan.TimelineRowCount | Should -Be 8
        $readCount.Value | Should -Be 3
        @(Import-Csv -Path $timeline).Count | Should -Be 8
        @($scan.Notes | Where-Object { $_ -match 'parent resolution stopped at the 1-second time budget' }).Count | Should -Be 1
    }
}

Describe 'Get-FileSystemJournal OfflineMftAnalysis integration' {
    It 'parses a real acquired-file fixture on a non-Windows host and maps the MFT summary' {
        $path = Join-Path $TestDrive 'integration.mft'
        $timeline = Join-Path $TestDrive 'integration.csv'
        New-OfflineFixtureFile -Path $path | Out-Null
        $result = InModuleScope -ModuleName $script:ModuleName -ArgumentList $path, $timeline -ScriptBlock {
            param($mftPath, $timelinePath)
            $originalOs = $env:OS
            try {
                $env:OS = 'Unix'
                Get-FileSystemJournal -Mode OfflineMftAnalysis -DriveLetter '!!' -MftPath $mftPath -TimelineCsvPath $timelinePath -IncludeAll -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }
        }

        $result.Mode | Should -Be 'OfflineMftAnalysis'
        $result.Records.Count | Should -Be 5
        $result.PreviousRecords.Count | Should -Be 1
        $result.Summary.Source | Should -Be 'OfflineMft'
        $result.Summary.RecordsScanned | Should -Be 6
        $result.Summary.DeletedCount | Should -Be 1
        $result.Summary.SuspectCount | Should -Be 0
        $result.Summary.UnresolvedPathCount | Should -Be 3
        $result.Summary.Truncated | Should -BeFalse
        $result.Summary.Incomplete | Should -BeFalse
        $result.Summary.StopReason | Should -Be 'Complete'
        $result.Summary.Success | Should -BeTrue
        $result.Summary.IncludeDeleted | Should -BeTrue
        $result.Summary.TimelineRowCount | Should -Be 48
        $result.Summary.TimelineCsvPath | Should -Be $timeline
        $result.IsElevated | Should -BeFalse
        @($result.Notes | Where-Object { $_ -match 'not Windows-only' }).Count | Should -Be 1
        Test-Path -Path $timeline | Should -BeTrue
    }

    It 'maps physical truncation to Truncated in the public summary' {
        $path = Join-Path $TestDrive 'integration-truncated.mft'
        $fixture = New-OfflineFixtureFile -Path $path
        [byte[]]$bytes = @(0) * ($fixture.Length + 100)
        [Array]::Copy($fixture, 0, $bytes, 0, $fixture.Length)
        [Array]::Copy($fixture, 0, $bytes, $fixture.Length, 100)
        [IO.File]::WriteAllBytes($path, $bytes)
        $result = InModuleScope -ModuleName $script:ModuleName -ArgumentList $path -ScriptBlock {
            param($mftPath)
            $originalOs = $env:OS
            try {
                $env:OS = 'Unix'
                Get-FileSystemJournal -Mode OfflineMftAnalysis -MftPath $mftPath -IncludeAll -WarningAction SilentlyContinue
            }
            finally {
                $env:OS = $originalOs
            }
        }

        $result.Records.Count | Should -Be 5
        $result.PreviousRecords.Count | Should -Be 1
        $result.Summary.Success | Should -BeTrue
        $result.Summary.Truncated | Should -BeTrue
        $result.Summary.Incomplete | Should -BeTrue
        $result.Summary.StopReason | Should -Be 'TruncatedRecord'
        $result.Summary.RecordsScanned | Should -Be 6
        $result.Summary.PartialTrailingBytes | Should -Be 100
        $result.Summary.MalformedRecords | Should -Be 1
    }

    It 'requires MftPath only for offline mode' {
        {
            InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
                Get-FileSystemJournal -Mode OfflineMftAnalysis -WarningAction SilentlyContinue
            }
        } | Should -Throw '*MftPath is required*'
    }
}
