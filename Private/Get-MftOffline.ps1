<#
.SYNOPSIS
    Parses an acquired NTFS $MFT file or an injected offline record source (private).
.DESCRIPTION
    Streams FILE records through the MftNative parser with mandatory fixup validation,
    separates not-in-use previous-existence evidence, resolves sequence-checked paths,
    and optionally writes a timestamp-sorted timeline CSV with bounded memory use.
.NOTES
    This helper performs pure .NET IO and is available on Windows, macOS, and Linux.
#>

function ConvertTo-MftOfflineRecord {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$OfflineRecord
    )

    $record = ConvertTo-MftNativeRecord -NativeRecord $OfflineRecord.Record
    $record.Source = 'OfflineMft'
    $record | Add-Member -MemberType NoteProperty -Name BestEffortPath -Value $OfflineRecord.BestEffortPath
    $record | Add-Member -MemberType NoteProperty -Name PathStatus -Value ([string]$OfflineRecord.PathStatus)
    $record | Add-Member -MemberType NoteProperty -Name EvidenceType -Value $(if ($OfflineRecord.EvidenceNote) { 'PreviousExistence' } else { 'CurrentRecord' })
    $record | Add-Member -MemberType NoteProperty -Name EvidenceNote -Value $OfflineRecord.EvidenceNote
    $record | Add-Member -MemberType NoteProperty -Name RecordBytes -Value $OfflineRecord.RecordBytes
    return $record
}

function Get-MftOffline {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [string]$MftPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'RecordSource')]
        [ValidateNotNull()]
        [scriptblock]$RecordSource,

        [Parameter(Mandatory = $true, ParameterSetName = 'RecordSource')]
        [ValidateScript({ $_ -ge 0 })]
        [long]$SourceLength,

        [Parameter(ParameterSetName = 'RecordSource')]
        [ValidateNotNull()]
        [scriptblock]$ElapsedClock = { [long]0 },

        [Parameter()]
        [ValidateRange(0, 65536)]
        [int]$RecordSizeBytes = 0,

        [Parameter()]
        [ValidateRange(1, 65536)]
        [int]$BytesPerSector = 512,

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 50000,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$MaxSeconds = 300,

        [Parameter()]
        [switch]$IncludeDeleted = $true,

        [Parameter()]
        [switch]$IncludeAll,

        [Parameter()]
        [string]$TimelineCsvPath
    )

    $nativeResult = $null
    $failureReason = 'InvocationFailed'
    $failureMessage = $null

    try {
        if (-not (Initialize-MftNativeType)) {
            $failureReason = 'TypeInitializationFailed'
            throw "Native MFT type initialization failed: $script:MftNativeTypeError"
        }

        if ($PSCmdlet.ParameterSetName -eq 'RecordSource') {
            $reader = [MftNative+MftOfflineRecordReader]$RecordSource
            $clock = [MftNative+MftElapsedClock]$ElapsedClock
            $nativeResult = [MftNative]::AnalyzeOffline(
                $SourceLength,
                $RecordSizeBytes,
                $BytesPerSector,
                $MaxRecords,
                $MaxSeconds,
                [bool]$IncludeDeleted,
                [bool]$IncludeAll,
                $TimelineCsvPath,
                $reader,
                $clock)
        }
        else {
            $nativeResult = [MftNative]::ReadOffline(
                $MftPath,
                $RecordSizeBytes,
                $BytesPerSector,
                $MaxRecords,
                $MaxSeconds,
                [bool]$IncludeDeleted,
                [bool]$IncludeAll,
                $TimelineCsvPath)
        }
    }
    catch {
        $failureMessage = "Offline MFT invocation failed: $($_.Exception.Message)"
    }

    if ($null -eq $nativeResult) {
        return [PSCustomObject]@{
            Records                    = @()
            PreviousRecords            = @()
            Success                    = $false
            Error                      = $failureMessage
            Source                     = 'OfflineMft'
            Notes                      = @($failureMessage)
            Incomplete                 = $false
            Truncated                  = $false
            StopReason                 = $failureReason
            RecordsScanned             = [long]0
            DeletedCount               = 0
            SuspectCount               = 0
            UnresolvedPathCount        = 0
            MalformedRecords           = 0
            AttributeListRecords       = 0
            MissingStandardInformation = 0
            MissingFileName            = 0
            ExtensionRecordsSkipped    = 0
            EstimatedMftRecords        = [long]0
            SourceLength               = if ($PSCmdlet.ParameterSetName -eq 'RecordSource') { $SourceLength } else { [long]0 }
            RecordSizeBytes            = $RecordSizeBytes
            BytesPerFileRecord         = $RecordSizeBytes
            BytesPerSector             = $BytesPerSector
            PartialTrailingBytes       = 0
            TimelineCsvPath            = $TimelineCsvPath
            TimelineRowCount           = [long]0
            MaxRecords                 = $MaxRecords
            MaxSeconds                 = $MaxSeconds
            IncludeDeleted             = [bool]$IncludeDeleted
            IncludeAll                 = [bool]$IncludeAll
            ElapsedMilliseconds        = [long]0
        }
    }

    $records = @($nativeResult.Records | ForEach-Object { ConvertTo-MftOfflineRecord -OfflineRecord $_ })
    $previousRecords = @($nativeResult.PreviousRecords | ForEach-Object { ConvertTo-MftOfflineRecord -OfflineRecord $_ })
    return [PSCustomObject]@{
        Records                    = $records
        PreviousRecords            = $previousRecords
        Success                    = [bool]$nativeResult.Success
        Error                      = if ($null -ne $nativeResult.Error) { [string]$nativeResult.Error } else { $null }
        Source                     = 'OfflineMft'
        Notes                      = @($nativeResult.Notes | ForEach-Object { [string]$_ })
        Incomplete                 = [bool]$nativeResult.Incomplete
        Truncated                    = [bool]$nativeResult.Truncated
        StopReason                   = [string]$nativeResult.StopReason
        RecordsScanned             = [long]$nativeResult.RecordsScanned
        DeletedCount               = [int]$nativeResult.DeletedCount
        SuspectCount                 = [int]$nativeResult.SuspectCount
        UnresolvedPathCount        = [int]$nativeResult.UnresolvedPathCount
        MalformedRecords           = [int]$nativeResult.MalformedRecords
        AttributeListRecords       = [int]$nativeResult.AttributeListRecords
        MissingStandardInformation = [int]$nativeResult.MissingStandardInformation
        MissingFileName            = [int]$nativeResult.MissingFileName
        ExtensionRecordsSkipped    = [int]$nativeResult.ExtensionRecordsSkipped
        EstimatedMftRecords        = [long]$nativeResult.EstimatedMftRecords
        SourceLength               = [long]$nativeResult.SourceLength
        RecordSizeBytes            = [int]$nativeResult.RecordSizeBytes
        BytesPerFileRecord         = [int]$nativeResult.BytesPerFileRecord
        BytesPerSector             = [int]$nativeResult.BytesPerSector
        PartialTrailingBytes       = [int]$nativeResult.PartialTrailingBytes
        TimelineCsvPath            = if ($null -ne $nativeResult.TimelineCsvPath) { [string]$nativeResult.TimelineCsvPath } else { $null }
        TimelineRowCount           = [long]$nativeResult.TimelineRowCount
        MaxRecords                 = [int]$nativeResult.MaxRecords
        MaxSeconds                 = [int]$nativeResult.MaxSeconds
        IncludeDeleted             = [bool]$nativeResult.IncludeDeleted
        IncludeAll                 = [bool]$nativeResult.IncludeAll
        ElapsedMilliseconds        = [long]$nativeResult.ElapsedMilliseconds
    }
}
