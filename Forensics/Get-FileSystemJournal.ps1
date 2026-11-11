function Get-FileSystemJournal {
    <#
    .SYNOPSIS
        Parses NTFS USN change journal and file-system metadata for forensic analysis
    .DESCRIPTION
        Reads the NTFS USN change journal through binary native APIs, with an
        English-locale fsutil fallback, to surface file creation, deletion, and
        rename activity. Also summarizes MFT statistics from fsutil volume
        metadata, scans targeted paths for timestomp indicators, compares SI/FN
        timestamps in live FILE records, and parses an already acquired $MFT file.
        Live raw-volume acquisition is out of scope. Offline not-in-use records are
        previous-existence evidence, not proof of deletion time or deleted content.
    .PARAMETER DriveLetter
        NTFS volume to analyze (default: C; not used by OfflineMftAnalysis)
    .PARAMETER Mode
        Analysis mode: USNJournal, MFTSummary, TimestompScan, MftTimestompScan, or OfflineMftAnalysis
    .PARAMETER MaxRecords
        Maximum journal records, files, live MFT records, or offline FILE records to scan
    .PARAMETER MaxSeconds
        Maximum live or offline MFT scan time in seconds (default: 300)
    .PARAMETER IncludeAll
        Return every parsed live or offline in-use MFT base record instead of only timestomp suspects
    .PARAMETER MftPath
        Already acquired $MFT file. Required when Mode is OfflineMftAnalysis.
    .PARAMETER TimelineCsvPath
        Optional timestamp-sorted SI/FN timeline CSV for OfflineMftAnalysis.
    .PARAMETER RecordSizeBytes
        Optional offline FILE record size override. Zero detects the size from the first FILE header.
    .PARAMETER IncludeDeleted
        Include not-in-use records as previous-existence evidence in OfflineMftAnalysis (default: true)
    .PARAMETER ScanPaths
        Paths scanned in TimestompScan mode (default: user Desktop, Downloads, Temp)
    .PARAMETER OutputPath
        Optional CSV file path for exporting collected records
    .EXAMPLE
        Get-FileSystemJournal -DriveLetter C -Mode USNJournal -MaxRecords 5000
    .EXAMPLE
        Get-FileSystemJournal -Mode TimestompScan -ScanPaths "C:\Users\victim\Downloads" -OutputPath "C:\IR\timestomp.csv"
    .EXAMPLE
        Get-FileSystemJournal -Mode MftTimestompScan -DriveLetter C -MaxRecords 50000 -MaxSeconds 300
    .EXAMPLE
        Get-FileSystemJournal -Mode OfflineMftAnalysis -MftPath "D:\Evidence\MFT.bin" -TimelineCsvPath "D:\IR\mft-timeline.csv"
    .OUTPUTS
        PSCustomObject with Mode, Records, PreviousRecords, Summary, Notes, and Recommendations
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [ValidateSet('USNJournal', 'MFTSummary', 'TimestompScan', 'MftTimestompScan', 'OfflineMftAnalysis')]
        [string]$Mode = 'USNJournal',

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 10000,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$MaxSeconds = 300,

        [Parameter()]
        [switch]$IncludeAll,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$MftPath,

        [Parameter()]
        [string]$TimelineCsvPath,

        [Parameter()]
        [ValidateRange(0, 65536)]
        [int]$RecordSizeBytes = 0,

        [Parameter()]
        [switch]$IncludeDeleted = $true,

        [Parameter()]
        [string[]]$ScanPaths,

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        $isOfflineMftMode = ($Mode -eq 'OfflineMftAnalysis')
        if ($isOfflineMftMode -and [string]::IsNullOrWhiteSpace($MftPath)) {
            throw [System.Management.Automation.ParameterBindingException]::new('MftPath is required when Mode is OfflineMftAnalysis.')
        }

        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  FILE SYSTEM JOURNAL FORENSICS" -ForegroundColor Cyan
        Write-Host "  USN Journal / MFT / Timestomp Analysis" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Mode: $Mode" -ForegroundColor Yellow
        if ($isOfflineMftMode) {
            Write-Host "MFT: $MftPath" -ForegroundColor Yellow
        }
        else {
            Write-Host "Drive: $DriveLetter" -ForegroundColor Yellow
        }
        Write-Host "Max Records: $MaxRecords" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

        $drive = $DriveLetter.Trim().TrimEnd(':', '\')
        $driveIsValid = ($drive -cmatch '^[A-Za-z]$')
        if ($driveIsValid) {
            $drive = $drive.ToUpperInvariant()
        }

        $isWindowsPlatform = ($env:OS -eq 'Windows_NT')

        $isAdmin = $false
        if ($isWindowsPlatform -and -not $isOfflineMftMode) {
            $isAdmin = Test-JournalElevation
        }

        $mftSummaryTemplate = @{
            RecordsScanned             = [long]0
            NativeRecordsReturned      = [long]0
            ReturnedRecords            = 0
            PreviousRecordsReturned    = 0
            DeletedCount               = 0
            SuspectCount               = 0
            UnresolvedPathCount        = 0
            MalformedRecords           = 0
            AttributeListRecords       = 0
            MissingStandardInformation = 0
            MissingFileName            = 0
            ExtensionRecordsSkipped    = 0
            NotInUseRecordsSkipped     = 0
            SkippedOrdinalCount        = [long]0
            EstimatedMftRecords        = [long]0
            SourceLength               = [long]0
            PartialTrailingBytes       = 0
            BytesPerSector             = 0
            BytesPerFileRecord         = 0
            ElapsedMilliseconds        = [long]0
            MaxRecords                 = $MaxRecords
            MaxSeconds                 = $MaxSeconds
            IncludeAll                 = [bool]$IncludeAll
            IncludeDeleted             = [bool]$IncludeDeleted
            TimelineCsvPath            = $null
            TimelineRowCount           = [long]0
            Success                    = $false
            Truncated                  = $false
            Incomplete                 = $false
            StopReason                 = 'NotStarted'
            Source                     = 'Unavailable'
        }

        $result = [PSCustomObject]@{
            CollectionDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName    = $env:COMPUTERNAME
            DriveLetter     = $drive
            Mode            = $Mode
            IsElevated      = $isAdmin
            Records         = @()
            PreviousRecords = @()
            Summary         = if ($Mode -eq 'MftTimestompScan' -or $isOfflineMftMode) { $mftSummaryTemplate.Clone() } else { @{ Source = 'Unavailable' } }
            Notes           = @()
            Recommendations = @()
        }

        if (-not $isOfflineMftMode) {
            if (-not $driveIsValid) {
                Write-Warning "Invalid DriveLetter '$drive': exactly one ASCII letter is required. Collection will be skipped."
            }
            if (-not $isWindowsPlatform) {
                Write-Warning "Get-FileSystemJournal requires Windows (NTFS volume + fsutil.exe). Current platform is not Windows."
            }
            elseif (-not $isAdmin) {
                Write-Warning "Administrator privileges are required to read the USN journal and volume metadata. Some sections will be skipped."
            }
        }

        if ($Mode -eq 'TimestompScan' -and (-not $ScanPaths -or @($ScanPaths).Count -eq 0)) {
            $defaultPaths = @()
            if ($env:USERPROFILE) {
                $defaultPaths += (Join-Path $env:USERPROFILE 'Desktop')
                $defaultPaths += (Join-Path $env:USERPROFILE 'Downloads')
            }
            if ($env:TEMP) {
                $defaultPaths += $env:TEMP
            }
            $ScanPaths = $defaultPaths
        }
    }

    process {
        try {
            if ($isOfflineMftMode) {
                Write-Host "`n[*] Streaming the acquired MFT through the offline FILE-record parser..." -ForegroundColor Cyan
                try {
                    $offlineParameters = @{
                        MftPath         = $MftPath
                        RecordSizeBytes = $RecordSizeBytes
                        MaxRecords      = $MaxRecords
                        MaxSeconds      = $MaxSeconds
                        IncludeDeleted  = [bool]$IncludeDeleted
                        IncludeAll      = [bool]$IncludeAll
                    }
                    if (-not [string]::IsNullOrWhiteSpace($TimelineCsvPath)) {
                        $offlineParameters.TimelineCsvPath = $TimelineCsvPath
                    }
                    $offlineResult = Get-MftOffline @offlineParameters
                    foreach ($note in @($offlineResult.Notes)) {
                        $result.Notes += $note
                    }
                    if ($offlineResult.Error) {
                        $result.Notes += "Offline MFT collection status: $($offlineResult.Error)"
                    }

                    $activeRecords = @($offlineResult.Records)
                    $previousRecords = @($offlineResult.PreviousRecords)
                    $result.Records = $activeRecords
                    $result.PreviousRecords = $previousRecords
                    $result.Summary = $mftSummaryTemplate.Clone()
                    $result.Summary.RecordsScanned = [long]$offlineResult.RecordsScanned
                    $result.Summary.NativeRecordsReturned = [long]0
                    $result.Summary.ReturnedRecords = $activeRecords.Count
                    $result.Summary.PreviousRecordsReturned = $previousRecords.Count
                    $result.Summary.DeletedCount = [int]$offlineResult.DeletedCount
                    $result.Summary.SuspectCount = [int]$offlineResult.SuspectCount
                    $result.Summary.UnresolvedPathCount = [int]$offlineResult.UnresolvedPathCount
                    $result.Summary.MalformedRecords = [int]$offlineResult.MalformedRecords
                    $result.Summary.AttributeListRecords = [int]$offlineResult.AttributeListRecords
                    $result.Summary.MissingStandardInformation = [int]$offlineResult.MissingStandardInformation
                    $result.Summary.MissingFileName = [int]$offlineResult.MissingFileName
                    $result.Summary.ExtensionRecordsSkipped = [int]$offlineResult.ExtensionRecordsSkipped
                    $result.Summary.NotInUseRecordsSkipped = if ($IncludeDeleted) { 0 } else { [int]$offlineResult.DeletedCount }
                    $result.Summary.EstimatedMftRecords = [long]$offlineResult.EstimatedMftRecords
                    $result.Summary.SourceLength = [long]$offlineResult.SourceLength
                    $result.Summary.PartialTrailingBytes = [int]$offlineResult.PartialTrailingBytes
                    $result.Summary.BytesPerSector = [int]$offlineResult.BytesPerSector
                    $result.Summary.BytesPerFileRecord = [int]$offlineResult.BytesPerFileRecord
                    $result.Summary.ElapsedMilliseconds = [long]$offlineResult.ElapsedMilliseconds
                    $result.Summary.TimelineCsvPath = $offlineResult.TimelineCsvPath
                    $result.Summary.TimelineRowCount = [long]$offlineResult.TimelineRowCount
                    $result.Summary.Success = [bool]$offlineResult.Success
                    $result.Summary.Truncated = [bool]$offlineResult.Truncated
                    $result.Summary.Incomplete = [bool]$offlineResult.Incomplete
                    $result.Summary.StopReason = [string]$offlineResult.StopReason
                    $result.Summary.Source = 'OfflineMft'

                    if (-not $offlineResult.Success) {
                        Write-Warning "Offline MFT analysis did not complete successfully: $($offlineResult.Error)"
                    }
                    Write-Host "  Records scanned: $($offlineResult.RecordsScanned); suspects: $($offlineResult.SuspectCount); previous records: $($previousRecords.Count)" -ForegroundColor Green
                    if ($offlineResult.TimelineCsvPath) {
                        Write-Host "  Timeline rows: $($offlineResult.TimelineRowCount); CSV: $($offlineResult.TimelineCsvPath)" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Offline MFT analysis failed: $($_.Exception.Message)"
                    $result.Notes += "Offline MFT analysis failed without a live fallback: $($_.Exception.Message)"
                    $result.Summary = $mftSummaryTemplate.Clone()
                    $result.Summary.StopReason = 'InvocationFailed'
                    $result.Summary.Source = 'OfflineMft'
                }

                $result.Notes += "OfflineMftAnalysis reads only the supplied acquired file through pure .NET IO; it performs no live FSCTL enumeration or raw-volume acquisition and is not Windows-only."
                $result.Notes += "Records contains in-use timestomp suspects unless IncludeAll is set. PreviousRecords separately contains requested not-in-use records; their timestamps are not deletion times."
                $result.Recommendations += "Preserve the acquired MFT read-only, validate the evidence hash independently, and correlate previous records with other artifacts before inferring deletion or deletion time."
                $result.Recommendations += "Review UnresolvedPathCount, MalformedRecords, Truncated, Incomplete, and StopReason before drawing volume-wide conclusions; unresolved and cyclic paths are never silently completed."
            }
            elseif (-not $driveIsValid) {
                $result.Notes += "Invalid DriveLetter '$drive': exactly one ASCII letter is required. Collection was skipped."
                if ($Mode -eq 'MftTimestompScan') {
                    $result.Summary.StopReason = 'InvalidDriveLetter'
                }
                $result.Recommendations += "Provide one ASCII drive letter, such as C or D."
            }
            elseif (-not $isWindowsPlatform) {
                $result.Notes += "Platform check failed: NTFS journal and fsutil.exe are only available on Windows. No data was collected."
                if ($Mode -eq 'MftTimestompScan') {
                    $result.Notes += "Native MFT SI/FN scanning was skipped: FSCTL_GET_NTFS_FILE_RECORD is only available on Windows."
                    $result.Summary.StopReason = 'UnsupportedPlatform'
                }
                $result.Recommendations += "Run this function on a Windows host against an NTFS volume."
            }
            else {
                switch ($Mode) {

                    'USNJournal' {
                        Write-Host "`n[*] Reading USN change journal on $drive`:..." -ForegroundColor Cyan

                        try {
                            $collection = Get-UsnJournalCollection -DriveLetter $drive -MaxRecords $MaxRecords -Elevated:$isAdmin
                            foreach ($note in @($collection.Notes)) {
                                $result.Notes += $note
                            }

                            if (-not $collection.Success) {
                                $fsutilExitCode = $collection.FsutilExitCode
                                if ($collection.AccessDenied) {
                                    Write-Warning "fsutil denied access to the USN journal (exit code $fsutilExitCode); fsutil requires elevation or access denied. Rerun from an elevated prompt."
                                    $result.Notes += "USN journal read failed: fsutil requires elevation or access denied."
                                }
                                else {
                                    Write-Warning "fsutil usn readjournal failed with exit code $fsutilExitCode."
                                    $result.Notes += "USN journal read failed: fsutil exited with code $fsutilExitCode."
                                }
                            }
                            else {
                                $journalRecords = @($collection.Records)
                                Write-Host "  Parsed $($journalRecords.Count) journal records via $($collection.Source)" -ForegroundColor Green

                                $resolveCap = 250
                                $resolveCount = 0
                                $skipped128BitPaths = 0
                                $capped64BitPathSkipped = $false
                                $pathCache = @{}
                                foreach ($record in $journalRecords) {
                                    if ($null -eq $record.FileReferenceNumber) { continue }
                                    if ($record.FileReferenceNumber -match '^0x[0-9A-Fa-f]{32}$') {
                                        $skipped128BitPaths++
                                        continue
                                    }
                                    if ($pathCache.ContainsKey($record.FileReferenceNumber)) {
                                        $record.FullPath = $pathCache[$record.FileReferenceNumber]
                                        continue
                                    }
                                    if ($resolveCount -ge $resolveCap) {
                                        $capped64BitPathSkipped = $true
                                        continue
                                    }
                                    $resolveCount++
                                    $resolvedPath = Resolve-UsnJournalPath -DriveLetter $drive -FileReferenceNumber $record.FileReferenceNumber
                                    $pathCache[$record.FileReferenceNumber] = $resolvedPath
                                    if ($resolvedPath) {
                                        $record.FullPath = $resolvedPath
                                    }
                                }
                                Write-Verbose "Resolved full paths for $resolveCount unique file reference numbers (cap $resolveCap)."
                                if ($skipped128BitPaths -gt 0) {
                                    $result.Notes += "Full-path resolution was skipped for $skipped128BitPaths records with 128-bit file identifiers; the existing fsutil resolver is validated only for 64-bit NTFS identifiers."
                                }
                                if ($capped64BitPathSkipped) {
                                    $result.Notes += "Full-path resolution was capped at $resolveCap unique file reference numbers; the USN journal stores names, not paths, so remaining records have no directory context."
                                }

                                $result.Records = $journalRecords

                                $createdRecords = @($journalRecords | Where-Object { $_.ReasonFlags -contains 'FILE_CREATE' })
                                $deletedCount = @($journalRecords | Where-Object { $_.ReasonFlags -contains 'FILE_DELETE' }).Count
                                $renamedCount = @($journalRecords | Where-Object { $_.ReasonFlags -contains 'RENAME_OLD_NAME' }).Count

                                $executableExtensions = @('.exe', '.dll', '.ps1', '.bat')
                                $executableCreations = @($createdRecords | Where-Object {
                                    $null -ne $_.FileName -and
                                    $executableExtensions -contains ([System.IO.Path]::GetExtension($_.FileName)).ToLower()
                                })

                                $topDirectories = @($journalRecords |
                                    Where-Object { $_.FullPath } |
                                    ForEach-Object {
                                        try { Split-Path -Path $_.FullPath -Parent -ErrorAction Stop } catch { $null }
                                    } |
                                    Where-Object { $_ } |
                                    Group-Object |
                                    Sort-Object Count -Descending |
                                    Select-Object -First 10 |
                                    ForEach-Object { [PSCustomObject]@{ Directory = $_.Name; ChangeCount = $_.Count } })

                                if ($topDirectories.Count -eq 0) {
                                    $result.Notes += "Top-directory ranking unavailable: journal records could not be resolved to full paths (deleted files and non-elevated runs commonly fail resolution)."
                                }

                                $result.Summary = @{
                                    TotalRecords        = $journalRecords.Count
                                    FilesCreated        = $createdRecords.Count
                                    FilesDeleted        = $deletedCount
                                    FilesRenamed        = $renamedCount
                                    ExecutableCreations = @($executableCreations | ForEach-Object {
                                        [PSCustomObject]@{
                                            FileName    = $_.FileName
                                            FullPath    = $_.FullPath
                                            TimeStamp   = if ($_.TimeStamp) { $_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss') } else { $_.TimeStampText }
                                            ReasonFlags = @($_.ReasonFlags) -join '|'
                                        }
                                    })
                                    TopDirectories      = $topDirectories
                                    Source              = $collection.Source
                                }

                                if ($collection.Source -eq 'Native') {
                                    $result.Notes += "Journal records were read through binary FSCTL_QUERY_USN_JOURNAL and FSCTL_READ_USN_JOURNAL calls; no localized text parsing was used."
                                }
                                else {
                                    $result.Notes += "Journal output is text-parsed from 'fsutil usn readjournal'; fields are limited to what fsutil prints (file name, reason bitmask, time stamp, USN, file reference number)."
                                }
                                $result.Notes += "The journal is circular; records shown cover only the collected window and older history may already be overwritten."

                                $result.Recommendations += "Review executable creation events for unexpected binaries consistent with ingress tool transfer (MITRE ATT&CK T1105)."
                                $result.Recommendations += "Export and preserve the journal promptly during incident response before rollover destroys older records."
                                $result.Recommendations += "Correlate FILE_CREATE/RENAME sequences with process and network telemetry before attributing malicious intent."

                                Write-Host "  Files created: $($createdRecords.Count), deleted: $deletedCount, renamed: $renamedCount" -ForegroundColor Gray
                                if ($executableCreations.Count -gt 0) {
                                    Write-Host "`n  Executable creation events (T1105-style evidence):" -ForegroundColor Yellow
                                    foreach ($exe in $executableCreations) {
                                        $exeTime = if ($exe.TimeStamp) { $exe.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss') } else { $exe.TimeStampText }
                                        $exePath = if ($exe.FullPath) { $exe.FullPath } else { $exe.FileName }
                                        Write-Host "    [$exeTime] $exePath" -ForegroundColor Red
                                    }
                                }
                                if ($topDirectories.Count -gt 0) {
                                    Write-Host "`n  Top directories by change count:" -ForegroundColor Gray
                                    foreach ($dir in $topDirectories) {
                                        Write-Host "    $($dir.ChangeCount)x $($dir.Directory)" -ForegroundColor Gray
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Warning "Failed to read or parse the USN journal - $_"
                            $result.Notes += "USN journal collection failed: $_"
                        }
                    }

                    'MFTSummary' {
                        Write-Host "`n[*] Collecting MFT summary for $drive`:..." -ForegroundColor Cyan

                        try {
                            $ntfsLines = @(Get-FsutilOutput -Arguments @('fsinfo', 'ntfsinfo', "$drive`:"))
                            $fsutilExitCode = $script:FsutilLastExitCode

                            if ($fsutilExitCode -ne 0) {
                                if ($fsutilExitCode -eq 1 -or $fsutilExitCode -eq 5) {
                                    Write-Warning "fsutil denied access to volume metadata (exit code $fsutilExitCode); fsutil requires elevation or access denied. Rerun from an elevated prompt."
                                    $result.Notes += "MFT summary collection failed: fsutil requires elevation or access denied."
                                }
                                else {
                                    Write-Warning "fsutil fsinfo ntfsinfo failed with exit code $fsutilExitCode."
                                    $result.Notes += "MFT summary collection failed: fsutil exited with code $fsutilExitCode."
                                }
                            }
                            else {
                                $volumeInfo = @{}
                                foreach ($line in $ntfsLines) {
                                    if ($null -eq $line -or $line -match '^\s*$') { continue }
                                    if ($line -match '^\s*(?<key>[^:=]+?)\s*:\s*(?<value>.*)$') {
                                        $volumeInfo[$Matches.key.Trim()] = $Matches.value.Trim()
                                    }
                                    else {
                                        Write-Verbose "Skipping unrecognized ntfsinfo line: $line"
                                    }
                                }

                                $mftValidBytes = $null
                                if ($volumeInfo.Count -gt 0) {
                                    $expectedFields = @('Mft Valid Data Length', 'Bytes Per FileRecord Segment', 'Mft Start Lcn', 'Mft2 Start Lcn', 'Mft Zone Start', 'Mft Zone End')
                                    $matchedFields = @($expectedFields | Where-Object { $volumeInfo.ContainsKey($_) })
                                    if ($matchedFields.Count -eq 0) {
                                        Write-Warning "fsutil ntfsinfo returned data but none of the expected volume fields were recognized; localized fsutil output cannot be mapped (English locale required). MFT summary values will be null."
                                        $result.Notes += "MFT summary values unavailable: localized fsutil ntfsinfo output cannot be parsed; English locale is required."
                                    }
                                }
                                if ($volumeInfo.ContainsKey('Mft Valid Data Length')) {
                                    $mftValidBytes = ConvertFrom-JournalNumericText -Text $volumeInfo['Mft Valid Data Length']
                                }
                                $recordSizeBytes = $null
                                if ($volumeInfo.ContainsKey('Bytes Per FileRecord Segment')) {
                                    $recordSizeBytes = ConvertFrom-JournalNumericText -Text $volumeInfo['Bytes Per FileRecord Segment']
                                }

                                $estimatedRecords = $null
                                if ($null -ne $mftValidBytes -and $null -ne $recordSizeBytes -and $recordSizeBytes -gt 0) {
                                    $estimatedRecords = [Math]::Floor($mftValidBytes / $recordSizeBytes)
                                }

                                $infoRecords = @($volumeInfo.GetEnumerator() | Sort-Object Name | ForEach-Object {
                                    [PSCustomObject]@{ Property = $_.Key; Value = $_.Value }
                                })
                                $result.Records = $infoRecords

                                $result.Summary = @{
                                    MftSizeBytes           = $mftValidBytes
                                    MftSizeMB              = if ($null -ne $mftValidBytes) { [Math]::Round($mftValidBytes / 1MB, 2) } else { $null }
                                    MftRecordSizeBytes     = $recordSizeBytes
                                    EstimatedMftRecords    = $estimatedRecords
                                    MftStartLcn            = if ($volumeInfo.ContainsKey('Mft Start Lcn')) { $volumeInfo['Mft Start Lcn'] } else { $null }
                                    Mft2StartLcn           = if ($volumeInfo.ContainsKey('Mft2 Start Lcn')) { $volumeInfo['Mft2 Start Lcn'] } else { $null }
                                    MftZoneStart           = if ($volumeInfo.ContainsKey('Mft Zone Start')) { $volumeInfo['Mft Zone Start'] } else { $null }
                                    MftZoneEnd             = if ($volumeInfo.ContainsKey('Mft Zone End')) { $volumeInfo['Mft Zone End'] } else { $null }
                                    PropertiesReported     = $infoRecords.Count
                                    Source                 = 'Fsutil'
                                }

                                $result.Notes += "Summary-level view only: values come from 'fsutil fsinfo ntfsinfo' volume metadata."
                                $result.Notes += "This mode does not parse individual FILE records; use MftTimestompScan for live in-use SI/FN candidates or OfflineMftAnalysis for an already acquired MFT copy. Live raw-volume acquisition and deleted-content recovery remain out of scope."

                                $result.Recommendations += "For per-record analysis of an acquired `$MFT copy, use OfflineMftAnalysis with an optional TimelineCsvPath; validate findings with an independent parser when the evidence warrants it."
                                $result.Recommendations += "A large or rapidly growing MFT valid data length relative to expectations can indicate mass file creation (staging or encryption activity); baseline before alerting."

                                if ($null -ne $mftValidBytes) {
                                    Write-Host "  MFT valid data: $([Math]::Round($mftValidBytes / 1MB, 2)) MB" -ForegroundColor Green
                                }
                                if ($null -ne $estimatedRecords) {
                                    Write-Host "  Estimated MFT records: $estimatedRecords" -ForegroundColor Green
                                }
                            }
                        }
                        catch {
                            Write-Warning "Failed to collect MFT summary - $_"
                            $result.Notes += "MFT summary collection failed: $_"
                        }
                    }

                    'MftTimestompScan' {
                        Write-Host "`n[*] Scanning live in-use MFT records for SI/FN timestomp candidates..." -ForegroundColor Cyan

                        if (-not $isAdmin) {
                            $result.Notes += "Native MFT SI/FN scanning was skipped: administrator elevation is required to open the NTFS volume."
                            $result.Summary.StopReason = 'ElevationRequired'
                        }
                        else {
                            try {
                                $nativeResult = Get-MftNative -DriveLetter $drive -MaxRecords $MaxRecords -MaxSeconds $MaxSeconds -IncludeAll:$IncludeAll
                                foreach ($note in @($nativeResult.Notes)) {
                                    $result.Notes += $note
                                }
                                if ($nativeResult.Error) {
                                    $result.Notes += "Native MFT collection status: $($nativeResult.Error)"
                                }

                                $allRecords = @($nativeResult.Records)
                                $suspectRecords = @($allRecords | Where-Object { $_.TimestompSuspect })
                                $result.Records = if ($IncludeAll) { $allRecords } else { $suspectRecords }
                                $result.Summary = $mftSummaryTemplate.Clone()
                                $result.Summary.RecordsScanned = [long]$nativeResult.RecordsScanned
                                $result.Summary.NativeRecordsReturned = [long]$nativeResult.RecordsScanned
                                $result.Summary.ReturnedRecords = $allRecords.Count
                                $result.Summary.SuspectCount = [int]$nativeResult.SuspectCount
                                $result.Summary.MalformedRecords = [int]$nativeResult.MalformedRecords
                                $result.Summary.AttributeListRecords = [int]$nativeResult.AttributeListRecords
                                $result.Summary.MissingStandardInformation = [int]$nativeResult.MissingStandardInformation
                                $result.Summary.MissingFileName = [int]$nativeResult.MissingFileName
                                $result.Summary.ExtensionRecordsSkipped = [int]$nativeResult.ExtensionRecordsSkipped
                                $result.Summary.NotInUseRecordsSkipped = [int]$nativeResult.NotInUseRecordsSkipped
                                $result.Summary.SkippedOrdinalCount = [long]$nativeResult.SkippedOrdinalCount
                                $result.Summary.EstimatedMftRecords = [long]$nativeResult.EstimatedMftRecords
                                $result.Summary.BytesPerSector = [int]$nativeResult.BytesPerSector
                                $result.Summary.BytesPerFileRecord = [int]$nativeResult.BytesPerFileRecord
                                $result.Summary.ElapsedMilliseconds = [long]$nativeResult.ElapsedMilliseconds
                                $result.Summary.Success = [bool]$nativeResult.Success
                                $result.Summary.Truncated = [bool]$nativeResult.Truncated
                                $result.Summary.Incomplete = [bool]$nativeResult.Incomplete
                                $result.Summary.StopReason = [string]$nativeResult.StopReason
                                $result.Summary.Source = 'NativeMft'

                                if (-not $nativeResult.Success) {
                                    Write-Warning "Native MFT collection failed: $($nativeResult.Error)"
                                }
                                Write-Host "  Records scanned: $($nativeResult.RecordsScanned); suspects: $($nativeResult.SuspectCount)" -ForegroundColor Green
                            }
                            catch {
                                Write-Warning "Native MFT SI/FN scanning failed: $($_.Exception.Message)"
                                $result.Notes += "Native MFT SI/FN scanning failed without a fallback: $($_.Exception.Message)"
                                $result.Summary = $mftSummaryTemplate.Clone()
                                $result.Summary.StopReason = 'InvocationFailed'
                            }
                        }

                        $result.Notes += "MFT timestomp candidates alert only when raw SI.Created is earlier than FN.Created for any preserved FN attribute. Other raw creation/modified mismatches remain supporting evidence; UTC display and delta fields require .NET-valid FILETIME values."
                        $result.Notes += "FSCTL_GET_NTFS_FILE_RECORD returns only in-use records. Skipped ordinals can be unused or uninitialized entries and are not deleted-file evidence."
                        $result.Notes += "Records with attribute lists have limited coverage because extension attributes are not resolved by this scan."
                        $result.Recommendations += "Validate SI/FN candidates against an acquired `$MFT and an independent parser; legitimate installers, restores, copies, and timestamp-preserving tools can produce the same signal (MITRE ATT&CK T1070.006)."
                        $result.Recommendations += "Increase MaxRecords or MaxSeconds and review Summary.StopReason whenever Truncated or Incomplete is true before drawing volume-wide conclusions."
                    }

                    'TimestompScan' {
                        Write-Host "`n[*] Scanning for timestomp indicators..." -ForegroundColor Cyan

                        $creationRecords = @()
                        $journalSource = 'Unavailable'
                        if ($isAdmin) {
                            try {
                                Write-Host "  Reading USN journal for creation-record comparison..." -ForegroundColor Gray
                                $collection = Get-UsnJournalCollection -DriveLetter $drive -MaxRecords $MaxRecords -Elevated
                                foreach ($note in @($collection.Notes)) {
                                    $result.Notes += $note
                                }
                                $fsutilExitCode = $collection.FsutilExitCode
                                if (-not $collection.Success) {
                                    if ($collection.AccessDenied) {
                                        Write-Warning "fsutil denied access to the USN journal (exit code $fsutilExitCode); fsutil requires elevation or access denied; journal comparison will be skipped."
                                        $result.Notes += "USN journal comparison skipped: fsutil requires elevation or access denied."
                                    }
                                    else {
                                        Write-Warning "fsutil usn readjournal failed with exit code $fsutilExitCode; journal comparison will be skipped."
                                        $result.Notes += "USN journal comparison skipped: fsutil exited with code $fsutilExitCode."
                                    }
                                }
                                else {
                                    $journalSource = $collection.Source
                                    $creationRecords = @($collection.Records |
                                        Where-Object { $_.ReasonFlags -contains 'FILE_CREATE' -and $null -ne $_.TimeStamp })
                                    Write-Host "  Loaded $($creationRecords.Count) journal creation records via $journalSource" -ForegroundColor Gray
                                }
                            }
                            catch {
                                Write-Warning "Could not read the USN journal for comparison - $_"
                                $result.Notes += "USN journal comparison skipped: $_"
                            }
                        }
                        else {
                            $result.Notes += "USN journal comparison skipped: elevation required. Only pre-2000/future timestamp anomalies are reported."
                        }

                        $filesScanned = 0
                        $suspicious = @()

                        foreach ($scanPath in @($ScanPaths)) {
                            if ($null -eq $scanPath) { continue }
                            if (-not (Test-Path $scanPath)) {
                                Write-Verbose "Scan path not found: $scanPath"
                                continue
                            }

                            try {
                                Write-Host "  Scanning: $scanPath..." -ForegroundColor Gray

                                $files = @(Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
                                    Select-Object -First $MaxRecords)

                                foreach ($file in $files) {
                                    if ($filesScanned -ge $MaxRecords) { break }
                                    $filesScanned++

                                    $evaluation = Test-TimestompSignature -FileInfo $file -CreationRecords $creationRecords

                                    if ($evaluation.Indicators.Count -gt 0) {
                                        $suspicious += [PSCustomObject]@{
                                            FileName            = $file.Name
                                            FullPath            = $file.FullName
                                            LastWriteTime       = $file.LastWriteTime
                                            CreationTime        = $file.CreationTime
                                            JournalCreationTime = $evaluation.JournalCreationTime
                                            Indicators          = $evaluation.Indicators
                                            Assessment          = 'Heuristic finding - validate with $MFT $FN timestamps before concluding timestomping'
                                        }
                                    }
                                }

                                Write-Host "    Scanned $($files.Count) files" -ForegroundColor Gray
                            }
                            catch {
                                Write-Warning "Could not scan $scanPath - $_"
                            }
                        }

                        $result.Records = $suspicious

                        $backdatedCount = @($suspicious | Where-Object { $_.Indicators -contains 'BACKDATED_SI_TIMESTAMP' }).Count
                        $pre2000Count = @($suspicious | Where-Object { $_.Indicators -contains 'PRE_2000_TIMESTAMP' }).Count
                        $futureCount = @($suspicious | Where-Object { $_.Indicators -contains 'FUTURE_TIMESTAMP' }).Count

                        $result.Summary = @{
                            FilesScanned            = $filesScanned
                            SuspiciousFiles         = $suspicious.Count
                            BackdatedSiCount        = $backdatedCount
                            Pre2000TimestampCount   = $pre2000Count
                            FutureTimestampCount    = $futureCount
                            JournalCreationRecords  = $creationRecords.Count
                            ScanPaths               = @($ScanPaths)
                            Source                  = $journalSource
                        }

                        $result.Notes += "Timestomp detection is a HEURISTIC: a `$SI LastWriteTime earlier than the file's USN journal creation record is a classic timestomp signature, but legitimate tools (archivers, installers, backup restore) also rewrite timestamps."
                        $result.Notes += "Journal records are matched to scanned files by full path when resolvable, otherwise by file name only; name-only matches can produce false positives for files sharing a name in different directories."

                        $result.Recommendations += "Validate flagged files against `$MFT `$FN attribute timestamps before concluding anti-forensic activity (MITRE ATT&CK T1070.006)."
                        $result.Recommendations += "Preserve flagged files and the volume journal before remediation; re-scanning after cleanup destroys evidence."

                        Write-Host "`n  Files scanned: $filesScanned" -ForegroundColor Green
                        Write-Host "  Suspicious files: $($suspicious.Count)" -ForegroundColor $(if ($suspicious.Count -gt 0) { 'Yellow' } else { 'Green' })

                        if ($suspicious.Count -gt 0) {
                            Write-Host "`n  Timestomp indicators (heuristic):" -ForegroundColor Yellow
                            foreach ($hit in ($suspicious | Select-Object -First 25)) {
                                Write-Host "    $($hit.FullPath)" -ForegroundColor Red
                                Write-Host "      `$SI LastWriteTime: $($hit.LastWriteTime) | Journal creation: $($hit.JournalCreationTime) | $($hit.Indicators -join ', ')" -ForegroundColor Gray
                            }
                            if ($suspicious.Count -gt 25) {
                                Write-Host "    ... and $($suspicious.Count - 25) more (see Records / CSV export)" -ForegroundColor Gray
                            }
                        }
                    }
                }

                if ($OutputPath) {
                    Write-Host "`n[*] Exporting records to CSV..." -ForegroundColor Cyan

                    try {
                        $csvPath = $OutputPath
                        if ($csvPath -notmatch '(?i)\.csv$') {
                            $csvPath = "$csvPath.csv"
                        }
                        $parentDir = Split-Path -Path $csvPath -Parent
                        if ($parentDir -and -not (Test-Path $parentDir)) {
                            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
                        }

                        $exportRows = @($result.Records | ForEach-Object {
                            $row = $_
                            $flattened = [ordered]@{}
                            foreach ($prop in $row.PSObject.Properties) {
                                $value = $prop.Value
                                if ($null -ne $value -and $value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                                    $flattened[$prop.Name] = (@($value) -join '|')
                                }
                                elseif ($value -is [datetime]) {
                                    $flattened[$prop.Name] = $value.ToString('yyyy-MM-dd HH:mm:ss')
                                }
                                elseif ($value -is [string] -and $value -match '^[=+\-@\t\r\n]') {
                                    # Prefix formula-leading characters so attacker-controlled
                                    # file names cannot execute when the CSV is opened in a
                                    # spreadsheet application; in-memory records stay pristine
                                    $flattened[$prop.Name] = "'" + $value
                                }
                                else {
                                    $flattened[$prop.Name] = $value
                                }
                            }
                            [PSCustomObject]$flattened
                        })

                        @($exportRows) | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                        Write-Host "  CSV export saved: $csvPath" -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "CSV export failed - $_"
                    }
                }
            }
        }
        catch {
            Write-Error "Error during file system journal analysis - $_"
            throw
        }
    }

    end {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "  FILE SYSTEM JOURNAL ANALYSIS COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green

        Write-Host "`nMode: $($result.Mode)" -ForegroundColor Cyan
        Write-Host "  Records collected: $(@($result.Records).Count)" -ForegroundColor White
        if ($isOfflineMftMode) {
            Write-Host "  Previous records collected: $(@($result.PreviousRecords).Count)" -ForegroundColor White
        }
        Write-Host "  Elevated: $($result.IsElevated)" -ForegroundColor $(if ($result.IsElevated) { 'White' } else { 'Yellow' })

        if ($result.Notes.Count -gt 0) {
            Write-Host "`nCapability Notes:" -ForegroundColor Cyan
            foreach ($note in $result.Notes) {
                Write-Host "  - $note" -ForegroundColor Gray
            }
        }

        if ($result.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Yellow
            foreach ($recommendation in $result.Recommendations) {
                Write-Host "  - $recommendation" -ForegroundColor Gray
            }
        }

        return $result
    }
}

function Get-FsutilOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = @(& fsutil @Arguments 2>&1)
    $script:FsutilLastExitCode = $LASTEXITCODE
    return @($output | ForEach-Object { "$_" })
}

function Get-UsnJournalCollection {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 10000,

        [Parameter()]
        [switch]$Elevated
    )

    $notes = @()
    $nativeAttempted = $false
    $drive = $DriveLetter.Trim().TrimEnd(':', '\')
    if ($drive -cnotmatch '^[A-Za-z]$') {
        $validationMessage = "Invalid DriveLetter '$drive': exactly one ASCII letter is required. Collection was skipped."
        Write-Warning $validationMessage
        return [PSCustomObject]@{
            Records          = @()
            Success          = $false
            Error            = $validationMessage
            Source           = 'Unavailable'
            NextUsn          = [long]0
            FsutilExitCode   = $null
            AccessDenied     = $false
            NativeAttempted  = $false
            Incomplete       = $false
            Notes            = @($validationMessage)
        }
    }
    $DriveLetter = $drive.ToUpperInvariant()

    if ($Elevated) {
        $nativeAttempted = $true
        $nativeResult = $null
        $nativeError = $null

        try {
            $nativeResult = Get-UsnJournalNative -DriveLetter $DriveLetter -MaxRecords $MaxRecords
        }
        catch {
            $nativeError = "Native USN journal invocation failed: $($_.Exception.Message)"
        }

        if ($null -ne $nativeResult) {
            $notes += @($nativeResult.Notes)
            $nativeError = $nativeResult.Error
            $nativeRecords = @($nativeResult.Records)

            if ($nativeResult.Success -or $nativeRecords.Count -gt 0) {
                $mappedRecords = @($nativeRecords | ForEach-Object {
                    ConvertTo-UsnJournalNativeRecord -NativeRecord $_
                })

                return [PSCustomObject]@{
                    Records          = $mappedRecords
                    Success          = $true
                    Error            = $nativeError
                    Source           = 'Native'
                    NextUsn          = [long]$nativeResult.NextUsn
                    FsutilExitCode   = $null
                    AccessDenied     = $false
                    NativeAttempted  = $true
                    Incomplete       = [bool]$nativeResult.Incomplete
                    Notes            = $notes
                }
            }
        }

        $notes += 'native journal read unavailable; using fsutil (English-locale output required)'
        if ($null -ne $nativeResult -and $null -ne $nativeResult.PSObject.Properties['UnavailableReason'] -and
            $nativeResult.UnavailableReason -eq 'ConstrainedLanguage') {
            $notes += 'Native USN journal reading was skipped because effective ConstrainedLanguage does not permit dynamic compilation (reason: ConstrainedLanguage).'
        }
        if ($nativeError) {
            $notes += "Native USN journal read failed before collection: $nativeError"
        }
    }

    $rawLines = @(Get-FsutilOutput -Arguments @('usn', 'readjournal', "$DriveLetter`:"))
    $fsutilExitCode = $script:FsutilLastExitCode
    $accessDenied = ($fsutilExitCode -eq 1 -or $fsutilExitCode -eq 5)

    if ($fsutilExitCode -ne 0) {
        return New-Object PSObject -Property ([ordered]@{
            Records          = @()
            Success          = $false
            Error            = "fsutil usn readjournal failed with exit code $fsutilExitCode."
            Source           = 'Fsutil'
            NextUsn          = [long]0
            FsutilExitCode   = $fsutilExitCode
            AccessDenied     = $accessDenied
            NativeAttempted  = $nativeAttempted
            Incomplete       = $false
            Notes            = $notes
        })
    }

    $journalRecords = @(ConvertFrom-UsnJournalOutput -Lines $rawLines -MaxRecords $MaxRecords)
    return New-Object PSObject -Property ([ordered]@{
        Records          = $journalRecords
        Success          = $true
        Error            = $null
        Source           = 'Fsutil'
        NextUsn          = [long]0
        FsutilExitCode   = $fsutilExitCode
        AccessDenied     = $false
        NativeAttempted  = $nativeAttempted
        Incomplete       = $false
        Notes            = $notes
    })
}

function ConvertTo-UsnJournalNativeRecord {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$NativeRecord
    )

    $reasonMask = [uint32]$NativeRecord.ReasonMask
    $timeStamp = $null
    $timeStampText = $null
    if ($null -ne $NativeRecord.TimeStamp) {
        $timeStamp = [DateTime]$NativeRecord.TimeStamp
        $timeStampText = $timeStamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($NativeRecord.MajorVersion -eq 3) {
        if ($null -eq $NativeRecord.FileReferenceNumber128 -or $NativeRecord.FileReferenceNumber128.Length -ne 16 -or
            $null -eq $NativeRecord.ParentFileReferenceNumber128 -or $NativeRecord.ParentFileReferenceNumber128.Length -ne 16) {
            throw 'A V3 USN record must contain two complete 16-byte file identifiers.'
        }
        $fileReference = '0x' + ([BitConverter]::ToString($NativeRecord.FileReferenceNumber128)).Replace('-', '').ToLowerInvariant()
        $parentReference = '0x' + ([BitConverter]::ToString($NativeRecord.ParentFileReferenceNumber128)).Replace('-', '').ToLowerInvariant()
    }
    else {
        $fileReference = '0x' + ([uint64]$NativeRecord.FileReferenceNumber).ToString('x')
        $parentReference = '0x' + ([uint64]$NativeRecord.ParentFileReferenceNumber).ToString('x')
    }

    $reasonFlags = @(Get-UsnReasonFlagNames -Mask $reasonMask)
    $reason = '0x' + $reasonMask.ToString('x8')
    if ($reasonFlags.Count -gt 0) {
        $reason += ': ' + ($reasonFlags -join ' | ')
    }

    return [PSCustomObject]@{
        FileName                  = [string]$NativeRecord.FileName
        FullPath                  = $null
        Reason                    = $reason
        ReasonMask                = $reasonMask
        ReasonFlags               = $reasonFlags
        TimeStamp                 = $timeStamp
        TimeStampText             = $timeStampText
        Usn                       = '0x' + ([long]$NativeRecord.Usn).ToString('x')
        FileReferenceNumber       = $fileReference
        ParentFileReferenceNumber = $parentReference
    }
}

function Test-JournalElevation {
    [CmdletBinding()]
    param()

    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function ConvertFrom-UsnJournalOutput {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Lines = @(),

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 10000
    )

    $records = @()
    $current = $null

    foreach ($line in $Lines) {
        if ($records.Count -ge $MaxRecords) { break }
        if ($null -eq $line -or $line -match '^\s*$') { continue }

        if ($line -match '(?i)USN_RECORD') {
            if ($null -ne $current) {
                $records += (New-UsnJournalRecord -Fields $current)
            }
            $current = @{}
            continue
        }

        if ($line -notmatch '^\s*(?<key>[^:=]+?)\s*:\s*(?<value>.*)$') {
            Write-Verbose "Skipping unrecognized journal line: $line"
            continue
        }

        $rawKey = $Matches.key.Trim()
        $value = $Matches.value.Trim()

        $normalizedKey = $null
        if ($rawKey -match '^(?i)file name$') { $normalizedKey = 'FileName' }
        elseif ($rawKey -match '^(?i)reason$') { $normalizedKey = 'Reason' }
        elseif ($rawKey -match '^(?i)time stamp$') { $normalizedKey = 'TimeStamp' }
        elseif ($rawKey -match '^(?i)usn$') { $normalizedKey = 'Usn' }
        elseif ($rawKey -match '^(?i)file reference number$') { $normalizedKey = 'FileReferenceNumber' }

        if ($null -eq $normalizedKey) {
            Write-Verbose "Skipping unrecognized journal field '$rawKey' in line: $line"
            continue
        }

        if ($null -eq $current) {
            $current = @{}
        }

        if ($current.ContainsKey($normalizedKey)) {
            $records += (New-UsnJournalRecord -Fields $current)
            if ($records.Count -ge $MaxRecords) { break }
            $current = @{}
        }

        $current[$normalizedKey] = $value
    }

    if ($null -ne $current -and $records.Count -lt $MaxRecords -and @($current.Keys).Count -gt 0) {
        $records += (New-UsnJournalRecord -Fields $current)
    }

    if ($records.Count -eq 0) {
        $contentLines = @($Lines | Where-Object { $null -ne $_ -and $_ -notmatch '^\s*$' })
        if ($contentLines.Count -gt 0) {
            Write-Warning "fsutil returned USN journal output but no records could be parsed; localized fsutil output is not supported (English locale required for USN journal parsing)."
        }
    }

    return @($records)
}

function New-UsnJournalRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Fields
    )

    $fileName = if ($Fields.ContainsKey('FileName')) { $Fields['FileName'] } else { $null }
    $reasonText = if ($Fields.ContainsKey('Reason')) { $Fields['Reason'] } else { '' }
    $timeStampText = if ($Fields.ContainsKey('TimeStamp')) { $Fields['TimeStamp'] } else { $null }
    $usnText = if ($Fields.ContainsKey('Usn')) { $Fields['Usn'] } else { $null }
    $fileReference = if ($Fields.ContainsKey('FileReferenceNumber')) { $Fields['FileReferenceNumber'] } else { $null }

    $reasonMask = $null
    $maskMatch = [regex]::Match($reasonText, '0x(?<hex>[0-9A-Fa-f]+)')
    if ($maskMatch.Success) {
        try {
            $reasonMask = [Convert]::ToUInt32($maskMatch.Groups['hex'].Value, 16)
        }
        catch {
            $reasonMask = $null
        }
    }

    $reasonFlags = @()
    if ($null -ne $reasonMask) {
        $reasonFlags = @(Get-UsnReasonFlagNames -Mask $reasonMask)
    }
    if ($reasonFlags.Count -eq 0 -and $reasonText) {
        $reasonFlags = @(Get-UsnReasonFlagNames -ReasonText $reasonText)
    }

    $timeStamp = $null
    if ($timeStampText) {
        $parsedDate = [datetime]::MinValue
        if ([datetime]::TryParse($timeStampText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
            $timeStamp = $parsedDate
        }
        else {
            Write-Verbose "Could not parse journal time stamp '$timeStampText' with the invariant culture; localized fsutil timestamps require an English locale. TimeStamp is set to null."
        }
    }

    return [PSCustomObject]@{
        FileName            = $fileName
        FullPath            = $null
        Reason              = $reasonText
        ReasonMask          = $reasonMask
        ReasonFlags         = $reasonFlags
        TimeStamp           = $timeStamp
        TimeStampText       = $timeStampText
        Usn                       = $usnText
        FileReferenceNumber       = $fileReference
        ParentFileReferenceNumber = $null
    }
}

function Get-UsnReasonFlagNames {
    [CmdletBinding()]
    param(
        [Parameter()]
        [uint32]$Mask = 0,

        [Parameter()]
        [string]$ReasonText
    )

    $flagMap = [ordered]@{
        'DATA_OVERWRITE'        = [uint32]0x00000001
        'DATA_EXTEND'           = [uint32]0x00000002
        'DATA_TRUNCATION'       = [uint32]0x00000004
        'NAMED_DATA_OVERWRITE'  = [uint32]0x00000010
        'NAMED_DATA_EXTEND'     = [uint32]0x00000020
        'NAMED_DATA_TRUNCATION' = [uint32]0x00000040
        'FILE_CREATE'           = [uint32]0x00000100
        'FILE_DELETE'           = [uint32]0x00000200
        'EA_CHANGE'             = [uint32]0x00000400
        'SECURITY_CHANGE'       = [uint32]0x00000800
        'RENAME_OLD_NAME'       = [uint32]0x00001000
        'RENAME_NEW_NAME'       = [uint32]0x00002000
        'INDEXABLE_CHANGE'      = [uint32]0x00004000
        'BASIC_INFO_CHANGE'     = [uint32]0x00008000
        'HARD_LINK_CHANGE'      = [uint32]0x00010000
        'COMPRESSION_CHANGE'    = [uint32]0x00020000
        'ENCRYPTION_CHANGE'     = [uint32]0x00040000
        'OBJECT_ID_CHANGE'      = [uint32]0x00080000
        'REPARSE_POINT_CHANGE'  = [uint32]0x00100000
        'STREAM_CHANGE'         = [uint32]0x00200000
        'TRANSACTED_CHANGE'     = [uint32]0x00400000
        'INTEGRITY_CHANGE'      = [uint32]0x00800000
        'CLOSE'                 = [uint32]2147483648
    }

    $names = @()

    if ($Mask -ne 0) {
        foreach ($flagName in $flagMap.Keys) {
            if (($Mask -band $flagMap[$flagName]) -eq $flagMap[$flagName]) {
                $names += $flagName
            }
        }
    }
    elseif ($ReasonText) {
        $haystack = ($ReasonText.ToUpper() -replace '[^A-Z0-9]', '')
        foreach ($flagName in $flagMap.Keys) {
            $needle = $flagName -replace '_', ''
            if ($haystack.Contains($needle)) {
                $names += $flagName
            }
        }
    }

    return @($names)
}

function Resolve-UsnJournalPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DriveLetter = 'C',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileReferenceNumber
    )

    try {
        $drive = $DriveLetter.Trim().TrimEnd(':', '\').ToUpper()
        $output = @(Get-FsutilOutput -Arguments @('file', 'queryfilenamebyid', "$drive`:\", $FileReferenceNumber))

        foreach ($line in $output) {
            if ($null -ne $line -and $line -match '\\\\\?\\(?<path>.+?)\s*$') {
                return $Matches.path
            }
        }

        Write-Verbose "No path returned for file reference number $FileReferenceNumber (file may be deleted)."
    }
    catch {
        Write-Verbose "Path resolution failed for file reference number $FileReferenceNumber - $_"
    }

    return $null
}

function ConvertFrom-JournalNumericText {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $cleaned = $Text.Trim()
    try {
        if ($cleaned -match '0x(?<hex>[0-9A-Fa-f]+)') {
            return [Convert]::ToUInt64($Matches.hex, 16)
        }
        $digitsOnly = $cleaned -replace '[^0-9]', ''
        if ($digitsOnly) {
            return [Convert]::ToUInt64($digitsOnly, 10)
        }
    }
    catch {
        Write-Verbose "Could not parse numeric value: $Text"
    }

    return $null
}

function Test-TimestompSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$FileInfo,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$CreationRecords = @()
    )

    $indicators = @()

    $lastWriteUtc = $null
    if ($null -ne $FileInfo.PSObject.Properties['LastWriteTimeUtc'] -and $null -ne $FileInfo.LastWriteTimeUtc) {
        $lastWriteUtc = [datetime]$FileInfo.LastWriteTimeUtc
        if ($lastWriteUtc.Kind -eq [DateTimeKind]::Local) {
            $lastWriteUtc = $lastWriteUtc.ToUniversalTime()
        }
        elseif ($lastWriteUtc.Kind -eq [DateTimeKind]::Unspecified) {
            $lastWriteUtc = [datetime]::SpecifyKind($lastWriteUtc, [DateTimeKind]::Utc)
        }
    }
    elseif ($null -ne $FileInfo.PSObject.Properties['LastWriteTime'] -and $null -ne $FileInfo.LastWriteTime) {
        $lastWriteUtc = [datetime]$FileInfo.LastWriteTime
        if ($lastWriteUtc.Kind -eq [DateTimeKind]::Unspecified) {
            $lastWriteUtc = [datetime]::SpecifyKind($lastWriteUtc, [DateTimeKind]::Local)
        }
        $lastWriteUtc = $lastWriteUtc.ToUniversalTime()
    }

    $fileName = $null
    if ($null -ne $FileInfo.PSObject.Properties['Name']) {
        $fileName = $FileInfo.Name
    }
    $fullName = $null
    if ($null -ne $FileInfo.PSObject.Properties['FullName']) {
        $fullName = $FileInfo.FullName
    }

    $journalCreationTime = $null
    $journalCreationTimeUtc = $null
    foreach ($record in @($CreationRecords)) {
        if ($null -eq $record -or $null -eq $record.TimeStamp) { continue }

        $pathMatch = ($null -ne $record.FullPath -and $null -ne $fullName -and $record.FullPath -ieq $fullName)
        $nameMatch = ($null -eq $record.FullPath -and $null -ne $record.FileName -and $null -ne $fileName -and $record.FileName -ieq $fileName)
        if (-not ($pathMatch -or $nameMatch)) { continue }

        $recordTimeUtc = [datetime]$record.TimeStamp
        if ($recordTimeUtc.Kind -eq [DateTimeKind]::Unspecified) {
            $recordTimeUtc = [datetime]::SpecifyKind($recordTimeUtc, [DateTimeKind]::Local)
        }
        if ($recordTimeUtc.Kind -ne [DateTimeKind]::Utc) {
            $recordTimeUtc = $recordTimeUtc.ToUniversalTime()
        }

        if ($null -eq $journalCreationTimeUtc -or [DateTime]::Compare($recordTimeUtc, $journalCreationTimeUtc) -gt 0) {
            $journalCreationTime = $record.TimeStamp
            $journalCreationTimeUtc = $recordTimeUtc
        }
    }

    if ($null -ne $lastWriteUtc) {
        if ($null -ne $journalCreationTimeUtc -and [DateTime]::Compare($lastWriteUtc, $journalCreationTimeUtc) -lt 0) {
            $indicators += 'BACKDATED_SI_TIMESTAMP'
        }
        $pre2000Utc = [datetime]::SpecifyKind([datetime]'2000-01-01', [DateTimeKind]::Utc)
        if ([DateTime]::Compare($lastWriteUtc, $pre2000Utc) -lt 0) {
            $indicators += 'PRE_2000_TIMESTAMP'
        }
        if ([DateTime]::Compare($lastWriteUtc, [DateTime]::UtcNow) -gt 0) {
            $indicators += 'FUTURE_TIMESTAMP'
        }
    }

    return [PSCustomObject]@{
        Indicators          = @($indicators)
        JournalCreationTime = $journalCreationTime
    }
}
