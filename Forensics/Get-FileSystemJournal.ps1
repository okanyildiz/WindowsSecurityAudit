function Get-FileSystemJournal {
    <#
    .SYNOPSIS
        Parses NTFS USN change journal and file-system metadata for forensic analysis
    .DESCRIPTION
        Reads the NTFS USN change journal via fsutil to surface file creation,
        deletion, and rename activity, summarizes MFT statistics from volume
        metadata, and scans targeted paths for timestomp indicators by comparing
        StandardInformation timestamps against journal creation records.
        Raw $MFT record carving is out of scope; this function operates at the
        summary level exposed by fsutil.
    .PARAMETER DriveLetter
        NTFS volume to analyze (default: C)
    .PARAMETER Mode
        Analysis mode: USNJournal, MFTSummary, or TimestompScan (default: USNJournal)
    .PARAMETER MaxRecords
        Maximum journal records to parse or files to scan (default: 10000)
    .PARAMETER ScanPaths
        Paths scanned in TimestompScan mode (default: user Desktop, Downloads, Temp)
    .PARAMETER OutputPath
        Optional CSV file path for exporting collected records
    .EXAMPLE
        Get-FileSystemJournal -DriveLetter C -Mode USNJournal -MaxRecords 5000
    .EXAMPLE
        Get-FileSystemJournal -Mode TimestompScan -ScanPaths "C:\Users\victim\Downloads" -OutputPath "C:\IR\timestomp.csv"
    .OUTPUTS
        PSCustomObject with Mode, Records, Summary, Notes, and Recommendations
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [ValidateSet('USNJournal', 'MFTSummary', 'TimestompScan')]
        [string]$Mode = 'USNJournal',

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 10000,

        [Parameter()]
        [string[]]$ScanPaths,

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  FILE SYSTEM JOURNAL FORENSICS" -ForegroundColor Cyan
        Write-Host "  USN Journal / MFT / Timestomp Analysis" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Mode: $Mode" -ForegroundColor Yellow
        Write-Host "Drive: $DriveLetter" -ForegroundColor Yellow
        Write-Host "Max Records: $MaxRecords" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

        $drive = $DriveLetter.Trim().TrimEnd(':', '\').ToUpper()

        $isWindowsPlatform = ($env:OS -eq 'Windows_NT')

        $isAdmin = $false
        if ($isWindowsPlatform) {
            $isAdmin = Test-JournalElevation
        }

        $result = [PSCustomObject]@{
            CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName   = $env:COMPUTERNAME
            DriveLetter    = $drive
            Mode           = $Mode
            IsElevated     = $isAdmin
            Records        = @()
            Summary        = @{}
            Notes          = @()
            Recommendations = @()
        }

        if (-not $isWindowsPlatform) {
            Write-Warning "Get-FileSystemJournal requires Windows (NTFS volume + fsutil.exe). Current platform is not Windows."
        }
        elseif (-not $isAdmin) {
            Write-Warning "Administrator privileges are required to read the USN journal and volume metadata. Some sections will be skipped."
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
            if (-not $isWindowsPlatform) {
                $result.Notes += "Platform check failed: NTFS journal and fsutil.exe are only available on Windows. No data was collected."
                $result.Recommendations += "Run this function on a Windows host against an NTFS volume."
            }
            else {
                switch ($Mode) {

                    'USNJournal' {
                        Write-Host "`n[*] Reading USN change journal on $drive`:..." -ForegroundColor Cyan

                        try {
                            $rawLines = @(Get-FsutilOutput -Arguments @('usn', 'readjournal', "$drive`:"))
                            $fsutilExitCode = $script:FsutilLastExitCode

                            if ($fsutilExitCode -ne 0) {
                                if ($fsutilExitCode -eq 5) {
                                    Write-Warning "fsutil denied access to the USN journal (exit code 5). Rerun from an elevated prompt."
                                    $result.Notes += "USN journal read failed: fsutil requires administrative privileges."
                                }
                                else {
                                    Write-Warning "fsutil usn readjournal failed with exit code $fsutilExitCode."
                                    $result.Notes += "USN journal read failed: fsutil exited with code $fsutilExitCode."
                                }
                            }
                            else {
                                $journalRecords = @(ConvertFrom-UsnJournalOutput -Lines $rawLines -MaxRecords $MaxRecords)
                                Write-Host "  Parsed $($journalRecords.Count) journal records" -ForegroundColor Green

                                $resolveCap = 250
                                $resolveCount = 0
                                $pathCache = @{}
                                foreach ($record in $journalRecords) {
                                    if ($null -eq $record.FileReferenceNumber) { continue }
                                    if ($pathCache.ContainsKey($record.FileReferenceNumber)) {
                                        $record.FullPath = $pathCache[$record.FileReferenceNumber]
                                        continue
                                    }
                                    if ($resolveCount -ge $resolveCap) { continue }
                                    $resolveCount++
                                    $resolvedPath = Resolve-UsnJournalPath -DriveLetter $drive -FileReferenceNumber $record.FileReferenceNumber
                                    $pathCache[$record.FileReferenceNumber] = $resolvedPath
                                    if ($resolvedPath) {
                                        $record.FullPath = $resolvedPath
                                    }
                                }
                                Write-Verbose "Resolved full paths for $resolveCount unique file reference numbers (cap $resolveCap)."
                                if ($journalRecords.Count -gt $resolveCap) {
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
                                }

                                $result.Notes += "Journal output is text-parsed from 'fsutil usn readjournal'; fields are limited to what fsutil prints (file name, reason bitmask, time stamp, USN, file reference number)."
                                $result.Notes += "The journal is circular; records shown cover only the window fsutil returned and older history may already be overwritten."

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
                                if ($fsutilExitCode -eq 5) {
                                    Write-Warning "fsutil denied access to volume metadata (exit code 5). Rerun from an elevated prompt."
                                    $result.Notes += "MFT summary collection failed: fsutil requires administrative privileges."
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
                                }

                                $result.Notes += "Summary-level view only: values come from 'fsutil fsinfo ntfsinfo' volume metadata."
                                $result.Notes += "Raw `$MFT record parsing (per-entry `$SI/`$FN attribute decoding) requires direct disk access or third-party libraries and is intentionally out of scope for this function."

                                $result.Recommendations += "For per-record `$MFT analysis, pair this summary with a dedicated parser (e.g., MFTECmd) run against an acquired `$MFT copy."
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

                    'TimestompScan' {
                        Write-Host "`n[*] Scanning for timestomp indicators..." -ForegroundColor Cyan

                        $creationRecords = @()
                        if ($isAdmin) {
                            try {
                                Write-Host "  Reading USN journal for creation-record comparison..." -ForegroundColor Gray
                                $rawLines = @(Get-FsutilOutput -Arguments @('usn', 'readjournal', "$drive`:"))
                                $fsutilExitCode = $script:FsutilLastExitCode
                                if ($fsutilExitCode -ne 0) {
                                    if ($fsutilExitCode -eq 5) {
                                        Write-Warning "fsutil denied access to the USN journal (exit code 5); journal comparison will be skipped."
                                        $result.Notes += "USN journal comparison skipped: fsutil requires administrative privileges."
                                    }
                                    else {
                                        Write-Warning "fsutil usn readjournal failed with exit code $fsutilExitCode; journal comparison will be skipped."
                                        $result.Notes += "USN journal comparison skipped: fsutil exited with code $fsutilExitCode."
                                    }
                                }
                                else {
                                    $creationRecords = @(ConvertFrom-UsnJournalOutput -Lines $rawLines -MaxRecords $MaxRecords |
                                        Where-Object { $_.ReasonFlags -contains 'FILE_CREATE' -and $null -ne $_.TimeStamp })
                                    Write-Host "  Loaded $($creationRecords.Count) journal creation records" -ForegroundColor Gray
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
        Usn                 = $usnText
        FileReferenceNumber = $fileReference
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

    $lastWrite = $null
    if ($null -ne $FileInfo.PSObject.Properties['LastWriteTime'] -and $null -ne $FileInfo.LastWriteTime) {
        $lastWrite = $FileInfo.LastWriteTime
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
    foreach ($record in @($CreationRecords)) {
        if ($null -eq $record -or $null -eq $record.TimeStamp) { continue }

        $pathMatch = ($null -ne $record.FullPath -and $null -ne $fullName -and $record.FullPath -ieq $fullName)
        $nameMatch = ($null -eq $record.FullPath -and $null -ne $record.FileName -and $null -ne $fileName -and $record.FileName -ieq $fileName)

        if (($pathMatch -or $nameMatch) -and ($null -eq $journalCreationTime -or $record.TimeStamp -gt $journalCreationTime)) {
            $journalCreationTime = $record.TimeStamp
        }
    }

    if ($null -ne $lastWrite) {
        if ($null -ne $journalCreationTime -and $lastWrite -lt $journalCreationTime) {
            $indicators += 'BACKDATED_SI_TIMESTAMP'
        }
        if ($lastWrite -lt [datetime]'2000-01-01') {
            $indicators += 'PRE_2000_TIMESTAMP'
        }
        if ($lastWrite -gt (Get-Date)) {
            $indicators += 'FUTURE_TIMESTAMP'
        }
    }

    return [PSCustomObject]@{
        Indicators          = @($indicators)
        JournalCreationTime = $journalCreationTime
    }
}
