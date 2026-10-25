function Get-UserActivityArtifacts {
    <#
    .SYNOPSIS
        Collects user activity forensic artifacts from Windows user profiles
    .DESCRIPTION
        Gathers per-user activity evidence for DFIR investigations:
        - Recycle Bin $I metadata files (header version 2 / Windows 10+): decodes
          original path, file size, and deletion time (FILETIME UTC). Version 1
          headers are decoded best-effort. Unknown versions or malformed headers
          are skipped with Verbose output.
        - Recent + Desktop LNK shortcuts: resolves target path, arguments, and
          working directory via WScript.Shell COM (per-file try/catch; targets
          are reported as unresolved off-Windows or when COM is unavailable).
        - JumpLists: enumerates AutomaticDestinations files with timestamps only.
          Embedded targets are NOT parsed - this is enumeration, labeled as such.
        - Windows Timeline (ActivitiesCache.db): copies the database with a raw
          FileStream (FileShare.ReadWrite fallback for locked files) and reports
          size/mtime only. No SQLite parsing is performed (no dependency).
        MITRE ATT&CK references are heuristic mappings, not assertions.
    .PARAMETER UserProfile
        One or more user profile paths (default: all profiles under C:\Users)
    .PARAMETER RecycleBinRoot
        Root of the Recycle Bin to scan for $I files (default: C:\$Recycle.Bin)
    .PARAMETER OutputPath
        Optional directory for CSV export (RecycleBin.csv, RecentLinks.csv,
        JumpLists.csv, Timeline.csv) and Timeline database copies
    .EXAMPLE
        Get-UserActivityArtifacts
        Get-UserActivityArtifacts -UserProfile "C:\Users\jdoe" -OutputPath "E:\Evidence\UserActivity"
    .OUTPUTS
        PSCustomObject with RecycleBin, RecentLinks, JumpLists, Timeline and Summary
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$UserProfile,

        [Parameter()]
        [string]$RecycleBinRoot = 'C:\$Recycle.Bin',

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        Write-Host "=== USER ACTIVITY ARTIFACTS ===" -ForegroundColor Cyan
        Write-Host "Scan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            ProfilesAnalyzed = @()
            RecycleBin = @()
            RecentLinks = @()
            JumpLists = @()
            Timeline = @()
            Summary = @{
                ProfilesAnalyzed = 0
                RecycleBinEntries = 0
                RecentLinks = 0
                ResolvedLinks = 0
                JumpListFiles = 0
                TimelineDatabases = 0
                Errors = 0
            }
        }

        # Resolve target profiles
        $profiles = @()
        if ($UserProfile) {
            foreach ($profile in $UserProfile) {
                if (Test-Path $profile -PathType Container) {
                    $profiles += (Get-Item $profile).FullName
                }
                else {
                    Write-Warning "User profile not found: $profile"
                }
            }
        }
        else {
            if (Test-Path 'C:\Users' -PathType Container) {
                $profiles = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty FullName)
            }
            else {
                Write-Verbose "Default profile root C:\Users not found - no profiles to analyze"
            }
        }

        # WScript.Shell COM for LNK resolution (Windows only)
        $shellCom = $null
        $lnkResolutionAvailable = $false
        try {
            $shellCom = New-Object -ComObject WScript.Shell -ErrorAction Stop
            $lnkResolutionAvailable = $true
        }
        catch {
            Write-Verbose "WScript.Shell COM unavailable (non-Windows host or restricted) - LNK targets will be reported as unresolved"
        }

        function Read-RecycleBinMetadata {
            param([string]$Path)

            $stream = $null
            $reader = $null
            try {
                $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                if ($stream.Length -lt 24) {
                    Write-Verbose "Skipping $Path - file too small for an `$I header ($($stream.Length) bytes)"
                    return
                }

                $reader = New-Object System.IO.BinaryReader($stream)
                $headerVersion = $reader.ReadInt64()
                $fileSizeBytes = $reader.ReadInt64()
                $deletionFileTime = $reader.ReadInt64()

                $originalPath = $null
                if ($headerVersion -eq 2) {
                    if ($stream.Length -lt 28) {
                        Write-Verbose "Skipping $Path - truncated version 2 header"
                        return
                    }
                    $pathCharCount = $reader.ReadInt32()
                    if ($pathCharCount -le 0 -or $pathCharCount -gt 32767) {
                        Write-Verbose "Skipping $Path - implausible path length $pathCharCount in version 2 header"
                        return
                    }
                    $pathBytes = $reader.ReadBytes($pathCharCount * 2)
                    if ($pathBytes.Length -lt ($pathCharCount * 2)) {
                        Write-Verbose "Skipping $Path - truncated path data in version 2 header"
                        return
                    }
                    $originalPath = [System.Text.Encoding]::Unicode.GetString($pathBytes).TrimEnd([char]0)
                }
                elseif ($headerVersion -eq 1) {
                    if ($stream.Length -lt 544) {
                        Write-Verbose "Skipping $Path - truncated version 1 header"
                        return
                    }
                    $pathBytes = $reader.ReadBytes(520)
                    $rawPath = [System.Text.Encoding]::Unicode.GetString($pathBytes)
                    $nullIndex = $rawPath.IndexOf([char]0)
                    if ($nullIndex -ge 0) {
                        $originalPath = $rawPath.Substring(0, $nullIndex)
                    }
                    else {
                        $originalPath = $rawPath
                    }
                }
                else {
                    Write-Verbose "Skipping $Path - unsupported `$I header version $headerVersion"
                    return
                }

                $deletionTimeUtc = $null
                try {
                    $deletionTimeUtc = [DateTime]::FromFileTimeUtc($deletionFileTime)
                }
                catch {
                    Write-Verbose "Skipping deletion time in $Path - invalid FILETIME value $deletionFileTime"
                }

                return [PSCustomObject]@{
                    OriginalPath = $originalPath
                    FileSizeBytes = $fileSizeBytes
                    DeletionTimeUtc = $deletionTimeUtc
                    HeaderVersion = $headerVersion
                }
            }
            catch {
                Write-Verbose "Could not parse $Path - $_"
                return
            }
            finally {
                if ($null -ne $reader) { $reader.Dispose() }
                if ($null -ne $stream) { $stream.Dispose() }
            }
        }
    }

    process {
        try {
            # 1. RECYCLE BIN $I FILES (system-wide, tagged by owner SID folder)
            Write-Host "`n[1/4] Parsing Recycle Bin `$I metadata files..." -ForegroundColor Cyan

            try {
                if (Test-Path $RecycleBinRoot -PathType Container) {
                    $sidFolders = @(Get-ChildItem -Path $RecycleBinRoot -Directory -Force -ErrorAction SilentlyContinue)
                    $iFiles = @()
                    foreach ($sidFolder in $sidFolders) {
                        $iFiles += @(Get-ChildItem -Path $sidFolder.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue |
                            ForEach-Object { [PSCustomObject]@{ File = $_; OwnerSid = $sidFolder.Name } })
                    }

                    foreach ($entry in $iFiles) {
                        $metadata = Read-RecycleBinMetadata -Path $entry.File.FullName
                        if ($null -eq $metadata) {
                            continue
                        }

                        $results.RecycleBin += [PSCustomObject]@{
                            MetadataFile = $entry.File.FullName
                            OwnerSid = $entry.OwnerSid
                            OriginalPath = $metadata.OriginalPath
                            FileSizeBytes = $metadata.FileSizeBytes
                            DeletionTimeUtc = $metadata.DeletionTimeUtc
                            HeaderVersion = $metadata.HeaderVersion
                            MitreAttack = 'T1074.001 (heuristic - locally staged/deleted data)'
                        }
                    }

                    Write-Host "  Decoded $(@($results.RecycleBin).Count) `$I files ($($iFiles.Count) found)" -ForegroundColor Green
                }
                else {
                    Write-Host "  Recycle Bin root not found: $RecycleBinRoot" -ForegroundColor Gray
                }
            }
            catch {
                Write-Warning "Error parsing Recycle Bin artifacts - $_"
                $results.Summary.Errors++
            }

            # 2. RECENT + DESKTOP LNK SHORTCUTS
            Write-Host "`n[2/4] Analyzing Recent and Desktop shortcuts..." -ForegroundColor Cyan

            foreach ($profile in $profiles) {
                try {
                    $lnkLocations = @(
                        (Join-Path $profile 'AppData\Roaming\Microsoft\Windows\Recent'),
                        (Join-Path $profile 'Desktop')
                    )

                    foreach ($location in $lnkLocations) {
                        if (-not (Test-Path $location -PathType Container)) {
                            continue
                        }

                        $lnkFiles = @(Get-ChildItem -Path $location -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue)

                        foreach ($lnkFile in $lnkFiles) {
                            $targetPath = $null
                            $targetArguments = $null
                            $workingDirectory = $null
                            $resolved = $false

                            if ($lnkResolutionAvailable) {
                                try {
                                    $shortcut = $shellCom.CreateShortcut($lnkFile.FullName)
                                    if ($null -ne $shortcut) {
                                        if ($shortcut.PSObject.Properties['TargetPath']) { $targetPath = $shortcut.TargetPath }
                                        if ($shortcut.PSObject.Properties['Arguments']) { $targetArguments = $shortcut.Arguments }
                                        if ($shortcut.PSObject.Properties['WorkingDirectory']) { $workingDirectory = $shortcut.WorkingDirectory }
                                    }
                                    if (-not [string]::IsNullOrEmpty($targetPath)) {
                                        $resolved = $true
                                    }
                                }
                                catch {
                                    Write-Verbose "Could not resolve shortcut $($lnkFile.FullName) - $_"
                                }
                            }

                            $results.RecentLinks += [PSCustomObject]@{
                                Profile = $profile
                                Location = $(if ($location -like '*\Recent') { 'Recent' } else { 'Desktop' })
                                LinkFile = $lnkFile.FullName
                                LinkLastWriteTime = $lnkFile.LastWriteTime
                                TargetPath = $targetPath
                                TargetArguments = $targetArguments
                                WorkingDirectory = $workingDirectory
                                Resolved = $resolved
                                ResolutionMethod = $(if ($lnkResolutionAvailable) { 'WScript.Shell COM' } else { 'Unavailable (COM not present)' })
                                MitreAttack = 'T1547 (heuristic - shortcut-based persistence indicator)'
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error analyzing shortcuts for profile $profile - $_"
                    $results.Summary.Errors++
                }
            }

            $results.Summary.RecentLinks = @($results.RecentLinks).Count
            $results.Summary.ResolvedLinks = @($results.RecentLinks | Where-Object { $_.Resolved }).Count
            Write-Host "  Processed $($results.Summary.RecentLinks) shortcuts ($($results.Summary.ResolvedLinks) resolved)" -ForegroundColor Green

            # 3. JUMPLISTS (AutomaticDestinations enumeration only)
            Write-Host "`n[3/4] Enumerating JumpList files..." -ForegroundColor Cyan

            foreach ($profile in $profiles) {
                try {
                    $jumpListPath = Join-Path $profile 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'

                    if (Test-Path $jumpListPath -PathType Container) {
                        $jumpListFiles = @(Get-ChildItem -Path $jumpListPath -Filter '*.automaticDestinations-ms' -File -Force -ErrorAction SilentlyContinue)

                        foreach ($jumpListFile in $jumpListFiles) {
                            $results.JumpLists += [PSCustomObject]@{
                                Profile = $profile
                                JumpListFile = $jumpListFile.FullName
                                AppId = $jumpListFile.BaseName
                                SizeBytes = $jumpListFile.Length
                                LastWriteTime = $jumpListFile.LastWriteTime
                                Note = 'Enumeration only - embedded JumpList targets not parsed'
                                MitreAttack = 'T1074.001 (heuristic - user file interaction evidence)'
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error enumerating JumpLists for profile $profile - $_"
                    $results.Summary.Errors++
                }
            }

            $results.Summary.JumpListFiles = @($results.JumpLists).Count
            Write-Host "  Found $($results.Summary.JumpListFiles) JumpList files" -ForegroundColor Green

            # 4. WINDOWS TIMELINE (ActivitiesCache.db copy, size/mtime only)
            Write-Host "`n[4/4] Collecting Windows Timeline databases..." -ForegroundColor Cyan

            foreach ($profile in $profiles) {
                try {
                    $timelineRoot = Join-Path $profile 'AppData\Local\ConnectedDevicesPlatform'

                    if (Test-Path $timelineRoot -PathType Container) {
                        $timelineDbs = @(Get-ChildItem -Path $timelineRoot -Filter 'ActivitiesCache.db' -File -Recurse -Force -ErrorAction SilentlyContinue)

                        foreach ($db in $timelineDbs) {
                            $copiedTo = $null
                            $copySucceeded = $false
                            $copyNote = 'Not copied (no OutputPath specified)'

                            if ($OutputPath) {
                                $timelineCopyDir = Join-Path $OutputPath 'TimelineCopies'
                                if (-not (Test-Path $timelineCopyDir -PathType Container)) {
                                    New-Item -Path $timelineCopyDir -ItemType Directory -Force | Out-Null
                                }

                                $profileName = Split-Path $profile -Leaf
                                $destFile = Join-Path $timelineCopyDir "$($profileName)_$($db.Directory.Name)_ActivitiesCache.db"

                                $sourceStream = $null
                                $destStream = $null
                                try {
                                    # Raw FileStream copy with ReadWrite share to handle locked database
                                    $sourceStream = New-Object System.IO.FileStream($db.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                                    $destStream = New-Object System.IO.FileStream($destFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                                    $sourceStream.CopyTo($destStream)
                                    $copiedTo = $destFile
                                    $copySucceeded = $true
                                    $copyNote = 'Copied via raw FileStream (FileShare.ReadWrite)'
                                }
                                catch {
                                    Write-Warning "ActivitiesCache.db locked or unreadable - skipping copy: $($db.FullName)"
                                    $copyNote = "Copy failed (locked or unreadable): $_"
                                }
                                finally {
                                    if ($null -ne $destStream) { $destStream.Dispose() }
                                    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
                                }
                            }

                            $results.Timeline += [PSCustomObject]@{
                                Profile = $profile
                                DatabasePath = $db.FullName
                                SizeBytes = $db.Length
                                LastWriteTime = $db.LastWriteTime
                                CopiedTo = $copiedTo
                                CopySucceeded = $copySucceeded
                                Note = "Raw copy and metadata only - SQLite parsing not performed (no dependency). $copyNote"
                                MitreAttack = 'T1074.001 (heuristic - user activity timeline evidence)'
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error collecting Timeline for profile $profile - $_"
                    $results.Summary.Errors++
                }
            }

            $results.Summary.TimelineDatabases = @($results.Timeline).Count
            Write-Host "  Found $($results.Summary.TimelineDatabases) Timeline databases" -ForegroundColor Green
        }
        catch {
            Write-Error "Error during user activity artifact collection: $_"
            throw
        }
    }

    end {
        $results.ProfilesAnalyzed = @($profiles)
        $results.Summary.ProfilesAnalyzed = @($profiles).Count
        $results.Summary.RecycleBinEntries = @($results.RecycleBin).Count

        # CSV export
        if ($OutputPath) {
            try {
                if (-not (Test-Path $OutputPath -PathType Container)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }

                if (@($results.RecycleBin).Count -gt 0) {
                    $results.RecycleBin | Export-Csv -Path (Join-Path $OutputPath 'RecycleBin.csv') -NoTypeInformation
                }
                if (@($results.RecentLinks).Count -gt 0) {
                    $results.RecentLinks | Export-Csv -Path (Join-Path $OutputPath 'RecentLinks.csv') -NoTypeInformation
                }
                if (@($results.JumpLists).Count -gt 0) {
                    $results.JumpLists | Export-Csv -Path (Join-Path $OutputPath 'JumpLists.csv') -NoTypeInformation
                }
                if (@($results.Timeline).Count -gt 0) {
                    $results.Timeline | Export-Csv -Path (Join-Path $OutputPath 'Timeline.csv') -NoTypeInformation
                }

                Write-Host "`nCSV exports written to: $OutputPath" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not export CSV files to $OutputPath - $_"
            }
        }

        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "  USER ACTIVITY ANALYSIS COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  Profiles analyzed: $($results.Summary.ProfilesAnalyzed)" -ForegroundColor White
        Write-Host "  Recycle Bin entries: $($results.Summary.RecycleBinEntries)" -ForegroundColor White
        Write-Host "  Recent/Desktop links: $($results.Summary.RecentLinks) ($($results.Summary.ResolvedLinks) resolved)" -ForegroundColor White
        Write-Host "  JumpList files: $($results.Summary.JumpListFiles)" -ForegroundColor White
        Write-Host "  Timeline databases: $($results.Summary.TimelineDatabases)" -ForegroundColor White
        Write-Host "  Errors: $($results.Summary.Errors)" -ForegroundColor $(if($results.Summary.Errors -gt 0){'Yellow'}else{'White'})

        return $results
    }
}
