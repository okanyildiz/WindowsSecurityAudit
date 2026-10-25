function Compare-SecurityBaseline {
    <#
    .SYNOPSIS
        Compares a saved security baseline against a current security state and reports drift
    .DESCRIPTION
        Loads a previously saved security baseline from JSON (for example the output of
        Get-SecurityBaseline or Invoke-SecurityAssessment piped to ConvertTo-Json) and compares
        it against a second state. The current state is either loaded from a second JSON file
        (-CurrentPath) or captured live via Get-SecurityBaseline when -CurrentPath is omitted.
        Every differing property is classified as Improved, Degraded, New, Removed, or Changed,
        and a summary with an overall trend is produced. Results can optionally be exported as
        JSON (full result) and CSV (changes only) via -OutputPath.
    .PARAMETER BaselinePath
        Path to the previously saved baseline JSON file (mandatory)
    .PARAMETER CurrentPath
        Path to a JSON file containing the current state. When omitted, the current state is
        captured live by calling Get-SecurityBaseline
    .PARAMETER OutputPath
        Directory where the comparison result (JSON) and the list of changes (CSV) are written
    .EXAMPLE
        Compare-SecurityBaseline -BaselinePath "C:\Audits\baseline.json"
        Compares the saved baseline against the live system state
    .EXAMPLE
        Compare-SecurityBaseline -BaselinePath "C:\Audits\baseline.json" -CurrentPath "C:\Audits\current.json" -OutputPath "C:\Audits\Drift"
        Compares two saved states and exports the result as JSON and CSV
    .OUTPUTS
        PSCustomObject with CompareDate, Categories, Changes, and Summary properties
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$BaselinePath,

        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$CurrentPath,

        [Parameter(Position = 2)]
        [string]$OutputPath
    )

    begin {
        Write-Host "Starting Security Baseline Comparison..." -ForegroundColor Cyan

        # Properties that hold volatile timestamps are excluded from drift detection
        $script:noisePattern = '(^|\.)(ScanDate|CollectionDate|CompareDate|LastBootUpTime|LocalDateTime|InstallDate|LastUpdateCheck)$'

        $changes = @()
        $unchangedCount = 0
        $categories = @()

        # Flattens a nested PSCustomObject/array graph into a path -> leaf-value map
        function ConvertTo-FlatMap {
            param(
                [object]$Node,
                [string]$Path,
                [hashtable]$Map
            )

            if ($null -eq $Node) {
                $Map[$Path] = '(null)'
                return
            }

            if ($Node -is [System.Management.Automation.PSCustomObject]) {
                foreach ($prop in $Node.PSObject.Properties) {
                    $childPath = if ($Path) { "$Path.$($prop.Name)" } else { $prop.Name }
                    ConvertTo-FlatMap -Node $prop.Value -Path $childPath -Map $Map
                }
            }
            elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
                $items = @($Node)
                if ($items.Count -eq 0) {
                    $Map[$Path] = '(empty)'
                }
                for ($i = 0; $i -lt $items.Count; $i++) {
                    ConvertTo-FlatMap -Node $items[$i] -Path "$Path[$i]" -Map $Map
                }
            }
            else {
                $Map[$Path] = "$Node"
            }
        }

        # Maps boolean-like strings to numbers so direction of change can be determined
        function ConvertTo-ComparableValue {
            param([string]$Value)

            if ($null -eq $Value) { return $null }
            switch -Regex ($Value) {
                '^(True|On|Enabled|Yes|1)$'  { return 1.0 }
                '^(False|Off|Disabled|No|0)$' { return 0.0 }
            }
            $number = 0.0
            if ([double]::TryParse($Value, [ref]$number)) { return $number }
            return $null
        }

        # Decides whether a changed value is an improvement or a degradation
        function Get-ChangeDirection {
            param(
                [string]$Path,
                [string]$BaselineValue,
                [string]$CurrentValue
            )

            $goodDirection = 0  # 1 = higher is better, -1 = lower is better, 0 = unknown
            switch -Regex ($Path) {
                'PendingUpdates|Vulnerabilit|Issue|Error|Failed|Risk|Threat|Exposure' { $goodDirection = -1; break }
                'Enabled|Protection|EnableLUA|Encryption|Score|Secure|Compliant|Health' { $goodDirection = 1; break }
            }

            if ($goodDirection -eq 0) { return 'Changed' }

            $baseNumber = ConvertTo-ComparableValue -Value $BaselineValue
            $currentNumber = ConvertTo-ComparableValue -Value $CurrentValue
            if ($null -eq $baseNumber -or $null -eq $currentNumber) { return 'Changed' }

            $delta = $currentNumber - $baseNumber
            if ($delta -eq 0) { return 'Changed' }
            if (($delta -gt 0 -and $goodDirection -eq 1) -or ($delta -lt 0 -and $goodDirection -eq -1)) {
                return 'Improved'
            }
            return 'Degraded'
        }
    }

    process {
        try {
            # Load the saved baseline
            Write-Host "Loading baseline from: $BaselinePath" -ForegroundColor Yellow
            try {
                $baselineJson = Get-Content -Path $BaselinePath -Raw -ErrorAction Stop
                $baseline = $baselineJson | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                Write-Error "Could not load baseline file '$BaselinePath': $_"
                throw
            }

            # Load or capture the current state
            $currentSource = "Live capture (Get-SecurityBaseline)"
            $current = $null
            if ($CurrentPath) {
                $currentSource = $CurrentPath
                Write-Host "Loading current state from: $CurrentPath" -ForegroundColor Yellow
                try {
                    $currentJson = Get-Content -Path $CurrentPath -Raw -ErrorAction Stop
                    $current = $currentJson | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    Write-Error "Could not load current state file '$CurrentPath': $_"
                    throw
                }
            }
            else {
                Write-Host "Capturing current state via Get-SecurityBaseline..." -ForegroundColor Yellow
                if (-not (Get-Command -Name Get-SecurityBaseline -ErrorAction SilentlyContinue)) {
                    Write-Error "Get-SecurityBaseline is not available. Provide -CurrentPath or load the WindowsSecurityAudit module."
                    throw "Get-SecurityBaseline not found"
                }
                try {
                    $current = Get-SecurityBaseline -ErrorAction Stop
                }
                catch {
                    Write-Warning "Live capture with Get-SecurityBaseline failed: $_"
                    throw
                }
            }

            # Flatten both states into comparable maps
            Write-Host "Comparing security states..." -ForegroundColor Yellow
            $baselineMap = @{}
            $currentMap = @{}
            ConvertTo-FlatMap -Node $baseline -Path '' -Map $baselineMap
            ConvertTo-FlatMap -Node $current -Path '' -Map $currentMap

            # Build the list of compared categories (top-level property names)
            $categorySet = @{}
            foreach ($key in @($baselineMap.Keys) + @($currentMap.Keys)) {
                if ($key -match $script:noisePattern) { continue }
                $topLevel = ($key -split '\.')[0] -replace '\[.*$', ''
                if ($topLevel) { $categorySet[$topLevel] = $true }
            }
            $categories = @($categorySet.Keys | Sort-Object)

            # Detect changed, new, and removed properties
            foreach ($key in @($baselineMap.Keys | Sort-Object)) {
                if ($key -match $script:noisePattern) { continue }

                $baselineValue = $baselineMap[$key]
                if (-not $currentMap.ContainsKey($key)) {
                    $changes += [PSCustomObject]@{
                        Property       = $key
                        BaselineValue  = $baselineValue
                        CurrentValue   = '(missing)'
                        ChangeType     = 'Removed'
                    }
                    continue
                }

                $currentValue = $currentMap[$key]
                if ($baselineValue -eq $currentValue) {
                    $unchangedCount++
                }
                else {
                    $changes += [PSCustomObject]@{
                        Property       = $key
                        BaselineValue  = $baselineValue
                        CurrentValue   = $currentValue
                        ChangeType     = (Get-ChangeDirection -Path $key -BaselineValue $baselineValue -CurrentValue $currentValue)
                    }
                }
            }

            foreach ($key in @($currentMap.Keys | Sort-Object)) {
                if ($key -match $script:noisePattern) { continue }
                if (-not $baselineMap.ContainsKey($key)) {
                    $changes += [PSCustomObject]@{
                        Property       = $key
                        BaselineValue  = '(missing)'
                        CurrentValue   = $currentMap[$key]
                        ChangeType     = 'New'
                    }
                }
            }

            $changes = @($changes | Sort-Object ChangeType, Property)
        }
        catch {
            Write-Error "Error during security baseline comparison: $_"
            throw
        }
    }

    end {
        # Build summary
        $improvedCount = @($changes | Where-Object { $_.ChangeType -eq 'Improved' }).Count
        $degradedCount = @($changes | Where-Object { $_.ChangeType -eq 'Degraded' }).Count
        $newCount = @($changes | Where-Object { $_.ChangeType -eq 'New' }).Count
        $removedCount = @($changes | Where-Object { $_.ChangeType -eq 'Removed' }).Count

        $overallTrend = 'Stable'
        if ($improvedCount -gt 0 -and $degradedCount -gt 0) {
            $overallTrend = 'Mixed'
        }
        elseif ($improvedCount -gt $degradedCount) {
            $overallTrend = 'Improved'
        }
        elseif ($degradedCount -gt $improvedCount) {
            $overallTrend = 'Degraded'
        }
        elseif ($newCount -gt 0 -or $removedCount -gt 0) {
            $overallTrend = 'Changed'
        }

        $summary = [PSCustomObject]@{
            ImprovedCount  = $improvedCount
            DegradedCount  = $degradedCount
            NewCount       = $newCount
            RemovedCount   = $removedCount
            UnchangedCount = $unchangedCount
            TotalChanges   = @($changes).Count
            OverallTrend   = $overallTrend
        }

        $result = [PSCustomObject]@{
            CompareDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName    = $env:COMPUTERNAME
            BaselineSource  = $BaselinePath
            CurrentSource   = $currentSource
            Categories      = $categories
            Changes         = $changes
            Summary         = $summary
        }

        # Display results
        Write-Host "`nComparison Results" -ForegroundColor Cyan
        Write-Host "------------------" -ForegroundColor Cyan
        if ($changes.Count -eq 0) {
            Write-Host "No drift detected - current state matches the baseline." -ForegroundColor Green
        }
        else {
            foreach ($change in $changes) {
                $color = switch ($change.ChangeType) {
                    'Improved' { 'Green' }
                    'Degraded' { 'Red' }
                    default    { 'Yellow' }
                }
                Write-Host ("[{0}] {1}: '{2}' -> '{3}'" -f $change.ChangeType, $change.Property, $change.BaselineValue, $change.CurrentValue) -ForegroundColor $color
            }
        }
        Write-Host ("Summary: {0} improved, {1} degraded, {2} new, {3} removed, {4} unchanged - Trend: {5}" -f
            $improvedCount, $degradedCount, $newCount, $removedCount, $unchangedCount, $overallTrend) -ForegroundColor Cyan

        # Export results if path specified
        if ($OutputPath) {
            try {
                if (-not (Test-Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                }
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $jsonFile = Join-Path -Path $OutputPath -ChildPath "CompareResult_$timestamp.json"
                $csvFile = Join-Path -Path $OutputPath -ChildPath "CompareChanges_$timestamp.csv"

                $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
                $changes | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8

                Write-Host "Results exported to: $jsonFile" -ForegroundColor Green
                Write-Host "Changes exported to: $csvFile" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not export comparison results to '$OutputPath': $_"
            }
        }

        return $result
    }
}
