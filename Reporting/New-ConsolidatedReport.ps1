function New-ConsolidatedReport {
    <#
    .SYNOPSIS
        Generates ONE interactive HTML report combining all major security modules

    .DESCRIPTION
        Consolidated reporting engine that collects results from the core audit
        functions of the WindowsSecurityAudit module and renders a single,
        self-contained interactive HTML report with embedded Chart.js charts:

        - Assessment     : Invoke-SecurityAssessment
        - Defender       : Get-DefenderStatus
        - Compliance     : Test-CISBenchmark
        - ThreatHunting  : Get-ThreatIntelligence
        - Vulnerability  : Get-VulnerabilityAssessment
        - Forensics      : Get-ArtifactCollection

        Every collector runs inside its own try/catch block. If a collector is
        unavailable, fails, or live collection is skipped, the corresponding
        report section is marked as "Not collected" instead of aborting the
        report.

        The report contains:
        - Summary card grid (security score, findings totals, section status)
        - Doughnut chart of findings by severity (Critical/High/Medium/Low)
        - Bar chart of per-category scores
        - Per-section detail cards

        Chart.js is referenced from the jsDelivr CDN
        (https://cdn.jsdelivr.net/npm/chart.js), so charts require internet
        access when the report is viewed. All other markup is self-contained.

    .PARAMETER OutputPath
        Directory where the HTML report (and optional JSON export) is saved.
        The directory is created if it does not exist.
        Default: current directory

    .PARAMETER IncludeSections
        Report sections to include. Each section maps to one collector function.
        Valid values: Assessment, Defender, Compliance, ThreatHunting,
        Vulnerability, Forensics
        Default: all sections

    .PARAMETER SkipDataCollection
        Do not run any live collector functions. Sections without data supplied
        via -FromJsonPath are marked "Not collected". Useful for testing report
        rendering on systems where the audit functions cannot run.

    .PARAMETER FromJsonPath
        Path to a JSON file with previously saved collector outputs. When
        provided, live data collection is skipped and section data is loaded
        from this file. The JSON must be an object whose property names match
        the section names (Assessment, Defender, Compliance, ThreatHunting,
        Vulnerability, Forensics). Use -SaveJson on a live run to produce a
        compatible file.

    .PARAMETER SaveJson
        Also export the collected raw section data to a timestamped JSON file
        next to the HTML report. The file can be reused later via -FromJsonPath.

    .PARAMETER OpenInBrowser
        Automatically open the generated report in the default browser.

    .EXAMPLE
        New-ConsolidatedReport
        Full consolidated report with live data collection from all six sections

    .EXAMPLE
        New-ConsolidatedReport -IncludeSections Assessment,Defender -OutputPath "C:\Reports"
        Report limited to the Assessment and Defender sections, saved to C:\Reports

    .EXAMPLE
        New-ConsolidatedReport -OutputPath "C:\Reports" -SaveJson
        Live report that also exports the raw collected data as JSON for later reuse

    .EXAMPLE
        New-ConsolidatedReport -FromJsonPath "C:\Reports\ConsolidatedReportData_20251024_120000.json"
        Regenerate the HTML report from previously saved JSON without running collectors

    .OUTPUTS
        PSCustomObject with report metadata (Success, ReportPath, JsonPath,
        SectionsCollected, SectionsNotCollected, TotalFindings, GenerationTime)
        and the HTML file itself:
        - ConsolidatedSecurityReport_YYYYMMDD_HHMMSS.html
        - ConsolidatedReportData_YYYYMMDD_HHMMSS.json (if -SaveJson)

    .NOTES
        Author: WindowsSecurityAudit Module
        Version: 1.0.0

        Requires: PowerShell 5.1 or higher
        Administrator privileges recommended for complete live data collection
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Get-Location).Path,

        [Parameter()]
        [ValidateSet('Assessment', 'Defender', 'Compliance', 'ThreatHunting', 'Vulnerability', 'Forensics')]
        [string[]]$IncludeSections = @('Assessment', 'Defender', 'Compliance', 'ThreatHunting', 'Vulnerability', 'Forensics'),

        [Parameter()]
        [switch]$SkipDataCollection,

        [Parameter()]
        [string]$FromJsonPath,

        [Parameter()]
        [switch]$SaveJson,

        [Parameter()]
        [switch]$OpenInBrowser
    )

    begin {
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  CONSOLIDATED SECURITY REPORT" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan

        $reportStartTime = Get-Date
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        # All supported sections in stable display order
        $allSections = @('Assessment', 'Defender', 'Compliance', 'ThreatHunting', 'Vulnerability', 'Forensics')

        # Map each section to its live collector function
        $sectionCollectors = @{
            Assessment    = 'Invoke-SecurityAssessment'
            Defender      = 'Get-DefenderStatus'
            Compliance    = 'Test-CISBenchmark'
            ThreatHunting = 'Get-ThreatIntelligence'
            Vulnerability = 'Get-VulnerabilityAssessment'
            Forensics     = 'Get-ArtifactCollection'
        }

        # Validate and create output path
        if (-not (Test-Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to create output directory: $_"
                throw
            }
        }

        # Validate JSON input path early (fatal if invalid)
        if ($FromJsonPath) {
            if (-not (Test-Path $FromJsonPath)) {
                Write-Error "JSON input file not found: $FromJsonPath"
                throw "JSON input file not found: $FromJsonPath"
            }
            Write-Host "Mode: OFFLINE - loading data from $FromJsonPath" -ForegroundColor Yellow
        }
        elseif ($SkipDataCollection) {
            Write-Host "Mode: NO COLLECTION - sections will be marked 'Not collected'" -ForegroundColor Yellow
        }
        else {
            Write-Host "Mode: LIVE COLLECTION - $($IncludeSections -join ', ')" -ForegroundColor Yellow
        }
    }

    process {
        try {
            # ============================================
            # HELPER FUNCTIONS (function-scoped, strict-mode safe)
            # ============================================
            function Get-SafeProperty {
                param($Object, $PropertyName, $Default = $null)
                if ($null -eq $Object) { return $Default }
                if ($Object -is [System.Collections.IDictionary]) {
                    if ($Object.Contains($PropertyName)) {
                        $value = $Object[$PropertyName]
                        if ($null -eq $value) { return $Default }
                        return $value
                    }
                    return $Default
                }
                if ($Object.PSObject.Properties[$PropertyName]) {
                    $value = $Object.$PropertyName
                    if ($null -eq $value) { return $Default }
                    return $value
                }
                return $Default
            }

            function Get-SeverityCounts {
                param($Data, [int]$Depth = 0)
                $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
                if ($null -eq $Data) { return $counts }
                if ($Depth -gt 2) { return $counts }

                # Case 1: array of finding objects with a Severity property
                if ($Data -is [array]) {
                    foreach ($item in $Data) {
                        $sev = Get-SafeProperty $item 'Severity' ''
                        switch -Regex ("$sev") {
                            '^Critical' { $counts.Critical++ }
                            '^High'     { $counts.High++ }
                            '^Medium'   { $counts.Medium++ }
                            '^Low'      { $counts.Low++ }
                        }
                    }
                    return $counts
                }

                # Case 2: object (or nested Summary) with numeric severity properties
                # Array-valued properties (e.g. Findings) are inspected recursively
                $containers = @($Data)
                $summary = Get-SafeProperty $Data 'Summary' $null
                if ($null -ne $summary) { $containers += $summary }

                foreach ($container in $containers) {
                    if ($null -eq $container) { continue }
                    $memberPairs = @()
                    if ($container -is [System.Collections.IDictionary]) {
                        foreach ($name in @($container.Keys)) {
                            $memberPairs += [PSCustomObject]@{ Name = "$name"; Value = $container[$name] }
                        }
                    }
                    else {
                        $memberPairs = @($container.PSObject.Properties)
                    }

                    foreach ($member in $memberPairs) {
                        $value = $member.Value
                        if ($value -is [array]) {
                            $nested = Get-SeverityCounts $value ($Depth + 1)
                            $counts.Critical += $nested.Critical
                            $counts.High     += $nested.High
                            $counts.Medium   += $nested.Medium
                            $counts.Low      += $nested.Low
                            continue
                        }
                        $num = $value -as [int]
                        if ($null -eq $num) { continue }
                        if ($member.Name -match 'Total|Score|Percent') { continue }
                        if ($member.Name -match 'Critical') { $counts.Critical += $num }
                        elseif ($member.Name -match 'High') { $counts.High += $num }
                        elseif ($member.Name -match 'Medium') { $counts.Medium += $num }
                        elseif ($member.Name -match 'Low')  { $counts.Low += $num }
                    }
                }

                return $counts
            }

            function Get-SectionScore {
                param($Data)
                if ($null -eq $Data) { return $null }

                # Direct score properties in priority order
                # NOTE: $null -as [double] yields 0, so null must be filtered BEFORE
                # the numeric cast or every missing property would score as 0
                foreach ($name in @('OverallSecurityScore', 'SecurityScore', 'ComplianceScore', 'Score')) {
                    $value = Get-SafeProperty $Data $name $null
                    if ($null -eq $value) { continue }
                    $num = $value -as [double]
                    if ($null -ne $num) { return [Math]::Round($num, 1) }
                }

                # Nested Summary score properties
                $summary = Get-SafeProperty $Data 'Summary' $null
                if ($null -ne $summary) {
                    foreach ($name in @('OverallSecurityScore', 'SecurityScore', 'ComplianceScore', 'CompliancePercentage', 'Score')) {
                        $value = Get-SafeProperty $summary $name $null
                        if ($null -eq $value) { continue }
                        $num = $value -as [double]
                        if ($null -ne $num) { return [Math]::Round($num, 1) }
                    }
                }

                return $null
            }

            function Get-SectionHighlights {
                param($Data, [int]$MaxItems = 8)
                $highlights = @()
                if ($null -eq $Data) { return $highlights }

                # Top-level scalar properties only - safe for arbitrary collector output
                $props = @()
                if ($Data -is [System.Collections.IDictionary]) {
                    foreach ($key in @($Data.Keys)) {
                        $props += [PSCustomObject]@{ Name = "$key"; Value = $Data[$key] }
                    }
                }
                elseif (-not ($Data -is [array]) -and $null -ne $Data.PSObject) {
                    $props = @($Data.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -or $_.MemberType -eq 'Property' })
                }

                foreach ($prop in $props) {
                    if (@($highlights).Count -ge $MaxItems) { break }
                    $value = $prop.Value
                    if ($null -eq $value) { continue }
                    # Only simple scalar values make readable highlights
                    if ($value -is [string] -or $value -is [bool] -or
                        $value -is [int] -or $value -is [long] -or
                        $value -is [double] -or $value -is [datetime] -or
                        $value -is [enum]) {
                        $text = "$value"
                        if ($text.Length -gt 80) { $text = $text.Substring(0, 77) + '...' }
                        $highlights += @{ Label = "$($prop.Name)"; Value = $text }
                    }
                }

                return $highlights
            }

            # ============================================
            # LOAD JSON DATA (if provided)
            # ============================================
            $jsonData = $null
            if ($FromJsonPath) {
                Write-Host "`n[LOADING JSON DATA]" -ForegroundColor Cyan
                try {
                    $jsonData = Get-Content $FromJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    Write-Host "  Loaded: $FromJsonPath" -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to parse JSON input file: $_"
                    throw
                }
            }

            # ============================================
            # COLLECT SECTION DATA
            # ============================================
            Write-Host "`n[DATA COLLECTION PHASE]" -ForegroundColor Cyan

            $sectionResults = @{}
            $sectionIndex = 0

            foreach ($section in $allSections) {
                if (-not ($IncludeSections -contains $section)) { continue }
                $sectionIndex++

                $result = @{
                    Status     = 'Not collected'
                    Data       = $null
                    Score      = $null
                    Findings   = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
                    Highlights = @()
                }

                $jsonSectionData = $null
                if ($null -ne $jsonData) {
                    $jsonSectionData = Get-SafeProperty $jsonData $section $null
                }

                if ($null -ne $jsonSectionData) {
                    # Data supplied from previously saved JSON output
                    $result.Status = 'Loaded from JSON'
                    $result.Data = $jsonSectionData
                    Write-Host "  [$sectionIndex] $section : loaded from JSON" -ForegroundColor Green
                }
                elseif (-not $SkipDataCollection -and -not $FromJsonPath) {
                    # Live collection with per-section error isolation
                    $collectorName = $sectionCollectors[$section]
                    $collectorCmd = Get-Command $collectorName -ErrorAction SilentlyContinue

                    if ($null -eq $collectorCmd) {
                        Write-Warning "  [$sectionIndex] $section : collector '$collectorName' not available - section not collected"
                    }
                    else {
                        try {
                            $collected = & $collectorName -ErrorAction Stop
                            if ($null -ne $collected) {
                                $result.Status = 'Collected'
                                $result.Data = $collected
                                Write-Host "  [$sectionIndex] $section : $collectorName OK" -ForegroundColor Green
                            }
                            else {
                                Write-Warning "  [$sectionIndex] $section : $collectorName returned no data"
                            }
                        }
                        catch {
                            Write-Warning "  [$sectionIndex] $section : $collectorName failed: $_"
                        }
                    }
                }
                else {
                    Write-Host "  [$sectionIndex] $section : skipped (no live collection)" -ForegroundColor Gray
                }

                # Derive metrics from whatever data is available
                if ($null -ne $result.Data) {
                    $result.Score = Get-SectionScore $result.Data
                    $result.Findings = Get-SeverityCounts $result.Data
                    $result.Highlights = @(Get-SectionHighlights $result.Data)
                }

                $sectionResults[$section] = $result
            }

            # ============================================
            # AGGREGATE SUMMARY METRICS
            # ============================================
            Write-Host "`n[AGGREGATING RESULTS]" -ForegroundColor Cyan

            $totalFindings = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
            $collectedCount = 0
            $categoryScores = @()

            foreach ($section in $allSections) {
                if (-not $sectionResults.ContainsKey($section)) { continue }
                $result = $sectionResults[$section]

                if ($result.Status -ne 'Not collected') { $collectedCount++ }

                $totalFindings.Critical += $result.Findings.Critical
                $totalFindings.High     += $result.Findings.High
                $totalFindings.Medium   += $result.Findings.Medium
                $totalFindings.Low      += $result.Findings.Low

                $categoryScores += @{
                    Section  = $section
                    Score    = $(if ($null -ne $result.Score) { $result.Score } else { 0 })
                    HasScore = ($null -ne $result.Score)
                    Status   = $result.Status
                }
            }

            $grandTotal = $totalFindings.Critical + $totalFindings.High + $totalFindings.Medium + $totalFindings.Low

            # Overall score: average of sections that produced a score, $null if none did
            # (HasScore distinguishes a genuinely collected 0 from "no score available")
            $knownScores = @($categoryScores | Where-Object { $_.Status -ne 'Not collected' -and $_.HasScore } | ForEach-Object { $_.Score })
            $overallScore = $null
            if (@($knownScores).Count -gt 0) {
                $overallScore = [Math]::Round(($knownScores | Measure-Object -Average).Average, 1)
            }

            Write-Host "  Sections collected: $collectedCount/$(@($IncludeSections).Count)" -ForegroundColor White
            Write-Host "  Total findings: $grandTotal (Critical: $($totalFindings.Critical), High: $($totalFindings.High), Medium: $($totalFindings.Medium), Low: $($totalFindings.Low))" -ForegroundColor $(
                if ($totalFindings.Critical -gt 0) { 'Red' }
                elseif ($totalFindings.High -gt 0) { 'Yellow' }
                else { 'Green' }
            )
            if ($null -ne $overallScore) {
                Write-Host "  Overall score: $overallScore%" -ForegroundColor $(
                    if ($overallScore -ge 80) { 'Green' }
                    elseif ($overallScore -ge 60) { 'Yellow' }
                    else { 'Red' }
                )
            }

            # ============================================
            # BUILD REPORT DATA
            # ============================================
            $reportData = @{
                GeneratedDate    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Hostname         = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'Unknown' })
                DomainName       = $(if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { 'WORKGROUP' })
                Username         = $(if ($env:USERNAME) { $env:USERNAME } else { 'Unknown' })
                DataSource       = $(if ($FromJsonPath) { 'JSON' } elseif ($SkipDataCollection) { 'None' } else { 'Live' })
                Sections         = $sectionResults
                SectionOrder     = @($allSections | Where-Object { $sectionResults.ContainsKey($_) })
                TotalFindings    = $totalFindings
                GrandTotal       = $grandTotal
                OverallScore     = $overallScore
                CategoryScores   = $categoryScores
                CollectedCount   = $collectedCount
                SectionCount     = @($IncludeSections).Count
            }

            # ============================================
            # GENERATE HTML REPORT
            # ============================================
            Write-Host "`n[GENERATING HTML REPORT]" -ForegroundColor Cyan

            $htmlFile = Join-Path $OutputPath "ConsolidatedSecurityReport_$timestamp.html"
            Generate-ConsolidatedReportHTML -ReportData $reportData -OutputFile $htmlFile

            Write-Host "  Report saved: $htmlFile" -ForegroundColor Green
            Write-Host "  File size: $([Math]::Round((Get-Item $htmlFile).Length / 1KB, 2)) KB" -ForegroundColor Gray

            # ============================================
            # OPTIONAL JSON EXPORT
            # ============================================
            $jsonOutFile = $null
            if ($SaveJson) {
                try {
                    $jsonOutFile = Join-Path $OutputPath "ConsolidatedReportData_$timestamp.json"
                    $jsonExport = @{}
                    foreach ($section in $reportData.SectionOrder) {
                        $jsonExport[$section] = $sectionResults[$section].Data
                    }
                    $jsonExport | ConvertTo-Json -Depth 10 | Out-File $jsonOutFile -Encoding UTF8 -Force
                    Write-Host "  Raw data saved: $jsonOutFile" -ForegroundColor Green
                }
                catch {
                    Write-Warning "  Failed to save JSON export: $_"
                    $jsonOutFile = $null
                }
            }

            if ($OpenInBrowser) {
                Write-Host "`n[OPENING IN BROWSER]" -ForegroundColor Cyan
                try {
                    Start-Process $htmlFile
                }
                catch {
                    Write-Warning "  Failed to open report in browser: $_"
                }
            }

            # ============================================
            # RETURN SUMMARY OBJECT
            # ============================================
            $notCollected = @($reportData.SectionOrder | Where-Object { $sectionResults[$_].Status -eq 'Not collected' })

            return [PSCustomObject]@{
                Success              = $true
                ReportPath           = $htmlFile
                JsonPath             = $jsonOutFile
                DataSource           = $reportData.DataSource
                GeneratedDate        = $reportData.GeneratedDate
                SectionsCollected    = $collectedCount
                SectionsNotCollected = @($notCollected)
                TotalFindings        = $grandTotal
                CriticalFindings     = $totalFindings.Critical
                HighFindings         = $totalFindings.High
                MediumFindings       = $totalFindings.Medium
                LowFindings          = $totalFindings.Low
                OverallScore         = $overallScore
                GenerationTime       = [Math]::Round(((Get-Date) - $reportStartTime).TotalSeconds, 2)
            }
        }
        catch {
            Write-Error "Consolidated report generation failed: $_"
            Write-Host "`nStack Trace:" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor Gray
            throw
        }
    }

    end {
        $totalTime = [Math]::Round(((Get-Date) - $reportStartTime).TotalSeconds, 2)

        Write-Host "`n================================================================" -ForegroundColor Green
        Write-Host "  CONSOLIDATED REPORT COMPLETE" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Total Execution Time: $totalTime seconds" -ForegroundColor White
    }
}

# ============================================
# HELPER FUNCTION: Generate Consolidated Report HTML
# ============================================
function Generate-ConsolidatedReportHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    # Severity colors (match New-SecurityDashboard / Generate-DashboardHTML style)
    $criticalColor = '#d32f2f'
    $highColor     = '#f57c00'
    $mediumColor   = '#fbc02d'
    $lowColor      = '#388e3c'
    $accentColor   = '#0078d4'

    # Score color
    $scoreDisplay = $(if ($null -ne $ReportData.OverallScore) { "$($ReportData.OverallScore)%" } else { 'N/A' })
    $scoreColor = $(if ($null -eq $ReportData.OverallScore) { '#666666' }
                    elseif ($ReportData.OverallScore -ge 80) { '#107c10' }
                    elseif ($ReportData.OverallScore -ge 60) { '#f7630c' }
                    else { '#d13438' })

    # Chart.js datasets (labels are fixed internal values - safe to embed)
    $severityLabels = "'Critical','High','Medium','Low'"
    $severityValues = "$($ReportData.TotalFindings.Critical),$($ReportData.TotalFindings.High),$($ReportData.TotalFindings.Medium),$($ReportData.TotalFindings.Low)"

    $categoryLabels = (@($ReportData.CategoryScores) | ForEach-Object { "'$($_.Section)'" }) -join ','
    $categoryValues = (@($ReportData.CategoryScores) | ForEach-Object { $_.Score }) -join ','

    # Build HTML using StringBuilder to avoid parse errors
    $html = New-Object System.Text.StringBuilder

    [void]$html.AppendLine("<!DOCTYPE html>")
    [void]$html.AppendLine("<html lang='en'>")
    [void]$html.AppendLine("<head>")
    [void]$html.AppendLine("  <meta charset='UTF-8'>")
    [void]$html.AppendLine("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    [void]$html.AppendLine("  <title>Consolidated Security Report - $($ReportData.Hostname)</title>")
    [void]$html.AppendLine("  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
    [void]$html.AppendLine("  <style>")
    [void]$html.AppendLine("    * { margin: 0; padding: 0; box-sizing: border-box; }")
    [void]$html.AppendLine("    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f5f5f5; color: #333333; padding: 20px; line-height: 1.6; }")
    [void]$html.AppendLine("    .container { max-width: 1600px; margin: 0 auto; }")
    [void]$html.AppendLine("    .header { background: linear-gradient(135deg, #0d47a1, #1565c0); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }")
    [void]$html.AppendLine("    .header h1 { font-size: 32px; margin-bottom: 5px; }")
    [void]$html.AppendLine("    .header-subtitle { font-size: 14px; opacity: 0.9; margin-bottom: 15px; }")
    [void]$html.AppendLine("    .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }")
    [void]$html.AppendLine("    .header-info-item { background: rgba(255,255,255,0.1); padding: 10px; border-radius: 5px; }")
    [void]$html.AppendLine("    .header-info-label { font-size: 11px; opacity: 0.8; }")
    [void]$html.AppendLine("    .header-info-value { font-size: 14px; font-weight: 600; margin-top: 3px; }")
    [void]$html.AppendLine("    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }")
    [void]$html.AppendLine("    .card { background: #ffffff; border: 1px solid #dddddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); transition: transform 0.2s; }")
    [void]$html.AppendLine("    .card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }")
    [void]$html.AppendLine("    .card-header { font-size: 16px; font-weight: 600; color: #0078d4; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #dddddd; }")
    [void]$html.AppendLine("    .large-metric { text-align: center; padding: 30px 15px; }")
    [void]$html.AppendLine("    .large-metric-value { font-size: 64px; font-weight: bold; margin-bottom: 8px; }")
    [void]$html.AppendLine("    .large-metric-label { font-size: 16px; color: #666; }")
    [void]$html.AppendLine("    .metric { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #f0f0f0; }")
    [void]$html.AppendLine("    .metric:last-child { border-bottom: none; }")
    [void]$html.AppendLine("    .metric-label { font-size: 14px; color: #666; }")
    [void]$html.AppendLine("    .metric-value { font-size: 16px; font-weight: bold; }")
    [void]$html.AppendLine("    .critical { color: $criticalColor; }")
    [void]$html.AppendLine("    .high { color: $highColor; }")
    [void]$html.AppendLine("    .medium { color: $mediumColor; }")
    [void]$html.AppendLine("    .low { color: $lowColor; }")
    [void]$html.AppendLine("    h2 { color: #0078d4; margin: 30px 0 15px 0; padding-left: 10px; border-left: 4px solid #0078d4; font-size: 20px; }")
    [void]$html.AppendLine("    .chart-container { position: relative; height: 280px; margin-top: 15px; }")
    [void]$html.AppendLine("    .status-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }")
    [void]$html.AppendLine("    .status-ok { background: #dff6dd; color: #107c10; }")
    [void]$html.AppendLine("    .status-none { background: #f0f0f0; color: #666666; }")
    [void]$html.AppendLine("    .footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid #dddddd; text-align: center; color: #999; font-size: 12px; }")
    [void]$html.AppendLine("    @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } .header h1 { font-size: 24px; } .large-metric-value { font-size: 48px; } }")
    [void]$html.AppendLine("  </style>")
    [void]$html.AppendLine("</head>")
    [void]$html.AppendLine("<body>")
    [void]$html.AppendLine("  <div class='container'>")

    # Header
    [void]$html.AppendLine("    <div class='header'>")
    [void]$html.AppendLine("      <h1>Consolidated Security Report</h1>")
    [void]$html.AppendLine("      <div class='header-subtitle'>Unified assessment across all major modules - WindowsSecurityAudit Module</div>")
    [void]$html.AppendLine("      <div class='header-info'>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Hostname</div><div class='header-info-value'>$($ReportData.Hostname)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Domain</div><div class='header-info-value'>$($ReportData.DomainName)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>User</div><div class='header-info-value'>$($ReportData.Username)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Generated</div><div class='header-info-value'>$($ReportData.GeneratedDate)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Data Source</div><div class='header-info-value'>$($ReportData.DataSource)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Sections</div><div class='header-info-value'>$($ReportData.CollectedCount)/$($ReportData.SectionCount) collected</div></div>")
    [void]$html.AppendLine("      </div>")
    [void]$html.AppendLine("    </div>")

    # ============================================
    # SUMMARY CARD GRID
    # ============================================
    [void]$html.AppendLine("    <div class='grid'>")

    # Overall Score Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='large-metric'>")
    [void]$html.AppendLine("          <div class='large-metric-value' style='color: $scoreColor;'>$scoreDisplay</div>")
    [void]$html.AppendLine("          <div class='large-metric-label'>Overall Security Score</div>")
    [void]$html.AppendLine("        </div>")
    [void]$html.AppendLine("      </div>")

    # Total Findings Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='large-metric'>")
    [void]$html.AppendLine("          <div class='large-metric-value' style='color: $accentColor;'>$($ReportData.GrandTotal)</div>")
    [void]$html.AppendLine("          <div class='large-metric-label'>Total Findings</div>")
    [void]$html.AppendLine("        </div>")
    [void]$html.AppendLine("      </div>")

    # Findings by Severity Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='card-header'>Findings by Severity</div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Critical</span><span class='metric-value critical'>$($ReportData.TotalFindings.Critical)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>High</span><span class='metric-value high'>$($ReportData.TotalFindings.High)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Medium</span><span class='metric-value medium'>$($ReportData.TotalFindings.Medium)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Low</span><span class='metric-value low'>$($ReportData.TotalFindings.Low)</span></div>")
    [void]$html.AppendLine("      </div>")

    # Collection Status Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='card-header'>Collection Status</div>")
    foreach ($section in $ReportData.SectionOrder) {
        $sectionResult = $ReportData.Sections[$section]
        $statusText = "$($sectionResult.Status)"
        $badgeClass = $(if ($statusText -eq 'Not collected') { 'status-none' } else { 'status-ok' })
        [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>$section</span><span class='status-badge $badgeClass'>$statusText</span></div>")
    }
    [void]$html.AppendLine("      </div>")

    [void]$html.AppendLine("    </div>")

    # ============================================
    # CHARTS
    # ============================================
    [void]$html.AppendLine("    <h2>Visual Analytics</h2>")
    [void]$html.AppendLine("    <div class='grid'>")
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='card-header'>Findings by Severity</div>")
    [void]$html.AppendLine("        <div class='chart-container'><canvas id='severityChart'></canvas></div>")
    [void]$html.AppendLine("      </div>")
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='card-header'>Category Scores</div>")
    [void]$html.AppendLine("        <div class='chart-container'><canvas id='categoryChart'></canvas></div>")
    [void]$html.AppendLine("      </div>")
    [void]$html.AppendLine("    </div>")

    # Chart.js initialization
    [void]$html.AppendLine("    <script>")
    [void]$html.AppendLine("      const sCtx = document.getElementById('severityChart').getContext('2d');")
    [void]$html.AppendLine("      new Chart(sCtx, {")
    [void]$html.AppendLine("        type: 'doughnut',")
    [void]$html.AppendLine("        data: {")
    [void]$html.AppendLine("          labels: [$severityLabels],")
    [void]$html.AppendLine("          datasets: [{")
    [void]$html.AppendLine("            data: [$severityValues],")
    [void]$html.AppendLine("            backgroundColor: ['$criticalColor', '$highColor', '$mediumColor', '$lowColor']")
    [void]$html.AppendLine("          }]")
    [void]$html.AppendLine("        },")
    [void]$html.AppendLine("        options: {")
    [void]$html.AppendLine("          responsive: true,")
    [void]$html.AppendLine("          maintainAspectRatio: false,")
    [void]$html.AppendLine("          plugins: { legend: { position: 'bottom' } }")
    [void]$html.AppendLine("        }")
    [void]$html.AppendLine("      });")
    [void]$html.AppendLine("      const cCtx = document.getElementById('categoryChart').getContext('2d');")
    [void]$html.AppendLine("      new Chart(cCtx, {")
    [void]$html.AppendLine("        type: 'bar',")
    [void]$html.AppendLine("        data: {")
    [void]$html.AppendLine("          labels: [$categoryLabels],")
    [void]$html.AppendLine("          datasets: [{")
    [void]$html.AppendLine("            label: 'Category Score',")
    [void]$html.AppendLine("            data: [$categoryValues],")
    [void]$html.AppendLine("            backgroundColor: '$accentColor'")
    [void]$html.AppendLine("          }]")
    [void]$html.AppendLine("        },")
    [void]$html.AppendLine("        options: {")
    [void]$html.AppendLine("          responsive: true,")
    [void]$html.AppendLine("          maintainAspectRatio: false,")
    [void]$html.AppendLine("          plugins: { legend: { display: false } },")
    [void]$html.AppendLine("          scales: { y: { beginAtZero: true, max: 100 } }")
    [void]$html.AppendLine("        }")
    [void]$html.AppendLine("      });")
    [void]$html.AppendLine("    </script>")

    # ============================================
    # PER-SECTION DETAIL CARDS
    # ============================================
    [void]$html.AppendLine("    <h2>Section Details</h2>")
    [void]$html.AppendLine("    <div class='grid'>")

    foreach ($section in $ReportData.SectionOrder) {
        $sectionResult = $ReportData.Sections[$section]
        $statusText = "$($sectionResult.Status)"
        $badgeClass = $(if ($statusText -eq 'Not collected') { 'status-none' } else { 'status-ok' })

        [void]$html.AppendLine("      <div class='card'>")
        [void]$html.AppendLine("        <div class='card-header'>$section <span class='status-badge $badgeClass' style='float: right;'>$statusText</span></div>")

        if ($null -ne $sectionResult.Score) {
            [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Score</span><span class='metric-value'>$($sectionResult.Score)%</span></div>")
        }

        $sectionFindings = $sectionResult.Findings
        $sectionTotal = $sectionFindings.Critical + $sectionFindings.High + $sectionFindings.Medium + $sectionFindings.Low
        [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Findings</span><span class='metric-value'>$sectionTotal</span></div>")

        # Best-effort scalar highlights from the raw collector output
        foreach ($highlight in @($sectionResult.Highlights)) {
            $label = "$($highlight.Label)" -replace '<', '&lt;' -replace '>', '&gt;'
            $value = "$($highlight.Value)" -replace '<', '&lt;' -replace '>', '&gt;'
            [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>$label</span><span class='metric-value' style='font-size: 13px;'>$value</span></div>")
        }

        [void]$html.AppendLine("      </div>")
    }

    [void]$html.AppendLine("    </div>")

    # Footer
    [void]$html.AppendLine("    <div class='footer'>")
    [void]$html.AppendLine("      <p><strong>WindowsSecurityAudit Module - Consolidated Security Report</strong></p>")
    [void]$html.AppendLine("      <p>Generated: $($ReportData.GeneratedDate) | Host: $($ReportData.Hostname) | Data Source: $($ReportData.DataSource) | Sections: $($ReportData.CollectedCount)/$($ReportData.SectionCount)</p>")
    [void]$html.AppendLine("      <p>Charts powered by Chart.js (jsDelivr CDN) - internet access required for chart rendering</p>")
    [void]$html.AppendLine("    </div>")

    [void]$html.AppendLine("  </div>")
    [void]$html.AppendLine("</body>")
    [void]$html.AppendLine("</html>")

    # Save HTML to file
    $html.ToString() | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
}
