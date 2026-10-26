function Export-AttackNavigatorLayer {
    <#
    .SYNOPSIS
        Exports threat hunting findings as a MITRE ATT&CK Navigator layer
    .DESCRIPTION
        Converts findings from WindowsSecurityAudit threat hunting functions (such as
        Get-MITREAttackMapping or Find-APTIndicators) into the MITRE ATT&CK Navigator
        layer JSON format (v4.x) so SOC teams can visualize technique coverage at
        https://mitre-attack.github.io/attack-navigator/.

        Input can be supplied directly via the pipeline (-InputObject) or loaded from
        a previously saved JSON file (-InputPath). Technique scores are derived from
        finding severity and detection counts and rendered with a red-yellow gradient.
        The generated file is validated to ensure it parses as JSON and contains all
        keys required by ATT&CK Navigator.
    .PARAMETER InputObject
        Findings object(s), typically the output of Get-MITREAttackMapping,
        Find-APTIndicators, or any object exposing TechniqueID properties.
        Accepts pipeline input.
    .PARAMETER InputPath
        Path to a JSON file previously saved from a threat hunting function
        (e.g. Get-MITREAttackMapping -FullAnalysis | ConvertTo-Json -Depth 10 | Set-Content findings.json)
    .PARAMETER OutputPath
        Path of the ATT&CK Navigator layer file to create. If an existing directory
        is supplied, a timestamped .json file is created inside it.
    .PARAMETER LayerName
        Display name of the layer in ATT&CK Navigator.
        Defaults to 'WindowsSecurityAudit Findings'.
    .PARAMETER Score
        Fixed score (0-100) applied to every technique. When omitted, each technique
        is scored automatically from its highest severity and detection count.
    .EXAMPLE
        Get-MITREAttackMapping -FullAnalysis | Export-AttackNavigatorLayer -OutputPath C:\Reports\layer.json
    .EXAMPLE
        Export-AttackNavigatorLayer -InputPath C:\Reports\findings.json -OutputPath C:\Reports\layer.json -LayerName "Workstation Hunt"
    .EXAMPLE
        Find-APTIndicators -DeepScan | Export-AttackNavigatorLayer -OutputPath C:\Reports -Score 80
    .OUTPUTS
        PSCustomObject with export details (OutputPath, TechniqueCount, DetectionCount)
    #>

    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Pipeline', Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [object[]]$InputObject,

        [Parameter(ParameterSetName = 'File', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InputPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$LayerName = 'WindowsSecurityAudit Findings',

        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$Score
    )

    begin {
        Write-Host "=== ATT&CK NAVIGATOR LAYER EXPORT ===" -ForegroundColor Cyan
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        Write-Host "Input Mode: $($PSCmdlet.ParameterSetName)" -ForegroundColor Yellow

        $useFixedScore = $PSBoundParameters.ContainsKey('Score')

        # Severity weights used to score techniques on a 0-100 scale
        $severityScores = @{
            'Critical' = 100
            'High'     = 75
            'Medium'   = 50
            'Low'      = 25
        }
        $defaultSeverityScore = 10

        # Map module tactic names to ATT&CK Navigator kebab-case tactic names
        $tacticNameMap = @{
            'InitialAccess'      = 'initial-access'
            'Execution'          = 'execution'
            'Persistence'        = 'persistence'
            'PrivilegeEscalation'= 'privilege-escalation'
            'DefenseEvasion'     = 'defense-evasion'
            'CredentialAccess'   = 'credential-access'
            'Discovery'          = 'discovery'
            'LateralMovement'    = 'lateral-movement'
            'Collection'         = 'collection'
            'CommandAndControl'  = 'command-and-control'
            'Exfiltration'       = 'exfiltration'
            'Impact'             = 'impact'
        }

        # Red-yellow gradient endpoint interpolation (yellow #FFE766 -> red #FF6666)
        $getGradientColor = {
            param([int]$Value)
            $clamped = [Math]::Min(100, [Math]::Max(0, $Value))
            $ratio = $clamped / 100.0
            $red   = 255
            $green = [int](231 + ((102 - 231) * $ratio))
            $blue  = [int](102 + ((102 - 102) * $ratio))
            return ('#{0:X2}{1:X2}{2:X2}' -f $red, $green, $blue)
        }

        $detectionRecords = [System.Collections.ArrayList]@()

        function New-TechniqueRecord {
            param(
                [string]$Id,
                [string]$Name,
                [string]$Tactic,
                [string]$Severity,
                [string]$Evidence,
                [string]$Source
            )
            return [PSCustomObject]@{
                TechniqueID     = $Id
                TechniqueName   = $Name
                Tactic          = $Tactic
                Severity        = $Severity
                Evidence        = $Evidence
                DetectionSource = $Source
            }
        }

        function Get-TechniqueRecord {
            param([AllowNull()][object]$Item)

            $records = @()

            if ($null -eq $Item) {
                return $records
            }

            # Plain strings: scan for ATT&CK technique ID references
            if ($Item -is [string]) {
                foreach ($match in [regex]::Matches($Item, 'T\d{4}(\.\d{3})?')) {
                    $records += New-TechniqueRecord -Id $match.Value -Name '' -Tactic '' -Severity '' -Evidence 'Text reference' -Source 'Raw'
                }
                return $records
            }

            # Hashtable / dictionary containers
            if ($Item -is [System.Collections.IDictionary]) {
                if ($Item.Contains('DetectedTechniques') -and $null -ne $Item['DetectedTechniques']) {
                    foreach ($subItem in @($Item['DetectedTechniques'])) {
                        $records += @(Get-TechniqueRecord -Item $subItem)
                    }
                    return $records
                }
                if ($Item.Contains('TechniqueID') -and $null -ne $Item['TechniqueID']) {
                    $dictId = [string]$Item['TechniqueID']
                    if ($dictId -match '^T\d{4}(\.\d{3})?$') {
                        $records += New-TechniqueRecord -Id $dictId `
                            -Name $(if ($Item.Contains('TechniqueName')) { [string]$Item['TechniqueName'] } else { '' }) `
                            -Tactic $(if ($Item.Contains('Tactic')) { [string]$Item['Tactic'] } else { '' }) `
                            -Severity $(if ($Item.Contains('Severity')) { [string]$Item['Severity'] } else { '' }) `
                            -Evidence $(if ($Item.Contains('Evidence')) { [string]$Item['Evidence'] } else { '' }) `
                            -Source $(if ($Item.Contains('DetectionSource')) { [string]$Item['DetectionSource'] } else { '' })
                    }
                    return $records
                }
                # Fallback: scan string values for technique ID references
                foreach ($key in @($Item.Keys)) {
                    if ($Item[$key] -is [string]) {
                        foreach ($match in [regex]::Matches($Item[$key], 'T\d{4}(\.\d{3})?')) {
                            $records += New-TechniqueRecord -Id $match.Value -Name '' -Tactic '' -Severity '' -Evidence "$key reference" -Source 'Raw'
                        }
                    }
                }
                return $records
            }

            $props = $Item.PSObject.Properties

            # Get-MITREAttackMapping style container: recurse into DetectedTechniques
            if ($null -ne $props['DetectedTechniques'] -and $null -ne $Item.DetectedTechniques) {
                foreach ($subItem in @($Item.DetectedTechniques)) {
                    $records += @(Get-TechniqueRecord -Item $subItem)
                }
                return $records
            }

            # Find-APTIndicators style container: recurse into Indicators members
            if ($null -ne $props['Indicators'] -and $null -ne $Item.Indicators) {
                $indicatorContainer = $Item.Indicators
                if ($indicatorContainer -is [System.Collections.IDictionary]) {
                    foreach ($key in @($indicatorContainer.Keys)) {
                        foreach ($subItem in @($indicatorContainer[$key])) {
                            $records += @(Get-TechniqueRecord -Item $subItem)
                        }
                    }
                }
                else {
                    foreach ($containerProp in @($indicatorContainer.PSObject.Properties)) {
                        foreach ($subItem in @($containerProp.Value)) {
                            $records += @(Get-TechniqueRecord -Item $subItem)
                        }
                    }
                }
                return $records
            }

            # Detection object exposing a TechniqueID property
            if ($null -ne $props['TechniqueID'] -and $null -ne $Item.TechniqueID) {
                $id = [string]$Item.TechniqueID
                if ($id -match '^T\d{4}(\.\d{3})?$') {
                    $records += New-TechniqueRecord -Id $id `
                        -Name $(if ($null -ne $props['TechniqueName']) { [string]$Item.TechniqueName } else { '' }) `
                        -Tactic $(if ($null -ne $props['Tactic']) { [string]$Item.Tactic } else { '' }) `
                        -Severity $(if ($null -ne $props['Severity']) { [string]$Item.Severity } else { '' }) `
                        -Evidence $(if ($null -ne $props['Evidence']) { [string]$Item.Evidence } else { '' }) `
                        -Source $(if ($null -ne $props['DetectionSource']) { [string]$Item.DetectionSource } else { '' })
                }
                return $records
            }

            # Fallback: scan string properties for technique ID references
            $itemSeverity = ''
            if ($null -ne $props['Severity'] -and $null -ne $Item.Severity) {
                $itemSeverity = [string]$Item.Severity
            }
            foreach ($prop in $props) {
                if ($prop.Value -is [string]) {
                    foreach ($match in [regex]::Matches($prop.Value, 'T\d{4}(\.\d{3})?')) {
                        $records += New-TechniqueRecord -Id $match.Value -Name '' -Tactic '' -Severity $itemSeverity -Evidence "$($prop.Name) reference" -Source 'Raw'
                    }
                }
            }
            return $records
        }

        # Load findings from a previously saved JSON file
        if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
                Write-Error "Input file not found: $InputPath"
                throw "Input file not found: $InputPath"
            }
            try {
                $rawJson = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 -ErrorAction Stop
                $loadedFindings = $rawJson | ConvertFrom-Json -ErrorAction Stop
                foreach ($loadedItem in @($loadedFindings)) {
                    foreach ($record in @(Get-TechniqueRecord -Item $loadedItem)) {
                        [void]$detectionRecords.Add($record)
                    }
                }
                Write-Host "Loaded findings from: $InputPath" -ForegroundColor Yellow
            }
            catch {
                Write-Error "Failed to read or parse input file '$InputPath': $_"
                throw
            }
        }
    }

    process {
        if ($null -ne $InputObject) {
            foreach ($item in $InputObject) {
                if ($null -eq $item) {
                    continue
                }
                try {
                    foreach ($record in @(Get-TechniqueRecord -Item $item)) {
                        [void]$detectionRecords.Add($record)
                    }
                }
                catch {
                    Write-Warning "Error extracting technique data from input item: $_"
                }
            }
        }
    }

    end {
        try {
            Write-Host "`nBuilding ATT&CK Navigator layer..." -ForegroundColor Cyan

            # Aggregate detections per technique ID
            $techniqueMap = [ordered]@{}
            foreach ($record in $detectionRecords) {
                if ($null -eq $record) {
                    continue
                }
                $id = $record.TechniqueID
                if ([string]::IsNullOrWhiteSpace($id)) {
                    continue
                }

                if (-not $techniqueMap.Contains($id)) {
                    $techniqueMap[$id] = @{
                        Detections        = 0
                        BestSeverity      = ''
                        BestSeverityScore = 0
                        Names             = @()
                        Tactic            = ''
                        Sources           = @()
                        Evidences         = @()
                    }
                }
                $entry = $techniqueMap[$id]
                $entry.Detections++

                if ($severityScores.ContainsKey($record.Severity)) {
                    $recordSeverityScore = $severityScores[$record.Severity]
                }
                else {
                    $recordSeverityScore = $defaultSeverityScore
                }
                if ($recordSeverityScore -gt $entry.BestSeverityScore) {
                    $entry.BestSeverityScore = $recordSeverityScore
                    $entry.BestSeverity = $record.Severity
                }

                if (-not [string]::IsNullOrWhiteSpace($record.TechniqueName) -and
                    $entry.Names -notcontains $record.TechniqueName -and
                    $entry.Names.Count -lt 3) {
                    $entry.Names += $record.TechniqueName
                }

                if (-not [string]::IsNullOrWhiteSpace($record.Tactic) -and
                    [string]::IsNullOrWhiteSpace($entry.Tactic)) {
                    $entry.Tactic = $record.Tactic
                }

                if (-not [string]::IsNullOrWhiteSpace($record.DetectionSource) -and
                    $entry.Sources -notcontains $record.DetectionSource) {
                    $entry.Sources += $record.DetectionSource
                }

                if (-not [string]::IsNullOrWhiteSpace($record.Evidence) -and
                    $entry.Evidences -notcontains $record.Evidence -and
                    $entry.Evidences.Count -lt 3) {
                    $evidence = $record.Evidence
                    if ($evidence.Length -gt 120) {
                        $evidence = $evidence.Substring(0, 117) + '...'
                    }
                    $entry.Evidences += $evidence
                }
            }

            # Build technique entries with severity-based gradient scores
            $techniques = @()
            $severitiesSeen = @{}

            foreach ($id in @($techniqueMap.Keys)) {
                $entry = $techniqueMap[$id]

                if ($useFixedScore) {
                    $scoreValue = $Score
                }
                else {
                    $scoreValue = [Math]::Min(100, $entry.BestSeverityScore + (($entry.Detections - 1) * 5))
                }

                $commentParts = @("Detections: $($entry.Detections)")
                if (-not [string]::IsNullOrWhiteSpace($entry.BestSeverity)) {
                    $commentParts += "Highest severity: $($entry.BestSeverity)"
                }
                if ($entry.Names.Count -gt 0) {
                    $commentParts += ($entry.Names -join ' / ')
                }
                if (-not [string]::IsNullOrWhiteSpace($entry.Tactic)) {
                    $commentParts += "Tactic: $($entry.Tactic)"
                }
                if ($entry.Sources.Count -gt 0) {
                    $commentParts += "Sources: $($entry.Sources -join ', ')"
                }
                if ($entry.Evidences.Count -gt 0) {
                    $commentParts += "Evidence: $($entry.Evidences -join '; ')"
                }
                $comment = $commentParts -join ' | '
                if ($comment.Length -gt 500) {
                    $comment = $comment.Substring(0, 497) + '...'
                }

                $techniqueEntry = [ordered]@{
                    techniqueID = $id
                    score       = $scoreValue
                    color       = (& $getGradientColor $scoreValue)
                    comment     = $comment
                    enabled     = $true
                    links       = @()
                    metadata    = @()
                }
                if (-not [string]::IsNullOrWhiteSpace($entry.Tactic) -and $tacticNameMap.ContainsKey($entry.Tactic)) {
                    $techniqueEntry['tactic'] = $tacticNameMap[$entry.Tactic]
                }
                $techniques += $techniqueEntry

                if (-not [string]::IsNullOrWhiteSpace($entry.BestSeverity)) {
                    $severitiesSeen[$entry.BestSeverity] = $true
                }
            }

            # Sort techniques by score (descending), then technique ID
            $techniques = @($techniques | Sort-Object -Property @{ Expression = 'score'; Descending = $true }, @{ Expression = 'techniqueID'; Descending = $false })

            if ($techniques.Count -eq 0) {
                Write-Warning "No ATT&CK technique IDs found in the input. An empty layer will be exported."
            }

            # Legend items for observed severities
            $severityLegendColors = @{
                'Critical' = '#FF6666'
                'High'     = '#FFB366'
                'Medium'   = '#FFE766'
                'Low'      = '#FFFFB3'
            }
            $legendItems = @()
            foreach ($severityName in @('Critical', 'High', 'Medium', 'Low')) {
                if ($severitiesSeen.ContainsKey($severityName)) {
                    $legendItems += [ordered]@{
                        label = "$severityName severity detections"
                        color = $severityLegendColors[$severityName]
                    }
                }
            }
            if ($useFixedScore) {
                $legendItems += [ordered]@{ label = "Fixed score applied: $Score"; color = '' }
            }
            else {
                $legendItems += [ordered]@{ label = 'Score = severity weight + detection count'; color = '' }
            }

            # ATT&CK Navigator layer format v4.x
            $layer = [ordered]@{
                name        = $LayerName
                versions    = [ordered]@{
                    attack    = '16'
                    navigator = '5.1.0'
                    layer     = '4.5'
                }
                domain      = 'enterprise-attack'
                description = "Generated by the WindowsSecurityAudit module on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'). $($detectionRecords.Count) detection(s) across $($techniqueMap.Count) unique technique(s)."
                filters     = [ordered]@{
                    platforms = @('Windows')
                }
                sorting     = 3
                layout      = [ordered]@{
                    layout              = 'side'
                    aggregateFunction   = 'average'
                    showID              = $false
                    showName            = $true
                    showAggregateScores = $false
                    countUnscored       = $false
                }
                hideDisabled = $false
                techniques   = $techniques
                gradient     = [ordered]@{
                    colors   = @('#FFE766', '#FF6666')
                    minValue = 0
                    maxValue = 100
                }
                legendItems = $legendItems
                metadata    = @(
                    [ordered]@{ name = 'Generated by'; value = 'WindowsSecurityAudit module' }
                    [ordered]@{ name = 'Total detections'; value = "$($detectionRecords.Count)" }
                    [ordered]@{ name = 'Unique techniques'; value = "$($techniqueMap.Count)" }
                )
                links                          = @()
                showTacticRowBackground        = $false
                tacticRowBackground            = '#DDDDDD'
                selectTechniquesAcrossTactics  = $true
                selectSubtechniquesWithParent  = $false
            }

            # Resolve output path (accept a directory or a file path)
            $resolvedOutput = $OutputPath
            if (Test-Path -LiteralPath $resolvedOutput -PathType Container) {
                $resolvedOutput = Join-Path -Path $resolvedOutput -ChildPath ("AttackNavigatorLayer_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            }
            if ([System.IO.Path]::GetExtension($resolvedOutput) -ne '.json') {
                $resolvedOutput += '.json'
            }
            if ([System.IO.Path]::IsPathRooted($resolvedOutput)) {
                $fullPath = $resolvedOutput
            }
            else {
                $fullPath = Join-Path -Path (Get-Location).Path -ChildPath $resolvedOutput
            }

            $parentDir = Split-Path -Path $fullPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
                New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
            }

            # Write layer JSON (UTF-8 without BOM for ATT&CK Navigator compatibility)
            $layerJson = $layer | ConvertTo-Json -Depth 10
            [System.IO.File]::WriteAllText($fullPath, $layerJson)

            # Validate the exported layer parses as JSON and contains required keys
            Write-Host "Validating exported layer..." -ForegroundColor Cyan
            try {
                $savedJson = [System.IO.File]::ReadAllText($fullPath)
                $parsedLayer = $savedJson | ConvertFrom-Json -ErrorAction Stop

                $requiredKeys = @('name', 'versions', 'domain', 'techniques', 'gradient', 'legendItems')
                foreach ($key in $requiredKeys) {
                    if ($null -eq $parsedLayer.PSObject.Properties[$key]) {
                        throw "Missing required layer key: $key"
                    }
                }
                foreach ($versionKey in @('attack', 'navigator', 'layer')) {
                    if ($null -eq $parsedLayer.versions.PSObject.Properties[$versionKey]) {
                        throw "Missing required versions key: $versionKey"
                    }
                }
                if ($parsedLayer.domain -ne 'enterprise-attack') {
                    throw "Unexpected domain value: $($parsedLayer.domain)"
                }
                Write-Host "Layer validated: JSON parses and contains all required keys" -ForegroundColor Green
            }
            catch {
                Write-Error "Generated layer file failed validation: $_"
                throw
            }

            Write-Host "`n=== EXPORT COMPLETE ===" -ForegroundColor Green
            Write-Host "`nLayer Summary:" -ForegroundColor Cyan
            Write-Host "  Layer Name: $LayerName" -ForegroundColor White
            Write-Host "  Unique Techniques: $($techniqueMap.Count)" -ForegroundColor White
            Write-Host "  Total Detections: $($detectionRecords.Count)" -ForegroundColor White
            Write-Host "  Output File: $fullPath" -ForegroundColor White

            if ($techniques.Count -gt 0) {
                Write-Host "`nTop Scored Techniques:" -ForegroundColor Cyan
                $techniques | Select-Object -First 5 | ForEach-Object {
                    Write-Host "  $($_.techniqueID) [Score: $($_.score)]" -ForegroundColor Yellow
                }
            }

            Write-Host "`nImport the layer into ATT&CK Navigator:" -ForegroundColor Cyan
            Write-Host "  https://mitre-attack.github.io/attack-navigator/" -ForegroundColor Gray

            return [PSCustomObject]@{
                LayerName      = $LayerName
                OutputPath     = $fullPath
                TechniqueCount = $techniqueMap.Count
                DetectionCount = $detectionRecords.Count
                NavigatorUrl   = 'https://mitre-attack.github.io/attack-navigator/'
            }
        }
        catch {
            Write-Error "Error exporting ATT&CK Navigator layer: $_"
            throw
        }
    }
}
