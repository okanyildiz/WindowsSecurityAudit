function Test-SystemIntegrity {
    <#
    .SYNOPSIS
        Tests Windows system file integrity
    .DESCRIPTION
        Runs SFC and DISM commands to check and verify system file integrity
    .PARAMETER RepairFiles
        Attempt to repair corrupted files if found
    .PARAMETER DetailedScan
        Perform a more thorough system scan
    .EXAMPLE
        Test-SystemIntegrity
        Test-SystemIntegrity -RepairFiles -DetailedScan
    .OUTPUTS
        PSCustomObject with integrity check results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$RepairFiles,
        
        [Parameter()]
        [switch]$DetailedScan
    )
    
    begin {
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges. Please run PowerShell as Administrator."
        }
        
        Write-Host "Starting System Integrity Check..." -ForegroundColor Cyan
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            SFCResult = $null
            DISMResult = $null
            CorruptedFiles = @()
            RepairAttempted = $false
            RepairSuccessful = $false
            RepairGuidance = $null
            WindowsUpdateServices = @()  # Added this property
        }
    }
    
    process {
        try {
            # Run SFC scan
            Write-Host "Running System File Checker (SFC)..." -ForegroundColor Yellow
            $scanStart = Get-Date
            $sfcOutput = & sfc /scannow 2>&1 | Out-String
            $sfcExitCode = $LASTEXITCODE

            # SFC output text is fully localized, so it is NEVER used for the
            # verdict; the exit code and the CBS.log '[SR]'/'Cannot repair'
            # tokens (written in English by the SFC engine regardless of UI
            # language), filtered to the current scan window, are the only
            # locale-invariant sources
            $cbsLogPath = "$env:windir\Logs\CBS\CBS.log"
            $cbsLogAvailable = Test-Path $cbsLogPath
            $cannotRepairLines = @()
            $cbsTimestampsParseable = $false
            if ($cbsLogAvailable) {
                $cbsTail = @(Get-Content $cbsLogPath -Tail 500 -ErrorAction SilentlyContinue)
                $cbsTailFilter = Select-CbsTailForCurrentScan -Lines $cbsTail -Since $scanStart
                $cbsTimestampsParseable = $cbsTailFilter.TimestampsParseable
                $cannotRepairLines = @($cbsTailFilter.Lines | Where-Object { $_ -match '\[SR\]' -and $_ -match 'Cannot repair' })
            }

            # Localized SFC console text as a verbose hint only - never a verdict input
            if ($sfcOutput -match 'Windows Resource Protection') {
                $sfcHint = @($sfcOutput -split '\r?\n' | Where-Object { $_ -match 'Windows Resource Protection' } | Select-Object -First 1)
                if ($sfcHint.Count -gt 0) { Write-Verbose "SFC output hint (localized, informational only): $($sfcHint[0].Trim())" }
            }

            if ($sfcExitCode -ne 0) {
                # Covers the 'could not perform the requested operation' case -
                # SFC exits non-zero there, no text matching needed
                $results.SFCResult = "SFC could not complete scan - may need to run in Safe Mode"
                Write-Warning "SFC could not complete the scan (exit code $sfcExitCode)"
            }
            elseif ($cannotRepairLines.Count -gt 0) {
                $results.SFCResult = "Corrupt files found"
                if (-not $cbsTimestampsParseable) {
                    $results.SFCResult = "Corrupt files found (possible stale CBS.log entries)"
                }

                $results.CorruptedFiles = $cannotRepairLines

                if ($RepairFiles) {
                    # SFC already repaired everything it could during /scannow; the
                    # remaining 'Cannot repair' files need a DISM RestoreHealth pass
                    # first. Report honest guidance instead of faking a repair attempt.
                    $results.RepairGuidance = 'SFC already repairs what it can during /scannow. For the files listed in CorruptedFiles run: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow again.'
                    Write-Warning $results.RepairGuidance
                }
            }
            elseif ($cbsLogAvailable -and $cbsTimestampsParseable) {
                # Exit code 0 and the current-scan CBS.log window was actually
                # examined (timestamps parsed) with no 'Cannot repair' markers
                $results.SFCResult = "No integrity violations found"
                Write-Host "SFC: No integrity violations found" -ForegroundColor Green
            }
            else {
                # Inconclusive: CBS.log missing or its timestamps unparseable -
                # never report 'healthy' from a parse miss
                $results.SFCResult = "Scan completed - check CBS.log for details"
            }
            
            # Run DISM if detailed scan requested
            if ($DetailedScan) {
                Write-Host "Running DISM health check..." -ForegroundColor Yellow

                # Check image health
                $dismCheck = & dism /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
                $dismCheckExitCode = $LASTEXITCODE

                # DISM output text is fully localized and CheckHealth returns 0 for
                # both 'healthy' and 'repairable', so neither the output text nor
                # the exit code alone can separate those; servicing-stack CBS.log
                # markers (component-store corruption, written in English by the
                # engine), filtered to the current scan window, are the only
                # locale-invariant source. English DISM text is never matched.
                $storeCorruptionLines = @()
                $dismTimestampsParseable = $false
                if ($cbsLogAvailable) {
                    $dismTail = @(Get-Content $cbsLogPath -Tail 500 -ErrorAction SilentlyContinue)
                    $dismTailFilter = Select-CbsTailForCurrentScan -Lines $dismTail -Since $scanStart
                    $dismTimestampsParseable = $dismTailFilter.TimestampsParseable
                    $storeCorruptionLines = @($dismTailFilter.Lines | Where-Object { $_ -match '(?i)component store' -and $_ -match '(?i)corrupt' })
                }

                # Localized DISM console text as a verbose hint only - never a verdict input
                if ($dismCheck -match '(?i)component store') {
                    $dismHint = @($dismCheck -split '\r?\n' | Where-Object { $_ -match '(?i)component store' } | Select-Object -First 1)
                    if ($dismHint.Count -gt 0) { Write-Verbose "DISM output hint (localized, informational only): $($dismHint[0].Trim())" }
                }

                $repairable = ($storeCorruptionLines.Count -gt 0)

                if ($dismCheckExitCode -ne 0) {
                    $results.DISMResult = "DISM CheckHealth failed (exit code $dismCheckExitCode) - review CBS.log"
                    Write-Warning "DISM CheckHealth failed with exit code $dismCheckExitCode"
                }
                elseif ($repairable) {
                    $results.DISMResult = "Repairable corruption detected"
                    if (-not $dismTimestampsParseable -and $storeCorruptionLines.Count -gt 0) {
                        $results.DISMResult = "Repairable corruption detected (possible stale CBS.log entries)"
                    }

                    if ($RepairFiles) {
                        Write-Host "Attempting DISM repair..." -ForegroundColor Yellow
                        $null = & dism /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
                        $dismRepairExitCode = $LASTEXITCODE
                        $results.RepairAttempted = $true

                        if ($dismRepairExitCode -eq 0) {
                            $results.RepairSuccessful = $true
                            $results.DISMResult = "Repaired successfully"
                            Write-Host "DISM repair completed successfully" -ForegroundColor Green
                        }
                        else {
                            $results.DISMResult = "Repair failed (exit code $dismRepairExitCode) - review CBS.log"
                            Write-Warning "DISM RestoreHealth failed with exit code $dismRepairExitCode"
                        }
                    }
                }
                elseif ($cbsLogAvailable -and $dismTimestampsParseable) {
                    # Exit code 0 and the current-scan CBS.log window was actually
                    # examined (timestamps parsed) with no corruption markers
                    $results.DISMResult = "Healthy"
                    Write-Host "DISM: System image is healthy" -ForegroundColor Green
                }
                else {
                    # Inconclusive: CBS.log missing or its timestamps unparseable -
                    # never report 'healthy' from a parse miss
                    $results.DISMResult = "Check completed - review CBS.log"
                }
            }
            
            # Check Windows Update components
            Write-Host "Checking Windows Update components..." -ForegroundColor Yellow
            $serviceNames = @('wuauserv', 'cryptSvc', 'bits', 'msiserver')
            $services = @()
            
            foreach ($serviceName in $serviceNames) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $services += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        Status = $service.Status
                        StartType = $service.StartType
                    }
                }
            }
            
            $results.WindowsUpdateServices = $services
            
        }
        catch {
            Write-Error "Error during system integrity check: $_"
            throw
        }
    }
    
    end {
        return $results
    }
}

function Select-CbsTailForCurrentScan {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Lines = @(),

        [Parameter(Mandatory = $true)]
        [datetime]$Since
    )

    $windowStart = $Since.AddMinutes(-5)
    $currentScanLines = @()
    $timestampsParseable = $false

    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        if ($line -match '^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
            try {
                $lineTime = [datetime]::ParseExact($Matches.ts, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
                $timestampsParseable = $true
                if ($lineTime -ge $windowStart) {
                    $currentScanLines += $line
                }
            } catch { }
        }
    }

    $filteredLines = @($Lines)
    if ($timestampsParseable) {
        $filteredLines = @($currentScanLines)
    }

    [PSCustomObject]@{
        Lines = $filteredLines
        TimestampsParseable = $timestampsParseable
    }
}
