function Invoke-EnterpriseSecurityScan {
    <#
    .SYNOPSIS
        Performs security scans across multiple systems in an enterprise environment
    .DESCRIPTION
        Executes comprehensive security assessments on multiple remote computers simultaneously,
        collecting and aggregating results for enterprise-wide security analysis.

        Two execution modes are available:

        Built-in checks (default): a fixed set of native-cmdlet checks (Defender, firewall,
        UAC, updates, local admins, event log and disk health) runs on each target and a
        SecurityScore (0-100) is computed per system.

        Module function deployment (-UseModuleFunctions): the WindowsSecurityAudit module is
        packaged into a temporary zip archive, copied to each reachable target over a PowerShell
        session (Copy-Item -ToSession) into a remote temp directory, imported there, and the
        curated function bundle selected via -RemoteFunctionSet (Quick, Standard, or Deep) is
        executed with default parameters. The remote temp directory is removed again in a
        finally block on every path. Results are returned verbatim under Details.ModuleResults.
        The SecurityScore is only meaningful for the built-in checks; for module deployments
        any 'Findings' collections emitted by the module functions are rolled up heuristically
        (severity/category tagging) into the per-system Findings list - this roll-up is a
        heuristic convenience, not a detection guarantee. Remote targets require PowerShell
        5.1+ with remoting enabled and Expand-Archive available.

        Fleet hardening: connectivity is probed in parallel through the runspace pool before
        any scan job is queued (-ProbeTimeoutSec bounds each probe), and every scan job is
        bounded by -HostTimeoutSec; jobs exceeding the limit are stopped, disposed, and
        reported with Status 'Timeout'. Per-host failures never abort the fleet run.
    .PARAMETER ComputerName
        Array of computer names or IP addresses to scan. Optional when -TargetFile is used
    .PARAMETER TargetFile
        Path to a CSV file containing a 'ComputerName' column with the targets to scan.
        Entries are combined with -ComputerName and de-duplicated
    .PARAMETER Credential
        PSCredential object for remote authentication. Never written to logs or output
    .PARAMETER ScanType
        Type of built-in scan: Quick, Standard, or Comprehensive
    .PARAMETER UseModuleFunctions
        Deploy the WindowsSecurityAudit module to each target and run the real module
        functions selected by -RemoteFunctionSet instead of the built-in native-cmdlet checks
    .PARAMETER RemoteFunctionSet
        Curated module function bundle to run remotely: Quick (Get-SecurityBaseline,
        Get-DefenderStatus), Standard (Quick + Find-SuspiciousProcesses,
        Find-PersistenceMechanisms, Get-SystemInfo), or Deep (Standard +
        Get-CredentialAccessEvents, Find-DefenseEvasion, Find-LateralMovement,
        Get-VulnerabilityAssessment). Default: Standard
    .PARAMETER ModulePath
        Explicit path to the WindowsSecurityAudit module root to package. When omitted, the
        root is resolved from the running module (or the parent of this script's folder)
    .PARAMETER ProbeTimeoutSec
        Maximum seconds to wait for each parallel connectivity probe (default: 3)
    .PARAMETER HostTimeoutSec
        Maximum seconds each per-host scan job may run before it is stopped, disposed, and
        marked with Status 'Timeout' (default: 300)
    .PARAMETER MaxThreads
        Maximum number of concurrent scans (1-512, default: 10)
    .PARAMETER OutputPath
        Path to save scan results
    .EXAMPLE
        Invoke-EnterpriseSecurityScan -ComputerName "SERVER01","SERVER02" -ScanType Standard
        Invoke-EnterpriseSecurityScan -ComputerName (Get-Content servers.txt) -Credential $cred -MaxThreads 20
    .EXAMPLE
        Invoke-EnterpriseSecurityScan -TargetFile targets.csv -UseModuleFunctions -RemoteFunctionSet Deep -Credential $cred -HostTimeoutSec 600
        Deploys the module to every host listed in targets.csv and runs the Deep function bundle
    .EXAMPLE
        Invoke-EnterpriseSecurityScan -ComputerName "SERVER01" -UseModuleFunctions -WhatIf
        Shows what would be packaged, deployed, and executed without changing anything
    .OUTPUTS
        PSCustomObject with enterprise scan results
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$TargetFile,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [ValidateSet('Quick', 'Standard', 'Comprehensive')]
        [string]$ScanType = 'Standard',

        [Parameter()]
        [switch]$UseModuleFunctions,

        [Parameter()]
        [ValidateSet('Quick', 'Standard', 'Deep')]
        [string]$RemoteFunctionSet = 'Standard',

        [Parameter()]
        [string]$ModulePath,

        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$ProbeTimeoutSec = 3,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$HostTimeoutSec = 300,

        [Parameter()]
        [ValidateRange(1, 512)]
        [int]$MaxThreads = 10,

        [Parameter()]
        [string]$OutputPath = "C:\EnterpriseScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )

    begin {
        $zipPath = $null
        $zipLeafName = $null
        $moduleRoot = $null
        $remoteFunctions = @()

        # Assemble the target list from -ComputerName and/or -TargetFile
        $targetComputers = @()
        if ($null -ne $ComputerName) {
            $targetComputers += $ComputerName
        }
        if (-not [string]::IsNullOrWhiteSpace($TargetFile)) {
            if (-not (Test-Path -Path $TargetFile -PathType Leaf)) {
                Write-Error "Target file not found: $TargetFile"
                throw "Target file not found: $TargetFile"
            }
            try {
                $targetRows = @(Import-Csv -Path $TargetFile -ErrorAction Stop)
            }
            catch {
                Write-Error "Could not parse target file '$TargetFile': $_"
                throw
            }
            if ($targetRows.Count -eq 0) {
                Write-Error "Target file '$TargetFile' contains no rows"
                throw "Target file '$TargetFile' contains no rows"
            }
            if ($null -eq $targetRows[0].PSObject.Properties['ComputerName']) {
                Write-Error "Target file '$TargetFile' must contain a 'ComputerName' column"
                throw "Target file '$TargetFile' must contain a 'ComputerName' column"
            }
            foreach ($row in $targetRows) {
                if (-not [string]::IsNullOrWhiteSpace($row.ComputerName)) {
                    $targetComputers += $row.ComputerName.Trim()
                }
            }
        }
        $targetComputers = @($targetComputers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        if ($targetComputers.Count -eq 0) {
            Write-Error "No target computers specified. Provide -ComputerName and/or -TargetFile."
            throw "No target computers specified"
        }

        Write-Host "=== ENTERPRISE SECURITY SCAN ===" -ForegroundColor Cyan
        Write-Host "Target Systems: $($targetComputers.Count)" -ForegroundColor Yellow
        Write-Host "Scan Type: $ScanType" -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow

        # Check if testing locally
        $isLocalTest = $targetComputers.Count -eq 1 -and ($targetComputers[0] -eq $env:COMPUTERNAME -or $targetComputers[0] -eq 'localhost' -or $targetComputers[0] -eq '127.0.0.1')

        if ($isLocalTest) {
            Write-Warning "Local testing detected. Ensure PSRemoting is enabled with 'Enable-PSRemoting -Force'"
        }

        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            if ($PSCmdlet.ShouldProcess($OutputPath, 'Create output directory')) {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            }
        }

        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScanType = $ScanType
            TotalSystems = $targetComputers.Count
            SystemResults = @()
            Summary = @{
                Successful = 0
                Failed = 0
                TimedOut = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
                LowFindings = 0
            }
            FailedSystems = @()
        }

        # Curated module function bundles for -UseModuleFunctions
        $quickFunctions = @('Get-SecurityBaseline', 'Get-DefenderStatus')
        $standardFunctions = @($quickFunctions) + @('Find-SuspiciousProcesses', 'Find-PersistenceMechanisms', 'Get-SystemInfo')
        $deepFunctions = @($standardFunctions) + @('Get-CredentialAccessEvents', 'Find-DefenseEvasion', 'Find-LateralMovement', 'Get-VulnerabilityAssessment')
        switch ($RemoteFunctionSet) {
            'Quick'    { $remoteFunctions = $quickFunctions }
            'Standard' { $remoteFunctions = $standardFunctions }
            'Deep'     { $remoteFunctions = $deepFunctions }
        }

        if ($UseModuleFunctions) {
            Write-Host "Mode: Module function deployment ($RemoteFunctionSet set)" -ForegroundColor Yellow
            Write-Host "Remote Functions: $($remoteFunctions -join ', ')" -ForegroundColor Yellow

            # Resolve the module root from -ModulePath, the running module, or this script's parent folder
            if (-not [string]::IsNullOrWhiteSpace($ModulePath)) {
                $moduleRoot = $ModulePath
            }
            else {
                $owningModule = $MyInvocation.MyCommand.Module
                if ($null -ne $owningModule -and -not [string]::IsNullOrEmpty($owningModule.ModuleBase)) {
                    $moduleRoot = $owningModule.ModuleBase
                }
                elseif (-not [string]::IsNullOrEmpty($PSScriptRoot)) {
                    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
                }
            }

            if ([string]::IsNullOrEmpty($moduleRoot) -or -not (Test-Path -Path $moduleRoot -PathType Container)) {
                Write-Error "Unable to locate the WindowsSecurityAudit module root. Provide -ModulePath."
                throw "Module root not found"
            }

            $moduleEntryPoints = @(Get-ChildItem -Path $moduleRoot -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.psd1', '.psm1') })
            if ($moduleEntryPoints.Count -eq 0) {
                Write-Error "No .psd1 or .psm1 found under module root '$moduleRoot'"
                throw "No module entry point found under '$moduleRoot'"
            }

            # Package the module into a temporary zip archive for deployment
            $zipLeafName = "WindowsSecurityAudit_$([guid]::NewGuid().ToString('N')).zip"
            $candidateZipPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $zipLeafName
            if ($PSCmdlet.ShouldProcess($moduleRoot, "Package module to temporary archive '$candidateZipPath' for deployment to $($targetComputers.Count) system(s)")) {
                try {
                    $moduleContent = @(Get-ChildItem -Path $moduleRoot -Force -ErrorAction Stop | Where-Object { $_.Name -ne '.git' })
                    Compress-Archive -Path $moduleContent.FullName -DestinationPath $candidateZipPath -Force -ErrorAction Stop
                    $zipPath = $candidateZipPath
                    $zipSizeKB = [math]::Round((Get-Item -Path $zipPath).Length / 1KB, 1)
                    Write-Host "Module packaged: $zipPath ($zipSizeKB KB)" -ForegroundColor Yellow
                }
                catch {
                    Write-Error "Failed to package module from '$moduleRoot': $_"
                    throw
                }
            }
        }

        # Script block for remote execution of the built-in native-cmdlet checks
        $scanScriptBlock = {
            param($ScanType)

            $result = [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Status = 'Success'
                SecurityScore = 0
                Findings = @()
                Details = @{}
            }

            try {
                # Quick baseline check
                $baseline = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($baseline) {
                    $result.SecurityScore += if ($baseline.RealTimeProtectionEnabled) { 20 } else { 0 }
                    $result.Details.WindowsDefender = $baseline.RealTimeProtectionEnabled

                    if (-not $baseline.RealTimeProtectionEnabled) {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Critical'
                            Category = 'Windows Defender'
                            Finding = 'Real-time protection is disabled'
                        }
                    }
                }

                # Firewall check
                $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $firewallEnabled = @($firewall | Where-Object { $_.Enabled -eq $true }).Count
                $result.SecurityScore += ($firewallEnabled * 10)
                $result.Details.FirewallProfiles = $firewallEnabled

                if ($firewallEnabled -lt 3) {
                    $result.Findings += [PSCustomObject]@{
                        Severity = 'High'
                        Category = 'Firewall'
                        Finding = "Only $firewallEnabled firewall profiles enabled"
                    }
                }

                # UAC check
                $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $uacProps = Get-ItemProperty -Path $uacKey -ErrorAction SilentlyContinue
                $uacEnabled = if ($null -ne $uacProps -and $uacProps.PSObject.Properties['EnableLUA']) { $uacProps.EnableLUA } else { $null }
                $result.SecurityScore += if ($uacEnabled -eq 1) { 15 } else { 0 }
                $result.Details.UACEnabled = ($uacEnabled -eq 1)

                if ($uacEnabled -ne 1) {
                    $result.Findings += [PSCustomObject]@{
                        Severity = 'High'
                        Category = 'UAC'
                        Finding = 'User Account Control is disabled'
                    }
                }

                # Windows Update check
                try {
                    $updateSession = New-Object -ComObject Microsoft.Update.Session
                    $updateSearcher = $updateSession.CreateUpdateSearcher()
                    $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates.Count
                    $result.Details.PendingUpdates = $pendingUpdates

                    if ($pendingUpdates -eq 0) {
                        $result.SecurityScore += 15
                    } else {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Medium'
                            Category = 'Updates'
                            Finding = "$pendingUpdates pending Windows updates"
                        }
                    }
                } catch {
                    $result.Details.PendingUpdates = "Unable to check"
                }

                # Additional checks for Standard/Comprehensive scans
                if ($ScanType -in @('Standard', 'Comprehensive')) {
                    # Check for admin accounts
                    $adminAccounts = @()
                    $adminLookupSucceeded = $false
                    if (Get-Command Get-AdminGroupMembers -ErrorAction SilentlyContinue) {
                        $adminAccounts = @(Get-AdminGroupMembers)
                        $adminLookupSucceeded = ((Get-Variable -Name AdminGroupLookupSucceeded -Scope Script -ValueOnly -ErrorAction SilentlyContinue) -eq $true)
                    }
                    if ($adminLookupSucceeded) {
                        $adminCount = $adminAccounts.Count
                        $result.Details.AdminAccounts = $adminCount

                        if ($adminCount -gt 3) {
                            $result.Findings += [PSCustomObject]@{
                                Severity = 'Medium'
                                Category = 'Accounts'
                                Finding = "$adminCount administrator accounts (excessive)"
                            }
                        }
                    } else {
                        $result.Details.AdminAccounts = 'Unknown'
                    }

                    # Check for suspicious services
                    $suspiciousServices = @(Get-Service | Where-Object {
                        $_.StartType -eq 'Automatic' -and
                        $_.Status -eq 'Running' -and
                        $_.ServiceName -notmatch '^(Win|Dhcp|Dns|W3SVC|MSSQL|SQL)'
                    })

                    if ($suspiciousServices.Count -gt 50) {
                        $result.Findings += [PSCustomObject]@{
                            Severity = 'Low'
                            Category = 'Services'
                            Finding = "$($suspiciousServices.Count) non-standard services running"
                        }
                    }
                }

                # Comprehensive scan additions
                if ($ScanType -eq 'Comprehensive') {
                    # Check event logs
                    $recentErrors = @(Get-WinEvent -FilterHashtable @{
                        LogName = 'System'
                        Level = 2
                        StartTime = (Get-Date).AddDays(-1)
                    } -MaxEvents 100 -ErrorAction SilentlyContinue)

                    $result.Details.RecentErrors = $recentErrors.Count

                    # Check disk space
                    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
                    foreach ($drive in $drives) {
                        if ($drive.Size -gt 0) {
                            $freePercent = ($drive.FreeSpace / $drive.Size) * 100
                            if ($freePercent -lt 10) {
                                $result.Findings += [PSCustomObject]@{
                                    Severity = 'High'
                                    Category = 'Disk Space'
                                    Finding = "Drive $($drive.DeviceID) has less than 10% free space"
                                }
                            }
                        }
                    }
                }

                # Calculate final score
                $result.SecurityScore = [Math]::Min($result.SecurityScore, 100)

            }
            catch {
                $result.Status = 'Error'
                $result.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Category = 'Scan Error'
                    Finding = $_.Exception.Message
                }
            }

            return $result
        }

        # Worker for one host: deploy the module over a PS session, run the selected module
        # functions remotely, and remove the remote temp directory on every path
        $moduleWorker = {
            param($Computer, $Cred, [bool]$HasCredential, $ZipPath, $ZipFileName, [string[]]$FunctionNames)

            $result = [PSCustomObject]@{
                ComputerName = $Computer
                ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Status = 'Success'
                SecurityScore = 0
                Findings = @()
                Details = @{}
            }

            $session = $null
            $remoteTempDir = $null
            try {
                $sessionParams = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
                if ($HasCredential) { $sessionParams['Credential'] = $Cred }
                $session = New-PSSession @sessionParams

                $remoteTempDir = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    $dir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("WSA_Scan_" + [guid]::NewGuid().ToString('N'))
                    New-Item -Path $dir -ItemType Directory -Force | Out-Null
                    $dir
                }

                # Never feed a host-supplied path straight into Copy-Item or Remove-Item:
                # only accept the exact temp shape this script asked the host to create
                if ($remoteTempDir -isnot [string] -or $remoteTempDir -notmatch 'WSA_Scan_[0-9a-fA-F]{32}$') {
                    $remoteTempDir = $null
                    throw "Remote host returned an unexpected temp path; aborting deployment before any copy or cleanup runs."
                }

                Copy-Item -Path $ZipPath -Destination $remoteTempDir -ToSession $session -Force -ErrorAction Stop

                $remoteResult = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    param($TempDir, $ZipFileName, $FunctionNames)

                    $runOutput = [PSCustomObject]@{ Results = [ordered]@{}; Errors = @() }
                    try {
                        $zipFile = Join-Path -Path $TempDir -ChildPath $ZipFileName
                        $extractDir = Join-Path -Path $TempDir -ChildPath 'Module'
                        Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force -ErrorAction Stop

                        $manifest = @(Get-ChildItem -Path $extractDir -Filter '*.psd1' -Recurse -File | Select-Object -First 1)
                        $rootModule = @(Get-ChildItem -Path $extractDir -Filter '*.psm1' -Recurse -File | Select-Object -First 1)
                        $importTarget = $null
                        if ($manifest.Count -gt 0) { $importTarget = $manifest[0].FullName }
                        elseif ($rootModule.Count -gt 0) { $importTarget = $rootModule[0].FullName }
                        if ($null -eq $importTarget) { throw "No .psd1 or .psm1 found in the deployed module archive" }

                        Import-Module $importTarget -Force -ErrorAction Stop

                        foreach ($functionName in $FunctionNames) {
                            try {
                                $runOutput.Results[$functionName] = & $functionName
                            }
                            catch {
                                $runOutput.Errors += ("{0}: {1}" -f $functionName, $_.Exception.Message)
                            }
                        }
                    }
                    finally {
                        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    return $runOutput
                } -ArgumentList $remoteTempDir, $ZipFileName, $FunctionNames

                $moduleResults = $null
                $functionErrors = @()
                if ($null -ne $remoteResult) {
                    if ($null -ne $remoteResult.PSObject.Properties['Results']) { $moduleResults = $remoteResult.Results }
                    if ($null -ne $remoteResult.PSObject.Properties['Errors'] -and $null -ne $remoteResult.Errors) { $functionErrors = @($remoteResult.Errors) }
                }

                $result.Details.ModuleDeployed = $true
                $result.Details.RemoteFunctionSet = ($FunctionNames -join ', ')
                $result.Details.ModuleResults = $moduleResults
                $result.Details.FunctionErrors = $functionErrors
                $result.Details.SecurityScoreNote = 'SecurityScore applies only to the built-in native-cmdlet scan; module function output is returned verbatim under Details.ModuleResults'

                # Heuristic roll-up: merge any Findings collections emitted by the module
                # functions and tag them with the source function name
                if ($null -ne $moduleResults) {
                    foreach ($functionName in $FunctionNames) {
                        $functionResult = $null
                        if ($moduleResults -is [System.Collections.IDictionary]) {
                            $functionResult = $moduleResults[$functionName]
                        }
                        elseif ($null -ne $moduleResults.PSObject.Properties[$functionName]) {
                            $functionResult = $moduleResults.PSObject.Properties[$functionName].Value
                        }
                        if ($null -eq $functionResult) { continue }
                        $findingsProperty = $functionResult.PSObject.Properties['Findings']
                        if ($null -eq $findingsProperty -or $null -eq $findingsProperty.Value) { continue }
                        foreach ($finding in @($findingsProperty.Value)) {
                            if ($null -eq $finding) { continue }
                            $severityValue = 'Informational'
                            if ($null -ne $finding.PSObject.Properties['Severity'] -and -not [string]::IsNullOrEmpty("$($finding.Severity)")) {
                                $severityValue = "$($finding.Severity)"
                            }
                            $categoryValue = $functionName
                            if ($null -ne $finding.PSObject.Properties['Category'] -and -not [string]::IsNullOrEmpty("$($finding.Category)")) {
                                $categoryValue = "$($finding.Category)"
                            }
                            $findingText = ($finding | Out-String).Trim()
                            if ($null -ne $finding.PSObject.Properties['Finding'] -and -not [string]::IsNullOrEmpty("$($finding.Finding)")) {
                                $findingText = "$($finding.Finding)"
                            }
                            $result.Findings += [PSCustomObject]@{
                                Severity = $severityValue
                                Category = $categoryValue
                                Finding = $findingText
                            }
                        }
                    }
                }
            }
            catch {
                $result.Status = 'Failed'
                $result.Details.Error = $_.Exception.Message
                $result.Findings += [PSCustomObject]@{
                    Severity = 'Critical'
                    Category = 'Connection'
                    Finding = $_.Exception.Message
                }
            }
            finally {
                if ($null -ne $session) {
                    if (-not [string]::IsNullOrEmpty($remoteTempDir)) {
                        try {
                            $null = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                                param($Dir)
                                Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
                            } -ArgumentList $remoteTempDir
                        }
                        catch {
                            Write-Verbose "Remote cleanup invocation failed for ${Computer}: $_"
                        }
                    }
                    Remove-PSSession $session
                }
            }

            return $result
        }
    }

    process {
        $runspacePool = $null
        $jobs = @()
        $probeJobs = @()
        try {
            Write-Host "`nStarting parallel scan of $($targetComputers.Count) systems..." -ForegroundColor Cyan

            # Propagate caller-defined function overrides (for example test doubles) for the
            # remoting cmdlets into the pool runspaces; in normal operation these commands are
            # cmdlets and nothing is propagated
            $shadowedCommands = @()
            foreach ($commandName in @('Test-Connection', 'New-PSSession', 'Copy-Item', 'Invoke-Command', 'Remove-PSSession')) {
                $functionCommand = @(Get-Command -Name $commandName -CommandType Function -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($functionCommand.Count -gt 0) { $shadowedCommands += $functionCommand[0] }
            }

            if ($shadowedCommands.Count -gt 0) {
                $initialState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                foreach ($functionCommand in $shadowedCommands) {
                    $initialState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($functionCommand.Name, $functionCommand.ScriptBlock)))
                }
                $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $initialState, $Host)
            }
            else {
                $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
            }
            $runspacePool.Open()

            # Phase 1: parallel connectivity probe for every target before any scan job is queued
            $reachableHosts = @()
            $probeApproved = $true
            if ($UseModuleFunctions) {
                $probeApproved = $PSCmdlet.ShouldProcess(($targetComputers -join ', '), "Probe connectivity with ${ProbeTimeoutSec}s per-host timeout")
            }

            if ($probeApproved) {
                Write-Host "Probing connectivity ($ProbeTimeoutSec s per-host timeout)..." -ForegroundColor Yellow

                foreach ($computer in $targetComputers) {
                    Write-Verbose "Queuing connectivity probe for: $computer"
                    $probe = [powershell]::Create()
                    $probe.RunspacePool = $runspacePool
                    $probe.AddScript({
                        param($Computer)
                        Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue
                    }).AddArgument($computer) | Out-Null

                    $probeJobs += [PSCustomObject]@{
                        Computer = $computer
                        Pipeline = $probe
                        Status = $probe.BeginInvoke()
                        StartTime = Get-Date
                    }
                }

                $pendingProbes = @($probeJobs)
                while ($pendingProbes.Count -gt 0) {
                    $stillPending = @()
                    foreach ($probeJob in $pendingProbes) {
                        if ($probeJob.Status.IsCompleted) {
                            $isReachable = $false
                            try {
                                $isReachable = @($probeJob.Pipeline.EndInvoke($probeJob.Status))[0]
                            }
                            catch {
                                Write-Verbose "Probe failed for $($probeJob.Computer): $_"
                                $isReachable = $false
                            }
                            $probeJob.Pipeline.Dispose()
                            $probeJob.Pipeline = $null

                            if ($true -eq $isReachable) {
                                $reachableHosts += $probeJob.Computer
                            }
                            else {
                                Write-Warning "Cannot reach $($probeJob.Computer) - skipping"
                                $results.FailedSystems += [PSCustomObject]@{
                                    ComputerName = $probeJob.Computer
                                    Reason = 'Unreachable'
                                }
                                $results.Summary.Failed++
                            }
                        }
                        elseif (((Get-Date) - $probeJob.StartTime).TotalSeconds -gt $ProbeTimeoutSec) {
                            try { $probeJob.Pipeline.Stop() } catch { Write-Verbose "Probe stop failed for $($probeJob.Computer): $_" }
                            $probeJob.Pipeline.Dispose()
                            $probeJob.Pipeline = $null
                            Write-Warning "Connectivity probe timed out for $($probeJob.Computer) - skipping"
                            $results.FailedSystems += [PSCustomObject]@{
                                ComputerName = $probeJob.Computer
                                Reason = "Unreachable (probe timeout after $ProbeTimeoutSec s)"
                            }
                            $results.Summary.Failed++
                        }
                        else {
                            $stillPending += $probeJob
                        }
                    }
                    if ($stillPending.Count -gt 0) { Start-Sleep -Milliseconds 100 }
                    $pendingProbes = $stillPending
                }
            }
            else {
                $reachableHosts = $targetComputers
            }

            # Phase 2: queue one scan job per reachable host
            foreach ($computer in $reachableHosts) {
                if ($UseModuleFunctions) {
                    if (-not $PSCmdlet.ShouldProcess($computer, "Deploy WindowsSecurityAudit module and run '$RemoteFunctionSet' function set ($($remoteFunctions -join ', '))")) {
                        $results.SystemResults += [PSCustomObject]@{
                            ComputerName = $computer
                            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Status = 'WhatIf'
                            SecurityScore = 0
                            Findings = @()
                            Details = @{
                                PlannedAction = "Deploy module archive and run '$RemoteFunctionSet' function set"
                                Functions = ($remoteFunctions -join ', ')
                            }
                        }
                        continue
                    }
                    Write-Verbose "Queuing module deployment scan for: $computer"
                    $powershell = [powershell]::Create()
                    $powershell.RunspacePool = $runspacePool
                    $powershell.AddScript($moduleWorker).
                        AddArgument($computer).
                        AddArgument($Credential).
                        AddArgument(($null -ne $Credential)).
                        AddArgument($zipPath).
                        AddArgument($zipLeafName).
                        AddArgument([string[]]$remoteFunctions) | Out-Null

                    $jobs += [PSCustomObject]@{
                        Computer = $computer
                        Pipeline = $powershell
                        Status = $powershell.BeginInvoke()
                        StartTime = Get-Date
                    }
                    continue
                }

                Write-Verbose "Queuing scan for: $computer"

                # Create PowerShell instance
                $powershell = [powershell]::Create()
                $powershell.RunspacePool = $runspacePool

                # Add script and parameters
                if ($Credential) {
                    $powershell.AddScript({
                        param($Computer, $Cred, $ScriptBlock, $ScanType)
                        try {
                            Invoke-Command -ComputerName $Computer -Credential $Cred -ScriptBlock $ScriptBlock -ArgumentList $ScanType -ErrorAction Stop
                        } catch {
                            [PSCustomObject]@{
                                ComputerName = $Computer
                                Status = 'Failed'
                                SecurityScore = 0
                                Findings = @([PSCustomObject]@{
                                    Severity = 'Critical'
                                    Category = 'Connection'
                                    Finding = $_.Exception.Message
                                })
                                Details = @{}
                            }
                        }
                    }).AddArgument($computer).AddArgument($Credential).AddArgument($scanScriptBlock).AddArgument($ScanType) | Out-Null
                }
                else {
                    $powershell.AddScript({
                        param($Computer, $ScriptBlock, $ScanType)
                        try {
                            Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $ScanType -ErrorAction Stop
                        } catch {
                            [PSCustomObject]@{
                                ComputerName = $Computer
                                Status = 'Failed'
                                SecurityScore = 0
                                Findings = @([PSCustomObject]@{
                                    Severity = 'Critical'
                                    Category = 'Connection'
                                    Finding = $_.Exception.Message
                                })
                                Details = @{}
                            }
                        }
                    }).AddArgument($computer).AddArgument($scanScriptBlock).AddArgument($ScanType) | Out-Null
                }

                # Start async execution
                $jobs += [PSCustomObject]@{
                    Computer = $computer
                    Pipeline = $powershell
                    Status = $powershell.BeginInvoke()
                    StartTime = Get-Date
                }
            }

            # Collect results as jobs complete, enforcing the per-host execution timeout
            Write-Host "Scanning in progress..." -ForegroundColor Yellow
            $completed = 0
            $totalJobs = @($jobs).Count
            $pendingJobs = @($jobs)

            while ($pendingJobs.Count -gt 0) {
                $stillPending = @()
                foreach ($job in $pendingJobs) {
                    if ($job.Status.IsCompleted) {
                        try {
                            $result = @(@($job.Pipeline.EndInvoke($job.Status)) | Where-Object { $null -ne $_ } | Select-Object -Last 1)
                            if ($result.Count -gt 0) { $result = $result[0] } else { $result = $null }

                            if ($null -eq $result) {
                                $results.Summary.Failed++
                                $results.FailedSystems += [PSCustomObject]@{
                                    ComputerName = $job.Computer
                                    Reason = 'No result returned'
                                }
                            }
                            else {
                                $statusValue = 'Failed'
                                if ($null -ne $result.PSObject.Properties['Status'] -and -not [string]::IsNullOrEmpty("$($result.Status)")) {
                                    $statusValue = "$($result.Status)"
                                }

                                if ($statusValue -eq 'Success') {
                                    $results.Summary.Successful++

                                    # Count findings by severity
                                    $findingsProperty = $result.PSObject.Properties['Findings']
                                    if ($null -ne $findingsProperty -and $null -ne $findingsProperty.Value) {
                                        foreach ($finding in @($findingsProperty.Value)) {
                                            if ($null -eq $finding -or $null -eq $finding.PSObject.Properties['Severity']) { continue }
                                            switch ("$($finding.Severity)") {
                                                'Critical' { $results.Summary.CriticalFindings++ }
                                                'High' { $results.Summary.HighFindings++ }
                                                'Medium' { $results.Summary.MediumFindings++ }
                                                'Low' { $results.Summary.LowFindings++ }
                                            }
                                        }
                                    }
                                }
                                else {
                                    $results.Summary.Failed++
                                    $results.FailedSystems += [PSCustomObject]@{
                                        ComputerName = $job.Computer
                                        Reason = 'Scan failed'
                                    }
                                }

                                $results.SystemResults += $result
                            }
                        }
                        catch {
                            Write-Warning "Error collecting results from $($job.Computer): $_"
                            $results.Summary.Failed++
                        }
                        finally {
                            $job.Pipeline.Dispose()
                            $job.Pipeline = $null
                        }
                        $completed++
                    }
                    elseif (((Get-Date) - $job.StartTime).TotalSeconds -gt $HostTimeoutSec) {
                        try { $job.Pipeline.Stop() } catch { Write-Verbose "Stop failed for $($job.Computer): $_" }
                        $job.Pipeline.Dispose()
                        $job.Pipeline = $null

                        Write-Warning "Scan of $($job.Computer) timed out after $HostTimeoutSec seconds"
                        $results.Summary.Failed++
                        $results.Summary.TimedOut++
                        $results.FailedSystems += [PSCustomObject]@{
                            ComputerName = $job.Computer
                            Reason = "Timeout after $HostTimeoutSec seconds"
                        }
                        $results.SystemResults += [PSCustomObject]@{
                            ComputerName = $job.Computer
                            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Status = 'Timeout'
                            SecurityScore = 0
                            Findings = @()
                            Details = @{ Error = "Host execution exceeded the $HostTimeoutSec second limit" }
                        }
                        $completed++
                    }
                    else {
                        $stillPending += $job
                    }
                }

                if ($totalJobs -gt 0) {
                    Write-Progress -Activity "Enterprise Security Scan" -Status "Completed: $completed / $totalJobs" -PercentComplete (($completed / $totalJobs) * 100)
                }
                if ($stillPending.Count -gt 0) { Start-Sleep -Milliseconds 500 }
                $pendingJobs = $stillPending
            }

            Write-Progress -Activity "Enterprise Security Scan" -Completed

            # Runspace pool is closed/disposed in the finally block below

        }
        catch {
            Write-Error "Error during enterprise scan: $_"
            throw
        }
        finally {
            # Guarantee cleanup of async pipelines and the runspace pool, even on failure
            foreach ($job in @($jobs) + @($probeJobs)) {
                if ($null -ne $job.Pipeline) {
                    $job.Pipeline.Dispose()
                }
            }
            if ($null -ne $runspacePool) {
                if ($runspacePool.RunspacePoolStateInfo.State -eq 'Opened') {
                    $runspacePool.Close()
                }
                $runspacePool.Dispose()
            }
            if (-not [string]::IsNullOrEmpty($zipPath) -and (Test-Path -Path $zipPath -PathType Leaf)) {
                Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    end {
        # Generate summary report
        Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Green
        Write-Host "Total Systems: $($results.TotalSystems)" -ForegroundColor Cyan
        Write-Host "Successful: $($results.Summary.Successful)" -ForegroundColor Green
        Write-Host "Failed: $($results.Summary.Failed)" -ForegroundColor Red
        if ($results.Summary.TimedOut -gt 0) {
            Write-Host "Timed Out: $($results.Summary.TimedOut)" -ForegroundColor Red
        }
        Write-Host "`nFindings Summary:" -ForegroundColor Cyan
        Write-Host "  Critical: $($results.Summary.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High: $($results.Summary.HighFindings)" -ForegroundColor Yellow
        Write-Host "  Medium: $($results.Summary.MediumFindings)" -ForegroundColor Yellow
        Write-Host "  Low: $($results.Summary.LowFindings)" -ForegroundColor White

        # Save results
        if ($PSCmdlet.ShouldProcess($OutputPath, 'Save enterprise scan results (JSON/CSV)')) {
            $results | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputPath "EnterpriseScan_Results.json") -Encoding UTF8

            # Create CSV summary
            $results.SystemResults | Select-Object ComputerName, Status, SecurityScore, @{N='FindingsCount';E={$_.Findings.Count}} |
                Export-Csv (Join-Path $OutputPath "EnterpriseScan_Summary.csv") -NoTypeInformation

            # Export detailed findings
            $allFindings = @($results.SystemResults | ForEach-Object {
                $computer = $_.ComputerName
                $_.Findings | Select-Object @{N='Computer';E={$computer}}, Severity, Category, Finding
            })

            if ($allFindings.Count -gt 0) {
                $allFindings | Export-Csv (Join-Path $OutputPath "EnterpriseScan_Findings.csv") -NoTypeInformation
            }

            Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
        }

        return $results
    }
}
