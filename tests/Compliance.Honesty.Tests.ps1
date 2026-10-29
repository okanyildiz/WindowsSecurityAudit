#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Compliance-honesty regression tests for the Compliance/ test functions.
.DESCRIPTION
    Cross-platform tests (run green on macOS and on the Windows CI lint job).

    Regression-pin for the v1.6.x denominator bug: unevaluable controls used to be
    emitted as 'NotApplicable' (CIS: 'Manual') and were silently dropped from the
    compliance-percentage denominator, so e.g. PCI-DSS reported 100% while 8 of 18
    requirements (incl. Critical 3.5.1/11.3.1) were never evaluated.

    Three distinct states are pinned:
      * NotEvaluated - the tool tried but could not read the data. Stays in the
        denominator, never counts as compliant, and triggers a Write-Warning.
      * Manual       - human verification by design. Excluded from the denominator.
      * NotApplicable- truly not applicable. Excluded (no real occurrences today).

    Both scenarios stub the data-source functions inside the module session state
    (InModuleScope + function overrides, same pattern as the /tmp/wsa-repro
    scripts that demonstrated the bug) and pin the exact summary math:
      scoped    = Total - NotApplicable - Manual
      evaluated = scoped - NotEvaluated   (== Summary.EvaluatedControls)
      CompliancePercentage = compliant / scoped
      CoveragePercentage   = evaluated / scoped

    The module targets Windows PowerShell 5.1+, so only APIs available in
    5.1 are used here (no null-coalescing/ternary operators, no ForEach-Object -Parallel).

    Platform guard: the pinned scenarios model a host where the BitLocker, Defender
    (Get-MpComputerStatus) and secedit data sources are ABSENT - exactly the
    /tmp/wsa-repro runs. On a real Windows host those cmdlets exist and answer for
    real, so the pinned counts legitimately differ; both Describe blocks are skipped
    there (inverse of tests/Smoke.Windows.Tests.ps1).
#>

BeforeDiscovery {
    # $IsWindows only exists on PowerShell 6+; on Windows PowerShell 5.1 (which only
    # ships on Windows) fall back to $env:OS.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:IsWindowsHost = [bool]$IsWindows
    }
    else {
        $script:IsWindowsHost = ($env:OS -eq 'Windows_NT')
    }
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"

    Import-Module -Name $script:ModulePath -Force
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'PCI-DSS compliance honesty (NotEvaluated stays in the denominator)' -Skip:$script:IsWindowsHost {
    It 'pins the repro: Total=18 InPlace=10 Manual=6 NotEvaluated=2 Compliance=83.33 Coverage=83.33' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            # Save the module-private helpers the stubs replace; restore in finally.
            $savedHelpers = @{}
            foreach ($helperName in @('Get-LocalUserByRid', 'Get-LocalPasswordPolicy', 'Get-AuditPolicyTable')) {
                $savedHelpers[$helperName] = (Get-Command $helperName).ScriptBlock
            }

            # Stubs identical to the original repro scenario.
            function Get-NetFirewallProfile { 'Domain','Private','Public' | ForEach-Object { [pscustomobject]@{Name=$_;Enabled=$true;DefaultInboundAction='Block'} } }
            function Get-LocalUserByRid { param($Rid) [pscustomobject]@{Enabled=$false} }
            function Get-LocalPasswordPolicy { [pscustomobject]@{MinPasswordLength=14;MaxPasswordAgeDays=60;LockoutThreshold=5;Source='Api'} }
            function Get-AuditPolicyTable { param($Subcategory) $t=@{}; foreach ($n in $Subcategory) { $k=((Get-AuditSubcategoryGuid -Name $n) -replace '[{}]','').ToLowerInvariant(); $t[$k]=[pscustomobject]@{Value=3;Success=$true;Failure=$true} }; $t }
            function Get-WinEvent { [pscustomobject]@{MaximumSizeInBytes=200MB} }
            function Get-Service { [pscustomobject]@{Name='W32Time';Status='Running'} }

            try {
                # BitLocker/Get-MpComputerStatus deliberately NOT stubbed: on any host
                # without those cmdlets (or where they fail) 3.5.1 and 11.3.1 must
                # surface as NotEvaluated instead of vanishing from the denominator.
                $r = Test-PciDssCompliance -WarningVariable +pciWarnings 6>$null 3>$null
                $s = $r.Summary

                $r.Requirements.Count | Should -Be 18
                $s.InPlace | Should -Be 10
                $s.NotInPlace | Should -Be 0
                $s['Manual'] | Should -Be 6
                $s['NotEvaluated'] | Should -Be 2
                $s.NotApplicable | Should -Be 0
                $s.CompliancePercentage | Should -Be 83.33
                $s['CoveragePercentage'] | Should -Be 83.33
                $s.EvaluatedControls | Should -Be 10

                $notEvaluatedIds = @($r.Requirements | Where-Object Status -eq 'NotEvaluated' | ForEach-Object RequirementID)
                $notEvaluatedIds | Should -Be @('3.5.1', '11.3.1')

                # The six human-verification requirements are Manual, not NotApplicable.
                $manualIds = @($r.Requirements | Where-Object Status -eq 'Manual' | ForEach-Object RequirementID)
                $manualIds | Should -Be @('3.3.1', '3.6.1', '8.3.1', '11.5.1', '12.1.1', '12.10.1')

                # NotEvaluated requirements must produce the honesty warning and
                # per-requirement remediation recommendations.
                @($pciWarnings | Where-Object { "$_" -match '2 control\(s\) could not be evaluated and are counted as not compliant' }).Count |
                    Should -Be 1
                @($r.Recommendations | Where-Object { $_ -like 'Could not evaluate 3.5.1:*' }).Count | Should -Be 1
                @($r.Recommendations | Where-Object { $_ -like 'Could not evaluate 11.3.1:*' }).Count | Should -Be 1
            }
            finally {
                foreach ($helperName in $savedHelpers.Keys) {
                    Set-Item -Path "Function:\$helperName" -Value $savedHelpers[$helperName]
                }
                Remove-Item -Path Function:\Get-NetFirewallProfile, Function:\Get-WinEvent, Function:\Get-Service -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe 'CIS Benchmark compliance honesty (Manual bug fix + NotEvaluated)' -Skip:$script:IsWindowsHost {
    It 'pins the repro: Total=15 Passed=7 Manual=2 NotEvaluated=6 Compliance=53.85 Coverage=53.85' {
        InModuleScope -ModuleName $script:ModuleName -ScriptBlock {
            # Save the module-private helpers the stubs replace; restore in finally.
            $savedHelpers = @{}
            foreach ($helperName in @('Get-LocalUserByRid', 'Get-AuditPolicyTable')) {
                $savedHelpers[$helperName] = (Get-Command $helperName).ScriptBlock
            }

            # Stubs identical to the original repro scenario: no firewall profiles,
            # secedit export produces nothing -> CIS-1.1.1..5 and CIS-9.1.1 unevaluable.
            function Get-NetFirewallProfile { }
            function secedit { }
            function Get-LocalUserByRid { param($Rid) [pscustomobject]@{Enabled=$false} }
            function Get-AuditPolicyTable { param($Subcategory) $t=@{}; foreach ($n in $Subcategory) { $k=((Get-AuditSubcategoryGuid -Name $n) -replace '[{}]','').ToLowerInvariant(); $t[$k]=[pscustomobject]@{Value=3;Success=$true;Failure=$true} }; $t }
            function Test-Path { param($Path) $Path -like 'HKLM:*' }
            function Get-ItemProperty { [pscustomobject]@{DontDisplayLastUserName=1;NoLMHash=1} }

            try {
                $r = Test-CISBenchmark -Level 1 -WarningVariable +cisWarnings 6>$null 3>$null
                $s = $r.Summary

                $r.Controls.Count | Should -Be 15
                $s.Passed | Should -Be 7
                $s.Failed | Should -Be 0
                $s['Manual'] | Should -Be 2
                $s['NotEvaluated'] | Should -Be 6
                # Regression: NotApplicable must count only real NotApplicable controls
                # (it used to store the Manual count, which would be 8 here pre-remap).
                $s.NotApplicable | Should -Be 0
                $s.CompliancePercentage | Should -Be 53.85
                $s['CoveragePercentage'] | Should -Be 53.85
                $s.EvaluatedControls | Should -Be 7

                $notEvaluatedIds = @($r.Controls | Where-Object Status -eq 'NotEvaluated' | ForEach-Object ControlID)
                $notEvaluatedIds | Should -Be @('CIS-1.1.1', 'CIS-1.1.2', 'CIS-1.1.3', 'CIS-1.1.4', 'CIS-1.1.5', 'CIS-9.1.1')

                # CIS-2.2.1 / CIS-2.2.3 remain Manual by design.
                $manualIds = @($r.Controls | Where-Object Status -eq 'Manual' | ForEach-Object ControlID)
                $manualIds | Should -Be @('CIS-2.2.1', 'CIS-2.2.3')

                @($cisWarnings | Where-Object { "$_" -match '6 control\(s\) could not be evaluated and are counted as not compliant' }).Count |
                    Should -Be 1
                @($r.Recommendations | Where-Object { $_ -like 'Could not evaluate CIS-9.1.1:*' }).Count | Should -Be 1
            }
            finally {
                foreach ($helperName in $savedHelpers.Keys) {
                    Set-Item -Path "Function:\$helperName" -Value $savedHelpers[$helperName]
                }
                Remove-Item -Path Function:\Get-NetFirewallProfile, Function:\secedit, Function:\Test-Path, Function:\Get-ItemProperty -ErrorAction SilentlyContinue
            }
        }
    }
}
