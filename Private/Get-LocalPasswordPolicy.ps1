<#
.SYNOPSIS
    Locale-invariant local password/lockout policy helper (private).
.DESCRIPTION
    Get-LocalPasswordPolicy queries the local SAM account policy via
    NetUserModalsGet (netapi32, levels 0 and 3). When elevated, it merges
    PasswordComplexity/ClearTextPassword (and serves as full fallback) from a
    secedit /export INF whose [System Access] keys are English on all locales.
    NEVER calls 'net accounts' (localized output).
    ConvertTo-PolicyFromModals holds all pure unit/sentinel conversion logic so
    it can be tested off-Windows (no P/Invoke, no OS calls).
.NOTES
    Struct layouts verified from lmaccess.h (USER_MODALS_INFO_0/3).
    ALL NetApi time fields are SECONDS: USER_MODALS_INFO_0 max/min password age
    and force-logoff, and USER_MODALS_INFO_3 lockout duration and observation
    window (Microsoft Learn: usrmod3_lockout_duration "Specifies, in seconds...";
    usrmod3_lockout_observation_window "...in seconds").
    TIMEQ_FOREVER ([uint32]::MaxValue) maps to -1 ("never" / "until admin unlocks").
    Sentinel checks MUST compare against [uint32]::MaxValue, never 0xFFFFFFFF:
    PowerShell parses the literal 0xFFFFFFFF as [int] -1, so
    '[uint32]4294967295 -eq 0xFFFFFFFF' is $false and the branch never fires.
#>

function ConvertTo-PolicyFromModals {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        $Modals0,

        [Parameter()]
        $Modals3
    )

    $converted = [PSCustomObject]@{
        MinPasswordLength               = $null
        MaxPasswordAgeDays              = $null
        MinPasswordAgeDays              = $null
        PasswordHistoryLength           = $null
        ForceLogoffHours                = $null
        LockoutThreshold                = $null
        LockoutDurationMinutes          = $null
        LockoutObservationWindowMinutes = $null
    }

    if ($null -ne $Modals0) {
        $converted.MinPasswordLength = [int]$Modals0.usrmod0_min_passwd_len

        # USER_MODALS_INFO_0 ages are seconds; TIMEQ_FOREVER = [uint32]::MaxValue.
        if ($Modals0.usrmod0_max_passwd_age -eq [uint32]::MaxValue) {
            $converted.MaxPasswordAgeDays = -1
        }
        else {
            $converted.MaxPasswordAgeDays = [int][math]::Round($Modals0.usrmod0_max_passwd_age / 86400)
        }
        if ($Modals0.usrmod0_min_passwd_age -eq [uint32]::MaxValue) {
            $converted.MinPasswordAgeDays = -1
        }
        else {
            $converted.MinPasswordAgeDays = [int][math]::Round($Modals0.usrmod0_min_passwd_age / 86400)
        }
        if ($Modals0.usrmod0_force_logoff -eq [uint32]::MaxValue) {
            $converted.ForceLogoffHours = -1
        }
        else {
            $converted.ForceLogoffHours = [int][math]::Round($Modals0.usrmod0_force_logoff / 3600)
        }
        $converted.PasswordHistoryLength = [int]$Modals0.usrmod0_password_hist_len
    }

    if ($null -ne $Modals3) {
        # USER_MODALS_INFO_3 lockout duration and observation window are SECONDS
        # (Microsoft Learn), so divide by 60 to report minutes. TIMEQ_FOREVER
        # ([uint32]::MaxValue) duration = "until admin unlocks" -> -1, checked
        # BEFORE the seconds-to-minutes conversion.
        # Reported even when threshold is 0 (lockout disabled).
        if ($Modals3.usrmod3_lockout_duration -eq [uint32]::MaxValue) {
            $converted.LockoutDurationMinutes = -1
        }
        else {
            $converted.LockoutDurationMinutes = [int][math]::Round($Modals3.usrmod3_lockout_duration / 60)
        }
        if ($Modals3.usrmod3_lockout_observation_window -eq [uint32]::MaxValue) {
            $converted.LockoutObservationWindowMinutes = -1
        }
        else {
            $converted.LockoutObservationWindowMinutes = [int][math]::Round($Modals3.usrmod3_lockout_observation_window / 60)
        }
        $converted.LockoutThreshold = [int]$Modals3.usrmod3_lockout_threshold
    }

    return $converted
}

function Get-LocalPasswordPolicy {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $policy = [PSCustomObject]@{
        MinPasswordLength               = $null
        MaxPasswordAgeDays              = $null
        MinPasswordAgeDays              = $null
        PasswordHistoryLength           = $null
        LockoutThreshold                = $null
        LockoutDurationMinutes          = $null
        LockoutObservationWindowMinutes = $null
        ForceLogoffHours                = $null
        PasswordComplexity              = $null
        ClearTextPassword               = $null
        Source                          = 'Unavailable'
    }

    $isWindowsHost = $false
    try {
        $isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        # RuntimeInformation missing on old .NET Framework (PS 5.1)
        $isWindowsHost = ($env:OS -eq 'Windows_NT')
    }
    if (-not $isWindowsHost) {
        Write-Verbose 'Get-LocalPasswordPolicy: not a Windows host; local SAM policy not applicable'
        return $policy
    }

    # --- Primary: NetUserModalsGet levels 0 and 3 ---
    $netApiOk = $false
    $modals0 = $null
    $modals3 = $null
    if (-not ([bool]('NetApiModals' -as [type]))) {
        $netApiModalsSource = @'
using System;
using System.Runtime.InteropServices;
public static class NetApiModals {
    [StructLayout(LayoutKind.Sequential)]
    public struct USER_MODALS_INFO_0 {
        public uint usrmod0_min_passwd_len;
        public uint usrmod0_max_passwd_age;   // seconds
        public uint usrmod0_min_passwd_age;   // seconds
        public uint usrmod0_force_logoff;     // seconds; 0xFFFFFFFF = TIMEQ_FOREVER
        public uint usrmod0_password_hist_len;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct USER_MODALS_INFO_3 {
        public uint usrmod3_lockout_duration;           // seconds; 0xFFFFFFFF = TIMEQ_FOREVER
        public uint usrmod3_lockout_observation_window; // seconds; 0xFFFFFFFF = TIMEQ_FOREVER
        public uint usrmod3_lockout_threshold;
    }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserModalsGet(string server, int level, out IntPtr bufPtr);
    [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr bufPtr);
    public static USER_MODALS_INFO_0 GetLevel0(out uint netError) {
        IntPtr buf = IntPtr.Zero;
        netError = NetUserModalsGet(null, 0, out buf);
        if (netError != 0) { return new USER_MODALS_INFO_0(); }
        try { return (USER_MODALS_INFO_0)Marshal.PtrToStructure(buf, typeof(USER_MODALS_INFO_0)); }
        finally { NetApiBufferFree(buf); }
    }
    public static USER_MODALS_INFO_3 GetLevel3(out uint netError) {
        IntPtr buf = IntPtr.Zero;
        netError = NetUserModalsGet(null, 3, out buf);
        if (netError != 0) { return new USER_MODALS_INFO_3(); }
        try { return (USER_MODALS_INFO_3)Marshal.PtrToStructure(buf, typeof(USER_MODALS_INFO_3)); }
        finally { NetApiBufferFree(buf); }
    }
}
'@
        try {
            Add-Type -TypeDefinition $netApiModalsSource -ErrorAction Stop
        }
        catch {
            # Add-Type -TypeDefinition is blocked under Constrained Language Mode (JEA)
            Write-Verbose "Get-LocalPasswordPolicy: Add-Type NetApiModals failed: $($_.Exception.Message)"
        }
    }

    if ([bool]('NetApiModals' -as [type])) {
        $level0Error = [uint32]0
        try {
            $level0 = [NetApiModals]::GetLevel0([ref]$level0Error)
            if ($level0Error -eq 0) {
                $modals0 = $level0
                $netApiOk = $true
            }
            else {
                Write-Verbose "Get-LocalPasswordPolicy: NetUserModalsGet level 0 failed (netError $level0Error)"
            }
        }
        catch {
            Write-Verbose "Get-LocalPasswordPolicy: NetApi level 0 failed: $($_.Exception.Message)"
        }

        $level3Error = [uint32]0
        try {
            $level3 = [NetApiModals]::GetLevel3([ref]$level3Error)
            if ($level3Error -eq 0) {
                $modals3 = $level3
                $netApiOk = $true
            }
            else {
                Write-Verbose "Get-LocalPasswordPolicy: NetUserModalsGet level 3 failed (netError $level3Error)"
            }
        }
        catch {
            Write-Verbose "Get-LocalPasswordPolicy: NetApi level 3 failed: $($_.Exception.Message)"
        }

        if ($netApiOk) {
            $converted = ConvertTo-PolicyFromModals -Modals0 $modals0 -Modals3 $modals3
            $policy.MinPasswordLength = $converted.MinPasswordLength
            $policy.MaxPasswordAgeDays = $converted.MaxPasswordAgeDays
            $policy.MinPasswordAgeDays = $converted.MinPasswordAgeDays
            $policy.PasswordHistoryLength = $converted.PasswordHistoryLength
            $policy.ForceLogoffHours = $converted.ForceLogoffHours
            $policy.LockoutThreshold = $converted.LockoutThreshold
            $policy.LockoutDurationMinutes = $converted.LockoutDurationMinutes
            $policy.LockoutObservationWindowMinutes = $converted.LockoutObservationWindowMinutes
            $policy.Source = 'NetApi'
        }
    }

    # --- Secedit (elevated): full fallback, or merge of the two NetApi cannot see ---
    $isAdmin = $false
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isAdmin = $false
    }

    $needSecedit = (-not $netApiOk) -or ($null -eq $policy.PasswordComplexity)
    $seceditData = $null
    if ($needSecedit -and $isAdmin) {
        $secedit = Get-Command 'secedit.exe' -ErrorAction SilentlyContinue
        if ($null -eq $secedit) {
            $secedit = Get-Command 'secedit' -ErrorAction SilentlyContinue
        }
        if ($null -ne $secedit) {
            $tempFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('wsa-secpol-{0}.inf' -f [guid]::NewGuid().ToString('N'))
            try {
                $null = & $secedit.Source '/export' '/cfg' $tempFile '/quiet' 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $tempFile)) {
                    # INF is UTF-16 with BOM; Get-Content auto-detects.
                    # [System Access] keys are English on all locales.
                    $seceditData = @{}
                    $inSection = $false
                    foreach ($line in (Get-Content -LiteralPath $tempFile)) {
                        $trimmed = $line.Trim()
                        if ($trimmed -match '^\[') {
                            $inSection = ($trimmed -ieq '[System Access]')
                            continue
                        }
                        if ($inSection -and $trimmed -match '^([^=]+)=(.*)$') {
                            $seceditData[$Matches[1].Trim()] = $Matches[2].Trim()
                        }
                    }
                }
                else {
                    Write-Verbose "Get-LocalPasswordPolicy: secedit /export failed (exit $LASTEXITCODE)"
                }
            }
            catch {
                Write-Verbose "Get-LocalPasswordPolicy: secedit fallback failed: $($_.Exception.Message)"
            }
            finally {
                if (Test-Path -LiteralPath $tempFile -ErrorAction SilentlyContinue) {
                    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    if ($null -ne $seceditData) {
        if (-not $netApiOk) {
            # INF ages are already in days; -1 sentinel = never
            if ($seceditData.ContainsKey('MinimumPasswordLength') -and $seceditData['MinimumPasswordLength'] -match '^-?\d+$') {
                $policy.MinPasswordLength = [int]$seceditData['MinimumPasswordLength']
            }
            if ($seceditData.ContainsKey('MaximumPasswordAge') -and $seceditData['MaximumPasswordAge'] -match '^-?\d+$') {
                $policy.MaxPasswordAgeDays = [int]$seceditData['MaximumPasswordAge']
            }
            if ($seceditData.ContainsKey('MinimumPasswordAge') -and $seceditData['MinimumPasswordAge'] -match '^-?\d+$') {
                $policy.MinPasswordAgeDays = [int]$seceditData['MinimumPasswordAge']
            }
            if ($seceditData.ContainsKey('PasswordHistorySize') -and $seceditData['PasswordHistorySize'] -match '^-?\d+$') {
                $policy.PasswordHistoryLength = [int]$seceditData['PasswordHistorySize']
            }
            if ($seceditData.ContainsKey('LockoutBadCount') -and $seceditData['LockoutBadCount'] -match '^-?\d+$') {
                $policy.LockoutThreshold = [int]$seceditData['LockoutBadCount']
            }
            if ($seceditData.ContainsKey('LockoutDuration') -and $seceditData['LockoutDuration'] -match '^-?\d+$') {
                $policy.LockoutDurationMinutes = [int]$seceditData['LockoutDuration']
            }
            if ($seceditData.ContainsKey('ResetLockoutCount') -and $seceditData['ResetLockoutCount'] -match '^-?\d+$') {
                $policy.LockoutObservationWindowMinutes = [int]$seceditData['ResetLockoutCount']
            }
            $policy.Source = 'Secedit'
        }
        if ($seceditData.ContainsKey('PasswordComplexity') -and $seceditData['PasswordComplexity'] -match '^-?\d+$') {
            $policy.PasswordComplexity = ([int]$seceditData['PasswordComplexity'] -eq 1)
        }
        if ($seceditData.ContainsKey('ClearTextPassword') -and $seceditData['ClearTextPassword'] -match '^-?\d+$') {
            $policy.ClearTextPassword = ([int]$seceditData['ClearTextPassword'] -eq 1)
        }
        # Only claim '+Secedit' when the merge actually contributed one of the
        # two fields NetApi cannot see; an INF lacking both leaves Source='NetApi'.
        if ($netApiOk -and (($null -ne $policy.PasswordComplexity) -or ($null -ne $policy.ClearTextPassword))) {
            $policy.Source = 'NetApi+Secedit'
        }
    }

    if ($policy.Source -eq 'Unavailable') {
        Write-Verbose 'Get-LocalPasswordPolicy: all resolution strategies failed; returning Unavailable'
    }
    return $policy
}
