<#
.SYNOPSIS
    Locale-invariant advanced audit policy helpers (private).
.DESCRIPTION
    Get-AuditPolicyTable resolves per-subcategory audit policy settings keyed by
    subcategory GUID (GUIDs are locale-invariant; canonical English names come
    from the static map below). Resolution order:
      1. AuditQuerySystemPolicy API (advapi32)
      2. auditpol /backup CSV (elevated)
      3. auditpol /get CSV (English Inclusion text only, non-admin)
      4. Unavailable (all Values $null)
.NOTES
    GUID map verified against MS-GPAC and dsccommunity/AuditPolicyDsc
    ($AuditSubcategoryToGUIDHash, edited from "auditpol /list /subcategory:* /v").
#>

$script:AuditSubcategoryMap = @{
    'Security State Change'                  = '{0CCE9210-69AE-11D9-BED3-505054503030}'
    'Security System Extension'              = '{0CCE9211-69AE-11D9-BED3-505054503030}'
    'System Integrity'                       = '{0CCE9212-69AE-11D9-BED3-505054503030}'
    'IPsec Driver'                           = '{0CCE9213-69AE-11D9-BED3-505054503030}'
    'Other System Events'                    = '{0CCE9214-69AE-11D9-BED3-505054503030}'
    'Logon'                                  = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Logoff'                                 = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'Account Lockout'                        = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    'IPsec Main Mode'                        = '{0CCE9218-69AE-11D9-BED3-505054503030}'
    'IPsec Quick Mode'                       = '{0CCE9219-69AE-11D9-BED3-505054503030}'
    'IPsec Extended Mode'                    = '{0CCE921A-69AE-11D9-BED3-505054503030}'
    'Special Logon'                          = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'Other Logon/Logoff Events'              = '{0CCE921C-69AE-11D9-BED3-505054503030}'
    'Network Policy Server'                  = '{0CCE9243-69AE-11D9-BED3-505054503030}'
    'User / Device Claims'                   = '{0CCE9247-69AE-11D9-BED3-505054503030}'
    'Group Membership'                       = '{0CCE9249-69AE-11D9-BED3-505054503030}'
    'File System'                            = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Registry'                               = '{0CCE921E-69AE-11D9-BED3-505054503030}'
    'Kernel Object'                          = '{0CCE921F-69AE-11D9-BED3-505054503030}'
    'SAM'                                    = '{0CCE9220-69AE-11D9-BED3-505054503030}'
    'Certification Services'                 = '{0CCE9221-69AE-11D9-BED3-505054503030}'
    'Application Generated'                  = '{0CCE9222-69AE-11D9-BED3-505054503030}'
    'Handle Manipulation'                    = '{0CCE9223-69AE-11D9-BED3-505054503030}'
    'File Share'                             = '{0CCE9224-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Packet Drop'         = '{0CCE9225-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Connection'          = '{0CCE9226-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events'             = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'Detailed File Share'                    = '{0CCE9244-69AE-11D9-BED3-505054503030}'
    'Removable Storage'                      = '{0CCE9245-69AE-11D9-BED3-505054503030}'
    'Central Policy Staging'                 = '{0CCE9246-69AE-11D9-BED3-505054503030}'
    'Sensitive Privilege Use'                = '{0CCE9228-69AE-11D9-BED3-505054503030}'
    'Non Sensitive Privilege Use'            = '{0CCE9229-69AE-11D9-BED3-505054503030}'
    'Other Privilege Use Events'             = '{0CCE922A-69AE-11D9-BED3-505054503030}'
    'Process Creation'                       = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'Process Termination'                    = '{0CCE922C-69AE-11D9-BED3-505054503030}'
    'DPAPI Activity'                         = '{0CCE922D-69AE-11D9-BED3-505054503030}'
    'RPC Events'                             = '{0CCE922E-69AE-11D9-BED3-505054503030}'
    'Plug and Play Events'                   = '{0CCE9248-69AE-11D9-BED3-505054503030}'
    'Token Right Adjusted Events'            = '{0CCE924A-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'                    = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'Authentication Policy Change'           = '{0CCE9230-69AE-11D9-BED3-505054503030}'
    'Authorization Policy Change'            = '{0CCE9231-69AE-11D9-BED3-505054503030}'
    'MPSSVC Rule-Level Policy Change'        = '{0CCE9232-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Policy Change'       = '{0CCE9233-69AE-11D9-BED3-505054503030}'
    'Other Policy Change Events'             = '{0CCE9234-69AE-11D9-BED3-505054503030}'
    'User Account Management'                = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Computer Account Management'            = '{0CCE9236-69AE-11D9-BED3-505054503030}'
    'Security Group Management'              = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Distribution Group Management'          = '{0CCE9238-69AE-11D9-BED3-505054503030}'
    'Application Group Management'           = '{0CCE9239-69AE-11D9-BED3-505054503030}'
    'Other Account Management Events'        = '{0CCE923A-69AE-11D9-BED3-505054503030}'
    'Directory Service Access'               = '{0CCE923B-69AE-11D9-BED3-505054503030}'
    'Directory Service Changes'              = '{0CCE923C-69AE-11D9-BED3-505054503030}'
    'Directory Service Replication'          = '{0CCE923D-69AE-11D9-BED3-505054503030}'
    'Detailed Directory Service Replication' = '{0CCE923E-69AE-11D9-BED3-505054503030}'
    'Credential Validation'                  = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'Kerberos Service Ticket Operations'     = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    'Other Account Logon Events'             = '{0CCE9241-69AE-11D9-BED3-505054503030}'
    'Kerberos Authentication Service'        = '{0CCE9242-69AE-11D9-BED3-505054503030}'
}

$script:AuditPolicyTableCache = $null

function Copy-AuditPolicyTable {
    <#
    .SYNOPSIS
        Clones an audit policy table (new hashtable + shallow-cloned entry objects).
    .DESCRIPTION
        Cache entries are PSCustomObjects returned by reference; without a clone a
        caller mutating .Value/.Source would corrupt the session cache. Entries
        contain only scalars, so a shallow .PSObject.Copy() per entry suffices.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Table
    )

    $copy = @{}
    foreach ($key in $Table.Keys) {
        $copy[$key] = $Table[$key].PSObject.Copy()
    }
    return $copy
}

function Get-AuditSubcategoryGuid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($script:AuditSubcategoryMap.ContainsKey($Name)) {
        return $script:AuditSubcategoryMap[$Name]
    }
    foreach ($key in $script:AuditSubcategoryMap.Keys) {
        if ($key -ieq $Name) { return $script:AuditSubcategoryMap[$key] }
    }
    return $null
}

function ConvertFrom-AuditPolicyBackupCsv {
    <#
    .SYNOPSIS
        Parses an 'auditpol /backup' CSV into a locale-invariant GUID -> value map (private).
    .DESCRIPTION
        Returns a hashtable keyed by lowercase subcategory GUID (no braces) with the
        numeric Setting Value (0-3) for each row. Locale-dependent columns (header
        row, subcategory names, inclusion text) are never interpreted: the header
        row is skipped positionally and replaced by fixed English headers
        (WinLogKit PR #58 / AuditPolicyDsc pattern), rows are matched by GUID and
        numeric value only (which also drops the Option: rows), and rows are
        merged per GUID: the System row wins when present, otherwise the per-user
        row for that GUID is used (per-user-only subcategories are not dropped).
        Accepts either a file -Path or raw -Lines (first line = header in both cases).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Lines')]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    $values = @{}

    $rawLines = @()
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        # Backup file is ANSI/system codepage on localized Windows: read WITHOUT
        # -Encoding (forcing UTF8 corrupts it, salt#68354).
        $rawLines = @(Get-Content -LiteralPath $Path)
    }
    else {
        $rawLines = @($Lines)
    }

    $dataLines = @($rawLines | Select-Object -Skip 1 |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($dataLines.Count -eq 0) { return $values }

    $rows = @($dataLines | ConvertFrom-Csv -Header 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value')
    $guidPattern = '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$'
    $candidates = @()
    foreach ($row in $rows) {
        $rowGuid = ''
        if ($null -ne $row.Guid) { $rowGuid = ($row.Guid -replace '[{}]', '').Trim() }
        $rowValue = ''
        if ($null -ne $row.Value) { $rowValue = $row.Value.Trim() }
        # GUID/Value filters drop the Option: rows
        if ($rowGuid -match $guidPattern -and $rowValue -match '^[0-3]$') {
            $candidates += $row
        }
    }
    # Localized Windows may localize the Target column.
    # auditpol emits the System row before the per-user rows, but the merge below
    # is order-independent: per GUID the System row wins when present, otherwise
    # the per-user row for THAT GUID is used (per-user-only subcategories must
    # not be dropped just because other GUIDs have System rows).
    $seen = @{}
    $seenFromSystem = @{}
    foreach ($row in $candidates) {
        $key = (($row.Guid -replace '[{}]', '').Trim()).ToLowerInvariant()
        $isSystemRow = ($row.Target -eq 'System')
        if ($seen.ContainsKey($key)) {
            # First-wins among same-target duplicates; a later System row
            # overrides an already-recorded per-user row for the same GUID.
            if ($isSystemRow -and -not $seenFromSystem[$key]) {
                $values[$key] = [int]($row.Value.Trim())
                $seenFromSystem[$key] = $true
            }
            continue
        }
        $seen[$key] = $true
        $seenFromSystem[$key] = $isSystemRow
        $values[$key] = [int]($row.Value.Trim())
    }
    return $values
}

function Get-AuditPolicyTable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string[]]$Subcategory,

        [Parameter()]
        [switch]$Force
    )

    $subsetRequested = ($PSBoundParameters.ContainsKey('Subcategory') -and
        $null -ne $Subcategory -and $Subcategory.Count -gt 0)

    if (-not $subsetRequested -and -not $Force -and $null -ne $script:AuditPolicyTableCache) {
        # Clone on read: callers must not be able to mutate the cached entries
        return (Copy-AuditPolicyTable -Table $script:AuditPolicyTableCache)
    }

    if ($subsetRequested) {
        $names = @($Subcategory)
    }
    else {
        $names = @($script:AuditSubcategoryMap.Keys)
    }

    # Table keyed by lowercase GUID without braces
    $guidToName = @{}
    foreach ($name in $names) {
        $guid = Get-AuditSubcategoryGuid -Name $name
        if ($null -eq $guid) {
            Write-Verbose "Get-AuditPolicyTable: unknown subcategory name '$name' (skipped)"
            continue
        }
        $key = ($guid -replace '[{}]', '').ToLowerInvariant()
        $guidToName[$key] = $name
    }

    $table = @{}
    foreach ($key in $guidToName.Keys) {
        $table[$key] = [PSCustomObject]@{
            Guid    = ('{' + $key.ToUpperInvariant() + '}')
            Name    = $guidToName[$key]
            Value   = $null
            Success = $false
            Failure = $false
            Source  = 'Unavailable'
        }
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
        Write-Verbose 'Get-AuditPolicyTable: not a Windows host; audit policy not applicable'
        if (-not $subsetRequested) { $script:AuditPolicyTableCache = Copy-AuditPolicyTable -Table $table }
        return $table
    }

    $resolved = $false
    $auditpol = $null

    # --- Strategy 1: AuditQuerySystemPolicy API (HardeningLens pattern) ---
    if (-not ([bool]('AuditPolicyNative' -as [type]))) {
        $auditPolicyNativeSource = @'
using System;
using System.Runtime.InteropServices;
public static class AuditPolicyNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct AUDIT_POLICY_INFORMATION {
        public Guid AuditSubCategoryGuid;
        public UInt32 AuditingInformation;
        public Guid AuditCategoryGuid;
    }
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids, UInt32 PolicyCount, out IntPtr ppAuditPolicy);
    [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr buffer);
    public static AUDIT_POLICY_INFORMATION[] QueryPolicies(Guid[] guids, out int win32Error) {
        win32Error = 0;
        IntPtr buffer = IntPtr.Zero;
        if (!AuditQuerySystemPolicy(guids, (UInt32)guids.Length, out buffer)) {
            win32Error = Marshal.GetLastWin32Error();
            return null;
        }
        try {
            AUDIT_POLICY_INFORMATION[] result = new AUDIT_POLICY_INFORMATION[guids.Length];
            IntPtr current = buffer;
            int size = Marshal.SizeOf(typeof(AUDIT_POLICY_INFORMATION));
            for (int i = 0; i < guids.Length; i++) {
                result[i] = (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(current, typeof(AUDIT_POLICY_INFORMATION));
                current = new IntPtr(current.ToInt64() + size);
            }
            return result;
        } finally { AuditFree(buffer); }
    }
}
'@
        try {
            Add-Type -TypeDefinition $auditPolicyNativeSource -ErrorAction Stop
        }
        catch {
            # Add-Type -TypeDefinition is blocked under Constrained Language Mode (JEA)
            Write-Verbose "Get-AuditPolicyTable: Add-Type AuditPolicyNative failed: $($_.Exception.Message)"
        }
    }

    if ([bool]('AuditPolicyNative' -as [type])) {
        try {
            $guidList = New-Object 'System.Collections.Generic.List[guid]'
            foreach ($key in $guidToName.Keys) { $guidList.Add([guid]$key) }
            $win32Error = 0
            $policies = [AuditPolicyNative]::QueryPolicies($guidList.ToArray(), [ref]$win32Error)
            if ($null -ne $policies) {
                for ($i = 0; $i -lt $policies.Count; $i++) {
                    $key = $policies[$i].AuditSubCategoryGuid.ToString()
                    if (-not $table.ContainsKey($key)) { continue }
                    # POLICY_AUDIT_EVENT_SUCCESS=1, FAILURE=2, NONE=4; 4 and 0 both mean No Auditing
                    $raw = [int]$policies[$i].AuditingInformation
                    $success = [bool]($raw -band 1)
                    $failure = [bool]($raw -band 2)
                    $value = 0
                    if ($success) { $value += 1 }
                    if ($failure) { $value += 2 }
                    $entry = $table[$key]
                    $entry.Value = $value
                    $entry.Success = $success
                    $entry.Failure = $failure
                    $entry.Source = 'Api'
                    $resolved = $true
                }
            }
            else {
                # 5 = ACCESS_DENIED, 1314 = PRIVILEGE_NOT_HELD: fall through to next strategy
                Write-Verbose "Get-AuditPolicyTable: AuditQuerySystemPolicy failed (win32 $win32Error)"
            }
        }
        catch {
            Write-Verbose "Get-AuditPolicyTable: API strategy failed: $($_.Exception.Message)"
        }
    }

    # --- Strategy 2: auditpol /backup CSV (elevated) ---
    if (-not $resolved) {
        $auditpol = Get-Command 'auditpol.exe' -ErrorAction SilentlyContinue
        if ($null -eq $auditpol) {
            $auditpol = Get-Command 'auditpol' -ErrorAction SilentlyContinue
        }
        if ($null -ne $auditpol) {
            $tempFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('wsa-audit-{0}.csv' -f [guid]::NewGuid().ToString('N'))
            try {
                $null = & $auditpol.Source '/backup' "/file:$tempFile" 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $tempFile)) {
                    $backupValues = ConvertFrom-AuditPolicyBackupCsv -Path $tempFile
                    foreach ($key in $backupValues.Keys) {
                        if (-not $table.ContainsKey($key)) { continue }
                        $value = $backupValues[$key]
                        $entry = $table[$key]
                        $entry.Value = $value
                        $entry.Success = [bool]($value -band 1)
                        $entry.Failure = [bool]($value -band 2)
                        $entry.Source = 'BackupCsv'
                        $resolved = $true
                    }
                }
                else {
                    Write-Verbose "Get-AuditPolicyTable: auditpol /backup failed (exit $LASTEXITCODE); elevation required"
                }
            }
            catch {
                Write-Verbose "Get-AuditPolicyTable: backup CSV strategy failed: $($_.Exception.Message)"
            }
            finally {
                if (Test-Path -LiteralPath $tempFile -ErrorAction SilentlyContinue) {
                    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # --- Strategy 3: auditpol /get CSV (non-admin, English text only) ---
    if (-not $resolved -and $null -ne $auditpol) {
        try {
            $output = @(& $auditpol.Source '/get' '/category:*' '/r' 2>$null)
            if ($LASTEXITCODE -eq 0 -and $output.Count -gt 1) {
                $lines = @($output | Select-Object -Skip 1 |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                $rows = @($lines | ConvertFrom-Csv -Header 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion')
                foreach ($row in $rows) {
                    if ($null -eq $row.Guid) { continue }
                    $key = (($row.Guid -replace '[{}]', '').Trim()).ToLowerInvariant()
                    if (-not $table.ContainsKey($key)) { continue }
                    $inclusion = ''
                    if ($null -ne $row.Inclusion) { $inclusion = $row.Inclusion.Trim() }
                    # Interpret ONLY canonical English text; localized text stays honestly unknown
                    $value = $null
                    if ($inclusion -ieq 'Success and Failure') { $value = 3 }
                    elseif ($inclusion -ieq 'Success') { $value = 1 }
                    elseif ($inclusion -ieq 'Failure') { $value = 2 }
                    elseif ($inclusion -ieq 'No Auditing') { $value = 0 }
                    $entry = $table[$key]
                    if ($null -ne $value) {
                        $entry.Value = $value
                        $entry.Success = [bool]($value -band 1)
                        $entry.Failure = [bool]($value -band 2)
                    }
                    $entry.Source = 'GetQuery'
                    $resolved = $true
                }
            }
            else {
                Write-Verbose "Get-AuditPolicyTable: auditpol /get failed (exit $LASTEXITCODE)"
            }
        }
        catch {
            Write-Verbose "Get-AuditPolicyTable: get CSV strategy failed: $($_.Exception.Message)"
        }
    }

    if (-not $resolved) {
        Write-Verbose 'Get-AuditPolicyTable: all resolution strategies failed; returning Unavailable table'
    }

    if (-not $subsetRequested) {
        # Cache keeps its own copy so caller mutations of the returned table
        # cannot corrupt the session cache
        $script:AuditPolicyTableCache = Copy-AuditPolicyTable -Table $table
    }
    return $table
}
