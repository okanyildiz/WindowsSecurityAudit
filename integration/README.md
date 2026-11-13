<#
# Windows integration verification pack

This directory contains the manual-but-scripted Windows proof for behavior that
mocked tests and non-Windows CI cannot establish. The script imports
WindowsSecurityAudit v1.9.0 or a compatible later module and supports Windows
PowerShell 5.1 and PowerShell 7 on a real Windows host.

## Files

```text
integration/
    Invoke-WindowsIntegrationChecks.ps1  # check runner
    README.md                            # this runbook
    IntegrationReport.json               # generated or overwritten at run time
```

The two source files are ASCII-only and UTF-8 with BOM. No source outside this
directory is changed by the pack. The outer PowerShell block-comment markers
are intentional: they allow the requested `ParseFile` check to validate this
Markdown runbook as well as the script.

## Safety and side effects

Run on a disposable Windows endpoint or an approved test host.

- The default run makes no persistent configuration change. JEA temporarily
  registers `WSA-IntegrationTest`, scoped by role to the current administrator,
  and removes it in `finally`. The script refuses to overwrite a preexisting
  endpoint with that name. Initial endpoint enumeration and post-removal
  verification fail closed; an enumeration or verification error produces FAIL.
- JEA uses a temporary copy of the sample PSSC and a temporary transcript
  directory. Both are deleted. The unchanged repository sample is validated
  first. Registration and removal use `-NoServiceRestart` when the installed
  PowerShell exposes that parameter.
- The MFT and USN operations are read-only. The MFT scan is capped at 64 records
  by default and at 120 seconds.
- DPAPI uses canary data only. Supplying the alternate credential starts a
  short child PowerShell process as that identity; it creates no user account.
- `-IncludeDump` dumps only the running PowerShell process (`$PID`) as a Mini
  dump. It never targets LSASS. The dump directory is deleted in `finally`.
- Setting all four SIEM environment variables authorizes one real test event to
  be sent to the configured DCR stream. No event is sent when they are absent.
- The JSON report is overwritten on each run. It contains status evidence,
  host/module paths, and any matching Defender threat metadata, but no canary
  plaintext, credential password, OAuth client secret, or access token.

A cleanup error produces FAIL. A hard process kill can bypass PowerShell
`finally` handling; normal errors and a second completed run do not accumulate
endpoints or dump directories.

## Prerequisites

1. Use an elevated 64-bit PowerShell 5.1 or PowerShell 7 process on Windows.
   Non-admin or unsupported checks return UNVERIFIED rather than bypassing the
   prerequisite.
2. Use an NTFS volume for `-DriveLetter` (default `C`). The USN journal must
   exist and be readable. Journal inactivity is valid and does not fail the
   native-source check.
3. The module manifest defaults to `../WindowsSecurityAudit.psd1`, relative to
   this script. Use `-ModulePath` to select another manifest.
4. JEA has an additional requirement: the complete `WindowsSecurityAudit`
   module, including `RoleCapabilities/WindowsSecurityAudit.Scan.psrc`, must be
   discoverable by module name in an admin-controlled `PSModulePath` location.
   The module selected for name-based JEA loading must exactly match the base
   and version imported with `-ModulePath`. A newer or otherwise different
   highest-installed copy produces UNVERIFIED instead of being substituted. A
   repository imported only by an explicit path is not sufficient for JEA. The
   production ACL guidance in `JEA/README.md` still
   applies.
5. WinRM and loopback PowerShell remoting must work. The temporary role is
   assigned to the current administrator, not to the sample CONTOSO group.
6. FullLanguage and working runtime C# compilation are required to prove the
   native USN/MFT implementations. The DPAPI check reports the actual language
   mode, the module's compilation expectation, and a benign real compilation
   result. ConstrainedLanguage is not relabeled as a native-code pass.
7. `Get-MpThreatDetection` must be available for a complete AMSI/Defender
   result. Import success alone does not prove Defender history was inspected.
8. For the full DPAPI proof, prepare credentials for a different test identity
   that is allowed to log on locally. Do not use the same account as the
   elevated runner; same-SID execution is reported UNVERIFIED.
9. For `-IncludeDump`, allow enough temporary disk space and expect AV/EDR to
   inspect dump activity. A blocked or invalid dump is reported honestly.
10. For the SIEM probe, provide an Entra application with client-credentials
    access and Monitoring Metrics Publisher on the DCR. `WSA_TEST_DCR_URI` must
    be the full HTTPS stream URI in this form:

    ```text
    https://<endpoint>/dataCollectionRules/<dcr-id>/streams/<stream>?api-version=<version>
    ```

    Network access to `login.microsoftonline.com` and the ingestion endpoint is
    required.

## Run: elevated Windows PowerShell 5.1

Open **Windows PowerShell as Administrator**. Replace the repository path with
the actual local path.

```powershell
Set-Location 'C:\src\WindowsSecurityAudit'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\integration\Invoke-WindowsIntegrationChecks.ps1
$LASTEXITCODE
```

That base run exercises everything that needs no extra credential. It returns
1 until the required cross-user DPAPI proof and any other required
prerequisites are satisfied. For the full local pack, including the optional
self-dump:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { `$credential = Get-Credential -Message 'Enter a DIFFERENT test user for the DPAPI boundary'; & '.\integration\Invoke-WindowsIntegrationChecks.ps1' -DpapiAlternateCredential `$credential -IncludeDump }"
$LASTEXITCODE
```

## Run: elevated PowerShell 7

Open **pwsh as Administrator** from the same repository location.

```powershell
Set-Location 'C:\src\WindowsSecurityAudit'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\integration\Invoke-WindowsIntegrationChecks.ps1
$LASTEXITCODE
```

Full local pack:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -Command "& { `$credential = Get-Credential -Message 'Enter a DIFFERENT test user for the DPAPI boundary'; & '.\integration\Invoke-WindowsIntegrationChecks.ps1' -DpapiAlternateCredential `$credential -IncludeDump }"
$LASTEXITCODE
```

To use another NTFS drive, MFT cap, module manifest, or report location:

```powershell
pwsh -NoProfile -File .\integration\Invoke-WindowsIntegrationChecks.ps1 -DriveLetter D -MftMaxRecords 32 -ModulePath 'C:\Program Files\WindowsPowerShell\Modules\WindowsSecurityAudit\WindowsSecurityAudit.psd1' -ReportPath 'C:\AuditEvidence\IntegrationReport.json'
```

The custom report directory must already exist.

## Optional live Sentinel OAuth and ingestion

Set these variables in the elevated parent session so both PowerShell 5.1 and
pwsh child processes inherit them. `Get-Credential` avoids putting the client
secret on a command line or in shell history.

```powershell
$env:WSA_TEST_TENANT_ID = '00000000-0000-0000-0000-000000000000'
$siemCredential = Get-Credential -Message 'Enter the Entra client ID as UserName and the client secret as Password'
$env:WSA_TEST_CLIENT_ID = $siemCredential.UserName
$env:WSA_TEST_CLIENT_SECRET = $siemCredential.GetNetworkCredential().Password
$env:WSA_TEST_DCR_URI = 'https://<endpoint>/dataCollectionRules/<dcr-id>/streams/<stream>?api-version=<version>'

pwsh -NoProfile -File .\integration\Invoke-WindowsIntegrationChecks.ps1

Remove-Item Env:WSA_TEST_TENANT_ID, Env:WSA_TEST_CLIENT_ID, Env:WSA_TEST_CLIENT_SECRET, Env:WSA_TEST_DCR_URI
Remove-Variable siemCredential -ErrorAction SilentlyContinue
$LASTEXITCODE
```

Use `powershell.exe` instead of `pwsh` to run this probe on PowerShell 5.1.
The evidence states separately whether token acquisition and ingestion
succeeded. The `ProbeId` in the JSON report identifies the single test event
for correlation. If any variable is absent, no request is made: all absent
means UNVERIFIED; a partial set means FAIL.

## Checks and what they prove

| Check | Required for exit 0 | Proof and important limits |
| --- | --- | --- |
| JEA temporary endpoint | Yes | Requires the discoverable module base and version to match the imported target. Validates the unchanged sample PSSC, validates and registers a current-admin-scoped temporary PSSC, invokes the literal Quick wrapper through `New-PSSession -ConfigurationName`, requires both Quick results, and confirms an arbitrary `Get-Process` script block is denied. Endpoint enumeration and verified removal fail closed. It does not validate a production role group or WDAC policy. |
| DPAPI protection and identity boundary | Yes | Calls the module-internal `Protect-WsaDpapiData` and `Unprotect-WsaDpapiData` in module scope and verifies the LocalMachine round-trip and marker. With the alternate credential, a CurrentUser canary must fail decryption under a different SID. Also prints actual language mode and real compilation capability. Without the credential, the check is UNVERIFIED. |
| Native FSCTL USN journal | Yes | Calls `Get-FileSystemJournal -Mode USNJournal -MaxRecords 100` and requires `Summary.Source='Native'` when the journal is readable. Record count is evidence only; zero activity is allowed. An unreadable or absent journal is UNVERIFIED. A readable `fsutil` fallback is not accepted as native proof. |
| Native live MFT and sector-tail parsing | Yes | Calls `MftTimestompScan` with `-IncludeAll` and a small cap. Requires `NativeMft`, success, scanned records, valid record identities, coherent SI/FN data, valid FILE_NAME timestamp flags, zero malformed records, and consistent sector/file-record geometry. `StopReason='MaxRecords'` is an expected completed cap, not a volume-wide scan. No timestomp finding is asserted. |
| Optional self-process memory dump | No | Runs only with `-IncludeDump`. Requires both module-reported success and an actual nonempty file with an MDMP signature in the temporary directory. The file is then deleted. |
| Optional Sentinel OAuth and ingestion | No | Runs only with all four `WSA_TEST_*` variables. Uses the module's `Get-SiemAccessToken` path and `Send-SiemEvent` SentinelLogsIngestion destination. Requires one event in one successful batch with zero failures. |
| Module import and AMSI/Defender history | Yes | Imports the manifest and requires exactly 77 exported functions for v1.9.x. If available, `Get-MpThreatDetection` history is searched for resources under the imported module root. Any matching module-file detection is FAIL. This is import plus Defender-history evidence, not a claim about every third-party AV product. |

Optional checks do not gate the process exit code, even when an explicitly
requested optional check fails. Their status remains visible in the table and
JSON and must still be investigated.

## Read the results

The console table has three columns: `Check`, `Status`, and `Evidence`.

- `PASS`: the stated assertion completed with evidence.
- `FAIL`: an assertion failed, module behavior was unsafe or incorrect, a live
  operation was unexpectedly denied, or cleanup failed.
- `UNVERIFIED`: the check was optional and not requested, or a prerequisite was
  absent. UNVERIFIED is not PASS and never satisfies a required check.

`IntegrationReport.json` adds UTC time, host and PowerShell metadata, per-check
required flags, duration, structured details, counts, and the final exit code.
For example, inspect it with:

```powershell
$report = Get-Content -LiteralPath .\integration\IntegrationReport.json -Raw | ConvertFrom-Json
$report.Summary
$report.Checks | Select-Object Check, Status, Required, Evidence
$report.Checks | Where-Object Status -ne 'PASS' | Format-List *
```

Exit code semantics are strict:

- `0`: every required check is PASS and the report was written.
- `1`: any required check is FAIL or UNVERIFIED, or the report could not be
  written.

## Recovery after an interrupted JEA run

First confirm that `WSA-IntegrationTest` belongs to this pack and that no other
operator is using it. The runner never removes an endpoint that existed before
its run. After explicit confirmation, an administrator can inspect and remove
a stale test endpoint with:

```powershell
Get-PSSessionConfiguration -Name WSA-IntegrationTest
Unregister-PSSessionConfiguration -Name WSA-IntegrationTest -Force -NoServiceRestart
```

If this PowerShell version lacks `-NoServiceRestart`, omit it and plan for the
corresponding WinRM service restart behavior. Review temporary JEA transcript
or dump directories before deleting them, especially after a hard kill.
#>
