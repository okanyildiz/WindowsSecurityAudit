function Invoke-WsaExternalDumpCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter()]
        [string[]]$ArgumentList = @(),

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 300
    )

    $invokeResult = New-Object PSObject -Property ([ordered]@{
        ExitCode = $null
        Output = @()
        TimedOut = $false
        ErrorMessage = $null
    })
    $job = $null

    try {
        $job = Start-Job -ScriptBlock {
            param($CommandPath, $CommandArguments)

            $commandOutput = @(& $CommandPath @CommandArguments 2>&1)
            [PSCustomObject]@{
                ExitCode = $LASTEXITCODE
                Output = $commandOutput
            }
        } -ArgumentList $FilePath, (, $ArgumentList)

        $completedJob = $job | Wait-Job -Timeout $TimeoutSeconds
        if ($null -eq $completedJob) {
            $invokeResult.TimedOut = $true
            $invokeResult.ErrorMessage = "External dump command exceeded $TimeoutSeconds seconds."
            $job | Stop-Job -ErrorAction SilentlyContinue
        }
        else {
            $jobResult = $job | Receive-Job
            if ($null -eq $jobResult) {
                $invokeResult.ErrorMessage = 'External dump command returned no completion result.'
            }
            else {
                $invokeResult.ExitCode = $jobResult.ExitCode
                $invokeResult.Output = @($jobResult.Output)
            }
        }
    }
    catch {
        $invokeResult.ErrorMessage = $_.Exception.Message
    }
    finally {
        if ($null -ne $job) {
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }

    return $invokeResult
}

function Get-WsaDumpFileValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $validation = New-Object PSObject -Property ([ordered]@{
        IsValid = $false
        FileSize = [long]0
        ErrorMessage = $null
    })

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $validation.ErrorMessage = 'Dump file was not created.'
            return $validation
        }

        $dumpItem = Get-Item -LiteralPath $Path -ErrorAction Stop
        $validation.FileSize = [long]$dumpItem.Length
        if ($dumpItem.Length -le 0) {
            $validation.ErrorMessage = 'Dump file is empty.'
            return $validation
        }

        $stream = $null
        $signature = [byte[]]@(0, 0, 0, 0)
        $bytesRead = 0
        try {
            $stream = [System.IO.File]::Open(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            $bytesRead = $stream.Read($signature, 0, $signature.Length)
        }
        finally {
            if ($null -ne $stream) { $stream.Dispose() }
        }

        if ($bytesRead -ne 4 -or
            $signature[0] -ne 0x4D -or $signature[1] -ne 0x44 -or
            $signature[2] -ne 0x4D -or $signature[3] -ne 0x50) {
            $validation.ErrorMessage = 'Dump file does not have a valid MDMP signature.'
            return $validation
        }

        $validation.IsValid = $true
    }
    catch {
        $validation.ErrorMessage = "Dump file validation failed: $($_.Exception.Message)"
    }

    return $validation
}

function Export-MemoryDump {
    <#
    .SYNOPSIS
        Creates memory dumps for forensic analysis
    .DESCRIPTION
        Captures memory dumps of specific processes or full system memory using 
        multiple methods. Supports live system memory acquisition, process dumps,
        and LSASS dumps for credential analysis.
    .PARAMETER ProcessName
        Name of specific process to dump (e.g., 'lsass', 'chrome')
    .PARAMETER ProcessId
        Process ID to dump
    .PARAMETER DumpType
        Type of dump: Full, Mini, or LSASS
    .PARAMETER OutputPath
        Path to save memory dump files (default: C:\MemoryDumps)
    .PARAMETER UseProcDump
        Use Sysinternals ProcDump if available (more reliable)
    .PARAMETER Compress
        Compress dump file after creation
    .EXAMPLE
        Export-MemoryDump -ProcessName lsass -OutputPath "C:\Forensics"
        Export-MemoryDump -ProcessId 1234 -DumpType Full
    .OUTPUTS
        PSCustomObject with dump file information
    #>
    
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [string]$ProcessName,
        
        [Parameter()]
        [int]$ProcessId,
        
        [Parameter()]
        [ValidateSet('Full', 'Mini', 'LSASS')]
        [string]$DumpType = 'Mini',
        
        [Parameter()]
        [string]$OutputPath = 'C:\MemoryDumps',
        
        [Parameter()]
        [switch]$UseProcDump,
        
        [Parameter()]
        [switch]$Compress
    )
    
    begin {
        $effectiveLanguageMode = Get-WsaEffectiveLanguageMode
        $dynamicCompilationExpected = Test-WsaDynamicCompilationExpected

        $result = New-Object PSObject -Property ([ordered]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            DumpType = $DumpType
            ProcessName = $null
            ProcessId = $null
            DumpFile = $null
            FileSize = 0
            Success = $false
            Method = $null
            ErrorMessage = $null
            EffectiveLanguageMode = $effectiveLanguageMode
            DynamicCompilationExpected = $dynamicCompilationExpected
            UnavailableReason = $null
        })

        $languageModeUnavailable = ($effectiveLanguageMode -ne 'FullLanguage')
        if ($languageModeUnavailable) {
            $result.UnavailableReason = $effectiveLanguageMode
            $result.ErrorMessage = "Memory dump acquisition requires FullLanguage; effective language mode '$effectiveLanguageMode' cannot safely invoke the supported acquisition methods."
            Write-Warning "Export-MemoryDump: memory dump acquisition is unavailable in effective language mode '$effectiveLanguageMode'."
        }
        else {
            Write-Host "=== MEMORY DUMP EXPORT ===" -ForegroundColor Cyan
            Write-Host "Dump Type: $DumpType" -ForegroundColor Yellow
            Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow

            # Check if running as Administrator (Windows-only check; the WindowsPrincipal
            # APIs do not exist on other platforms)
            if ($env:OS -eq 'Windows_NT') {
                $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                if (-not $isAdmin) {
                    throw "This function requires Administrator privileges!"
                }
            }

            # Create output directory
            if (-not (Test-Path $OutputPath)) {
                if ($PSCmdlet.ShouldProcess($OutputPath, 'Create output directory')) {
                    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                    Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
                }
            }

            # Memory dumps (LSASS especially) can contain plaintext credentials, so restrict
            # the dump file to Administrators and SYSTEM instead of the inherited default
            # that grants every local user read access (mirrors the generated-script lockdown
            # in Register-ScheduledSecurityScan)
            function Protect-DumpFile {
                param([Parameter(Mandatory = $true)][string]$Path)
                if ($env:OS -ne 'Windows_NT') { return $true }
                $requiredSids = @('S-1-5-18', 'S-1-5-32-544')
                try {
                    $fileAcl = Get-Acl -Path $Path -ErrorAction Stop
                    $fileAcl.SetAccessRuleProtection($true, $false)
                    foreach ($existingRule in @($fileAcl.Access)) {
                        $null = $fileAcl.RemoveAccessRule($existingRule)
                    }
                    foreach ($sidString in $requiredSids) {
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                            (New-Object System.Security.Principal.SecurityIdentifier($sidString)),
                            [System.Security.AccessControl.FileSystemRights]::FullControl,
                            [System.Security.AccessControl.AccessControlType]::Allow)
                        $fileAcl.AddAccessRule($accessRule)
                    }
                    Set-Acl -Path $Path -AclObject $fileAcl -ErrorAction Stop
                }
                catch {
                    Write-Warning "Could not restrict permissions on '$Path'; the dump may contain credentials and may be readable by other local users: $_"
                    return $false
                }

                $appliedAcl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
                if ($null -eq $appliedAcl) {
                    Write-Warning "ACL verification FAILED on '$Path': could not re-read the ACL; the dump may contain credentials and may be readable by other local users."
                    return $false
                }
                $missingSids = @($requiredSids | Where-Object {
                    $sid = $_
                    -not @($appliedAcl.Access | Where-Object { Test-IdentityReferenceIsSid -IdentityReference $_.IdentityReference -Sid $sid }).Count
                })
                if ($missingSids.Count -gt 0) {
                    Write-Warning "ACL verification FAILED on '$Path': missing access rules for SID(s) $($missingSids -join ', '); the dump may contain credentials and may be readable by other local users."
                    return $false
                }
                return $true
            }

            # Pre-create the dump target as an empty, ACL-locked file so the dump content
            # is never written to a world-readable file (closes the create -> protect race:
            # writers that open the existing file inherit the locked ACL instead of the
            # permissive directory default)
            function Initialize-LockedDumpFile {
                param([Parameter(Mandatory = $true)][string]$Path)
                if (-not (Test-Path $Path)) {
                    New-Item -Path $Path -ItemType File -Force | Out-Null
                }
                $null = Protect-DumpFile -Path $Path
            }
        }
    }
    
    process {
        if ($languageModeUnavailable) { return }

        try {
            # Determine target process
            $targetProcess = $null
            
            if ($DumpType -eq 'LSASS') {
                Write-Host "`n[*] Targeting LSASS process for credential dump..." -ForegroundColor Cyan
                Write-Warning "LSASS dumps may trigger antivirus alerts!"
                
                $targetProcess = Get-Process -Name lsass -ErrorAction SilentlyContinue
                if (-not $targetProcess) {
                    Write-Error "Could not find LSASS process"
                    return
                }
                $ProcessName = 'lsass'
            }
            elseif ($ProcessId) {
                Write-Host "`n[*] Targeting Process ID: $ProcessId..." -ForegroundColor Cyan
                $targetProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
                if (-not $targetProcess) {
                    Write-Error "Process with ID $ProcessId not found. Use Get-Process to list running processes."
                    return
                }
                $ProcessName = $targetProcess.ProcessName
            }
            elseif ($ProcessName) {
                Write-Host "`n[*] Targeting Process: $ProcessName..." -ForegroundColor Cyan
                $targetProcess = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $targetProcess) {
                    Write-Error "Process '$ProcessName' not found. Use Get-Process to list running processes."
                    return
                }
            }
            else {
                Write-Error "No process specified. Use -ProcessName, -ProcessId, or -DumpType LSASS"
                return
            }
            
            $result.ProcessName = $targetProcess.ProcessName
            $result.ProcessId = $targetProcess.Id
            
            Write-Host "Process: $($targetProcess.ProcessName) (PID: $($targetProcess.Id))" -ForegroundColor Green
            
            # Generate dump filename
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $dumpFileName = "$($targetProcess.ProcessName)_$($targetProcess.Id)_${timestamp}.dmp"
            $dumpFilePath = Join-Path $OutputPath $dumpFileName
            $dumpTarget = "Process '$($targetProcess.ProcessName)' (PID: $($targetProcess.Id))"
            
            # METHOD 1: Try ProcDump if available and requested
            if ($UseProcDump) {
                Write-Host "`n[1/3] Attempting ProcDump method..." -ForegroundColor Cyan
                
                # Only search admin-controlled fixed paths. This function runs elevated
                # (and can target LSASS), so a procdump.exe planted in a user-writable
                # location (TEMP, current directory) would execute attacker-controlled
                # code with elevated privileges
                $procDumpPaths = @(
                    "C:\Tools\procdump.exe",
                    "C:\Tools\procdump64.exe"
                )
                
                $foundProcDump = $null
                foreach ($path in $procDumpPaths) {
                    if (Test-Path $path) {
                        $foundProcDump = $path
                        break
                    }
                }
                
                if ($foundProcDump) {
                    Write-Host "  Found ProcDump: $foundProcDump" -ForegroundColor Green
                    
                    $procDumpArgs = @(
                        "-accepteula",
                        "-ma",  # Full dump
                        $targetProcess.Id,
                        "`"$dumpFilePath`""
                    )
                    
                    if ($PSCmdlet.ShouldProcess($dumpTarget, 'Create memory dump')) {
                        try {
                            # Pre-create and ACL-lock the empty target so procdump writes
                            # into an already-locked file
                            Initialize-LockedDumpFile -Path $dumpFilePath

                            $procDumpResult = Invoke-WsaExternalDumpCommand -FilePath $foundProcDump -ArgumentList $procDumpArgs
                            if ($procDumpResult.TimedOut) {
                                throw "ProcDump timed out: $($procDumpResult.ErrorMessage)"
                            }
                            if ($procDumpResult.ExitCode -ne 0) {
                                throw "ProcDump exited with code '$($procDumpResult.ExitCode)'. $($procDumpResult.ErrorMessage)"
                            }

                            $validation = Get-WsaDumpFileValidation -Path $dumpFilePath
                            if (-not $validation.IsValid) {
                                throw "ProcDump created an invalid dump: $($validation.ErrorMessage)"
                            }

                            $result.Success = $true
                            $result.Method = "ProcDump"
                            $result.DumpFile = $dumpFilePath
                            Write-Host "  Successfully created dump with ProcDump" -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "ProcDump failed: $_"
                            $result.ErrorMessage = $_.Exception.Message
                            if (Test-Path -LiteralPath $dumpFilePath) {
                                Remove-Item -LiteralPath $dumpFilePath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                else {
                    Write-Host "  ProcDump not found, trying alternative methods..." -ForegroundColor Gray
                }
            }

            # METHOD 2: Use MiniDumpWriteDump with proper handle
            if (-not $result.Success -and -not $dynamicCompilationExpected) {
                if ($effectiveLanguageMode -eq 'FullLanguage') {
                    $result.UnavailableReason = 'DynamicCompilationUnavailable'
                }
                else {
                    $result.UnavailableReason = $effectiveLanguageMode
                }
                Write-Warning "Export-MemoryDump: MiniDumpWriteDump is unavailable in effective language mode '$effectiveLanguageMode'; trying the existing external-tool fallback when applicable."
            }
            if (-not $result.Success -and $dynamicCompilationExpected -and $PSCmdlet.ShouldProcess($dumpTarget, 'Create memory dump')) {
                Write-Host "`n[2/3] Attempting MiniDumpWriteDump method..." -ForegroundColor Cyan
                
                $processHandle = [IntPtr]::Zero
                $fileStream = $null
                
                try {
                    # FIXED: Define complete P/Invoke signatures with proper types
                    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ProcessDump {
    [Flags]
    public enum ProcessAccessFlags : uint {
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_QUERY_INFORMATION = 0x00000400
    }
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        ProcessAccessFlags processAccess,
        bool bInheritHandle,
        int processId
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint ProcessId,
        IntPtr hFile,
        uint DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam
    );
}
"@ -ErrorAction SilentlyContinue
                    
                    # FIXED: Open process handle with OpenProcess API
                    $processHandle = [ProcessDump]::OpenProcess(
                        [ProcessDump+ProcessAccessFlags]::PROCESS_ALL_ACCESS,
                        $false,
                        $targetProcess.Id
                    )
                    
                    if ($processHandle -eq [IntPtr]::Zero) {
                        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        throw "Failed to open process handle. Error code: $lastError (May need SeDebugPrivilege or SYSTEM access)"
                    }
                    
                    Write-Host "  Process handle obtained successfully" -ForegroundColor Green
                    
                    # Create dump file: pre-create and ACL-lock the empty target first
                    # so the dump content is written into an already-locked file
                    # (File::Create on an existing file preserves its security descriptor)
                    Initialize-LockedDumpFile -Path $dumpFilePath
                    $fileStream = [System.IO.File]::Create($dumpFilePath)
                    
                    # Determine dump type flag
                    $dumpTypeFlag = switch ($DumpType) {
                        'Full' { 2 }    # MiniDumpWithFullMemory
                        'Mini' { 0 }    # MiniDumpNormal
                        'LSASS' { 2 }   # Full dump for LSASS
                    }
                    
                    Write-Host "  Creating dump file..." -ForegroundColor Gray
                    
                    # Create the dump
                    $success = [ProcessDump]::MiniDumpWriteDump(
                        $processHandle,
                        [uint32]$targetProcess.Id,
                        $fileStream.SafeFileHandle.DangerousGetHandle(),
                        $dumpTypeFlag,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero
                    )
                    
                    $fileStream.Close()
                    $fileStream = $null
                    [ProcessDump]::CloseHandle($processHandle) | Out-Null
                    $processHandle = [IntPtr]::Zero
                    
                    if ($success) {
                        $validation = Get-WsaDumpFileValidation -Path $dumpFilePath
                        if (-not $validation.IsValid) {
                            throw "MiniDumpWriteDump created an invalid dump: $($validation.ErrorMessage)"
                        }

                        $result.Success = $true
                        $result.Method = "MiniDumpWriteDump"
                        $result.DumpFile = $dumpFilePath
                        Write-Host "  Successfully created dump with MiniDumpWriteDump" -ForegroundColor Green
                    }
                    else {
                        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        throw "MiniDumpWriteDump failed with error code: $lastError"
                    }
                }
                catch {
                    Write-Warning "MiniDumpWriteDump failed: $_"
                    $result.ErrorMessage = $_.Exception.Message
                    
                    # Release resources if the attempt failed after they were acquired
                    if ($null -ne $fileStream) { $fileStream.Dispose() }
                    if ($processHandle -ne [IntPtr]::Zero) { [ProcessDump]::CloseHandle($processHandle) | Out-Null }
                    
                    # Clean up failed dump file
                    if (Test-Path $dumpFilePath) {
                        Remove-Item $dumpFilePath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            # METHOD 3: Use rundll32.exe comsvcs.dll method (LSASS specific)
            if (-not $result.Success -and $DumpType -eq 'LSASS' -and $PSCmdlet.ShouldProcess($dumpTarget, 'Create memory dump (LSASS)')) {
                Write-Host "`n[3/3] Attempting comsvcs.dll method (LSASS specific)..." -ForegroundColor Cyan

                try {
                    $comsvcsPath = "$env:SystemRoot\System32\comsvcs.dll"
                    if (-not (Test-Path $comsvcsPath)) {
                        throw "comsvcs.dll was not found at '$comsvcsPath'."
                    }

                    Write-Host "  Using rundll32.exe with comsvcs.dll..." -ForegroundColor Gray
                    $arguments = @(
                        $comsvcsPath,
                        "MiniDump",
                        $targetProcess.Id,
                        "`"$dumpFilePath`"",
                        "full"
                    )

                    # The function already requires elevation. Pre-create and ACL-lock the
                    # target so rundll32 inherits the locked ACL when it writes the dump.
                    Initialize-LockedDumpFile -Path $dumpFilePath
                    $rundll32Path = "$env:SystemRoot\System32\rundll32.exe"
                    $comsvcsResult = Invoke-WsaExternalDumpCommand -FilePath $rundll32Path -ArgumentList $arguments
                    if ($comsvcsResult.TimedOut) {
                        throw "comsvcs.dll timed out: $($comsvcsResult.ErrorMessage)"
                    }
                    if ($comsvcsResult.ExitCode -ne 0) {
                        throw "comsvcs.dll exited with code '$($comsvcsResult.ExitCode)'. $($comsvcsResult.ErrorMessage)"
                    }

                    $validation = Get-WsaDumpFileValidation -Path $dumpFilePath
                    if (-not $validation.IsValid) {
                        throw "comsvcs.dll created an invalid dump: $($validation.ErrorMessage)"
                    }

                    $result.Success = $true
                    $result.Method = "comsvcs.dll"
                    $result.DumpFile = $dumpFilePath
                    Write-Host "  Successfully created LSASS dump with comsvcs.dll" -ForegroundColor Green
                }
                catch {
                    Write-Warning "comsvcs.dll method failed: $_"
                    $result.ErrorMessage = $_.Exception.Message
                    if (Test-Path -LiteralPath $dumpFilePath) {
                        Remove-Item -LiteralPath $dumpFilePath -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            if (-not $result.Success -and -not $dynamicCompilationExpected -and [string]::IsNullOrEmpty($result.ErrorMessage)) {
                $result.ErrorMessage = "MiniDumpWriteDump was skipped because dynamic compilation is not expected in effective language mode '$effectiveLanguageMode'."
            }

            # Check final result
            if ($result.Success -and (Test-Path $dumpFilePath)) {
                $dumpFile = Get-Item $dumpFilePath
                $result.FileSize = $dumpFile.Length
                $null = Protect-DumpFile -Path $dumpFilePath

                $fileSizeMB = [Math]::Round($dumpFile.Length / 1MB, 2)
                Write-Host "`n[SUCCESS] Memory dump created!" -ForegroundColor Green
                Write-Host "  File: $dumpFilePath" -ForegroundColor Cyan
                Write-Host "  Size: $fileSizeMB MB" -ForegroundColor Cyan
                Write-Host "  Method: $($result.Method)" -ForegroundColor Cyan
                
                # Compress if requested
                if ($Compress) {
                    Write-Host "`n[*] Compressing dump file..." -ForegroundColor Cyan
                    
                    try {
                        $zipPath = "$dumpFilePath.zip"
                        Compress-Archive -Path $dumpFilePath -DestinationPath $zipPath -CompressionLevel Optimal
                        
                        if (Test-Path $zipPath) {
                            $null = Protect-DumpFile -Path $zipPath
                            $zipFile = Get-Item $zipPath
                            $zipSizeMB = [Math]::Round($zipFile.Length / 1MB, 2)
                            $compressionRatio = [Math]::Round((1 - ($zipFile.Length / $dumpFile.Length)) * 100, 1)
                            
                            Write-Host "  Compressed: $zipPath" -ForegroundColor Green
                            Write-Host "  Compressed Size: $zipSizeMB MB" -ForegroundColor Cyan
                            Write-Host "  Compression Ratio: $compressionRatio%" -ForegroundColor Cyan
                            
                            # Optionally remove uncompressed file
                            Write-Host "`n  Remove original dump file? (Y/N)" -ForegroundColor Yellow -NoNewline
                            $removeOriginal = Read-Host
                            if ($removeOriginal -eq 'Y') {
                                Remove-Item $dumpFilePath -Force
                                Write-Host "  Removed original dump file" -ForegroundColor Gray
                                $result.DumpFile = $zipPath
                            }
                        }
                    }
                    catch {
                        Write-Warning "Compression failed: $_"
                    }
                }
                
                # Security recommendations
                Write-Host "`n[!] SECURITY RECOMMENDATIONS:" -ForegroundColor Yellow
                Write-Host "  1. Store dump files securely (contains sensitive data)" -ForegroundColor Yellow
                Write-Host "  2. Encrypt dump files before transferring" -ForegroundColor Yellow
                Write-Host "  3. Delete dump files after analysis" -ForegroundColor Yellow
                if ($DumpType -eq 'LSASS') {
                    Write-Host "  4. LSASS dumps may contain plaintext credentials!" -ForegroundColor Red
                    Write-Host "  5. Use Mimikatz or pypykatz for credential extraction" -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "`n[FAILED] Could not create memory dump" -ForegroundColor Red
                Write-Host "Possible reasons:" -ForegroundColor Yellow
                Write-Host "  - Insufficient permissions (need SeDebugPrivilege or SYSTEM)" -ForegroundColor Yellow
                Write-Host "  - Process is protected (PPL - Protected Process Light)" -ForegroundColor Yellow
                Write-Host "  - Antivirus/EDR blocking the operation" -ForegroundColor Yellow
                Write-Host "  - Insufficient disk space" -ForegroundColor Yellow
                
                if ($DumpType -eq 'LSASS') {
                    Write-Host "`nFor LSASS dumps, try:" -ForegroundColor Cyan
                    Write-Host "  - Using ProcDump: procdump.exe -accepteula -ma lsass.exe lsass.dmp" -ForegroundColor Gray
                    Write-Host "  - Task Manager: Right-click lsass.exe > Create dump file" -ForegroundColor Gray
                    Write-Host "  - Run PowerShell as SYSTEM: psexec -s -i powershell.exe" -ForegroundColor Gray
                }
            }
            
        }
        catch {
            Write-Error "Error during memory dump: $_"
            $result.Success = $false
            $result.ErrorMessage = $_.Exception.Message
        }
    }
    
    end {
        return $result
    }
}