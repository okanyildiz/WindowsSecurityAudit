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
    
    [CmdletBinding()]
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
        Write-Host "=== MEMORY DUMP EXPORT ===" -ForegroundColor Cyan
        Write-Host "Dump Type: $DumpType" -ForegroundColor Yellow
        Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
        
        # Check if running as Administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Warning "This function requires Administrator privileges!"
            Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
            return
        }
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
        }
        
        $result = [PSCustomObject]@{
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
        }
    }
    
    process {
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
            
            # METHOD 1: Try ProcDump if available and requested
            if ($UseProcDump) {
                Write-Host "`n[1/3] Attempting ProcDump method..." -ForegroundColor Cyan
                
                $procDumpPaths = @(
                    "C:\Tools\procdump.exe",
                    "C:\Tools\procdump64.exe",
                    "$env:TEMP\procdump.exe",
                    ".\procdump.exe"
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
                        $dumpFilePath
                    )
                    
                    try {
                        $procDumpResult = & $foundProcDump $procDumpArgs 2>&1
                        
                        if (Test-Path $dumpFilePath) {
                            $result.Success = $true
                            $result.Method = "ProcDump"
                            $result.DumpFile = $dumpFilePath
                            Write-Host "  Successfully created dump with ProcDump" -ForegroundColor Green
                        }
                    }
                    catch {
                        Write-Warning "ProcDump failed: $_"
                    }
                }
                else {
                    Write-Host "  ProcDump not found, trying alternative methods..." -ForegroundColor Gray
                }
            }
            
            # METHOD 2: Use MiniDumpWriteDump with proper handle
            if (-not $result.Success) {
                Write-Host "`n[2/3] Attempting MiniDumpWriteDump method..." -ForegroundColor Cyan
                
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
                    
                    # Create dump file
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
                    [ProcessDump]::CloseHandle($processHandle) | Out-Null
                    
                    if ($success -and (Test-Path $dumpFilePath)) {
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
                    
                    # Clean up failed dump file
                    if (Test-Path $dumpFilePath) {
                        Remove-Item $dumpFilePath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            # METHOD 3: Use rundll32.exe comsvcs.dll method (LSASS specific)
            if (-not $result.Success -and $DumpType -eq 'LSASS') {
                Write-Host "`n[3/3] Attempting comsvcs.dll method (LSASS specific)..." -ForegroundColor Cyan
                
                try {
                    $comsvcsPath = "$env:SystemRoot\System32\comsvcs.dll"
                    
                    if (Test-Path $comsvcsPath) {
                        Write-Host "  Using rundll32.exe with comsvcs.dll..." -ForegroundColor Gray
                        
                        # Build command
                        $arguments = @(
                            $comsvcsPath,
                            "MiniDump",
                            $targetProcess.Id,
                            "`"$dumpFilePath`"",
                            "full"
                        )
                        
                        # Run elevated
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName = "rundll32.exe"
                        $psi.Arguments = $arguments -join ' '
                        $psi.Verb = "runas"
                        $psi.WindowStyle = "Hidden"
                        
                        $proc = [System.Diagnostics.Process]::Start($psi)
                        $proc.WaitForExit(10000)  # Wait 10 seconds
                        
                        # Wait a moment for dump to complete
                        Start-Sleep -Seconds 2
                        
                        if (Test-Path $dumpFilePath) {
                            $result.Success = $true
                            $result.Method = "comsvcs.dll"
                            $result.DumpFile = $dumpFilePath
                            Write-Host "  Successfully created LSASS dump with comsvcs.dll" -ForegroundColor Green
                        }
                    }
                }
                catch {
                    Write-Warning "comsvcs.dll method failed: $_"
                }
            }
            
            # Check final result
            if ($result.Success -and (Test-Path $dumpFilePath)) {
                $dumpFile = Get-Item $dumpFilePath
                $result.FileSize = $dumpFile.Length
                
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