<#
.SYNOPSIS
    Reads USN journal records through native file system control calls (private).
.DESCRIPTION
    Get-UsnJournalNative uses FSCTL_QUERY_USN_JOURNAL and
    FSCTL_READ_USN_JOURNAL instead of parsing localized fsutil output. The C#
    ParseBuffer and ReadJournalChunks methods are cross-platform synthetic seams.
    Native failures before the first record are returned to the caller for
    fsutil fallback; failures after records are returned as partial evidence.
.NOTES
    All native allocation, marshaling, pinning, and buffer walking stays in C#
    for Windows PowerShell 5.1 compatibility and Constrained Language Mode
    fallback. No type is exported from the module.
#>

$script:UsnJournalNativeTypeError = $null
$script:UsnJournalNativeUnavailableReason = $null
$script:UsnJournalNativeEffectiveLanguageMode = 'Unavailable'
$script:UsnJournalNativeDynamicCompilationExpected = $false

function Initialize-UsnJournalNativeType {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $effectiveLanguageMode = Get-WsaEffectiveLanguageMode
    $dynamicCompilationExpected = Test-WsaDynamicCompilationExpected
    $script:UsnJournalNativeEffectiveLanguageMode = $effectiveLanguageMode
    $script:UsnJournalNativeDynamicCompilationExpected = $dynamicCompilationExpected
    $script:UsnJournalNativeUnavailableReason = $null

    if (-not $dynamicCompilationExpected) {
        $script:UsnJournalNativeUnavailableReason = 'ConstrainedLanguage'
        $script:UsnJournalNativeTypeError = "Dynamic compilation is not expected in effective language mode '$effectiveLanguageMode'."
        Write-Warning "Initialize-UsnJournalNativeType: native USN journal reading is unavailable in effective language mode '$effectiveLanguageMode'; callers must use the fsutil fallback."
        return $false
    }

    if ([bool]('UsnJournalNative' -as [type])) {
        return $true
    }

    $usnJournalNativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class UsnJournalNative {
    private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;

    private const int ERROR_INVALID_FUNCTION = 1;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_NOT_SUPPORTED = 50;
    private const int ERROR_INVALID_PARAMETER = 87;
    private const int ERROR_MORE_DATA = 234;
    private const int ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178;
    private const int ERROR_JOURNAL_NOT_ACTIVE = 1179;
    private const int ERROR_JOURNAL_ENTRY_DELETED = 1181;

    private const int InitialBufferSize = 64 * 1024;
    private const int MaximumBufferSize = 1024 * 1024;

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct USN_JOURNAL_DATA_V0 {
        internal ulong UsnJournalID;
        internal long FirstUsn;
        internal long NextUsn;
        internal long LowestValidUsn;
        internal long MaxUsn;
        internal ulong MaximumSize;
        internal ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct USN_JOURNAL_DATA_V1 {
        internal ulong UsnJournalID;
        internal long FirstUsn;
        internal long NextUsn;
        internal long LowestValidUsn;
        internal long MaxUsn;
        internal ulong MaximumSize;
        internal ulong AllocationDelta;
        internal ushort MinSupportedMajorVersion;
        internal ushort MaxSupportedMajorVersion;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct USN_JOURNAL_DATA_V2 {
        internal ulong UsnJournalID;
        internal long FirstUsn;
        internal long NextUsn;
        internal long LowestValidUsn;
        internal long MaxUsn;
        internal ulong MaximumSize;
        internal ulong AllocationDelta;
        internal ushort MinSupportedMajorVersion;
        internal ushort MaxSupportedMajorVersion;
        internal uint Flags;
        internal ulong RangeTrackChunkSize;
        internal long RangeTrackFileSizeThreshold;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct READ_USN_JOURNAL_DATA_V0 {
        internal long StartUsn;
        internal uint ReasonMask;
        internal uint ReturnOnlyOnClose;
        internal ulong Timeout;
        internal ulong BytesToWaitFor;
        internal ulong UsnJournalID;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct READ_USN_JOURNAL_DATA_V1 {
        internal long StartUsn;
        internal uint ReasonMask;
        internal uint ReturnOnlyOnClose;
        internal ulong Timeout;
        internal ulong BytesToWaitFor;
        internal ulong UsnJournalID;
        internal ushort MinMajorVersion;
        internal ushort MaxMajorVersion;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct USN_RECORD_COMMON_HEADER {
        internal uint RecordLength;
        internal ushort MajorVersion;
        internal ushort MinorVersion;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct USN_RECORD_V2_HEADER {
        internal uint RecordLength;
        internal ushort MajorVersion;
        internal ushort MinorVersion;
        internal ulong FileReferenceNumber;
        internal ulong ParentFileReferenceNumber;
        internal long Usn;
        internal long TimeStamp;
        internal uint Reason;
        internal uint SourceInfo;
        internal uint SecurityId;
        internal uint FileAttributes;
        internal ushort FileNameLength;
        internal ushort FileNameOffset;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct FILE_ID_128 {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] Identifier;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct USN_RECORD_V3_HEADER {
        internal uint RecordLength;
        internal ushort MajorVersion;
        internal ushort MinorVersion;
        internal FILE_ID_128 FileReferenceNumber;
        internal FILE_ID_128 ParentFileReferenceNumber;
        internal long Usn;
        internal long TimeStamp;
        internal uint Reason;
        internal uint SourceInfo;
        internal uint SecurityId;
        internal uint FileAttributes;
        internal ushort FileNameLength;
        internal ushort FileNameOffset;
    }

    public class UsnJournalRecord {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public string FileName;
        public ulong FileReferenceNumber;
        public ulong ParentFileReferenceNumber;
        public byte[] FileReferenceNumber128;
        public byte[] ParentFileReferenceNumber128;
        public long Usn;
        public DateTime? TimeStamp;
        public uint ReasonMask;
        public uint FileAttributes;
    }

    public class UsnBufferParseResult {
        public List<UsnJournalRecord> Records = new List<UsnJournalRecord>();
        public List<string> Diagnostics = new List<string>();
        public long NextUsn;
        public bool Success;
        public string Error;
    }

    public class UsnJournalReadResult {
        public List<UsnJournalRecord> Records = new List<UsnJournalRecord>();
        public List<string> Notes = new List<string>();
        public long NextUsn;
        public bool Success;
        public string Error;
    }

    public class UsnChunkReadContext {
        public long StartUsn;
        public byte[] OutputBuffer;
        public bool UseVersion1;
        public ushort MinMajorVersion;
        public ushort MaxMajorVersion;
    }

    public class UsnChunkReadResult {
        public bool Success;
        public uint BytesReturned;
        public int Win32Error;
    }

    public delegate UsnChunkReadResult UsnChunkReader(UsnChunkReadContext context);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    public static UsnBufferParseResult ParseBuffer(byte[] buffer, int bytesReturned, int maxRecords) {
        UsnBufferParseResult result = new UsnBufferParseResult();
        result.Success = false;

        if (buffer == null) {
            result.Error = "The USN journal buffer is null.";
            return result;
        }
        if (maxRecords < 1) {
            result.Error = "MaxRecords must be greater than zero.";
            return result;
        }
        if (bytesReturned < 8) {
            result.Error = "The USN journal buffer is shorter than its 8-byte continuation USN.";
            return result;
        }
        if (bytesReturned > buffer.Length) {
            result.Error = "The returned byte count exceeds the USN journal buffer length.";
            return result;
        }

        result.NextUsn = BitConverter.ToInt64(buffer, 0);
        int offset = 8;

        while (offset < bytesReturned && result.Records.Count < maxRecords) {
            int remaining = bytesReturned - offset;
            if (remaining < 8) {
                result.Error = string.Format(
                    "Trailing partial USN record header at buffer offset {0}: only {1} bytes remain.",
                    offset,
                    remaining);
                return result;
            }

            uint recordLength = BitConverter.ToUInt32(buffer, offset);
            ushort majorVersion = BitConverter.ToUInt16(buffer, offset + 4);
            ushort minorVersion = BitConverter.ToUInt16(buffer, offset + 6);

            if (recordLength < 8) {
                result.Error = string.Format(
                    "Invalid RecordLength {0} at buffer offset {1}: a record must be at least 8 bytes.",
                    recordLength,
                    offset);
                return result;
            }
            if (recordLength > (uint)remaining) {
                result.Error = string.Format(
                    "Invalid RecordLength {0} at buffer offset {1}: only {2} bytes remain.",
                    recordLength,
                    offset,
                    remaining);
                return result;
            }
            if ((recordLength & 7) != 0) {
                result.Error = string.Format(
                    "Invalid RecordLength {0} at buffer offset {1}: FSCTL records must be 8-byte aligned.",
                    recordLength,
                    offset);
                return result;
            }

            if (majorVersion != 2 && majorVersion != 3) {
                result.Diagnostics.Add(string.Format(
                    "Skipped unsupported USN record major version {0} at buffer offset {1} (RecordLength {2}).",
                    majorVersion,
                    offset,
                    recordLength));
                offset += (int)recordLength;
                continue;
            }

            int fixedPrefixSize = majorVersion == 2 ? 60 : 76;
            if (recordLength < (uint)fixedPrefixSize) {
                result.Error = string.Format(
                    "USN_RECORD_V{0} at buffer offset {1} has RecordLength {2}, shorter than its {3}-byte fixed prefix.",
                    majorVersion,
                    offset,
                    recordLength,
                    fixedPrefixSize);
                return result;
            }

            UsnJournalRecord record = new UsnJournalRecord();
            record.MajorVersion = majorVersion;
            record.MinorVersion = minorVersion;

            ushort fileNameLength;
            ushort fileNameOffset;
            long fileTime;

            if (majorVersion == 2) {
                record.FileReferenceNumber = BitConverter.ToUInt64(buffer, offset + 8);
                record.ParentFileReferenceNumber = BitConverter.ToUInt64(buffer, offset + 16);
                record.Usn = BitConverter.ToInt64(buffer, offset + 24);
                fileTime = BitConverter.ToInt64(buffer, offset + 32);
                record.ReasonMask = BitConverter.ToUInt32(buffer, offset + 40);
                record.FileAttributes = BitConverter.ToUInt32(buffer, offset + 52);
                fileNameLength = BitConverter.ToUInt16(buffer, offset + 56);
                fileNameOffset = BitConverter.ToUInt16(buffer, offset + 58);
            }
            else {
                record.FileReferenceNumber128 = new byte[16];
                record.ParentFileReferenceNumber128 = new byte[16];
                Array.Copy(buffer, offset + 8, record.FileReferenceNumber128, 0, 16);
                Array.Copy(buffer, offset + 24, record.ParentFileReferenceNumber128, 0, 16);
                record.Usn = BitConverter.ToInt64(buffer, offset + 40);
                fileTime = BitConverter.ToInt64(buffer, offset + 48);
                record.ReasonMask = BitConverter.ToUInt32(buffer, offset + 56);
                record.FileAttributes = BitConverter.ToUInt32(buffer, offset + 68);
                fileNameLength = BitConverter.ToUInt16(buffer, offset + 72);
                fileNameOffset = BitConverter.ToUInt16(buffer, offset + 74);
            }

            if ((fileNameLength & 1) != 0) {
                result.Error = string.Format(
                    "Invalid FileNameLength {0} at buffer offset {1}: UTF-16 names require an even byte count.",
                    fileNameLength,
                    offset);
                return result;
            }
            if (fileNameOffset < fixedPrefixSize) {
                result.Error = string.Format(
                    "Invalid FileNameOffset {0} at buffer offset {1}: the name overlaps the {2}-byte fixed prefix.",
                    fileNameOffset,
                    offset,
                    fixedPrefixSize);
                return result;
            }
            if ((int)fileNameOffset + (int)fileNameLength > (int)recordLength) {
                result.Error = string.Format(
                    "File name at buffer offset {0} extends beyond RecordLength {1} (FileNameOffset {2}, FileNameLength {3}).",
                    offset,
                    recordLength,
                    fileNameOffset,
                    fileNameLength);
                return result;
            }

            record.FileName = System.Text.Encoding.Unicode.GetString(
                buffer,
                offset + (int)fileNameOffset,
                (int)fileNameLength);

            try {
                record.TimeStamp = DateTime.FromFileTimeUtc(fileTime);
            }
            catch (ArgumentOutOfRangeException) {
                record.TimeStamp = null;
                result.Diagnostics.Add(string.Format(
                    "Invalid FILETIME {0} at buffer offset {1}; TimeStamp is null.",
                    fileTime,
                    offset));
            }

            result.Records.Add(record);
            offset += (int)recordLength;
        }

        result.Success = true;
        return result;
    }

    public static UsnJournalReadResult ReadJournal(string driveLetter, int maxRecords, uint reasonMask) {
        UsnJournalReadResult result = new UsnJournalReadResult();
        result.Success = false;

        if (string.IsNullOrWhiteSpace(driveLetter)) {
            result.Error = "DriveLetter cannot be empty.";
            return result;
        }
        if (maxRecords < 1) {
            result.Error = "MaxRecords must be greater than zero.";
            return result;
        }

        string drive = driveLetter.Trim().TrimEnd(':', '\\').ToUpperInvariant();
        if (drive.Length != 1 || !((drive[0] >= 'A' && drive[0] <= 'Z'))) {
            result.Error = "DriveLetter must contain exactly one ASCII letter.";
            return result;
        }

        string volumePath = @"\\.\" + drive + ":";

        try {
            using (SafeFileHandle volume = CreateFileW(
                volumePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero)) {

                if (volume == null || volume.IsInvalid) {
                    int openError = Marshal.GetLastWin32Error();
                    result.Error = FormatNativeError("CreateFileW", openError);
                    return result;
                }

                byte[] queryBuffer = new byte[80];
                uint queryBytesReturned = 0;
                bool queryOk;
                int queryError = 0;
                GCHandle queryPin = GCHandle.Alloc(queryBuffer, GCHandleType.Pinned);
                try {
                    queryOk = DeviceIoControl(
                        volume,
                        FSCTL_QUERY_USN_JOURNAL,
                        IntPtr.Zero,
                        0,
                        queryPin.AddrOfPinnedObject(),
                        (uint)queryBuffer.Length,
                        out queryBytesReturned,
                        IntPtr.Zero);
                    if (!queryOk) {
                        queryError = Marshal.GetLastWin32Error();
                    }
                }
                finally {
                    queryPin.Free();
                }

                if (!queryOk) {
                    result.Error = FormatNativeError("FSCTL_QUERY_USN_JOURNAL", queryError);
                    return result;
                }
                if (queryBytesReturned < 56 || queryBytesReturned > (uint)queryBuffer.Length) {
                    result.Error = string.Format(
                        "FSCTL_QUERY_USN_JOURNAL returned an invalid byte count: {0}.",
                        queryBytesReturned);
                    return result;
                }

                USN_JOURNAL_DATA_V0 queryData = new USN_JOURNAL_DATA_V0();
                queryData.UsnJournalID = BitConverter.ToUInt64(queryBuffer, 0);
                queryData.FirstUsn = BitConverter.ToInt64(queryBuffer, 8);
                queryData.NextUsn = BitConverter.ToInt64(queryBuffer, 16);
                queryData.LowestValidUsn = BitConverter.ToInt64(queryBuffer, 24);
                queryData.MaxUsn = BitConverter.ToInt64(queryBuffer, 32);
                queryData.MaximumSize = BitConverter.ToUInt64(queryBuffer, 40);
                queryData.AllocationDelta = BitConverter.ToUInt64(queryBuffer, 48);

                result.NextUsn = queryData.NextUsn;
                if (queryData.FirstUsn < queryData.LowestValidUsn) {
                    result.Notes.Add(string.Format(
                        "Possible USN journal discontinuity: FirstUsn {0} is below LowestValidUsn {1}.",
                        queryData.FirstUsn,
                        queryData.LowestValidUsn));
                }

                bool useVersion1 = queryBytesReturned >= 64;
                ushort minMajorVersion = 0;
                ushort maxMajorVersion = 0;
                if (useVersion1) {
                    ushort supportedMin = BitConverter.ToUInt16(queryBuffer, 56);
                    ushort supportedMax = BitConverter.ToUInt16(queryBuffer, 58);
                    minMajorVersion = Math.Max((ushort)2, supportedMin);
                    maxMajorVersion = Math.Min((ushort)3, supportedMax);
                    if (minMajorVersion > maxMajorVersion) {
                        result.Error = string.Format(
                            "The journal supports major versions {0} through {1}; this reader supports only V2 and V3 records.",
                            supportedMin,
                            supportedMax);
                        return result;
                    }
                }

                UsnJournalReadResult readResult = ReadJournalChunks(
                    queryData.FirstUsn,
                    queryData.NextUsn,
                    maxRecords,
                    useVersion1,
                    minMajorVersion,
                    maxMajorVersion,
                    delegate(UsnChunkReadContext context) {
                        UsnChunkReadResult chunkResult = new UsnChunkReadResult();
                        chunkResult.Success = ReadChunk(
                            volume,
                            queryData.UsnJournalID,
                            context.StartUsn,
                            reasonMask,
                            context.UseVersion1,
                            context.MinMajorVersion,
                            context.MaxMajorVersion,
                            context.OutputBuffer,
                            out chunkResult.BytesReturned,
                            out chunkResult.Win32Error);
                        return chunkResult;
                    });

                result.Records = readResult.Records;
                foreach (string note in readResult.Notes) {
                    result.Notes.Add(note);
                }
                result.NextUsn = readResult.NextUsn;
                result.Error = readResult.Error;
                result.Success = readResult.Success;
            }
        }
        catch (Exception exception) {
            result.Error = "Native USN journal read failed: " + exception.Message;
            result.Success = false;
        }

        return result;
    }

    public static UsnJournalReadResult ReadJournalChunks(
        long startUsn,
        long targetNextUsn,
        int maxRecords,
        bool useVersion1,
        ushort minMajorVersion,
        ushort maxMajorVersion,
        UsnChunkReader chunkReader) {

        UsnJournalReadResult result = new UsnJournalReadResult();
        result.Success = false;
        result.NextUsn = targetNextUsn;

        if (maxRecords < 1) {
            result.Error = "MaxRecords must be greater than zero.";
            return result;
        }
        if (chunkReader == null) {
            result.Error = "The USN journal chunk reader is null.";
            return result;
        }

        int bufferSize = InitialBufferSize;
        byte[] readBuffer = new byte[bufferSize];

        while (startUsn < targetNextUsn && result.Records.Count < maxRecords) {
            UsnChunkReadContext context = new UsnChunkReadContext();
            context.StartUsn = startUsn;
            context.OutputBuffer = readBuffer;
            context.UseVersion1 = useVersion1;
            context.MinMajorVersion = minMajorVersion;
            context.MaxMajorVersion = maxMajorVersion;

            UsnChunkReadResult chunkResult = chunkReader(context);
            if (chunkResult == null) {
                result.Error = "The USN journal chunk reader returned no result.";
                break;
            }

            if (!chunkResult.Success && useVersion1 && IsVersion1FallbackError(chunkResult.Win32Error)) {
                useVersion1 = false;
                context.UseVersion1 = false;
                context.MinMajorVersion = 0;
                context.MaxMajorVersion = 0;
                chunkResult = chunkReader(context);
                if (chunkResult == null) {
                    result.Error = "The USN journal chunk reader returned no result.";
                    break;
                }
            }

            if (!chunkResult.Success) {
                if (chunkResult.Win32Error == ERROR_MORE_DATA) {
                    if (bufferSize >= MaximumBufferSize) {
                        result.Error = "FSCTL_READ_USN_JOURNAL requires more than the 1 MiB buffer ceiling (ERROR_MORE_DATA).";
                        break;
                    }
                    bufferSize = Math.Min(bufferSize * 2, MaximumBufferSize);
                    readBuffer = new byte[bufferSize];
                    continue;
                }

                result.Error = FormatNativeError("FSCTL_READ_USN_JOURNAL", chunkResult.Win32Error);
                break;
            }

            if (chunkResult.BytesReturned > (uint)readBuffer.Length) {
                result.Error = string.Format(
                    "FSCTL_READ_USN_JOURNAL returned {0} bytes for a {1}-byte buffer.",
                    chunkResult.BytesReturned,
                    readBuffer.Length);
                break;
            }

            UsnBufferParseResult parsed = ParseBuffer(
                readBuffer,
                (int)chunkResult.BytesReturned,
                maxRecords - result.Records.Count);

            result.NextUsn = parsed.NextUsn;
            foreach (string diagnostic in parsed.Diagnostics) {
                result.Notes.Add(diagnostic);
            }
            result.Records.AddRange(parsed.Records);

            if (!parsed.Success) {
                result.Error = "Malformed USN journal data: " + parsed.Error;
                break;
            }
            if (result.Records.Count >= maxRecords) {
                break;
            }
            if (parsed.NextUsn == startUsn) {
                result.Notes.Add("USN journal continuation did not advance; collection stopped to avoid an infinite loop.");
                break;
            }
            if (parsed.NextUsn < startUsn) {
                result.Error = string.Format(
                    "Invalid USN continuation: next USN {0} is below start USN {1}.",
                    parsed.NextUsn,
                    startUsn);
                break;
            }

            startUsn = parsed.NextUsn;
        }

        result.Success = result.Error == null;
        return result;
    }

    private static bool ReadChunk(
        SafeFileHandle volume,
        ulong journalId,
        long startUsn,
        uint reasonMask,
        bool useVersion1,
        ushort minMajorVersion,
        ushort maxMajorVersion,
        byte[] outputBuffer,
        out uint bytesReturned,
        out int win32Error) {

        bytesReturned = 0;
        win32Error = 0;

        int inputSize = useVersion1
            ? Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V1))
            : Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
        IntPtr inputBuffer = Marshal.AllocHGlobal(inputSize);

        try {
            if (useVersion1) {
                READ_USN_JOURNAL_DATA_V1 input = new READ_USN_JOURNAL_DATA_V1();
                input.StartUsn = startUsn;
                input.ReasonMask = reasonMask;
                input.ReturnOnlyOnClose = 0;
                input.Timeout = 0;
                input.BytesToWaitFor = 0;
                input.UsnJournalID = journalId;
                input.MinMajorVersion = minMajorVersion;
                input.MaxMajorVersion = maxMajorVersion;
                Marshal.StructureToPtr(input, inputBuffer, false);
            }
            else {
                READ_USN_JOURNAL_DATA_V0 input = new READ_USN_JOURNAL_DATA_V0();
                input.StartUsn = startUsn;
                input.ReasonMask = reasonMask;
                input.ReturnOnlyOnClose = 0;
                input.Timeout = 0;
                input.BytesToWaitFor = 0;
                input.UsnJournalID = journalId;
                Marshal.StructureToPtr(input, inputBuffer, false);
            }

            GCHandle outputPin = GCHandle.Alloc(outputBuffer, GCHandleType.Pinned);
            try {
                bool readOk = DeviceIoControl(
                    volume,
                    FSCTL_READ_USN_JOURNAL,
                    inputBuffer,
                    (uint)inputSize,
                    outputPin.AddrOfPinnedObject(),
                    (uint)outputBuffer.Length,
                    out bytesReturned,
                    IntPtr.Zero);
                if (!readOk) {
                    win32Error = Marshal.GetLastWin32Error();
                }
                return readOk;
            }
            finally {
                outputPin.Free();
            }
        }
        finally {
            Marshal.FreeHGlobal(inputBuffer);
        }
    }

    private static bool IsVersion1FallbackError(int win32Error) {
        return win32Error == ERROR_INVALID_FUNCTION ||
            win32Error == ERROR_NOT_SUPPORTED ||
            win32Error == ERROR_INVALID_PARAMETER;
    }

    private static string FormatNativeError(string operation, int win32Error) {
        switch (win32Error) {
            case ERROR_ACCESS_DENIED:
                return operation + " failed: access denied; elevation is required (Win32 error 5).";
            case ERROR_JOURNAL_DELETE_IN_PROGRESS:
                return operation + " failed: USN journal deletion is in progress (Win32 error 1178).";
            case ERROR_JOURNAL_NOT_ACTIVE:
                return operation + " failed: the USN journal is not active (Win32 error 1179).";
            case ERROR_JOURNAL_ENTRY_DELETED:
                return operation + " failed: the requested USN entry was deleted or invalidated by journal rollover (Win32 error 1181).";
            default:
                return string.Format(
                    "{0} failed with Win32 error {1}.",
                    operation,
                    win32Error);
        }
    }
}
'@

    try {
        Add-Type -TypeDefinition $usnJournalNativeSource -ErrorAction Stop
        $script:UsnJournalNativeTypeError = $null
        return $true
    }
    catch {
        $script:UsnJournalNativeTypeError = $_.Exception.Message
        $script:UsnJournalNativeUnavailableReason = 'NativeCompilationFailed'
        Write-Warning "Initialize-UsnJournalNativeType: native USN compilation failed; callers must use the fsutil fallback: $($_.Exception.Message)"
        return $false
    }
}

function Get-UsnJournalNative {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 10000,

        [Parameter()]
        [uint32]$ReasonMask = [uint32]::MaxValue
    )

    if (-not (Initialize-UsnJournalNativeType)) {
        return [PSCustomObject]@{
            Records                    = @()
            Success                    = $false
            Error                      = "Native USN journal type initialization failed: $script:UsnJournalNativeTypeError"
            Source                     = 'Native'
            NextUsn                    = [long]0
            Notes                      = @()
            Incomplete                 = $false
            EffectiveLanguageMode      = $script:UsnJournalNativeEffectiveLanguageMode
            DynamicCompilationExpected = $script:UsnJournalNativeDynamicCompilationExpected
            UnavailableReason          = $script:UsnJournalNativeUnavailableReason
        }
    }

    $isWindowsHost = $false
    try {
        $isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        $isWindowsHost = ($env:OS -eq 'Windows_NT')
    }

    if (-not $isWindowsHost) {
        return [PSCustomObject]@{
            Records                    = @()
            Success                    = $false
            Error                      = 'Native USN journal reading is only available on Windows.'
            Source                     = 'Native'
            NextUsn                    = [long]0
            Notes                      = @()
            Incomplete                 = $false
            EffectiveLanguageMode      = $script:UsnJournalNativeEffectiveLanguageMode
            DynamicCompilationExpected = $script:UsnJournalNativeDynamicCompilationExpected
            UnavailableReason          = $script:UsnJournalNativeUnavailableReason
        }
    }

    try {
        $nativeResult = [UsnJournalNative]::ReadJournal($DriveLetter, $MaxRecords, $ReasonMask)
        $records = @($nativeResult.Records)
        $notes = @($nativeResult.Notes | ForEach-Object { [string]$_ })
        $incomplete = (-not $nativeResult.Success -and $records.Count -gt 0)
        if ($incomplete) {
            $notes += "Native USN journal collection is incomplete: $($nativeResult.Error)"
        }

        return [PSCustomObject]@{
            Records                    = $records
            Success                    = [bool]$nativeResult.Success
            Error                      = if ($null -ne $nativeResult.Error) { [string]$nativeResult.Error } else { $null }
            Source                     = 'Native'
            NextUsn                    = [long]$nativeResult.NextUsn
            Notes                      = $notes
            Incomplete                 = $incomplete
            EffectiveLanguageMode      = $script:UsnJournalNativeEffectiveLanguageMode
            DynamicCompilationExpected = $script:UsnJournalNativeDynamicCompilationExpected
            UnavailableReason          = $script:UsnJournalNativeUnavailableReason
        }
    }
    catch {
        return [PSCustomObject]@{
            Records                    = @()
            Success                    = $false
            Error                      = "Native USN journal invocation failed: $($_.Exception.Message)"
            Source                     = 'Native'
            NextUsn                    = [long]0
            Notes                      = @()
            Incomplete                 = $false
            EffectiveLanguageMode      = $script:UsnJournalNativeEffectiveLanguageMode
            DynamicCompilationExpected = $script:UsnJournalNativeDynamicCompilationExpected
            UnavailableReason          = $script:UsnJournalNativeUnavailableReason
        }
    }
}
