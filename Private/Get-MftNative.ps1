<#
.SYNOPSIS
    Reads live in-use NTFS FILE records through native file system control calls (private).
.DESCRIPTION
    Get-MftNative uses FSCTL_GET_NTFS_VOLUME_DATA and FSCTL_GET_NTFS_FILE_RECORD
    to compare Standard Information and File Name timestamps. ParseFileRecord and
    EnumerateRecords are cross-platform synthetic seams. FSCTL-returned records
    are parsed with applyFixups=false; raw offline records must opt in to fixups.
    The collector cannot return free or deleted records and is not a snapshot.
.NOTES
    Native allocation, pinning, and enumeration stay in C# for Windows PowerShell
    5.1 compatibility. No type is exported from the module.
#>

$script:MftNativeTypeError = $null

function Initialize-MftNativeType {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ([bool]('MftNative' -as [type])) {
        return $true
    }

    $mftNativeSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class MftNative {
    private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;
    private const uint FSCTL_GET_NTFS_FILE_RECORD = 0x00090068;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int VolumeDataSize = 96;
    private const int OutputPrefixSize = 12;
    private const int MaximumDiagnosticNotes = 100;
    private const long LargeOrdinalGap = 1024;

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct NTFS_VOLUME_DATA_BUFFER {
        internal long VolumeSerialNumber;
        internal long NumberSectors;
        internal long TotalClusters;
        internal long FreeClusters;
        internal long TotalReserved;
        internal uint BytesPerSector;
        internal uint BytesPerCluster;
        internal uint BytesPerFileRecordSegment;
        internal uint ClustersPerFileRecordSegment;
        internal long MftValidDataLength;
        internal long MftStartLcn;
        internal long Mft2StartLcn;
        internal long MftZoneStart;
        internal long MftZoneEnd;
    }

    public class MftFileNameInfo {
        public ulong ParentFileReferenceNumber;
        public long CreatedFileTime;
        public long ModifiedFileTime;
        public long MftChangedFileTime;
        public long AccessedFileTime;
        public bool CreatedValid;
        public bool ModifiedValid;
        public bool MftChangedValid;
        public bool AccessedValid;
        public DateTime? Created;
        public DateTime? Modified;
        public DateTime? MftChanged;
        public DateTime? Accessed;
        public string Name;
        public byte NameNamespace;
        public ushort AttributeId;
    }

    public class MftFileRecord {
        public long FileReferenceNumber;
        public uint HeaderRecordNumber;
        public bool HeaderRecordNumberPresent;
        public ushort SequenceNumber;
        public ushort LinkCount;
        public ushort Flags;
        public bool InUse;
        public bool IsDirectory;
        public bool IsExtensionRecord;
        public ulong BaseFileRecordReference;
        public string FileName;
        public ulong ParentFileReferenceNumber;
        public byte NameNamespace;
        public ushort FnAttributeId;
        public long SiCreatedFileTime;
        public long SiModifiedFileTime;
        public long SiMftChangedFileTime;
        public long SiAccessedFileTime;
        public long FnCreatedFileTime;
        public long FnModifiedFileTime;
        public long FnMftChangedFileTime;
        public long FnAccessedFileTime;
        public bool SiCreatedValid;
        public bool SiModifiedValid;
        public bool SiMftChangedValid;
        public bool SiAccessedValid;
        public bool FnCreatedValid;
        public bool FnModifiedValid;
        public bool FnMftChangedValid;
        public bool FnAccessedValid;
        public DateTime? SiCreated;
        public DateTime? SiModified;
        public DateTime? SiMftChanged;
        public DateTime? SiAccessed;
        public DateTime? FnCreated;
        public DateTime? FnModified;
        public DateTime? FnMftChanged;
        public DateTime? FnAccessed;
        public bool TimestompSuspect;
        public string SuspicionReason = string.Empty;
        public bool HasStandardInformation;
        public bool HasFileName;
        public bool HasAttributeList;
        public List<MftFileNameInfo> FileNames = new List<MftFileNameInfo>();
        public List<string> Notes = new List<string>();
    }

    public class MftParseResult {
        public bool Success;
        public string Error;
        public MftFileRecord Record;
        public byte[] RecordBytes;
    }

    public class MftOutputParseResult {
        public bool PrefixValid;
        public bool Success;
        public string Error;
        public long ActualFileReferenceNumber = -1;
        public MftParseResult ParseResult;
    }

    public class MftRecordReadContext {
        public long RequestedFileReferenceNumber;
        public byte[] OutputBuffer;
        public int RecordSize;
    }

    public class MftRecordReadResult {
        public bool Success;
        public uint BytesReturned;
        public int Win32Error;
    }

    public delegate MftRecordReadResult MftRecordReader(MftRecordReadContext context);
    public delegate long MftElapsedClock();

    public class MftScanResult {
        public List<MftFileRecord> Records = new List<MftFileRecord>();
        public List<string> Notes = new List<string>();
        public bool Success;
        public string Error;
        public bool Incomplete;
        public bool Truncated;
        public string StopReason;
        public int BytesPerSector;
        public int BytesPerFileRecord;
        public long EstimatedMftRecords;
        public long RecordsScanned;
        public int SuspectCount;
        public int MalformedRecords;
        public int AttributeListRecords;
        public int MissingStandardInformation;
        public int MissingFileName;
        public int ExtensionRecordsSkipped;
        public int NotInUseRecordsSkipped;
        public long SkippedOrdinalCount;
        public long ElapsedMilliseconds;
    }

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

    public static MftParseResult ParseFileRecord(byte[] record, bool applyFixups) {
        return ParseFileRecord(record, applyFixups, 512);
    }

    public static MftParseResult ParseFileRecord(byte[] record, bool applyFixups, int bytesPerSector) {
        MftParseResult result = new MftParseResult();
        result.Success = false;

        try {
            if (record == null) {
                result.Error = "The FILE record buffer is null.";
                return result;
            }
            if (record.Length < 48) {
                result.Error = "The FILE record is shorter than its 48-byte header.";
                return result;
            }
            if (record[0] != 0x46 || record[1] != 0x49 || record[2] != 0x4C || record[3] != 0x45) {
                result.Error = "The FILE record signature is not FILE.";
                return result;
            }

            ushort usaOffset = BitConverter.ToUInt16(record, 4);
            ushort usaCount = BitConverter.ToUInt16(record, 6);
            ushort firstAttributeOffset = BitConverter.ToUInt16(record, 20);
            uint usedSize = BitConverter.ToUInt32(record, 24);
            uint allocatedSize = BitConverter.ToUInt32(record, 28);

            if (usedSize > allocatedSize) {
                result.Error = "The FILE record used size exceeds its allocated size.";
                return result;
            }
            if (allocatedSize > (uint)record.Length) {
                result.Error = "The FILE record allocated size exceeds the supplied buffer.";
                return result;
            }
            if (usedSize < 48) {
                result.Error = "The FILE record used size is smaller than its header.";
                return result;
            }
            if (firstAttributeOffset < 0x30 || (firstAttributeOffset & 7) != 0 || firstAttributeOffset + 4 > usedSize) {
                result.Error = "The FILE record first attribute offset is invalid.";
                return result;
            }

            byte[] parsedBytes;
            if (applyFixups) {
                string fixupError;
                if (!TryApplyFixups(record, bytesPerSector, usaOffset, usaCount, firstAttributeOffset, out parsedBytes, out fixupError)) {
                    result.Error = fixupError;
                    return result;
                }
            }
            else {
                parsedBytes = new byte[record.Length];
                Buffer.BlockCopy(record, 0, parsedBytes, 0, record.Length);
            }

            MftFileRecord parsed = new MftFileRecord();
            parsed.HeaderRecordNumberPresent = usaOffset != 0x2A;
            parsed.HeaderRecordNumber = BitConverter.ToUInt32(parsedBytes, 44);
            parsed.FileReferenceNumber = parsed.HeaderRecordNumberPresent ? (long)parsed.HeaderRecordNumber : 0;
            parsed.SequenceNumber = BitConverter.ToUInt16(parsedBytes, 16);
            parsed.LinkCount = BitConverter.ToUInt16(parsedBytes, 18);
            parsed.Flags = BitConverter.ToUInt16(parsedBytes, 22);
            parsed.InUse = (parsed.Flags & 1) != 0;
            parsed.IsDirectory = (parsed.Flags & 2) != 0;
            parsed.BaseFileRecordReference = BitConverter.ToUInt64(parsedBytes, 32);
            parsed.IsExtensionRecord = parsed.BaseFileRecordReference != 0;

            int limit = (int)Math.Min(usedSize, Math.Min(allocatedSize, (uint)parsedBytes.Length));
            int offset = firstAttributeOffset;
            bool endMarkerFound = false;

            while (offset + 4 <= limit) {
                uint attributeType = BitConverter.ToUInt32(parsedBytes, offset);
                if (attributeType == 0xFFFFFFFF) {
                    endMarkerFound = true;
                    break;
                }
                if (offset + 24 > limit) {
                    result.Error = string.Format("Truncated attribute header at record offset {0}.", offset);
                    return result;
                }

                uint attributeLength = BitConverter.ToUInt32(parsedBytes, offset + 4);
                if (attributeLength < 24) {
                    result.Error = string.Format("Attribute length {0} at record offset {1} is smaller than 24 bytes.", attributeLength, offset);
                    return result;
                }
                if ((attributeLength & 7) != 0) {
                    result.Error = string.Format("Attribute length {0} at record offset {1} is not 8-byte aligned.", attributeLength, offset);
                    return result;
                }
                if (attributeLength > (uint)(limit - offset)) {
                    result.Error = string.Format("Attribute length {0} at record offset {1} extends beyond the record.", attributeLength, offset);
                    return result;
                }

                bool nonResident = parsedBytes[offset + 8] != 0;
                if (nonResident && attributeLength < 64) {
                    result.Error = string.Format("Non-resident attribute at record offset {0} is shorter than 64 bytes.", offset);
                    return result;
                }

                if (attributeType == 0x20) {
                    parsed.HasAttributeList = true;
                    parsed.Notes.Add("Attribute list present; extension attributes were not resolved, so SI/FN coverage may be incomplete.");
                }

                if (attributeType == 0x10 || attributeType == 0x30) {
                    if (nonResident) {
                        result.Error = string.Format("SI/FN attribute at record offset {0} must be resident.", offset);
                        return result;
                    }

                    int valueOffset;
                    int valueLength;
                    string valueError;
                    if (!TryGetResidentValue(parsedBytes, offset, attributeLength, out valueOffset, out valueLength, out valueError)) {
                        result.Error = valueError;
                        return result;
                    }

                    if (attributeType == 0x10) {
                        string siError = ParseStandardInformation(parsedBytes, valueOffset, valueLength, parsed);
                        if (siError != null) {
                            result.Error = siError;
                            return result;
                        }
                    }
                    else {
                        MftFileNameInfo fileName;
                        string fnError = ParseFileName(parsedBytes, valueOffset, valueLength, BitConverter.ToUInt16(parsedBytes, offset + 14), out fileName);
                        if (fnError != null) {
                            result.Error = fnError;
                            return result;
                        }
                        parsed.FileNames.Add(fileName);
                    }
                }

                offset += (int)attributeLength;
            }

            if (!endMarkerFound) {
                result.Error = "The FILE record attribute end marker was not found within its used size.";
                return result;
            }

            parsed.HasFileName = parsed.FileNames.Count > 0;
            MftFileNameInfo primaryName = SelectPrimaryFileName(parsed.FileNames);
            if (primaryName != null) {
                CopyPrimaryFileName(parsed, primaryName);
            }
            EvaluateTimestomp(parsed);

            result.Record = parsed;
            result.RecordBytes = parsedBytes;
            result.Success = true;
            return result;
        }
        catch (Exception exception) {
            result.Success = false;
            result.Record = null;
            result.RecordBytes = null;
            result.Error = "Malformed FILE record: " + exception.Message;
            return result;
        }
    }

    public static MftOutputParseResult ParseFileRecordOutputBuffer(
        byte[] output,
        int bytesReturned,
        long requestedFileReferenceNumber,
        int recordSize,
        bool applyFixups) {
        return ParseFileRecordOutputBuffer(output, bytesReturned, requestedFileReferenceNumber, recordSize, applyFixups, 512);
    }

    public static MftOutputParseResult ParseFileRecordOutputBuffer(
        byte[] output,
        int bytesReturned,
        long requestedFileReferenceNumber,
        int recordSize,
        bool applyFixups,
        int bytesPerSector) {

        MftOutputParseResult result = new MftOutputParseResult();
        if (output == null) {
            result.Error = "The FSCTL output buffer is null.";
            return result;
        }
        if (requestedFileReferenceNumber < 0) {
            result.Error = "The requested file reference number cannot be negative.";
            return result;
        }
        if (recordSize < 48 || recordSize > output.Length - OutputPrefixSize) {
            result.Error = "The FILE record size is invalid for the FSCTL output buffer.";
            return result;
        }
        if (bytesReturned < OutputPrefixSize || bytesReturned > output.Length) {
            result.Error = "The FSCTL output byte count is invalid.";
            return result;
        }

        ulong rawReference = BitConverter.ToUInt64(output, 0);
        long actual = (long)(rawReference & 0x0000FFFFFFFFFFFFUL);
        result.ActualFileReferenceNumber = actual;
        if (actual > requestedFileReferenceNumber) {
            result.Error = "The returned FILE record ordinal exceeds the requested ordinal.";
            return result;
        }

        uint returnedRecordLength = BitConverter.ToUInt32(output, 8);
        if (returnedRecordLength != (uint)recordSize) {
            result.Error = string.Format("The returned FileRecordLength {0} does not equal the volume record size {1}.", returnedRecordLength, recordSize);
            return result;
        }
        if (bytesReturned < OutputPrefixSize + recordSize) {
            result.Error = "The FSCTL output is shorter than its 12-byte prefix plus one FILE record.";
            return result;
        }

        result.PrefixValid = true;
        byte[] record = new byte[recordSize];
        Buffer.BlockCopy(output, OutputPrefixSize, record, 0, recordSize);
        result.ParseResult = ParseFileRecord(record, applyFixups, bytesPerSector);
        if (!result.ParseResult.Success) {
            result.Error = result.ParseResult.Error;
            return result;
        }

        MftFileRecord parsed = result.ParseResult.Record;
        parsed.FileReferenceNumber = actual;
        if (parsed.HeaderRecordNumberPresent && parsed.HeaderRecordNumber != (uint)actual) {
            if (parsed.HeaderRecordNumber == 0) {
                parsed.Notes.Add("The FILE header has no entry number; the FSCTL-returned ordinal is used as a fallback.");
            }
            else {
                result.Error = string.Format("The FILE header entry number {0} does not match the FSCTL-returned ordinal {1}.", parsed.HeaderRecordNumber, actual);
                return result;
            }
        }

        result.Success = true;
        return result;
    }

    public static MftScanResult EnumerateRecords(
        long estimatedCount,
        int recordSize,
        int bytesPerSector,
        int maxRecords,
        int maxSeconds,
        bool includeAll,
        MftRecordReader recordReader,
        MftElapsedClock clock) {
        return EnumerateRecords(estimatedCount, recordSize, bytesPerSector, maxRecords, maxSeconds, includeAll, recordReader, clock, CancellationToken.None);
    }

    public static MftScanResult EnumerateRecords(
        long estimatedCount,
        int recordSize,
        int bytesPerSector,
        int maxRecords,
        int maxSeconds,
        bool includeAll,
        MftRecordReader recordReader,
        MftElapsedClock clock,
        CancellationToken cancellationToken) {

        MftScanResult result = new MftScanResult();
        result.BytesPerSector = bytesPerSector;
        result.BytesPerFileRecord = recordSize;
        result.EstimatedMftRecords = estimatedCount;

        if (estimatedCount < 0 || recordSize < 48 || bytesPerSector <= 0 || maxRecords < 1 || maxSeconds < 1) {
            result.Error = "Invalid MFT enumeration bounds or volume geometry.";
            return result;
        }
        if (recordReader == null || clock == null) {
            result.Error = "The MFT record reader and elapsed clock are required.";
            return result;
        }
        if (recordSize > int.MaxValue - OutputPrefixSize) {
            result.Error = "The FILE record size is too large.";
            return result;
        }

        byte[] outputBuffer = new byte[OutputPrefixSize + recordSize];
        long request = estimatedCount - 1;
        result.Success = true;

        while (request >= 0) {
            result.ElapsedMilliseconds = Math.Max(0, clock());
            if (cancellationToken.IsCancellationRequested) {
                SetTruncated(result, "Canceled", "MFT scan canceled before the next native record call.");
                break;
            }
            if (result.RecordsScanned >= maxRecords) {
                SetTruncated(result, "MaxRecords", string.Format("MFT scan stopped at the MaxRecords cap of {0}; results are incomplete.", maxRecords));
                break;
            }
            if (result.ElapsedMilliseconds >= maxSeconds * 1000L) {
                SetTruncated(result, "MaxSeconds", string.Format("MFT scan stopped at the {0}-second time budget; results are incomplete.", maxSeconds));
                break;
            }

            MftRecordReadContext context = new MftRecordReadContext();
            context.RequestedFileReferenceNumber = request;
            context.OutputBuffer = outputBuffer;
            context.RecordSize = recordSize;

            MftRecordReadResult readResult;
            try {
                readResult = recordReader(context);
            }
            catch (Exception exception) {
                SetNativeError(result, "FSCTL_GET_NTFS_FILE_RECORD threw an exception: " + exception.Message);
                break;
            }

            result.ElapsedMilliseconds = Math.Max(0, clock());
            if (readResult == null) {
                SetNativeError(result, "FSCTL_GET_NTFS_FILE_RECORD returned no read result.");
                break;
            }
            if (!readResult.Success) {
                SetNativeError(result, FormatNativeError("FSCTL_GET_NTFS_FILE_RECORD", readResult.Win32Error));
                break;
            }

            MftOutputParseResult output = ParseFileRecordOutputBuffer(
                outputBuffer,
                readResult.BytesReturned > int.MaxValue ? -1 : (int)readResult.BytesReturned,
                request,
                recordSize,
                false,
                bytesPerSector);

            if (!output.PrefixValid) {
                SetNativeError(result, "Invalid FSCTL_GET_NTFS_FILE_RECORD output: " + output.Error);
                break;
            }

            long actual = output.ActualFileReferenceNumber;
            long gap = request - actual;
            if (gap > 0) {
                result.SkippedOrdinalCount += gap;
                if (gap >= LargeOrdinalGap) {
                    AddNote(result, string.Format("Skipped {0} ordinals between requested record {1} and returned record {2}; this gap is not deleted-file evidence.", gap, request, actual));
                }
            }

            result.RecordsScanned++;
            if (!output.Success) {
                result.MalformedRecords++;
                AddNote(result, string.Format("FILE record {0} was malformed and excluded from SI/FN comparison: {1}", actual, output.Error));
            }
            else {
                MftFileRecord record = output.ParseResult.Record;
                if (!record.InUse) {
                    result.NotInUseRecordsSkipped++;
                    AddNote(result, string.Format("FILE record {0} was not marked in use and was excluded from live findings.", actual));
                }
                else if (record.IsExtensionRecord) {
                    result.ExtensionRecordsSkipped++;
                    AddNote(result, string.Format("Extension FILE record {0} was excluded from base-record SI/FN comparison.", actual));
                }
                else {
                    if (record.HasAttributeList) {
                        result.AttributeListRecords++;
                        AddNote(result, string.Format("FILE record {0} has an attribute list; extension attributes were not resolved.", actual));
                    }
                    if (!record.HasStandardInformation) {
                        result.MissingStandardInformation++;
                    }
                    if (!record.HasFileName) {
                        result.MissingFileName++;
                    }
                    if (record.TimestompSuspect) {
                        result.SuspectCount++;
                    }
                    if (includeAll || record.TimestompSuspect) {
                        result.Records.Add(record);
                    }
                }
            }

            if (actual == 0) {
                result.StopReason = "Complete";
                break;
            }

            long nextRequest = actual - 1;
            if (nextRequest >= request) {
                SetNativeError(result, "MFT enumeration did not advance to a strictly lower ordinal.");
                break;
            }
            request = nextRequest;
        }

        if (result.StopReason == null && request < 0) {
            result.StopReason = "Complete";
        }
        if (result.StopReason == null) {
            result.StopReason = "Unknown";
            result.Success = false;
            result.Error = "MFT enumeration stopped without a defined reason.";
        }
        if (result.SkippedOrdinalCount > 0) {
            AddNote(result, string.Format("Skipped {0} ordinal(s) during downward enumeration; gaps can be unused or uninitialized entries and are not deleted-file evidence.", result.SkippedOrdinalCount));
        }
        result.ElapsedMilliseconds = Math.Max(0, clock());
        return result;
    }

    public static MftScanResult ReadMft(string driveLetter, int maxRecords, int maxSeconds, bool includeAll) {
        MftScanResult result = new MftScanResult();
        result.Success = false;

        if (string.IsNullOrWhiteSpace(driveLetter)) {
            result.Error = "DriveLetter cannot be empty.";
            return result;
        }
        if (maxRecords < 1 || maxSeconds < 1) {
            result.Error = "MaxRecords and MaxSeconds must be greater than zero.";
            return result;
        }

        string drive = driveLetter.Trim().TrimEnd(':', '\\').ToUpperInvariant();
        if (drive.Length != 1 || drive[0] < 'A' || drive[0] > 'Z') {
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
                    result.Error = FormatNativeError("CreateFileW", Marshal.GetLastWin32Error());
                    return result;
                }

                NTFS_VOLUME_DATA_BUFFER volumeData;
                string queryError;
                if (!TryQueryVolumeData(volume, out volumeData, out queryError)) {
                    result.Error = queryError;
                    return result;
                }
                if (volumeData.BytesPerSector == 0 || volumeData.BytesPerSector > int.MaxValue ||
                    volumeData.BytesPerFileRecordSegment < 48 || volumeData.BytesPerFileRecordSegment > int.MaxValue - OutputPrefixSize ||
                    volumeData.MftValidDataLength < 0) {
                    result.Error = "FSCTL_GET_NTFS_VOLUME_DATA returned invalid volume geometry.";
                    return result;
                }

                int recordSize = (int)volumeData.BytesPerFileRecordSegment;
                int sectorSize = (int)volumeData.BytesPerSector;
                long estimatedCount = volumeData.MftValidDataLength / recordSize;
                byte[] inputBuffer = new byte[8];
                byte[] outputBuffer = new byte[OutputPrefixSize + recordSize];
                Stopwatch stopwatch = Stopwatch.StartNew();

                MftRecordReader reader = delegate(MftRecordReadContext context) {
                    return ReadRecord(volume, context.RequestedFileReferenceNumber, inputBuffer, outputBuffer);
                };
                MftElapsedClock clock = delegate() {
                    return stopwatch.ElapsedMilliseconds;
                };

                result = EnumerateRecords(
                    estimatedCount,
                    recordSize,
                    sectorSize,
                    maxRecords,
                    maxSeconds,
                    includeAll,
                    reader,
                    clock,
                    CancellationToken.None);
                result.Notes.Insert(0, "Live FSCTL enumeration returns in-use records only; skipped ordinals are not deleted-file evidence.");
                result.Notes.Insert(1, "FSCTL file records are treated as filesystem-restored and parsed with applyFixups=false; raw-disk fixups are not reapplied.");
                result.Notes.Insert(2, "The live scan is not a point-in-time snapshot; files can change during enumeration.");
            }
        }
        catch (Exception exception) {
            result.Error = "Native MFT read failed: " + exception.Message;
            result.Success = false;
        }

        return result;
    }

    private static bool TryApplyFixups(
        byte[] record,
        int bytesPerSector,
        ushort usaOffset,
        ushort usaCount,
        ushort firstAttributeOffset,
        out byte[] repaired,
        out string error) {

        repaired = null;
        error = null;
        if (bytesPerSector <= 0 || (record.Length % bytesPerSector) != 0) {
            error = "The FILE record length is not a multiple of the sector size.";
            return false;
        }

        int expectedUsaCount = 1 + record.Length / bytesPerSector;
        if (usaCount != expectedUsaCount) {
            error = string.Format("The update sequence array count {0} does not match the expected count {1}.", usaCount, expectedUsaCount);
            return false;
        }
        if (usaOffset < 0x2A) {
            error = "The update sequence array offset overlaps the FILE header.";
            return false;
        }

        long usaEnd = (long)usaOffset + (long)usaCount * 2L;
        if (usaEnd > record.Length) {
            error = "The update sequence array extends beyond the FILE record.";
            return false;
        }
        if (firstAttributeOffset < usaEnd) {
            error = "The first attribute overlaps the update sequence array.";
            return false;
        }

        ushort updateSequence = BitConverter.ToUInt16(record, usaOffset);
        for (int index = 1; index < usaCount; index++) {
            long sectorTail = (long)index * bytesPerSector - 2L;
            if (sectorTail < 0 || sectorTail + 2 > record.Length) {
                error = "An update sequence sector tail extends beyond the FILE record.";
                return false;
            }
            ushort actualSequence = BitConverter.ToUInt16(record, (int)sectorTail);
            if (actualSequence != updateSequence) {
                error = string.Format("Update sequence mismatch at sector {0}: expected 0x{1:X4}, found 0x{2:X4}.", index, updateSequence, actualSequence);
                return false;
            }
        }

        repaired = new byte[record.Length];
        Buffer.BlockCopy(record, 0, repaired, 0, record.Length);
        for (int index = 1; index < usaCount; index++) {
            int sectorTail = index * bytesPerSector - 2;
            repaired[sectorTail] = record[usaOffset + index * 2];
            repaired[sectorTail + 1] = record[usaOffset + index * 2 + 1];
        }
        return true;
    }

    private static bool TryGetResidentValue(
        byte[] record,
        int attributeOffset,
        uint attributeLength,
        out int valueOffset,
        out int valueLength,
        out string error) {

        valueOffset = 0;
        valueLength = 0;
        error = null;
        uint rawValueLength = BitConverter.ToUInt32(record, attributeOffset + 16);
        ushort rawValueOffset = BitConverter.ToUInt16(record, attributeOffset + 20);
        if (rawValueOffset < 24 || rawValueOffset > attributeLength || rawValueLength > attributeLength - rawValueOffset) {
            error = string.Format("Resident value range at record offset {0} extends beyond its attribute.", attributeOffset);
            return false;
        }
        if (rawValueLength > int.MaxValue) {
            error = "A resident attribute value is too large to parse.";
            return false;
        }

        valueOffset = attributeOffset + rawValueOffset;
        valueLength = (int)rawValueLength;
        return true;
    }

    private static string ParseStandardInformation(byte[] record, int valueOffset, int valueLength, MftFileRecord target) {
        if (valueLength < 48) {
            return "The STANDARD_INFORMATION value is shorter than 48 bytes.";
        }

        long raw;
        bool valid;
        target.SiCreated = ReadFileTime(record, valueOffset, out raw, out valid);
        target.SiCreatedFileTime = raw;
        target.SiCreatedValid = valid;
        target.SiModified = ReadFileTime(record, valueOffset + 8, out raw, out valid);
        target.SiModifiedFileTime = raw;
        target.SiModifiedValid = valid;
        target.SiMftChanged = ReadFileTime(record, valueOffset + 16, out raw, out valid);
        target.SiMftChangedFileTime = raw;
        target.SiMftChangedValid = valid;
        target.SiAccessed = ReadFileTime(record, valueOffset + 24, out raw, out valid);
        target.SiAccessedFileTime = raw;
        target.SiAccessedValid = valid;
        target.HasStandardInformation = true;
        return null;
    }

    private static string ParseFileName(byte[] record, int valueOffset, int valueLength, ushort attributeId, out MftFileNameInfo fileName) {
        fileName = null;
        if (valueLength < 66) {
            return "The FILE_NAME value is shorter than its 66-byte fixed content.";
        }

        byte nameLength = record[valueOffset + 64];
        long nameBytes = (long)nameLength * 2L;
        if (nameBytes > valueLength - 66L) {
            return "The FILE_NAME Unicode name extends beyond its resident value.";
        }

        MftFileNameInfo parsed = new MftFileNameInfo();
        parsed.ParentFileReferenceNumber = BitConverter.ToUInt64(record, valueOffset);
        long raw;
        bool valid;
        parsed.Created = ReadFileTime(record, valueOffset + 8, out raw, out valid);
        parsed.CreatedFileTime = raw;
        parsed.CreatedValid = valid;
        parsed.Modified = ReadFileTime(record, valueOffset + 16, out raw, out valid);
        parsed.ModifiedFileTime = raw;
        parsed.ModifiedValid = valid;
        parsed.MftChanged = ReadFileTime(record, valueOffset + 24, out raw, out valid);
        parsed.MftChangedFileTime = raw;
        parsed.MftChangedValid = valid;
        parsed.Accessed = ReadFileTime(record, valueOffset + 32, out raw, out valid);
        parsed.AccessedFileTime = raw;
        parsed.AccessedValid = valid;
        parsed.NameNamespace = record[valueOffset + 65];
        parsed.Name = System.Text.Encoding.Unicode.GetString(record, valueOffset + 66, (int)nameBytes);
        parsed.AttributeId = attributeId;
        fileName = parsed;
        return null;
    }

    private static DateTime? ReadFileTime(byte[] record, int offset, out long raw, out bool valid) {
        raw = BitConverter.ToInt64(record, offset);
        try {
            DateTime value = DateTime.FromFileTimeUtc(raw);
            valid = true;
            return value;
        }
        catch (ArgumentOutOfRangeException) {
            valid = false;
            return null;
        }
    }

    private static MftFileNameInfo SelectPrimaryFileName(List<MftFileNameInfo> names) {
        MftFileNameInfo selected = null;
        int selectedRank = -1;
        foreach (MftFileNameInfo name in names) {
            int rank;
            switch (name.NameNamespace) {
                case 3: rank = 4; break;
                case 1: rank = 3; break;
                case 0: rank = 2; break;
                case 2: rank = 1; break;
                default: rank = 0; break;
            }
            if (rank > selectedRank) {
                selected = name;
                selectedRank = rank;
            }
        }
        return selected;
    }

    private static void CopyPrimaryFileName(MftFileRecord record, MftFileNameInfo name) {
        record.FileName = name.Name;
        record.ParentFileReferenceNumber = name.ParentFileReferenceNumber;
        record.NameNamespace = name.NameNamespace;
        record.FnAttributeId = name.AttributeId;
        record.FnCreatedFileTime = name.CreatedFileTime;
        record.FnModifiedFileTime = name.ModifiedFileTime;
        record.FnMftChangedFileTime = name.MftChangedFileTime;
        record.FnAccessedFileTime = name.AccessedFileTime;
        record.FnCreatedValid = name.CreatedValid;
        record.FnModifiedValid = name.ModifiedValid;
        record.FnMftChangedValid = name.MftChangedValid;
        record.FnAccessedValid = name.AccessedValid;
        record.FnCreated = name.Created;
        record.FnModified = name.Modified;
        record.FnMftChanged = name.MftChanged;
        record.FnAccessed = name.Accessed;
    }

    private static void EvaluateTimestomp(MftFileRecord record) {
        List<string> reasons = new List<string>();
        if (record.HasStandardInformation && record.HasFileName) {
            if (record.SiCreatedValid && record.FnCreatedValid && record.SiCreatedFileTime != record.FnCreatedFileTime) {
                reasons.Add(record.SiCreatedFileTime < record.FnCreatedFileTime ? "SI_CREATED_LT_FN_CREATED" : "SI_CREATED_GT_FN_CREATED");
            }
            if (record.SiModifiedValid && record.FnModifiedValid && record.SiModifiedFileTime != record.FnModifiedFileTime) {
                reasons.Add(record.SiModifiedFileTime < record.FnModifiedFileTime ? "SI_MODIFIED_LT_FN_MODIFIED" : "SI_MODIFIED_GT_FN_MODIFIED");
            }
        }
        record.TimestompSuspect = reasons.Count > 0;
        record.SuspicionReason = string.Join("; ", reasons.ToArray());
    }

    private static bool TryQueryVolumeData(SafeFileHandle volume, out NTFS_VOLUME_DATA_BUFFER volumeData, out string error) {
        volumeData = new NTFS_VOLUME_DATA_BUFFER();
        error = null;
        byte[] queryBuffer = new byte[VolumeDataSize];
        uint bytesReturned = 0;
        bool queryOk = false;
        int queryError = 0;
        GCHandle queryPin = GCHandle.Alloc(queryBuffer, GCHandleType.Pinned);
        try {
            queryOk = DeviceIoControl(
                volume,
                FSCTL_GET_NTFS_VOLUME_DATA,
                IntPtr.Zero,
                0,
                queryPin.AddrOfPinnedObject(),
                (uint)queryBuffer.Length,
                out bytesReturned,
                IntPtr.Zero);
            if (!queryOk) {
                queryError = Marshal.GetLastWin32Error();
            }
            else if (bytesReturned >= VolumeDataSize && bytesReturned <= (uint)queryBuffer.Length) {
                volumeData = (NTFS_VOLUME_DATA_BUFFER)Marshal.PtrToStructure(queryPin.AddrOfPinnedObject(), typeof(NTFS_VOLUME_DATA_BUFFER));
            }
        }
        finally {
            queryPin.Free();
        }

        if (!queryOk) {
            error = FormatNativeError("FSCTL_GET_NTFS_VOLUME_DATA", queryError);
            return false;
        }
        if (bytesReturned < VolumeDataSize || bytesReturned > (uint)queryBuffer.Length) {
            error = string.Format("FSCTL_GET_NTFS_VOLUME_DATA returned an invalid byte count: {0}.", bytesReturned);
            return false;
        }
        return true;
    }

    private static MftRecordReadResult ReadRecord(
        SafeFileHandle volume,
        long request,
        byte[] inputBuffer,
        byte[] outputBuffer) {

        MftRecordReadResult result = new MftRecordReadResult();
        byte[] requestBytes = BitConverter.GetBytes(request);
        Buffer.BlockCopy(requestBytes, 0, inputBuffer, 0, 8);
        GCHandle inputPin = GCHandle.Alloc(inputBuffer, GCHandleType.Pinned);
        try {
            GCHandle outputPin = GCHandle.Alloc(outputBuffer, GCHandleType.Pinned);
            try {
                result.Success = DeviceIoControl(
                    volume,
                    FSCTL_GET_NTFS_FILE_RECORD,
                    inputPin.AddrOfPinnedObject(),
                    8,
                    outputPin.AddrOfPinnedObject(),
                    (uint)outputBuffer.Length,
                    out result.BytesReturned,
                    IntPtr.Zero);
                if (!result.Success) {
                    result.Win32Error = Marshal.GetLastWin32Error();
                }
            }
            finally {
                outputPin.Free();
            }
        }
        finally {
            inputPin.Free();
        }
        return result;
    }

    private static void SetTruncated(MftScanResult result, string reason, string note) {
        result.Success = true;
        result.Incomplete = true;
        result.Truncated = true;
        result.StopReason = reason;
        AddNote(result, note);
    }

    private static void SetNativeError(MftScanResult result, string error) {
        result.Error = error;
        result.StopReason = "NativeError";
        result.Success = result.RecordsScanned > 0;
        result.Incomplete = result.RecordsScanned > 0;
        AddNote(result, result.Success
            ? "Native MFT collection was interrupted; earlier records are preserved as partial evidence: " + error
            : "Native MFT collection failed before any FILE record was returned: " + error);
    }

    private static void AddNote(MftScanResult result, string note) {
        if (result.Notes.Count < MaximumDiagnosticNotes) {
            result.Notes.Add(note);
        }
        else if (result.Notes.Count == MaximumDiagnosticNotes) {
            result.Notes.Add("Additional MFT diagnostics were suppressed; aggregate counters remain authoritative.");
        }
    }

    private static string FormatNativeError(string operation, int win32Error) {
        if (win32Error == ERROR_ACCESS_DENIED) {
            return operation + " failed: access denied; elevation is required (Win32 error 5).";
        }
        return string.Format("{0} failed with Win32 error {1}.", operation, win32Error);
    }
}
'@

    try {
        Add-Type -TypeDefinition $mftNativeSource -ErrorAction Stop
        $script:MftNativeTypeError = $null
        return $true
    }
    catch {
        $script:MftNativeTypeError = $_.Exception.Message
        Write-Verbose "Initialize-MftNativeType: Add-Type failed: $($_.Exception.Message)"
        return $false
    }
}

function ConvertTo-MftNativeRecord {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$NativeRecord
    )

    $recordNumber = [long]$NativeRecord.FileReferenceNumber
    $fileReference = ([uint64]$NativeRecord.SequenceNumber -shl 48) -bor [uint64]$recordNumber
    $createdDeltaTicks = $null
    if ($NativeRecord.SiCreatedValid -and $NativeRecord.FnCreatedValid) {
        $createdDeltaTicks = [long]$NativeRecord.FnCreatedFileTime - [long]$NativeRecord.SiCreatedFileTime
    }
    $modifiedDeltaTicks = $null
    if ($NativeRecord.SiModifiedValid -and $NativeRecord.FnModifiedValid) {
        $modifiedDeltaTicks = [long]$NativeRecord.FnModifiedFileTime - [long]$NativeRecord.SiModifiedFileTime
    }

    $fileNames = @($NativeRecord.FileNames | ForEach-Object {
        [PSCustomObject]@{
            FileName                  = [string]$_.Name
            ParentFileReferenceNumber = '0x' + ([uint64]$_.ParentFileReferenceNumber).ToString('x16')
            NameNamespace             = [byte]$_.NameNamespace
            FnAttributeId             = [uint16]$_.AttributeId
            FnCreated                 = if ($null -ne $_.Created) { [datetime]$_.Created } else { $null }
            FnModified                = if ($null -ne $_.Modified) { [datetime]$_.Modified } else { $null }
            FnMftChanged              = if ($null -ne $_.MftChanged) { [datetime]$_.MftChanged } else { $null }
            FnAccessed                = if ($null -ne $_.Accessed) { [datetime]$_.Accessed } else { $null }
        }
    })

    return [PSCustomObject]@{
        RecordNumber               = $recordNumber
        FileReferenceNumber        = '0x' + $recordNumber.ToString('x12')
        FileReference              = '0x' + $fileReference.ToString('x16')
        SequenceNumber             = [uint16]$NativeRecord.SequenceNumber
        LinkCount                  = [uint16]$NativeRecord.LinkCount
        InUse                      = [bool]$NativeRecord.InUse
        IsDirectory                = [bool]$NativeRecord.IsDirectory
        IsExtensionRecord          = [bool]$NativeRecord.IsExtensionRecord
        FileName                   = if ($null -ne $NativeRecord.FileName) { [string]$NativeRecord.FileName } else { $null }
        ParentFileReferenceNumber  = '0x' + ([uint64]$NativeRecord.ParentFileReferenceNumber).ToString('x16')
        NameNamespace              = [byte]$NativeRecord.NameNamespace
        FnAttributeId              = [uint16]$NativeRecord.FnAttributeId
        SiCreated                  = if ($null -ne $NativeRecord.SiCreated) { [datetime]$NativeRecord.SiCreated } else { $null }
        SiModified                 = if ($null -ne $NativeRecord.SiModified) { [datetime]$NativeRecord.SiModified } else { $null }
        SiMftChanged               = if ($null -ne $NativeRecord.SiMftChanged) { [datetime]$NativeRecord.SiMftChanged } else { $null }
        SiAccessed                 = if ($null -ne $NativeRecord.SiAccessed) { [datetime]$NativeRecord.SiAccessed } else { $null }
        FnCreated                  = if ($null -ne $NativeRecord.FnCreated) { [datetime]$NativeRecord.FnCreated } else { $null }
        FnModified                 = if ($null -ne $NativeRecord.FnModified) { [datetime]$NativeRecord.FnModified } else { $null }
        FnMftChanged               = if ($null -ne $NativeRecord.FnMftChanged) { [datetime]$NativeRecord.FnMftChanged } else { $null }
        FnAccessed                 = if ($null -ne $NativeRecord.FnAccessed) { [datetime]$NativeRecord.FnAccessed } else { $null }
        CreatedDeltaTicks          = $createdDeltaTicks
        ModifiedDeltaTicks         = $modifiedDeltaTicks
        TimestompSuspect           = [bool]$NativeRecord.TimestompSuspect
        SuspicionReason            = [string]$NativeRecord.SuspicionReason
        HasStandardInformation     = [bool]$NativeRecord.HasStandardInformation
        HasFileName                = [bool]$NativeRecord.HasFileName
        HasAttributeList           = [bool]$NativeRecord.HasAttributeList
        FileNames                  = $fileNames
        Notes                      = @($NativeRecord.Notes | ForEach-Object { [string]$_ })
        Assessment                 = 'Heuristic candidate - not proof of timestomping'
        Source                     = 'FSCTL_GET_NTFS_FILE_RECORD'
    }
}

function Get-MftNative {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxRecords = 50000,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$MaxSeconds = 300,

        [Parameter()]
        [switch]$IncludeAll
    )

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
            Records = @(); Success = $false; Error = 'Native MFT reading is only available on Windows.'
            Source = 'NativeMft'; Notes = @(); Incomplete = $false; Truncated = $false; StopReason = 'UnsupportedPlatform'
            RecordsScanned = [long]0; SuspectCount = 0; MalformedRecords = 0; AttributeListRecords = 0
            MissingStandardInformation = 0; MissingFileName = 0; ExtensionRecordsSkipped = 0; NotInUseRecordsSkipped = 0
            SkippedOrdinalCount = [long]0; EstimatedMftRecords = [long]0; BytesPerSector = 0; BytesPerFileRecord = 0; ElapsedMilliseconds = [long]0
        }
    }

    $isElevated = $false
    try {
        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isElevated = $false
    }
    if (-not $isElevated) {
        return [PSCustomObject]@{
            Records = @(); Success = $false; Error = 'Native MFT reading requires an elevated administrator session.'
            Source = 'NativeMft'; Notes = @(); Incomplete = $false; Truncated = $false; StopReason = 'ElevationRequired'
            RecordsScanned = [long]0; SuspectCount = 0; MalformedRecords = 0; AttributeListRecords = 0
            MissingStandardInformation = 0; MissingFileName = 0; ExtensionRecordsSkipped = 0; NotInUseRecordsSkipped = 0
            SkippedOrdinalCount = [long]0; EstimatedMftRecords = [long]0; BytesPerSector = 0; BytesPerFileRecord = 0; ElapsedMilliseconds = [long]0
        }
    }

    if (-not (Initialize-MftNativeType)) {
        return [PSCustomObject]@{
            Records = @(); Success = $false; Error = "Native MFT type initialization failed: $script:MftNativeTypeError"
            Source = 'NativeMft'; Notes = @(); Incomplete = $false; Truncated = $false; StopReason = 'TypeInitializationFailed'
            RecordsScanned = [long]0; SuspectCount = 0; MalformedRecords = 0; AttributeListRecords = 0
            MissingStandardInformation = 0; MissingFileName = 0; ExtensionRecordsSkipped = 0; NotInUseRecordsSkipped = 0
            SkippedOrdinalCount = [long]0; EstimatedMftRecords = [long]0; BytesPerSector = 0; BytesPerFileRecord = 0; ElapsedMilliseconds = [long]0
        }
    }

    try {
        $nativeResult = [MftNative]::ReadMft($DriveLetter, $MaxRecords, $MaxSeconds, [bool]$IncludeAll)
        $records = @($nativeResult.Records | ForEach-Object { ConvertTo-MftNativeRecord -NativeRecord $_ })
        $notes = @($nativeResult.Notes | ForEach-Object { [string]$_ })
        $incomplete = [bool]$nativeResult.Incomplete -or [bool]$nativeResult.Truncated -or
            (-not $nativeResult.Success -and $nativeResult.RecordsScanned -gt 0)
        $success = [bool]$nativeResult.Success -or $nativeResult.RecordsScanned -gt 0

        return [PSCustomObject]@{
            Records                    = $records
            Success                    = $success
            Error                      = if ($null -ne $nativeResult.Error) { [string]$nativeResult.Error } else { $null }
            Source                     = 'NativeMft'
            Notes                      = $notes
            Incomplete                 = $incomplete
            Truncated                  = [bool]$nativeResult.Truncated
            StopReason                 = [string]$nativeResult.StopReason
            RecordsScanned             = [long]$nativeResult.RecordsScanned
            SuspectCount               = [int]$nativeResult.SuspectCount
            MalformedRecords           = [int]$nativeResult.MalformedRecords
            AttributeListRecords       = [int]$nativeResult.AttributeListRecords
            MissingStandardInformation = [int]$nativeResult.MissingStandardInformation
            MissingFileName            = [int]$nativeResult.MissingFileName
            ExtensionRecordsSkipped    = [int]$nativeResult.ExtensionRecordsSkipped
            NotInUseRecordsSkipped     = [int]$nativeResult.NotInUseRecordsSkipped
            SkippedOrdinalCount        = [long]$nativeResult.SkippedOrdinalCount
            EstimatedMftRecords        = [long]$nativeResult.EstimatedMftRecords
            BytesPerSector             = [int]$nativeResult.BytesPerSector
            BytesPerFileRecord         = [int]$nativeResult.BytesPerFileRecord
            ElapsedMilliseconds        = [long]$nativeResult.ElapsedMilliseconds
        }
    }
    catch {
        return [PSCustomObject]@{
            Records = @(); Success = $false; Error = "Native MFT invocation failed: $($_.Exception.Message)"
            Source = 'NativeMft'; Notes = @(); Incomplete = $false; Truncated = $false; StopReason = 'InvocationFailed'
            RecordsScanned = [long]0; SuspectCount = 0; MalformedRecords = 0; AttributeListRecords = 0
            MissingStandardInformation = 0; MissingFileName = 0; ExtensionRecordsSkipped = 0; NotInUseRecordsSkipped = 0
            SkippedOrdinalCount = [long]0; EstimatedMftRecords = [long]0; BytesPerSector = 0; BytesPerFileRecord = 0; ElapsedMilliseconds = [long]0
        }
    }
}
