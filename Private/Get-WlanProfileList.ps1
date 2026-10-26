<#
.SYNOPSIS
    Locale-invariant WLAN profile list helper (private).
.DESCRIPTION
    Get-WlanProfileList enumerates Wi-Fi profiles via wlanapi.dll. Profiles and
    interface descriptions come straight from the API, so no locale parsing is
    involved. Returns an empty array (NOT an error) when: not Windows,
    wlanapi.dll missing, WlanSvc stopped (WlanOpenHandle error 1062 or any
    nonzero), or zero interfaces.
.NOTES
    P/Invoke signatures verbatim from ManagedWifi (Apache-2.0). All enumeration
    and marshaling happens inside C# to avoid the PS 5.1 binder picking wrong
    PtrToStructure overloads; every list buffer is freed with WlanFreeMemory.
#>

function Get-WlanProfileList {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $result = @()

    # Cheap pre-check so macOS/Linux dev boxes degrade silently
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
        Write-Verbose 'Get-WlanProfileList: not a Windows host; WLAN not applicable'
        return $result
    }

    if (-not ([bool]('WlanNative' -as [type]))) {
        $wlanNativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class WlanNative {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string InterfaceDescription;
        public int isState;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_PROFILE_INFO {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strProfileName;
        public uint dwFlags;
    }
    [DllImport("wlanapi.dll")]
    public static extern int WlanOpenHandle(uint clientVersion, IntPtr pReserved, out uint negotiatedVersion, out IntPtr clientHandle);
    [DllImport("wlanapi.dll")]
    public static extern int WlanEnumInterfaces(IntPtr clientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);
    [DllImport("wlanapi.dll")]
    public static extern int WlanGetProfileList(IntPtr clientHandle, [MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, IntPtr pReserved, out IntPtr ppProfileList);
    [DllImport("wlanapi.dll")]
    public static extern void WlanFreeMemory(IntPtr pMemory);
    [DllImport("wlanapi.dll")]
    public static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr pReserved);
    public class WlanProfile {
        public string Name;
        public uint Flags;
        public string InterfaceDescription;
    }
    public static WlanProfile[] GetProfiles(out int win32Error) {
        win32Error = 0;
        List<WlanProfile> profiles = new List<WlanProfile>();
        IntPtr clientHandle = IntPtr.Zero;
        uint negotiatedVersion = 0;
        int err = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle);
        if (err != 0) { win32Error = err; return null; }
        try {
            IntPtr pInterfaceList;
            err = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out pInterfaceList);
            if (err != 0) { win32Error = err; return null; }
            try {
                // List header is { uint dwNumberOfItems; uint dwIndex; } then the item array
                int interfaceCount = Marshal.ReadInt32(pInterfaceList);
                int interfaceSize = Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));
                IntPtr currentInterface = new IntPtr(pInterfaceList.ToInt64() + 8);
                for (int i = 0; i < interfaceCount; i++) {
                    WLAN_INTERFACE_INFO iface = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(currentInterface, typeof(WLAN_INTERFACE_INFO));
                    currentInterface = new IntPtr(currentInterface.ToInt64() + interfaceSize);
                    IntPtr pProfileList;
                    int profileErr = WlanGetProfileList(clientHandle, iface.InterfaceGuid, IntPtr.Zero, out pProfileList);
                    if (profileErr != 0) { continue; }
                    try {
                        int profileCount = Marshal.ReadInt32(pProfileList);
                        int profileSize = Marshal.SizeOf(typeof(WLAN_PROFILE_INFO));
                        IntPtr currentProfile = new IntPtr(pProfileList.ToInt64() + 8);
                        for (int j = 0; j < profileCount; j++) {
                            WLAN_PROFILE_INFO info = (WLAN_PROFILE_INFO)Marshal.PtrToStructure(currentProfile, typeof(WLAN_PROFILE_INFO));
                            currentProfile = new IntPtr(currentProfile.ToInt64() + profileSize);
                            WlanProfile profile = new WlanProfile();
                            profile.Name = info.strProfileName;
                            profile.Flags = info.dwFlags;
                            profile.InterfaceDescription = iface.InterfaceDescription;
                            profiles.Add(profile);
                        }
                    } finally { WlanFreeMemory(pProfileList); }
                }
            } finally { WlanFreeMemory(pInterfaceList); }
        } finally { WlanCloseHandle(clientHandle, IntPtr.Zero); }
        return profiles.ToArray();
    }
}
'@
        try {
            Add-Type -TypeDefinition $wlanNativeSource -ErrorAction Stop
        }
        catch {
            # Add-Type -TypeDefinition is blocked under Constrained Language Mode (JEA)
            Write-Verbose "Get-WlanProfileList: Add-Type WlanNative failed: $($_.Exception.Message)"
            return $result
        }
    }

    try {
        $win32Error = 0
        $profiles = [WlanNative]::GetProfiles([ref]$win32Error)
        if ($null -eq $profiles) {
            # 1062 = WlanSvc not running; any nonzero is 'not applicable', not an error
            Write-Verbose "Get-WlanProfileList: WLAN API unavailable (win32 $win32Error)"
            return $result
        }
        foreach ($profile in $profiles) {
            $flags = [uint32]$profile.Flags
            $result += [PSCustomObject]@{
                Name                 = $profile.Name
                Flags                = $flags
                IsGroupPolicy        = [bool]($flags -band 1)
                IsPerUser            = [bool]($flags -band 2)
                InterfaceDescription = $profile.InterfaceDescription
            }
        }
    }
    catch {
        # wlanapi.dll missing etc.: 'not applicable', not an error
        Write-Verbose "Get-WlanProfileList: enumeration failed: $($_.Exception.Message)"
        $result = @()
    }

    return $result
}
