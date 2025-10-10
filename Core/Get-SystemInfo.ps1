function Get-SystemInfo {
    <#
    .SYNOPSIS
        Retrieves comprehensive system information for security analysis
    .DESCRIPTION
        Collects detailed system information including hardware, OS, network configuration,
        installed software, and security-relevant settings
    .PARAMETER IncludeInstalledSoftware
        Include list of installed software
    .PARAMETER IncludeHotfixes
        Include list of installed Windows updates
    .EXAMPLE
        Get-SystemInfo
        Get-SystemInfo -IncludeInstalledSoftware -IncludeHotfixes
    .OUTPUTS
        PSCustomObject with system information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeInstalledSoftware,
        
        [Parameter()]
        [switch]$IncludeHotfixes
    )
    
    begin {
        Write-Verbose "Gathering system information..."
        $info = [PSCustomObject]@{
            CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerSystem = $null
            OperatingSystem = $null
            Hardware = $null
            Network = $null
            Security = $null
            InstalledSoftware = $null
            Hotfixes = $null
        }
    }
    
    process {
        try {
            # Computer System Information
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            $info.ComputerSystem = [PSCustomObject]@{
                Name = $cs.Name
                Domain = $cs.Domain
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                SystemType = $cs.SystemType
                TotalPhysicalMemory = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                NumberOfProcessors = $cs.NumberOfProcessors
                NumberOfLogicalProcessors = $cs.NumberOfLogicalProcessors
                PrimaryOwnerName = $cs.PrimaryOwnerName
                BootupState = $cs.BootupState
            }
            
            # Operating System Information
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $info.OperatingSystem = [PSCustomObject]@{
                Caption = $os.Caption
                Version = $os.Version
                BuildNumber = $os.BuildNumber
                Architecture = $os.OSArchitecture
                InstallDate = $os.InstallDate
                LastBootUpTime = $os.LastBootUpTime
                LocalDateTime = $os.LocalDateTime
                NumberOfUsers = $os.NumberOfUsers
                NumberOfProcesses = $os.NumberOfProcesses
                ServicePackMajorVersion = $os.ServicePackMajorVersion
                RegisteredUser = $os.RegisteredUser
                Organization = $os.Organization
                WindowsDirectory = $os.WindowsDirectory
                SystemDirectory = $os.SystemDirectory
            }
            
            # Hardware Information
            $cpu = Get-CimInstance -ClassName Win32_Processor
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
            
            $info.Hardware = [PSCustomObject]@{
                CPU = $cpu | Select-Object Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors
                Disks = $disk | ForEach-Object {
                    [PSCustomObject]@{
                        DeviceID = $_.DeviceID
                        VolumeName = $_.VolumeName
                        FileSystem = $_.FileSystem
                        Size = [math]::Round($_.Size / 1GB, 2)
                        FreeSpace = [math]::Round($_.FreeSpace / 1GB, 2)
                        PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
                    }
                }
            }
            
            # Network Configuration
            $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
            $netIP = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' }
            
            $info.Network = [PSCustomObject]@{
                Adapters = $netAdapters | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, Status
                IPAddresses = $netIP | Select-Object InterfaceAlias, IPAddress, PrefixLength
                DNSServers = Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -eq 2 } | 
                    Select-Object InterfaceAlias, ServerAddresses
                DefaultGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop
            }
            
            # Security Settings
# Security Settings
$info.Security = [PSCustomObject]@{
    LocalUsers = (Get-LocalUser).Count
    LocalAdministrators = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Count
    PasswordPolicy = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false } | 
        Select-Object Name, Enabled
    FirewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled
    AntivirusProduct = "Not detected"
}

# Try to get AV separately to avoid property errors
try {
    $avQuery = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    if ($avQuery) {
        $info.Security.AntivirusProduct = ($avQuery | Select-Object -First 1).displayName
    }
} catch {
    # AV info not available
}
            
            # Installed Software
           # Installed Software
if ($IncludeInstalledSoftware) {
    Write-Verbose "Gathering installed software list..."
    try {
        $software = @(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object @{N='DisplayName';E={$_.DisplayName}}, 
                         @{N='Publisher';E={$_.Publisher}}, 
                         @{N='InstallDate';E={$_.InstallDate}}, 
                         @{N='DisplayVersion';E={$_.DisplayVersion}} |
            Sort-Object DisplayName)
        
        $info.InstalledSoftware = $software
    } catch {
        Write-Verbose "Could not retrieve installed software: $_"
        $info.InstalledSoftware = @()
    }
}
            
            # Installed Hotfixes
            if ($IncludeHotfixes) {
                Write-Verbose "Gathering installed hotfixes..."
                $info.Hotfixes = Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy |
                    Sort-Object InstalledOn -Descending
            }
            
        }
        catch {
            Write-Error "Error gathering system information: $_"
            throw
        }
    }
    
    end {
        return $info
    }
}