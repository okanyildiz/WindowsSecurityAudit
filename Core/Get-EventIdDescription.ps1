function Get-EventIdDescription {
    <#
    .SYNOPSIS
        Gets detailed description and context for Windows Event IDs
    .DESCRIPTION
        Provides comprehensive information about Windows Event IDs including 
        security implications, MITRE ATT&CK mappings, and recommended actions
    .PARAMETER EventId
        Event ID to look up
    .PARAMETER Source
        Event source/provider name
    .EXAMPLE
        Get-EventIdDescription -EventId 4624
        Get-EventIdDescription -EventId 4625 -Source "Microsoft-Windows-Security-Auditing"
    .OUTPUTS
        PSCustomObject with event description and analysis
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$EventId,
        
        [Parameter(Position = 1)]
        [string]$Source = "Security"
    )
    
    # Event ID database with security context
    $eventDatabase = @{
        # Authentication Events
        4624 = @{
            Category = "Authentication"
            Description = "An account was successfully logged on"
            Severity = "Informational"
            MITREAttack = @("T1078 - Valid Accounts")
            SecurityImplication = "Normal login activity. Monitor for unusual times, sources, or logon types."
            RecommendedAction = "Review logon type, source IP, and time. Look for patterns."
            CommonLogonTypes = @{
                2 = "Interactive (local logon)"
                3 = "Network (e.g., shared folder access)"
                4 = "Batch (scheduled task)"
                5 = "Service"
                7 = "Unlock (workstation unlock)"
                8 = "NetworkCleartext (IIS basic auth)"
                9 = "NewCredentials (RunAs)"
                10 = "RemoteInteractive (RDP)"
                11 = "CachedInteractive (cached credentials)"
            }
        }
        
        4625 = @{
            Category = "Authentication"
            Description = "An account failed to log on"
            Severity = "Warning"
            MITREAttack = @("T1110 - Brute Force", "T1078 - Valid Accounts")
            SecurityImplication = "Failed login attempt. Multiple failures may indicate brute force attack or password spray."
            RecommendedAction = "Investigate source IP, account name, and failure reason. Check for patterns."
            CommonFailureReasons = @{
                "0xC000006D" = "Bad username or password"
                "0xC000006E" = "Account restriction"
                "0xC000006F" = "Logon outside allowed time"
                "0xC0000070" = "Workstation restriction"
                "0xC0000071" = "Password expired"
                "0xC0000072" = "Account disabled"
                "0xC0000193" = "Account expiration"
                "0xC0000224" = "Password change required"
                "0xC0000234" = "Account locked out"
            }
        }
        
        4634 = @{
            Category = "Authentication"
            Description = "An account was logged off"
            Severity = "Informational"
            MITREAttack = @()
            SecurityImplication = "Normal logoff activity. Correlate with 4624 for session duration."
            RecommendedAction = "Use to establish user activity timelines."
        }
        
        4648 = @{
            Category = "Authentication"
            Description = "A logon was attempted using explicit credentials"
            Severity = "Warning"
            MITREAttack = @("T1078 - Valid Accounts", "T1550 - Use Alternate Authentication Material")
            SecurityImplication = "RunAs or credential delegation. May indicate privilege escalation or lateral movement."
            RecommendedAction = "Verify the legitimacy of credential usage. Check target account and system."
        }
        
        4672 = @{
            Category = "Privilege Use"
            Description = "Special privileges assigned to new logon"
            Severity = "Warning"
            MITREAttack = @("T1078.003 - Valid Accounts: Local Accounts")
            SecurityImplication = "Administrative privileges granted. Monitor for unauthorized admin access."
            RecommendedAction = "Verify user should have admin rights. Correlate with 4624."
        }
        
        4688 = @{
            Category = "Process Tracking"
            Description = "A new process has been created"
            Severity = "Informational"
            MITREAttack = @("T1059 - Command and Scripting Interpreter")
            SecurityImplication = "Process creation tracking. Essential for detecting malicious execution."
            RecommendedAction = "Enable command-line logging. Monitor for suspicious processes."
        }
        
        4697 = @{
            Category = "System"
            Description = "A service was installed in the system"
            Severity = "Warning"
            MITREAttack = @("T1543.003 - Create or Modify System Process: Windows Service")
            SecurityImplication = "New service creation. Common persistence mechanism."
            RecommendedAction = "Verify service legitimacy, check binary location and signature."
        }
        
        4698 = @{
            Category = "Task Scheduler"
            Description = "A scheduled task was created"
            Severity = "Warning"
            MITREAttack = @("T1053.005 - Scheduled Task/Job: Scheduled Task")
            SecurityImplication = "Scheduled task creation. Common persistence and execution method."
            RecommendedAction = "Review task details, actions, and trigger conditions."
        }
        
        4699 = @{
            Category = "Task Scheduler"
            Description = "A scheduled task was deleted"
            Severity = "Informational"
            MITREAttack = @("T1070.004 - Indicator Removal: File Deletion")
            SecurityImplication = "Task deletion may indicate cleanup after compromise."
            RecommendedAction = "Investigate why task was deleted and by whom."
        }
        
        4700 = @{
            Category = "Task Scheduler"
            Description = "A scheduled task was enabled"
            Severity = "Warning"
            MITREAttack = @("T1053.005 - Scheduled Task/Job: Scheduled Task")
            SecurityImplication = "Task enabled - check if authorized."
            RecommendedAction = "Review task configuration and execution history."
        }
        
        4701 = @{
            Category = "Task Scheduler"
            Description = "A scheduled task was disabled"
            Severity = "Warning"
            MITREAttack = @("T1562.001 - Impair Defenses: Disable or Modify Tools")
            SecurityImplication = "Task disabled - may disable security monitoring."
            RecommendedAction = "Verify legitimacy of task disabling."
        }
        
        4719 = @{
            Category = "Policy Change"
            Description = "System audit policy was changed"
            Severity = "High"
            MITREAttack = @("T1562.002 - Impair Defenses: Disable Windows Event Logging")
            SecurityImplication = "Audit policy change. Attackers may disable logging."
            RecommendedAction = "Immediate investigation required. Verify authorization."
        }
        
        4720 = @{
            Category = "Account Management"
            Description = "A user account was created"
            Severity = "Warning"
            MITREAttack = @("T1136.001 - Create Account: Local Account")
            SecurityImplication = "New account creation. Verify legitimacy."
            RecommendedAction = "Check account permissions and creation context."
        }
        
        4722 = @{
            Category = "Account Management"
            Description = "A user account was enabled"
            Severity = "Warning"
            MITREAttack = @("T1098 - Account Manipulation")
            SecurityImplication = "Account enabled. May reactivate dormant account."
            RecommendedAction = "Verify authorization and account purpose."
        }
        
        4724 = @{
            Category = "Account Management"
            Description = "An attempt was made to reset an account's password"
            Severity = "Warning"
            MITREAttack = @("T1098 - Account Manipulation")
            SecurityImplication = "Password reset attempt. May indicate account takeover."
            RecommendedAction = "Verify user initiated reset. Check for unauthorized access."
        }
        
        4732 = @{
            Category = "Account Management"
            Description = "A member was added to a security-enabled local group"
            Severity = "High"
            MITREAttack = @("T1098 - Account Manipulation")
            SecurityImplication = "Group membership change. Critical for admin groups."
            RecommendedAction = "Verify authorization, especially for Administrators group."
        }
        
        4738 = @{
            Category = "Account Management"
            Description = "A user account was changed"
            Severity = "Warning"
            MITREAttack = @("T1098 - Account Manipulation")
            SecurityImplication = "Account properties modified. Check for suspicious changes."
            RecommendedAction = "Review what was changed and by whom."
        }
        
        4740 = @{
            Category = "Account Management"
            Description = "A user account was locked out"
            Severity = "Warning"
            MITREAttack = @("T1110 - Brute Force")
            SecurityImplication = "Account lockout. May indicate brute force attack."
            RecommendedAction = "Investigate source of failed attempts."
        }
        
        5140 = @{
            Category = "File Share"
            Description = "A network share object was accessed"
            Severity = "Informational"
            MITREAttack = @("T1021.002 - Remote Services: SMB/Windows Admin Shares")
            SecurityImplication = "Share access. Monitor for lateral movement."
            RecommendedAction = "Review accessed shares and source systems."
        }
        
        5145 = @{
            Category = "File Share"
            Description = "A network share object was checked to see whether client can be granted desired access"
            Severity = "Informational"
            MITREAttack = @("T1021.002 - Remote Services: SMB/Windows Admin Shares")
            SecurityImplication = "Detailed share access logging."
            RecommendedAction = "Use for forensic analysis of file access."
        }
        
        7045 = @{
            Category = "System"
            Description = "A service was installed in the system"
            Severity = "High"
            MITREAttack = @("T1543.003 - Create or Modify System Process: Windows Service")
            SecurityImplication = "Service installation. Common malware persistence."
            RecommendedAction = "Verify service binary, path, and digital signature."
        }
        
        1102 = @{
            Category = "System"
            Description = "The audit log was cleared"
            Severity = "Critical"
            MITREAttack = @("T1070.001 - Indicator Removal: Clear Windows Event Logs")
            SecurityImplication = "Log clearing. Strong indicator of compromise."
            RecommendedAction = "Immediate investigation. Check who cleared logs and why."
        }
    }
    
    # Look up event
    if ($eventDatabase.ContainsKey($EventId)) {
        $eventInfo = $eventDatabase[$EventId]
        
        $result = [PSCustomObject]@{
            EventId = $EventId
            Source = $Source
            Category = $eventInfo.Category
            Description = $eventInfo.Description
            Severity = $eventInfo.Severity
            MITREAttack = $eventInfo.MITREAttack
            SecurityImplication = $eventInfo.SecurityImplication
            RecommendedAction = $eventInfo.RecommendedAction
            AdditionalInfo = $null
        }
        
        # Add additional info if available
        if ($eventInfo.ContainsKey('CommonLogonTypes')) {
            $result.AdditionalInfo = $eventInfo.CommonLogonTypes
        }
        elseif ($eventInfo.ContainsKey('CommonFailureReasons')) {
            $result.AdditionalInfo = $eventInfo.CommonFailureReasons
        }
        
        return $result
    }
    else {
        # Return generic info for unknown events
        return [PSCustomObject]@{
            EventId = $EventId
            Source = $Source
            Category = "Unknown"
            Description = "Event ID not in database"
            Severity = "Unknown"
            MITREAttack = @()
            SecurityImplication = "Unknown event - requires manual research"
            RecommendedAction = "Check Microsoft documentation for event details"
            AdditionalInfo = $null
        }
    }
}