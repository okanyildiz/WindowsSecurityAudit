---
name: Bug report
about: Report a problem with the WindowsSecurityAudit module
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**Environment**
- Module version: [output of `Get-Module WindowsSecurityAudit` after importing, e.g. `1.3.0`]
- PowerShell version: [output of `$PSVersionTable.PSVersion`, e.g. `5.1.22621.2506` or `7.4.2`]
- Windows build: [output of `[System.Environment]::OSVersion.Version` or `winver`, e.g. `10.0.22631`]
- Execution context: [e.g. elevated prompt, scheduled task, remote session]

**Command run**
The exact command you ran, including all parameters:

```powershell
# e.g. Invoke-SecurityAssessment -IncludeCompliance -ExportPath C:\Reports
```

**Expected behavior**
What you expected the command to do.

**Actual behavior**
What actually happened, including the full error text if any:

```text
# paste error record or $Error[0] | Format-List * -Force output here
```

**Sanitized output**
If relevant, attach or paste the function's output (objects, exported report snippets). Remove hostnames, usernames, tenant IDs, IP addresses, API keys, and any other sensitive data before posting.

**Additional context**
Add any other context about the problem here.
