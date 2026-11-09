# Narrow JEA scan endpoint

This sample exposes only `WindowsSecurityAudit\Invoke-WsaRemoteFunctionSet` and its fixed Quick, Standard, and Deep scan sets. It does not expose arbitrary function names, script blocks, module paths, output paths, providers, external commands, remediation functions, or memory-dump functions. `Get-MultiSystemAudit` is outside this scenario because its remote script blocks have not been moved into a server-side wrapper.

## Install on every target

1. Install the complete WindowsSecurityAudit module under an admin-writable-only `PSModulePath` location, for example `C:\Program Files\WindowsPowerShell\Modules\WindowsSecurityAudit`. Keep `RoleCapabilities\WindowsSecurityAudit.Scan.psrc` inside that module directory. Do not install the module under a user's profile or another location writable by the connecting operators.
2. Copy `JEA\WindowsSecurityAudit.Sample.pssc` to an administrator-only configuration directory on the target.
3. Replace the example group `CONTOSO\WSA-Scan-Operators` with the intended operators group and replace the example transcript path if required.
4. Protect the module, role-capability file, session-configuration file, and transcript directory with ACLs. Only trusted administrators may change the module or JEA files. Limit transcript read access to authorized auditors and grant only the write access required for JEA transcription. A user-writable module or role file would become an elevation path.
5. From an elevated Windows PowerShell session on the target, validate and register the edited file:

```powershell
Test-PSSessionConfigurationFile -Path 'C:\ProgramData\JEAConfiguration\WindowsSecurityAudit.pssc'
Register-PSSessionConfiguration -Name WindowsSecurityAudit -Path 'C:\ProgramData\JEAConfiguration\WindowsSecurityAudit.pssc' -Force
```

Registration restarts the WinRM service. Test on a disposable Windows endpoint before fleet deployment.

## Run the curated scan

From the client, use the installed module and the same configuration name supplied during registration:

```powershell
Invoke-EnterpriseSecurityScan `
    -ComputerName srv1 `
    -ConfigurationName WindowsSecurityAudit `
    -UseModuleFunctions `
    -RemoteFunctionSet Standard
```

`-ConfigurationName` requires `-UseModuleFunctions` and rejects `-ModulePath`. This mode does not create or copy a ZIP, extract or import a module remotely, or clean up a remote temporary directory. `-WhatIf` creates neither a session nor a package. Omitting `-ConfigurationName` preserves the existing deployment workflow.

## Security and capability boundaries

The `RestrictedRemoteServer` session type gives the connecting user a `NoLanguage` session. The visible module function runs in the endpoint's default language mode, so trusted server-side commands and native compilation can work when that mode is `FullLanguage`. `NoLanguage` is not `ConstrainedLanguage`, and `FullLanguage` does not imply that JEA is absent.

Effective `ConstrainedLanguage`, commonly imposed by WDAC or AppLocker, blocks runtime C# compilation. The module detects the effective language mode and uses existing native-helper fallbacks with explicit diagnostics. This sample is a tested, curated scan path, not a claim that every exported function supports ConstrainedLanguage. Real WDAC policy behavior must be verified on a Windows test VM.

On a member server, the virtual account is normally a local administrator and uses the computer account for network access. JEA limits the operations available to the caller; it does not make every underlying check low privilege. Per-user artifacts describe the RunAs identity rather than the connecting user. Review this privilege and the virtual account's network access before registration.

The role intentionally has no `VisibleProviders` or `VisibleExternalCommands`. Trusted functions can still use required server-side providers and tools without making them available to the caller. Do not add wildcard functions, `Add-Type`, `Invoke-Command`, hardening functions, or dump functions to this role.

## Verification still required on Windows

Register a temporary endpoint and test from both Windows PowerShell 5.1 and PowerShell 7. Confirm that direct provider access and arbitrary script blocks fail while the visible wrapper succeeds. Check transcripts and the RunAs identity, then exercise real ConstrainedLanguage fallbacks under a WDAC test policy. These endpoint, NoLanguage, ACL, and WDAC integration checks cannot be established by the cross-platform mocked tests alone.
