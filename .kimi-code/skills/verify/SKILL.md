---
name: verify
description: Run this project's full verification battery (parse, manifest, import, analyzer, Pester, BOM guard) and report counts
type: prompt
whenToUse: Before any commit, after any code change, or when asked to verify the module is healthy
arguments:
  - scope
---

Run the full verification for WindowsSecurityAudit (scope: $scope, default: whole repo).

pwsh path: `~/.local/pwsh/pwsh`. Run from the repo root.

1. Parse every `.ps1` with `[System.Management.Automation.Language.Parser]::ParseFile` — 0 errors required.
2. `Test-ModuleManifest ./WindowsSecurityAudit.psd1` — must pass.
3. `Import-Module ./WindowsSecurityAudit.psd1 -Force` — expect 77 functions + 1 alias, no import output on success.
4. `Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error` — must be 0.
5. `Invoke-Pester -Path ./tests -Output Normal` — must be 0 failed (skips are platform-gated by design).
6. BOM guard: any `.ps1/.psm1/.psd1` with non-ASCII bytes must start with `EF BB BF`.

If any gate fails: report the failing file:line and the exact error, fix only within the current task's scope, and re-run until green. Never report 'done' with a red gate.
