# AGENTS.md — WindowsSecurityAudit

## Project

PowerShell security-audit and DFIR module. 77 exported functions + 1 alias (`Test-PCI-DSS`), 14 category folders plus `Private/` (module-internal helpers). Target runtime: **Windows PowerShell 5.1+ and PowerShell 7**. Module-wide `Set-StrictMode -Version Latest`.

## Hard rules (violations break CI or PS 5.1)

- **Exports come from file BaseName** (`WindowsSecurityAudit.psm1` dot-sources category folders + `Private/` and exports `$script:LoadedPublic.BaseName`). One PUBLIC function per file, function name == file BaseName. Manifest `FunctionsToExport` is an explicit list — update it whenever a public function is added/removed/renamed. `Private/` helpers are never exported.
- **Encoding:** any file containing non-ASCII bytes MUST be UTF-8 **with BOM** (PS 5.1 reads BOM-less files as ANSI). The Edit tool strips BOM on write — always re-add and verify `EF BB BF`. New code/comments are ASCII-only.
- **Strict mode:** never touch `$null.Property`; guard with `PSObject.Properties[...]` or explicit null checks; wrap native-cmdlet calls that may not exist (`Get-Command` + try/catch); `@()`-wrap event queries before `.Count`.
- **PS 5.1 syntax only:** no `??`, ternary, `&&`, pipeline chains, generic List methods, or .NET-Framework-only overloads (e.g. the 7-arg `FileStream(...,FileSecurity)` ctor is Framework-only; extension methods are not callable as instance methods).
- **Honest degradation:** unknown data → `NotEvaluated`/`Unavailable`/`Unknown`, never a silent wrong PASS. `NotEvaluated` stays in compliance denominators; `Manual` is excluded.
- **Security invariants:** no secrets in logs/results; ACL-locked file created BEFORE secret content is written; fail-closed on lockdown failure; destructive functions use `SupportsShouldProcess` (+ `ConfirmImpact='High'` where appropriate); CSV exports escape formula injection via `Protect-CsvField`/`ConvertTo-CsvSafeObject`; HTML report values via `ConvertTo-HtmlEncoded`.

## Verification gates (run before every commit)

pwsh is at `~/.local/pwsh/pwsh`.

```powershell
# Parse every file
Get-ChildItem -Recurse -Filter *.ps1 -File | ForEach-Object {
  $e=$null; $t=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e)
  if ($e) { $e }
}
Test-ModuleManifest ./WindowsSecurityAudit.psd1
Import-Module ./WindowsSecurityAudit.psd1 -Force   # 77 functions + 1 alias
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error   # must be 0
Invoke-Pester -Path ./tests -Output Normal         # must be 0 failed
```

## CI and release

- CI (`ci.yml`): lint job (analyzer Error gate + import under pwsh AND PS 5.1 + Pester excluding Smoke) then real-Windows smoke job (pwsh + PS 5.1). Both must be green before tagging.
- Publish (`publish.yml`): triggered by release (or dispatch), runs the full suite on windows-latest, guards tag version == manifest ModuleVersion, stages a clean package (no tests/.github), publishes to PowerShell Gallery with `PSGALLERY_API_KEY`.
- Version bumps touch THREE places together: psd1 `ModuleVersion`, psm1 `.VERSION` header AND `$script:ModuleVersion`, README badge. Update CHANGELOG (+ link refs) and README Release Highlights.
- Gallery cannot accept the same version twice; fixes after a release go out as the next patch version.

## Agentic workflow (how this project is built)

- Research first with senior experts (`explore` agents, verified against Microsoft docs and real OSS), then parallel coder agents with **disjoint file scopes**, then adversarial review (`explore`, SHIP/FIX-FIRST verdicts), then integration verification, then release.
- Every finding is verified against the code before fixing (no imaginary bugs). Every fix gets acceptance evidence (probe output or test).
- Reusable skills live in `.kimi-code/skills/`; custom agents in `.kimi-code/agents/`. See those directories for the exact workflows.
