---
name: release
description: Cut a release of WindowsSecurityAudit — version bump, CHANGELOG, CI gate, single tag, publish to PowerShell Gallery, package verification
type: prompt
whenToUse: When the user asks to release, tag, or publish a new version
arguments:
  - version
---

Release version: $version (e.g. 1.10.0). Do not reuse an existing tag (Gallery rejects re-uploads).

1. Bump in lockstep: `WindowsSecurityAudit.psd1` ModuleVersion, `WindowsSecurityAudit.psm1` `.VERSION` header AND `$script:ModuleVersion`, README version badge. Preserve UTF-8 BOM on psd1/README.
2. CHANGELOG.md: new section with only what was actually done + update the bottom link refs (`[Unreleased]` compares from the new tag).
3. Run the `verify` skill's full battery locally.
4. Commit and push to main.
5. Wait for BOTH CI jobs green: lint+test AND real-Windows smoke (pwsh and PS 5.1). On a transient Gallery download failure, rerun only that job.
6. Only then: `gh release create v$version` ONCE on the final commit (never move/delete an older tag).
7. The release event runs publish.yml (test gate + tag/manifest guard + staged clean package + Gallery publish). Watch it to success.
8. Verify on the Gallery:
   - `Find-Module WindowsSecurityAudit -RequiredVersion $version`
   - Download the nupkg from `https://www.powershellgallery.com/api/v2/package/WindowsSecurityAudit/$version`, unzip, and diff every `.ps*1` against the tag (no diffs allowed).
   - Confirm `tests/` and `.github/` are NOT in the package.
Report the release URL, publish run result, and the Gallery verification output.
