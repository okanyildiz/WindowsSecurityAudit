---
name: review-swarm
description: Adversarial multi-expert review of a change set — verify findings against code, then coordinate fixes with disjoint file scopes
type: prompt
whenToUse: After a feature wave or before a release, when the user asks for senior/expert/cross review
arguments:
  - target
---

Run the senior-expert adversarial review for: $target (commit SHA, version, or file set).

1. **Verify before fixing.** Launch parallel `explore` reviewers, each with a distinct lens (P/Invoke/native correctness, call-site logic/contracts, test adequacy, security). Every claimed finding must be confirmed against the actual code with file:line evidence — mark unverifiable claims NOT-FOUND instead of fixing them.
2. Each reviewer returns a verdict (SHIP / FIX-FIRST) plus severity-ranked findings with evidence and a concrete fix suggestion.
3. **Fix with parallel coder agents on disjoint file scopes** (no two agents editing the same file). Include the QA-driven test additions that pin each fixed behavior.
4. **Acceptance evidence required per finding**: a probe output or a passing test that would have caught the bug. No finding is 'fixed' without it.
5. Run the `verify` skill's full battery. On real-Windows CI failures, treat them as real bugs until proven environment flakes (rerun once to check).
6. Report a table: finding → severity → fix commit → acceptance output. Deviations from the original review instructions get a stated reason.
