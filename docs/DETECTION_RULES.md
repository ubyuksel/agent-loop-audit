# Exact rules 1.0.0

ALA001: three distinct request identities with exactly the same tool, arguments
and context in the last 64 requests within one segment: information only.
ALA002: three consecutive identical requests and complete identical known failure
outcomes: warning review candidate. ALA003: a block of 2-4 distinct-position
requests repeated at least three times, with complete exact outcomes and at least
one known failure: warning review candidate. ALA004: three consecutive identical
supported read commands, complete identical results and known success: warning
review candidate. None proves waste, intent, file state or confirmed executions.

Canonical JSON preserves types, ordered arrays, paths, options, quoting and
secrets. Freeform strings remain exact. No regex redaction precedes comparison.
Known polling, waiting, planning and discovery tools cannot produce warnings.
Read classification supports only literal one-path cat in an explicit POSIX shell
or Get-Content -LiteralPath with a single-quoted literal in explicit PowerShell.

Unknown events, user/turn/context/patch changes and opaque operations are barriers.
Late identity/result conflicts retract dependent candidates at EOF. Inherited,
inconsistent or truncated scope suppresses behavioral findings. Unknown outcomes
and neutral search exit 1 cannot qualify as known failures. Opaque tools can be
observed with ALA001 across adjacent exact repetitions of that same opaque request;
opaque changes and transitions to known tools reset the observation window. Opaque
requests remain ineligible for warnings. No fuzzy similarities.

Overlapping windows merge; warning evidence suppresses matching informational
occurrence sets, cycles suppress contained single-pattern candidates. Evidence
caps at 20 call/result lines, candidates at 2000; omitted candidates are flagged.
