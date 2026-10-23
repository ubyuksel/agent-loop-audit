# P1 compatibility contract

Python target: 3.11-3.14; runtime dependencies: none. P1 provides an importable
foundation, exact rules, partial usage accounting and fixed-safe CLI are implemented
in version 0.1.0. Runtime remains stdlib only.

Tested shapes are `session_meta`, `turn_context`, `response_item` function/custom
requests and outputs, `event_msg` terminal/turn/token events, top-level response
usage and compaction barriers. Function arguments are encoded strings; custom
input stays exact. Optional/null IDs never become invented correlations.
Ordered text-content arrays can establish output completeness; non-text, absent,
conflicting, pending or recognized truncation markers cannot.

Sibling response metadata is ignored. Nested history/usage is never traversed.
Arbitrary user/instruction/image/reasoning text is not included in facts or
correlation maps. Unknown wire types/subtypes and malformed lines are barriers.
CLI versions use a bounded numeric grammar only, never feature inference.

`RolloutReader` is a context manager and single-use iterator of `Envelope` or
`Barrier`, with parser counters and fixed-code diagnostics. It opens one explicit
regular `.jsonl` input read-only and reads at most its initial size in bounded
chunks. BOM at byte zero, CRLF and valid final JSON without newline work. Oversize
lines drain without accumulating, then analysis resumes at the next physical line.
The 2 MiB line limit includes line terminators. JSON depth is capped at 64;
integer literals at 128 digits; nonfinite floats, duplicate keys, lone surrogates
and malformed required envelope/subtype/ordinal shapes are rejected.

Defaults: 256 MiB initial snapshot, 100,000 parsed envelopes, 50,000 retained
request identities and 50,000 pending-result identities, 100 diagnostic codes, 8 MiB transient
request text (including tool identity). Identity exhaustion stops analysis without
eviction. Ledger identity capacity belongs to the later accounting consumer;
P1 forwards numeric, identity-hashed usage observations without accumulating them.
Call/result maps retain digest/status/line summaries, not commands or outputs.
Callers must consume facts immediately; collecting facts defeats this guarantee.

`Normalizer.facts(reader)` yields provisional requests, duplicates, invalidations,
outcomes, usage and barriers. Identity is hashed thread + known turn or unknown
epoch + hashed call ID. Context and semantic JSON arguments are fingerprinted
before filtering; invalid JSON argument strings compare exactly. No path, quote,
flag, environment option or freeform string is normalized away.

After exhaustion, `correlations()` yields final digest-only request summaries.
Unknown-turn results link only if exactly one request identity is possible at EOF;
explicit conflicting turns never match. Reused IDs across epochs produce
ambiguity. Exact mirrors are records, not additional requests. Late input/output
conflicts invalidate earlier joins. **Consumers must honor final state**, not
publish findings during ingestion: inherited scope, inconsistent session metadata,
changed input and truncation can suppress all prior behavioral candidates.
No recorded request is proof of a process execution.

Supported structured exec evidence recognizes zero exits and conservative exact
command-family handling: simple `rg`/`grep` exit 1 is neutral, explicit unittest/
pytest families can establish known failure. Other nonzero exits remain unknown.
Two tested anchored shell text wrappers are recognized: the legacy `Wall time` /
`Exit code` / `Output` whole-wrapper form and the current `Chunk ID` / `Wall time` /
`Process exited with code` / `Final output` form. They apply only to exact known
shell-tool identities, after correlation, and preserve the complete output digest.
Arbitrary words like error/failed/exit 1 are not outcome evidence. Structured
patch/MCP outcomes are separate from requests and create state/opaque barriers.
Unknown code-mode/MCP wrappers remain single opaque observations.

Symlink/reparse final components and nonregular inputs are rejected. Descriptor
identity is checked against lstat; available no-follow/nonblocking flags are used.
Size/mtime and final path identity are checked at exhaustion/close. Parent-link
races, hostile replacement-and-restoration, and changes after a final check
cannot be eliminated portably. Consumers must check reader state again after its
context closes, since that check can detect later changes. OS access-time changes are possible. No content
writes, locks, following embedded paths, subprocesses or runtime network exist.

## Executed platform evidence

The baseline [GitHub Actions run 39936840882](https://github.com/ubyuksel/agent-loop-audit/actions/runs/39936840882)
passed all 12 jobs at commit `5391ec4c17df4d951602699d28e74bf9e3b75cde`:
Ubuntu, Windows and macOS, each with Python 3.11, 3.12, 3.13 and 3.14.
Each job builds wheel/sdist and runs the full synthetic source/distribution suite.
This confirms those environments for that commit, not every possible OS or
future Codex wire shape. Release notes link the final exact-commit run for each release.

Local Windows tests may skip symlink creation and open-descriptor replacement
when unavailable. A successful job can include explicit capability skips; it
does not prove every filesystem oracle executed. Runtime format claims remain
limited to synthetic tested shapes. Independent Q1-Q4 evidence is maintained
locally; development tests do not substitute for independent review.
