# Partial observed usage

Any top-level response ledger selects response_ledger mode for the entire input.
Only owned unique (thread,response) identities contribute. Exact mirrors count
once; changed usage, turn or ownership invalidates the identity. Foreign/missing
ownership is excluded. Legacy and nested snapshots are never added to a ledger.

Without a ledger, the first valid cumulative snapshot is a baseline. Only adjacent
eligible monotonic intervals contribute; malformed/unknown records break epochs.
Component-set changes rebaseline. Any reset or compaction suspends later legacy
accounting. Last-only snapshots are unavailable. Inherited scopes disable legacy
deltas; owned response ledgers can still be observed there.

Each field is a nonnegative signed-64-bit integer, never bool/float/string. Cache
input cannot exceed input and reasoning output cannot exceed output. Missing
components remain null independently. Reported total is a separate observation:
cached input and reasoning are included subcomponents, never added again. No
costs, savings, billing, quota or per-tool attribution. V1 complete is always false.

Hand oracles (total_tokens): 100,150,150,200 -> 100; 100,150,20,60,150 -> 50;
100,gap,170,200 -> 30; 0,0 -> observed zero; a lone 100 -> unavailable.
Ledger A40,A40,B60 -> 100; A40,A45 -> unavailable; legacy100/200 then B30 -> 30.
Evidence intervals cap at 20. Ledger retention caps at 50000 identities; exhaustion
returns unavailable observed ledger totals rather than silently evicting conflicts.
