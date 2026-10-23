# Synthetic fixture provenance and physical line map

All three files are invented in this repository. No user rollout was opened,
copied, redacted or transformed. IDs, paths, commands, outputs and usage values
are arbitrary synthetic examples. They demonstrate wire shapes, not runtime
certification of the version string `0.0.1` or any historical Codex binary.

| Fixture | Physical lines (one record per line) |
|---|---|
| legacy_root.jsonl | 1 metadata; 2 legacy task_started; 3 function request A; 4 output A; 5 terminal event A; 6 cumulative token observation; 7 request B; 8 legacy task_complete |
| current_root.jsonl | 1 root metadata; 2 turn context; 3 namespaced function request A; 4 ordered text-content output A plus sibling metadata; 5 custom request B; 6 custom output B; 7 top-level response ledger observation; 8 turn_complete. Ordinals 0-7. |
| inherited_scope.jsonl | 1 child/root mismatch, subagent and history-base indicators; 2 request; 3 output. All behavioral eligibility suppressed; the history path is never opened. |

Expected request identities: 2 / 2 / 1 respectively. Missing outcomes and token
intervals stay unknown. Large, corrupt, canary and mutation inputs are generated
only in OS temporary directories by tests.

P2 additions (all invented): retry_loop lines 1 metadata, 2/4/6 calls,
3/5/7 identical known failures -> ALA002. negative_controls has two
calls on each side of a user barrier -> no finding. mixed_usage lines
2/3 cumulative, 4/5 response A mirror, 6 response B -> ledger-only 100.
