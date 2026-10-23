# Public report schema 1.0 / rules 1.0.0

Fixed roots: schema_version, tool_version, rules_version, source, coverage,
summary, token_usage, findings, diagnostics. Only fixed labels/enums, controlled
versions, bounded nonnegative integers, booleans, null and arrays/objects of those
values appear. No paths, timestamps, tool arguments/results, arbitrary names,
identifiers, hashes, model/provider/account data or exception text are exported.

Source label is input_1. Coverage always has complete:false and explicit behavior
supported/partial/unsupported, accounting observed_only/unavailable, fixed reason
codes and resource flags. Summary counts requests, not confirmed executions.
Token fields are partial recorded observations; missing values are null. Individual
records are signed64 nonnegative integers; aggregate Python integers may exceed
64 bits, bounded by the 100000-record ceiling times the maximum record value.

Findings have stable F IDs after rule priority ALA002/003/004/001 and physical-line
ordering. Fields: rule_id, level, confidence, title, tool_label, occurrences,
call_lines, outcome_lines, span, evidence_status, evidence_truncated,
recommendation, caveats. Evidence arrays cap at20; finding capacity2000.
Diagnostics contain only code, first physical line and aggregate count.

Default exit0 means a report was produced, never full coverage. Exit1 requires
--fail-on-findings plus a warning candidate; informational repetitions alone do
not trigger it. Exit2 is invalid/unreadable/nonregular/unsupported input or handled
audit failure. Exit3 is --strict plus any partial coverage/accounting, and wins
over1. V1 accounting is always partial/unavailable, so strict audits return3.
Keyboard interruption exits130. Broken output pipes close quietly. Handled audit
errors in JSON mode are one complete JSON object; argument errors use fixed text.
