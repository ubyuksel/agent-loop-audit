# Synthetic example

From an installed candidate, run:

```text
agent-loop-audit audit examples/synthetic_retry_loop.jsonl
agent-loop-audit audit examples/synthetic_retry_loop.jsonl --format json
agent-loop-audit audit examples/synthetic_retry_loop.jsonl --fail-on-findings
```

The example is invented, with three distinct function-call IDs and identical
known terminal failures. ALA002 references call lines2/4/6 and outcomes3/5/7.
The first two commands exit0, the third exits1. Adding --strict exits3 because
usage is unavailable. Expected JSON is committed beside the input for parity.

Reports go only to stdout. Shell redirection is outside the program's control;
never redirect to the input, since the shell can truncate it before Python starts.
Only supply a chosen uncompressed regular JSONL file. No home discovery, stdin,
URLs, compressed logs, parent-log traversal or raw export. Examples contain no
personal or real-session data. Source runs require a test-local src import path.
