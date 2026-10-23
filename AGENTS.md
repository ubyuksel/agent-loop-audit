# Agent Loop Audit authority

Work only in this isolated repository. The owner authorized local Git initialization
and waived remote/private-remote verification for local development on 2026-10-23.
The owner subsequently authorized a first commit, creation of the PRIVATE
ubyuksel/agent-loop-audit GitHub repository, origin setup and a normal initial
push only after successful security scans and tests. Stop on sensitive findings
or missing GitHub authentication. Do not change existing repository visibility,
make anything public, force-push, use paid APIs or contact others.
Do not inspect or modify neighboring projects. The owner explicitly
authorized sequential independent QA subagents through Q4; no parallel development agents.

The unchanged, ignored `.planning/` package controls implementation and exact
per-pass source write allowlists. For P1 use only the files listed in its block
in `.planning/04_CODEX_TASK_PACKAGES.md`; planning files are read-only. Generated
virtual environments/caches are ignored. Use synthetic fixtures only: no real
logs, credentials, home/config reads, raw report exports or private identifiers.

Runtime is Python stdlib only, read-only, offline and single-input. Never execute
log content or follow referenced paths. Raw internal facts must not be exported.
Setuptools is build tooling only. CLI/rules/accounting are later packages.

Run P1 unittest commands with the isolated interpreter and `-B`. Record exact
checks and candidate digests. Implementation tests are not independent QA.
QA requires a clean independent review context; do not start P2 before Q1_PASS
against this exact candidate. Preserve reviewer tests; never silently relax gates.
