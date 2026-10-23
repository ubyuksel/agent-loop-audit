# Agent Loop Audit

Private local candidate **0.1.0**. Inspect one explicitly selected Codex rollout
JSONL file offline and obtain conservative repetition/failure observations with
physical source-line evidence. Repetition is not proof of waste or intent.

Python 3.11-3.14 is the target. See `evidence/RELEASE_CANDIDATE.md` for actual
executed platform evidence; an unexecuted platform is not supported by assertion.
Runtime uses only the Python standard library, no inference, network, accounts,
telemetry, configuration discovery, subprocesses or third-party dependencies.

## Local installation

No public package/repository has been published. From this supplied checkout:

```text
python -m venv .local-env
.local-env/Scripts/python -m pip install --no-index --no-deps dist/agent_loop_audit-0.1.0-py3-none-any.whl
.local-env/Scripts/agent-loop-audit --help
.local-env/Scripts/agent-loop-audit audit examples/synthetic_retry_loop.jsonl --format json
```

On macOS/Linux use `.local-env/bin/python` and `.local-env/bin/agent-loop-audit`.
Those commands describe the portable interface; consult recorded matrix results
before treating them as executed platform evidence. The wheel needs no network.

## Behavior

`agent-loop-audit audit PATH [--format text|json] [--strict] [--fail-on-findings]`
also works through `python -m agent_loop_audit`. Help/version are supported.
ALA001 reports exact repeated requests; ALA002 repeated known terminal failures;
ALA003 exact short cycles; ALA004 identical complete read results. All warnings
are review candidates. Known polling, unknown outcomes, changed context/results,
patches, ambiguous IDs and inherited histories prevent confident warnings.

The invented example produces ALA002 at call lines2/4/6 and outcome lines3/5/7.
`examples/synthetic_retry_loop.expected.json` is generated from the executable.
`tests/fixtures/negative_controls.jsonl` demonstrates a legitimate user boundary.

Exit0 means a report was produced, not complete coverage. Warning flag1;
usage/input/error2; strict partial coverage3 (priority over1); interruption130.
V1 token accounting is always partial/unavailable, so strict audits return3.
Reported usage is observed ledger/delta evidence, never billing, account quota,
token costs, attributable tool usage or savings. Missing numbers remain null.

## Boundaries and privacy

One explicit regular uncompressed `.jsonl` file, opened read-only. No stdin,
recursive discovery, URLs, database, compressed rollout or Claude support.
Fork/subagent/history inputs suppress behavioral findings; owned response usage
may remain observable. Nested code-mode operations remain opaque. Raw paths,
commands/results, IDs, hashes, account/model fields and terminal escapes are
excluded from both report modes. This is not a general-purpose anonymizer.

Defaults: 256 MiB input, 2 MiB physical line, 100000 envelopes, 50000 request and
pending-result identities each, 50000 ledger identities, 64-call windows, 2000
retained findings, 20 evidence lines per array. Oversize/corrupt/unknown records
create explicit limitations. Parent-directory races cannot be eliminated fully.
Reading may update OS access times. stdout is the only report destination:
**never redirect output onto the input**, because the shell may truncate it first.

## Development and release status

See CONTRIBUTING.md and docs for exact contracts and test/build commands. All
fixtures are invented from public shape definitions; no real session log is used.
CI is staged locally with verified action pins; it has not been remotely run.
This project has no claimed OpenAI affiliation, adoption or measured user savings.

Distribution remains private. License/rightsholder approval, private security
reporting setup, trusted full history/archive secret scanning and missing OS/Python
matrix evidence are publication gates. LICENSE deliberately makes no MIT grant
until owner approval; no owner identity or reporting address has been invented.
