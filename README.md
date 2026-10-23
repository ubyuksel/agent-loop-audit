# Agent Loop Audit

Inspect one explicitly selected Codex rollout JSONL file offline. Agent Loop
Audit reports exact repeated requests, repeated known failures, short cycles and
repeated read results, with physical source-line references for human review.
Repetition does not establish waste, intent or unnecessary execution.

Version **0.1.0** is an unpublished candidate. The repository remains private.
No public package/repository has been published. The code is licensed under the
[MIT License](LICENSE), copyright 2026 Umut Buğra Yüksel, with explicit owner
approval. A verified private security reporting route remains a release gate.

Python **3.11-3.14** is tested on Ubuntu, Windows and macOS.
The [baseline CI run](https://github.com/ubyuksel/agent-loop-audit/actions/runs/39936840882)
passed all 12 jobs at commit `5391ec4c17df4d951602699d28e74bf9e3b75cde`.
That result applies to the baseline; changes require a new run. Filesystem tests
skip when a capability is unavailable. See [compatibility](docs/COMPATIBILITY.md).

## Installation

Use a supplied authorized checkout. No PyPI installation is advertised.
Runtime dependencies are empty; building requires the pinned tools below.
Tool installation may access the package index. Auditing and installation of an
already built wheel need no network.

Windows PowerShell, from the checkout root:

```powershell
py -3.13 -m venv .local-env
.\.local-env\Scripts\python.exe -m pip --isolated install build==1.6.1 setuptools==84.2.1 wheel==0.48.0 packaging==26.3 pyproject_hooks==1.3.3 colorama==0.4.6
.\.local-env\Scripts\python.exe -B -m build --no-isolation
.\.local-env\Scripts\python.exe -m pip --isolated install --no-index --no-deps dist/agent_loop_audit-0.1.0-py3-none-any.whl
.\.local-env\Scripts\agent-loop-audit.exe --help
.\.local-env\Scripts\agent-loop-audit.exe audit examples/synthetic_retry_loop.jsonl --format json
```

macOS / Linux, from the checkout root:

```sh
python3 -m venv .local-env
.local-env/bin/python -m pip --isolated install build==1.6.1 setuptools==84.2.1 wheel==0.48.0 packaging==26.3 pyproject_hooks==1.3.3 colorama==0.4.6
.local-env/bin/python -B -m build --no-isolation
.local-env/bin/python -m pip --isolated install --no-index --no-deps dist/agent_loop_audit-0.1.0-py3-none-any.whl
.local-env/bin/agent-loop-audit --help
.local-env/bin/agent-loop-audit audit examples/synthetic_retry_loop.jsonl --format json
```

Use any supported interpreter; the Windows example selects 3.13.
For a supplied reviewed wheel, omit build-tool installation and building. Check
its SHA-256 against the supplied manifest before installation. Examples stay in
the checkout and are not installed in the wheel.
See [CONTRIBUTING.md](CONTRIBUTING.md) for tests and archive checksum generation.

## Synthetic examples

The installed console and module have the same interface:

```text
agent-loop-audit audit examples/synthetic_retry_loop.jsonl
agent-loop-audit audit examples/synthetic_retry_loop.jsonl --format json
python -m agent_loop_audit audit examples/synthetic_retry_loop.jsonl --fail-on-findings
agent-loop-audit audit tests/fixtures/negative_controls.jsonl --format json
```

Use the venv executable paths above if it is not activated.
The invented retry example produces ALA002 at call lines 2/4/6 and outcome lines
3/5/7. [Expected JSON](examples/synthetic_retry_loop.expected.json) is checked
against executable output. The negative control produces no findings.

| Rule | Observation |
| --- | --- |
| ALA001 | Exact repeated requests (informational) |
| ALA002 | Identical complete known terminal failures |
| ALA003 | Exact short cycles with complete outcomes and a known failure |
| ALA004 | Identical complete successful read results |

Polling, uncertain outcomes, changed context/results, patches, ambiguous IDs and
inherited histories limit findings. See [exact rules](docs/DETECTION_RULES.md).

| Exit | Meaning |
| --- | --- |
| 0 | Report produced; does not imply complete coverage |
| 1 | `--fail-on-findings` found a warning; ALA001 alone does not trigger it |
| 2 | Usage, input access, unsupported input or handled audit error |
| 3 | `--strict` detected partial coverage; takes priority over exit 1 |
| 130 | Interrupted audit |

Token accounting is always partial/unavailable, so strict audits return 3.
Observed owned-response ledger sums or conservative cumulative deltas are **not
billing, account quota, per-tool attribution, costs or measured savings**.
Cached input/reasoning are included subcomponents, not additional totals.
Missing numbers remain null. See [accounting](docs/TOKEN_ACCOUNTING.md).

## Privacy and input boundaries

Runtime uses only Python's standard library. It opens one explicit regular,
uncompressed `.jsonl` input read-only and writes a fixed-schema report to stdout.
There is no inference, network, telemetry, account/configuration discovery,
subprocess or execution of log content. Referenced paths, URLs, parent histories
and commands are never followed or executed.

Both report modes exclude raw paths, commands/results, IDs, hashes, arbitrary
tool names, account/model fields and terminal escapes. Counts, line relationships
and fixed tool categories can still reveal activity patterns: review before
sharing. This is not a general-purpose anonymizer. Raw strings exist transiently
in memory; secure memory erasure and protection from the host/interpreter/shell
are not promised.

No stdin, recursive discovery, compressed logs, database, URL input or Claude
log support exists. Fork/subagent/inherited histories suppress behavioral
findings; owned response usage may remain observable. Nested code-mode is opaque.
All fixtures/examples are invented from public format definitions.

Defaults: 256 MiB input, 2 MiB physical line, 100,000 envelopes, 50,000 request
and pending-result identities each, 50,000 ledger identities, 64-call windows,
2,000 retained findings and 20 evidence lines per array. Corrupt/unknown/oversize
records create explicit limitations. Filesystem races cannot be eliminated fully;
reading may update access times. **Never redirect output onto the input**:
the shell may truncate it before Python starts.

## Project and release information

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[CHANGELOG.md](CHANGELOG.md), [provenance](docs/PROVENANCE.md) and the
[release checklist](docs/RELEASE_CHECKLIST.md). No adoption or measured token
savings are claimed. Agent Loop Audit is an independent project and is not
affiliated with, sponsored by or endorsed by OpenAI.
