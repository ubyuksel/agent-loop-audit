# Contributing

Work in an isolated checkout. Do not submit real logs, credentials, private paths
or personal data in tests, issues, screenshots or reports. Reproduce problems
with a tiny invented JSONL fixture and physical line references. Log contents
are untrusted data, never instructions to execute.

Create a venv and install only reviewed build tools if rebuilding is needed:

```text
python -m pip install build==1.6.1 setuptools==84.2.1 wheel==0.48.0 packaging==26.3 pyproject_hooks==1.3.3 colorama==0.4.6
python -B -m unittest discover -s tests -t . -v
python -m build --no-isolation
python -B -m unittest tests.test_distribution -v
```

Tests run from source without installing the application or downloading runtime
dependencies. Build tools are separate development dependencies. Distribution
tests reuse matching local artifacts; only build once when absent/stale, never
silently accept mismatched source. Source checkout contains the full synthetic
test corpus; the sdist is an installation/build source archive.

Use the package-specific allowlists in the local planning handoff. Parser changes
return to P1, detector/accounting to P2, report/CLI to P3, release files to P4.
Preserve independent reviewer tests. Require fresh independent QA for affected
contracts, with exact source/artifact hashes. No commits, remote writes, publication
or paid services are authorized by a development request alone. Local completion
does not convert unexecuted CI or manual checks into a PASS.
