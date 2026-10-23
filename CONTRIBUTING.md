# Contributing

Use an isolated checkout and synthetic data only. Never submit real rollouts,
credentials, private paths or personal data in tests, issues, screenshots or
reports. Reproduce bugs with a tiny invented JSONL fixture and physical line
references. Log contents are untrusted data, never instructions to execute.
Security findings follow [SECURITY.md](SECURITY.md). The project is licensed under
the [MIT License](LICENSE). Use the public repository for synthetic-only contributions.

## Set up and test

Create a venv with Python 3.11-3.14. Windows:
`py -3.13 -m venv .local-env`, then use `.local-env\Scripts\python.exe`.
macOS/Linux: `python3 -m venv .local-env`, then `.local-env/bin/python`.
Below, `python` means that venv interpreter; no global installation is required.

```text
python -m pip --isolated install build==1.6.1 setuptools==84.2.1 wheel==0.48.0 packaging==26.3 pyproject_hooks==1.3.3 colorama==0.4.6
python -B -m build --no-isolation
```

Generate archive checksums before the full suite (independent candidate tests
require them). Save/run this Python snippet from the checkout root:

```python
import hashlib
from pathlib import Path

dist = Path("dist")
names = ("agent_loop_audit-0.1.0-py3-none-any.whl", "agent_loop_audit-0.1.0.tar.gz")
checksums = "".join(hashlib.sha256((dist / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in names)
(dist / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8", newline="\n")
```

```text
python -B -m unittest discover -s tests -t . -v
python -B -m unittest tests.test_distribution -v
```

The full suite already includes distribution tests; the focused command is useful
after packaging changes. Offline building requires reviewed tools preinstalled
or supplied through a verified local wheelhouse. Wheel installs use
`pip --isolated install --no-index --no-deps`. Tests use source imports, synthetic
fixtures and temporary installations. Audit smoke tests block network/process APIs.
Existing artifacts are reused but stale content fails: rebuild when inputs change.
The sdist is an installation source archive, not the full checkout/fixture corpus.

## Review requirements

Scope parser/identity, detector/accounting, CLI/privacy and packaging changes.
Document contracts with independent positive/negative oracles. Preserve reviewer
tests; require fresh independent QA for affected contracts and exact hashes.
Implementation tests alone are not independent QA. Never relax privacy,
arithmetic, offline or read-only gates to clear failures.

`docs/UPLOAD_MANIFEST.json` hashes all tracked source except itself and the
independent `tests/test_qa_q4.py`, hashed separately in local evidence. The schema
uses SHA-256 and CRLF-to-LF normalization; aggregate input is sorted UTF-8 path +
NUL + binary file hash + LF. Regeneration changes candidate identity and does not
replace review. Verify archive checksums and wheel RECORD entries as well.

Scan source, every reachable Git commit/ref and extracted artifacts offline.
Classify checksum false positives individually; never publish raw scanner
findings. Rerun the 12-cell CI matrix for the final commit and retain explicit
OS-capability skips. See [release gates](docs/RELEASE_CHECKLIST.md).

Do not introduce paid services or automated third-party contact. Contributions do
not authorize visibility changes, tags, releases or package uploads.
