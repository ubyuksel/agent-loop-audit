"""Independent final-candidate checks; synthetic inputs and local artifacts only."""

import base64
import csv
import email
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = {"agent_loop_audit-0.1.0-py3-none-any.whl", "agent_loop_audit-0.1.0.tar.gz"}
MANIFEST_EXCLUSIONS = {"docs/UPLOAD_MANIFEST.json", "tests/test_qa_q4.py"}
APPROVED_MIT_LICENSE = """MIT License

Copyright (c) 2026 Umut Bu\u011fra Y\u00fcksel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_manifest_key")
        result[key] = value
    return result


def verify_source_manifest(root, names, raw):
    """Check a frozen reviewed manifest; never generate or update expectations."""
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "hash_algorithm", "normalization", "files", "source_digest"}:
        raise ValueError("manifest_schema")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["hash_algorithm"] != "sha256" or manifest["normalization"] != "crlf-to-lf":
        raise ValueError("manifest_format")
    files = manifest["files"]
    if not isinstance(files, dict) or not files or set(files) != set(names) - MANIFEST_EXCLUSIONS:
        raise ValueError("manifest_file_set")
    digest = hashlib.sha256()
    for name, wanted in sorted(files.items()):
        path = PurePosixPath(name)
        if path.is_absolute() or path.as_posix() != name or any(part in (".", "..") for part in path.parts) or "\\" in name or ":" in name:
            raise ValueError("manifest_unsafe_path")
        if not isinstance(wanted, str) or not re.fullmatch(r"[a-f0-9]{64}", wanted):
            raise ValueError("manifest_hash")
        local = root / name
        if any((root / PurePosixPath(*path.parts[:index])).is_symlink() for index in range(1, len(path.parts) + 1)):
            raise ValueError("manifest_symlink")
        actual = hashlib.sha256(local.read_bytes().replace(b"\r\n", b"\n")).digest()
        if actual.hex() != wanted:
            raise ValueError("manifest_content")
        digest.update(name.encode("utf-8") + b"\0" + actual + b"\n")
    if digest.hexdigest() != manifest["source_digest"]:
        raise ValueError("manifest_aggregate")


def verify_archive_checksums(root):
    sums = {}
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in sums:
            raise ValueError("archive_checksum_format")
        sums[match[2]] = match[1]
    if set(sums) != ARTIFACTS:
        raise ValueError("archive_checksum_file_set")
    for name, wanted in sums.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != wanted:
            raise ValueError("archive_checksum_mismatch")


class CandidateReview(unittest.TestCase):
    def test_p4_baseline_and_archive_checksums(self):
        paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode("utf-8").rstrip("\0").split("\0")
        verify_source_manifest(ROOT, paths, (ROOT / "docs/UPLOAD_MANIFEST.json").read_text(encoding="utf-8"))
        verify_archive_checksums(ROOT / "dist")

    def test_manifest_rejects_tampering_and_normalizes_checkout_line_endings(self):
        with tempfile.TemporaryDirectory(prefix="ala-manifest-") as folder:
            root = Path(folder)
            (root / "invented.txt").write_bytes(b"invented\r\n")
            file_hash = hashlib.sha256(b"invented\n").hexdigest()
            aggregate = hashlib.sha256(b"invented.txt\0" + bytes.fromhex(file_hash) + b"\n").hexdigest()
            manifest = {"schema_version": 1, "hash_algorithm": "sha256", "normalization": "crlf-to-lf", "files": {"invented.txt": file_hash}, "source_digest": aggregate}
            raw = json.dumps(manifest)
            verify_source_manifest(root, ["invented.txt"], raw)
            for names, candidate, error in ((["invented.txt", "unreviewed.txt"], raw, "manifest_file_set"), (["invented.txt"], raw.replace(aggregate, "0" * 64), "manifest_aggregate"), (["invented.txt"], raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'), "duplicate_manifest_key")):
                with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                    verify_source_manifest(root, names, candidate)
            (root / "invented.txt").write_bytes(b"changed\n")
            with self.assertRaisesRegex(ValueError, "manifest_content"):
                verify_source_manifest(root, ["invented.txt"], raw)

    def test_archive_checksums_reject_stale_missing_extra_and_duplicate_entries(self):
        with tempfile.TemporaryDirectory(prefix="ala-sums-") as folder:
            root = Path(folder)
            lines = []
            for name in sorted(ARTIFACTS):
                (root / name).write_bytes(b"invented archive")
                lines.append(hashlib.sha256(b"invented archive").hexdigest() + "  " + name)
            sums = root / "SHA256SUMS.txt"
            sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
            verify_archive_checksums(root)
            for content in (lines[0], "\n".join(lines + [lines[0]]), "\n".join(lines + ["0" * 64 + "  extra.zip"])):
                sums.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(ValueError):
                    verify_archive_checksums(root)
            sums.write_text("\n".join(lines), encoding="utf-8")
            (root / sorted(ARTIFACTS)[0]).write_bytes(b"changed archive")
            with self.assertRaisesRegex(ValueError, "archive_checksum_mismatch"):
                verify_archive_checksums(root)

    def test_wheel_exact_members_record_and_source_parity(self):
        prefix = "agent_loop_audit-0.1.0.dist-info/"
        runtime = {"agent_loop_audit/" + p.name for p in (ROOT/"src/agent_loop_audit").glob("*.py")}
        expected = runtime | {prefix + x for x in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD", "licenses/LICENSE")}
        with zipfile.ZipFile(ROOT/"dist/agent_loop_audit-0.1.0-py3-none-any.whl") as archive:
            self.assertEqual(set(archive.namelist()), expected)
            self.assertEqual(len(archive.namelist()), len(expected))
            for name in runtime:
                self.assertEqual(archive.read(name), (ROOT/"src"/name).read_bytes())
            self.assertEqual(archive.read(prefix+"licenses/LICENSE"), (ROOT/"LICENSE").read_bytes())
            meta = email.message_from_bytes(archive.read(prefix+"METADATA"))
            self.assertIsNone(meta.get("Requires-Dist"))
            self.assertEqual(meta["License-Expression"], "MIT")
            self.assertNotIn("Private :: Do Not Upload", meta.get_all("Classifier", []))
            self.assertEqual(archive.read(prefix+"licenses/LICENSE").decode("utf-8").replace("\r\n", "\n"), APPROVED_MIT_LICENSE)
            self.assertEqual(set(meta["Requires-Python"].split(",")), {">=3.11", "<3.15"})
            for name, checksum, size in csv.reader(io.StringIO(archive.read(prefix+"RECORD").decode())):
                if name.endswith("/RECORD"):
                    self.assertEqual((checksum, size), ("", ""))
                else:
                    payload = archive.read(name)
                    actual = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
                    self.assertEqual(checksum, "sha256="+actual)
                    self.assertEqual(int(size), len(payload))

    def test_sdist_safe_members_and_matching_source(self):
        with tarfile.open(ROOT/"dist/agent_loop_audit-0.1.0.tar.gz") as archive:
            seen = set()
            for member in archive.getmembers():
                self.assertNotIn(member.name, seen)
                seen.add(member.name)
                path = PurePosixPath(member.name)
                self.assertEqual(path.parts[0], "agent_loop_audit-0.1.0")
                self.assertFalse(path.is_absolute() or ".." in path.parts or "\\" in member.name)
                self.assertTrue(member.isdir() or member.isfile())
                if not member.isfile():
                    continue
                name = PurePosixPath(*path.parts[1:]).as_posix()
                allowed = name in {"LICENSE", "README.md", "pyproject.toml", "PKG-INFO", "setup.cfg"}
                allowed |= bool(re.fullmatch(r"src/agent_loop_audit/[a-z_]+\.py", name))
                allowed |= bool(re.fullmatch(r"src/agent_loop_audit\.egg-info/(PKG-INFO|SOURCES.txt|dependency_links.txt|entry_points.txt|top_level.txt)", name))
                allowed |= bool(re.fullmatch(r"tests/test_[a-z_0-9]+\.py", name))
                self.assertTrue(allowed, name)
                payload = archive.extractfile(member).read()
                if (ROOT/name).is_file() and not name.startswith("src/agent_loop_audit.egg-info/"):
                    self.assertEqual(payload, (ROOT/name).read_bytes())
                if name.endswith("PKG-INFO"):
                    meta = email.message_from_bytes(payload)
                    self.assertIsNone(meta.get("Requires-Dist"))
                    self.assertEqual(meta["License-Expression"], "MIT")
                    self.assertNotIn("Private :: Do Not Upload", meta.get_all("Classifier", []))

    def test_ci_and_public_release_security_claims(self):
        ci = (ROOT/".github/workflows/ci.yml").read_text()
        self.assertIn("on: [workflow_dispatch]", ci)
        self.assertIn("contents: read", ci)
        self.assertIn("persist-credentials: false", ci)
        self.assertIn("timeout-minutes: 20", ci)
        self.assertIn("cancel-in-progress: true", ci)
        self.assertIn("[ubuntu-latest, windows-latest, macos-latest]", ci)
        self.assertIn("['3.11', '3.12', '3.13', '3.14']", ci)
        pins = re.findall(r"uses: ([^\s]+)", ci)
        self.assertEqual(pins, ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0"])
        for forbidden in ("secrets.", "pull_request_target", "id-token", "contents: write", "upload-artifact", "pypa/", "workflow_run"):
            self.assertNotIn(forbidden, ci)
        provenance = (ROOT/"docs/PROVENANCE.md").read_text()
        for pin in pins:
            self.assertIn(pin.split("@")[1], provenance)
        self.assertEqual((ROOT/"LICENSE").read_text(encoding="utf-8"), APPROVED_MIT_LICENSE)
        project = tomllib.loads((ROOT/"pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertNotIn("Private :: Do Not Upload", project["classifiers"])
        security = (ROOT/"SECURITY.md").read_text(encoding="utf-8")
        readme = (ROOT/"README.md").read_text(encoding="utf-8")
        reporting_url = "https://github.com/ubyuksel/agent-loop-audit/security/advisories/new"
        for document in (security, readme):
            self.assertIn("](" + reporting_url + ")", document)
            reporting_links = re.findall(r"https://github\.com/[^\s)]+/security/advisories/new", document)
            self.assertEqual(reporting_links, [reporting_url])
        for required in (
            "Private vulnerability reporting is enabled",
            "`enabled: true`",
            "Report a vulnerability",
            "No test report was submitted",
            "minimal invented JSONL",
            "Never post vulnerability details, credentials, personal data or real Codex logs\nin public issues",
            "Do not include suspected real secret values even in private\nreports",
            "If the form is unavailable, keep vulnerability details private",
            "No response-time\nSLA is promised",
        ):
            self.assertIn(required, security)
        for required in (
            "Version **0.1.0**",
            "https://github.com/ubyuksel/agent-loop-audit/releases",
            "git clone --branch v0.1.0 --depth 1 https://github.com/ubyuksel/agent-loop-audit.git",
            "There is no PyPI release",
            "SHA256SUMS.txt",
            "python -m pip --isolated install --no-index --no-deps agent_loop_audit-0.1.0-py3-none-any.whl",
            "Release notes link the successful run for\nthe tagged commit",
        ):
            self.assertIn(required, readme)
        for document in (security, readme):
            for obsolete in (
                "unpublished candidate", "unpublished private candidate",
                "repository remains private", "no public package/repository has been published",
                "no public security reporting channel", "pending activation",
                "private security reporting route remains a release gate",
            ):
                self.assertNotIn(obsolete, " ".join(document.lower().split()))


class IndependentInstalledReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ala-q4-")
        cls.base = Path(cls.temp.name)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.cwd = cls.base/"empty"
        cls.cwd.mkdir()
        target = cls.base/"env"
        venv.EnvBuilder(with_pip=True).create(target)
        scripts = target/("Scripts" if os.name == "nt" else "bin")
        cls.python = scripts/("python.exe" if os.name == "nt" else "python")
        cls.console = scripts/("agent-loop-audit.exe" if os.name == "nt" else "agent-loop-audit")
        cls.env = os.environ.copy()
        cls.env.pop("PYTHONPATH", None)
        cls.env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
        install = subprocess.run([str(cls.python), "-B", "-m", "pip", "--isolated", "--disable-pip-version-check", "install", "--no-index", "--no-deps", str(ROOT/"dist/agent_loop_audit-0.1.0-py3-none-any.whl")], cwd=cls.cwd, env=cls.env, capture_output=True, text=True)
        if install.returncode:
            raise AssertionError("independent_offline_install_failed")
        guard = cls.base/"guard"
        guard.mkdir()
        (guard/"sitecustomize.py").write_text('import socket, subprocess\ndef deny(*a, **k): raise AssertionError("q4_offline_guard")\nsocket.socket=deny\nsocket.create_connection=deny\nsubprocess.Popen=deny\n', encoding="utf-8")
        cls.env["PYTHONPATH"] = str(guard)

    def run_cli(self, args, module=False):
        prefix = [str(self.python), "-B", "-m", "agent_loop_audit"] if module else [str(self.console)]
        return subprocess.run(prefix+args, cwd=self.cwd, env=self.env, capture_output=True, text=True)

    def test_installed_entries_exact_example_and_exit_priority(self):
        example = ROOT/"examples/synthetic_retry_loop.jsonl"
        before = example.read_bytes()
        expected = json.loads((ROOT/"examples/synthetic_retry_loop.expected.json").read_text())
        for module in (False, True):
            self.assertEqual(self.run_cli(["--help"], module).returncode, 0)
            result = self.run_cli(["audit", str(example), "--format", "json"], module)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout), expected)
        self.assertEqual(self.run_cli(["audit", str(example), "--fail-on-findings"]).returncode, 1)
        self.assertEqual(self.run_cli(["audit", str(example), "--fail-on-findings", "--strict"]).returncode, 3)
        self.assertEqual(example.read_bytes(), before)

    def test_installed_independent_arithmetic_scope_and_error_privacy(self):
        session = {"type": "session_meta", "payload": {"id": "q4-invented", "source": "cli"}}
        def ledger(identity, total):
            return {"type": "token_usage_record", "payload": {"thread_id": "q4-invented", "response_id": identity, "usage": {"input_tokens": total, "output_tokens": 0, "total_tokens": total}}}
        # Hand oracle: A40 mirror40 + B60 =100; late A45 removes all A ->60.
        for rows, wanted in (([session, ledger("a",40), ledger("a",40), ledger("b",60)],100), ([session, ledger("a",40), ledger("b",60), ledger("a",45)],60)):
            source = self.base/"invented.jsonl"
            source.write_text("".join(json.dumps(r)+"\n" for r in rows), encoding="utf-8")
            before = source.read_bytes()
            result = self.run_cli(["audit", str(source), "--format", "json"])
            self.assertEqual(result.returncode, 0)
            report = json.loads(result.stdout)
            self.assertEqual(report["token_usage"]["observed"]["total_tokens"], wanted)
            self.assertFalse(report["token_usage"]["complete"])
            self.assertEqual(source.read_bytes(), before)
        inherited = self.base/"inherited.jsonl"
        inherited.write_text(json.dumps({"type":"session_meta","payload":{"id":"q4-invented","source":"cli","history_base":"Q4_SECRET_CANARY"}})+"\n", encoding="utf-8")
        result = self.run_cli(["audit", str(inherited), "--format", "json"])
        report = json.loads(result.stdout)
        self.assertEqual(report["coverage"]["behavior"], "unsupported")
        self.assertEqual(report["findings"], [])
        for args in (["audit", str(self.base/"Q4_SECRET_CANARY.jsonl"), "--format", "json"], ["audit", str(inherited), "--format", "Q4_SECRET_CANARY"], ["--Q4_SECRET_CANARY"]):
            result = self.run_cli(args)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Q4_SECRET_CANARY", result.stdout+result.stderr)
            self.assertNotIn("\x1b", result.stdout+result.stderr)
            self.assertNotIn("Traceback", result.stdout+result.stderr)
