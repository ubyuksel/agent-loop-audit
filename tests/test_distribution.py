"""Local build/install harness. Network/subprocess bans apply inside audit, not pip."""

import email
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import unittest
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wheel = ROOT / "dist/agent_loop_audit-0.1.0-py3-none-any.whl"
        cls.sdist = ROOT / "dist/agent_loop_audit-0.1.0.tar.gz"
        if not cls.wheel.exists() or not cls.sdist.exists():
            result = subprocess.run([sys.executable,"-B","-m","build","--no-isolation"],cwd=ROOT,capture_output=True,text=True)
            if result.returncode:
                raise AssertionError("local_build_failed: " + result.stderr[-2000:])

    def test_archives_match_current_payload_and_have_no_runtime_dependencies(self):
        with zipfile.ZipFile(self.wheel) as archive:
            names = archive.namelist()
            self.assertTrue(names)
            for name in names:
                path = PurePosixPath(name)
                self.assertFalse(path.is_absolute() or ".." in path.parts)
                self.assertTrue(name.startswith(("agent_loop_audit/","agent_loop_audit-0.1.0.dist-info/")),name)
                self.assertNotIn("__pycache__",name)
                if name.startswith("agent_loop_audit/"):
                    self.assertTrue(name.endswith(".py"))
                    self.assertEqual(archive.read(name),(ROOT/"src"/name).read_bytes(),"stale wheel; rebuild required")
            metadata=email.message_from_bytes(archive.read("agent_loop_audit-0.1.0.dist-info/METADATA"))
            self.assertIsNone(metadata.get("Requires-Dist"))
            self.assertEqual(metadata["Version"],"0.1.0")
            self.assertEqual(metadata["License-Expression"],"LicenseRef-Private-Candidate-Pending")
        with tarfile.open(self.sdist,"r:gz") as archive:
            for member in archive.getmembers():
                path=PurePosixPath(member.name)
                self.assertFalse(path.is_absolute() or ".." in path.parts or member.issym() or member.islnk())
                relative=PurePosixPath(*path.parts[1:]).as_posix()
                self.assertFalse(any(x in path.parts for x in (".planning","evidence",".venv","reports","raw-logs","__pycache__")))
                if member.isfile():
                    self.assertTrue(relative in {"LICENSE","README.md","pyproject.toml","PKG-INFO","setup.cfg"}
                                    or relative.startswith(("src/agent_loop_audit/","src/agent_loop_audit.egg-info/","tests/test")),relative)
                    local=ROOT/relative
                    if local.is_file() and not relative.startswith("src/agent_loop_audit.egg-info/"):
                        self.assertEqual(archive.extractfile(member).read(),local.read_bytes(),"stale sdist; rebuild required")

    def test_clean_temp_install_offline_console_module_and_example(self):
        with tempfile.TemporaryDirectory(prefix="ala-installed-") as folder:
            base=Path(folder); target=base/"venv"; cwd=base/"empty"; cwd.mkdir()
            venv.EnvBuilder(with_pip=True).create(target)
            scripts=target/("Scripts" if os.name=="nt" else "bin")
            python=scripts/("python.exe" if os.name=="nt" else "python")
            console=scripts/("agent-loop-audit.exe" if os.name=="nt" else "agent-loop-audit")
            env=os.environ.copy(); env.pop("PYTHONPATH",None)
            env["PYTHONNOUSERSITE"]="1"; env["PYTHONDONTWRITEBYTECODE"]="1"
            install=subprocess.run([str(python),"-B","-m","pip","--isolated","--disable-pip-version-check","install","--no-index","--no-deps",str(self.wheel)],cwd=cwd,env=env,capture_output=True,text=True)
            self.assertEqual(install.returncode,0,install.stderr)
            guard=base/"guard"; guard.mkdir()
            (guard/"sitecustomize.py").write_text(
                'import socket, subprocess\ndef blocked(*a, **k): raise RuntimeError("offline_guard")\nsocket.socket=blocked\nsocket.create_connection=blocked\nsubprocess.Popen=blocked\n',encoding="utf-8")
            env["PYTHONPATH"]=str(guard)
            expected=json.loads((ROOT/"examples/synthetic_retry_loop.expected.json").read_text(encoding="utf-8"))
            for command in ([str(console),"--help"],[str(python),"-B","-m","agent_loop_audit","--help"],
                            [str(console),"--version"]):
                result=subprocess.run(command,cwd=cwd,env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
            source=ROOT/"examples/synthetic_retry_loop.jsonl"
            before=hashlib.sha256(source.read_bytes()).digest()
            for prefix in ([str(console)],[str(python),"-B","-m","agent_loop_audit"]):
                result=subprocess.run(prefix+["audit",str(source),"--format","json"],cwd=cwd,env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout),expected)
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(),before)
