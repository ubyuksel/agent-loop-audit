import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from agent_loop_audit.cli import main
from .support import encode,input_file,meta
from .test_rules import repeats


class CLITests(unittest.TestCase):
    def test_interrupt_and_broken_pipe_are_handled(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out), patch("agent_loop_audit.cli.audit",side_effect=KeyboardInterrupt):
            self.assertEqual(main(["audit","synthetic.jsonl","--format","json"]),130)
        self.assertEqual(json.loads(out.getvalue())["diagnostics"][0]["code"],"interrupted")
        class Broken:
            def write(self,text):
                raise BrokenPipeError
        with patch("sys.stdout",Broken()),patch("agent_loop_audit.cli.audit",return_value=({},0)), \
             patch("agent_loop_audit.cli.render_text",return_value="fixed"):
            self.assertEqual(main(["audit","synthetic.jsonl"]),0)
    def run_cli(self,*args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1]/"src")
        env["PYTHONNOUSERSITE"] = "1"
        with tempfile.TemporaryDirectory() as cwd:
            return subprocess.run([sys.executable,"-B","-m","agent_loop_audit",*args],cwd=cwd,env=env,capture_output=True,text=True,encoding="utf-8")

    def test_help_version_and_sanitized_usage(self):
        self.assertEqual(self.run_cli("--help").returncode,0)
        self.assertEqual(self.run_cli("--version").returncode,0)
        for args in (("CANARY",),("audit","CANARY","--format","CANARY"),("audit","CANARY","--CANARY")):
            result=self.run_cli(*args)
            self.assertEqual(result.returncode,2)
            self.assertNotIn("CANARY",result.stdout+result.stderr)

    def test_exit_precedence_and_unchanged_input(self):
        with input_file(encode(repeats())) as path:
            before=hashlib.sha256(path.read_bytes()).digest()
            for flags,code in [((),0),(("--fail-on-findings",),1),(("--strict",),3),(("--strict","--fail-on-findings"),3)]:
                result=self.run_cli("audit",str(path),"--format","json",*flags)
                self.assertEqual(result.returncode,code,result.stderr)
                self.assertEqual(json.loads(result.stdout)["findings"][0]["rule_id"],"ALA002")
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),before)

    def test_missing_empty_malformed_and_inherited(self):
        result=self.run_cli("audit","CANARY.jsonl","--format","json")
        self.assertEqual(result.returncode,2)
        self.assertNotIn("CANARY",result.stdout+result.stderr)
        json.loads(result.stdout)
        for data,expected in [(b"",2),(b"bad json\n",2),(encode([meta()]),0),(encode([meta(history_base="CANARY")]),0)]:
            with input_file(data) as path:
                result=self.run_cli("audit",str(path),"--format","json")
                self.assertEqual(result.returncode,expected,result.stderr)
                self.assertNotEqual(json.loads(result.stdout)["coverage"]["behavior"],"supported")
