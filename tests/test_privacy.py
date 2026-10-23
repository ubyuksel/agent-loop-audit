import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
from agent_loop_audit.cli import main
from .support import call, meta, output, encode, input_file


class PrivacyTests(unittest.TestCase):
    def test_canaries_and_audit_offline(self):
        canary = "CANARY_opaque_\x1b]52;c;injection\x07"
        data = [meta(id=canary, cwd=canary, cli_version=canary),call(canary, json.dumps({"cmd":canary}),name=canary),output(canary,canary)]
        for format_name in ("text","json"):
            with input_file(encode(data)) as path:
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                     patch.object(socket,"socket",side_effect=AssertionError("network")), \
                     patch.object(subprocess,"Popen",side_effect=AssertionError("process")):
                    self.assertEqual(main(["audit",str(path),"--format",format_name]),0)
                rendered = out.getvalue()+err.getvalue()
                for secret in ("CANARY",str(path),"\x1b","\x07"):
                    self.assertNotIn(secret, rendered)
                if format_name == "json":
                    json.loads(out.getvalue())
