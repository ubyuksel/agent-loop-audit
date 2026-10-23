import json
import unittest
from agent_loop_audit.cli import audit
from agent_loop_audit.report import make_report
from .support import encode,input_file
from .test_rules import repeats


class ReportTests(unittest.TestCase):
    def test_schema_determinism_and_evidence(self):
        with input_file(encode(repeats())) as path:
            first,status = audit(path)
            second,_ = audit(path)
        self.assertEqual(status,0)
        self.assertEqual(first,second)
        self.assertEqual(set(first), {"schema_version","tool_version","rules_version","source","coverage","summary","token_usage","findings","diagnostics"})
        self.assertEqual(first["findings"][0]["call_lines"],[2,4,6])
        self.assertFalse(first["coverage"]["complete"])
        self.assertEqual(make_report(error="CANARY")["diagnostics"][0]["code"],"audit_error")

    def test_large_evidence_is_bounded(self):
        with input_file(encode(repeats(80))) as path:
            report,_ = audit(path)
        self.assertEqual(len(report["findings"][0]["call_lines"]),20)
        self.assertEqual(report["findings"][0]["occurrences"],80)
