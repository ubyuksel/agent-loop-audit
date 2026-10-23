import unittest
from agent_loop_audit.fingerprint import fingerprint, read_like


class FingerprintTests(unittest.TestCase):
    def test_canonical_without_semantic_loss(self):
        tool = ("functions", "exec_command")
        self.assertEqual(fingerprint(tool, '{"b":2,"a":1}', "a"), fingerprint(tool, '{"a":1,"b":2}', "a"))
        variants = ['{"cmd":"cat a"}', '{"cmd":"cat b"}', '{"cmd":"cat \'a\'"}',
                    '{"cmd":"cat a","login":false}', '{"cmd":"cat a","env":{"X":"secret-a"}}',
                    '{"cmd":"cat a","env":{"X":"secret-b"}}']
        self.assertEqual(len({fingerprint(tool, v, "a") for v in variants}), len(variants))
        self.assertNotEqual(fingerprint(tool, '{}', None), fingerprint(tool, '{}', "cwd"))
        self.assertNotEqual(fingerprint(tool, '[1,2]', "a"), fingerprint(tool, '[2,1]', "a"))

    def test_conservative_reads(self):
        import json
        tool = (None, "exec_command")
        for shell, cmd, expected in [("bash", "cat -- 'one file'", True), ("pwsh", "Get-Content -LiteralPath 'a''b' -Raw", True),
                ("bash", "cat a | cat", False), ("bash", "cat $X", False), ("bash", "cat *.txt", False),
                ("bash", "cat a b", False), ("bash", "cat ~/a", False), ("unknown", "cat a", False)]:
            self.assertEqual(read_like(tool, json.dumps({"cmd": cmd, "shell": shell})), expected)
