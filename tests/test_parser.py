import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_loop_audit.models import Barrier, Diagnostics, Envelope, Limits
from agent_loop_audit.parser import InputError, RolloutReader
from .support import encode, event, input_file, meta


class ParserTests(unittest.TestCase):
    def read(self, data, limits=None):
        with input_file(data) as path:
            before = hashlib.sha256(path.read_bytes()).digest()
            with RolloutReader(path, limits) as reader:
                items = list(reader)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
            self.assertTrue(reader.state.finished)
            return reader, items

    def test_bom_crlf_blank_and_valid_tail(self):
        data = b"\xef\xbb\xbf" + encode([meta()]).replace(b"\n", b"\r\n") + b"\r\n" + encode([event("turn_context", {})]).rstrip()
        reader, items = self.read(data)
        self.assertEqual([i.line for i in items], [1, 3])
        self.assertEqual(reader.state.blank, 1)
        self.assertFalse(reader.state.input_changed)

    def test_corrupt_records_are_barriers_and_do_not_echo(self):
        invalid = [b"\xff", b'{"type":"a","type":"b","payload":{}}', b'{"type":"a","payload":{"n":NaN}}',
                   b'{"type":"a","payload":{"n":1e999}}', b"[]", b'{"type":"a","payload":null}',
                   b'{"type":"event_msg","payload":{"type":[]}}',
                   b'{"type":"a","payload":{"s":"\\ud800"}}',
                   b'{"type":"a","payload":{},"ordinal":true}',
                   b'{"type":"a","payload":{},"ordinal":-1}']
        reader, items = self.read(b"\n".join(invalid) + b"\n" + encode([meta()]))
        self.assertEqual(reader.state.skipped, len(invalid))
        self.assertTrue(all(isinstance(i, Barrier) for i in items[:-1]))
        self.assertIsInstance(items[-1], Envelope)

    def test_incomplete_tail(self):
        reader, items = self.read(encode([meta()]) + b'{"secret":"CANARY')
        self.assertEqual(items[-1].reason, "incomplete_tail")
        self.assertNotIn("CANARY", repr(reader.diagnostics))

    def test_depth_and_large_integer(self):
        bad = b'{"type":"x","payload":{"n":' + b"["*80 + b"0" + b"]"*80 + b"}}\n"
        bad += b'{"type":"x","payload":{"n":' + b"1"*200 + b"}}\n"
        reader, _ = self.read(bad + encode([meta()]))
        self.assertEqual(reader.state.skipped, 2)

    def test_oversize_line_drains_once_and_recovers(self):
        reader, items = self.read(b"X" * (2*1024*1024+300) + b"\n" + encode([meta()]))
        self.assertEqual([i.line for i in items], [1, 2])
        self.assertEqual(reader.diagnostics.items["oversize_record"].count, 1)
        self.assertIsInstance(items[1], Envelope)

    def test_snapshot_and_record_caps(self):
        with input_file(encode([meta()])) as path:
            with self.assertRaisesRegex(InputError, "input_too_large"):
                with RolloutReader(path, Limits(snapshot_bytes=2)):
                    pass
        reader, items = self.read(encode([meta(), meta(), meta()]), Limits(envelopes=2))
        self.assertTrue(reader.state.analysis_truncated)
        self.assertEqual(reader.state.parsed, 2)
        self.assertEqual(items[-1].reason, "analysis_truncated")

    def test_reject_nonregular_extension_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "directory.jsonl"
            directory.mkdir()
            with self.assertRaisesRegex(InputError, "nonregular_input"):
                with RolloutReader(directory):
                    pass
            target = Path(folder) / "target.jsonl"
            target.write_bytes(encode([meta()]))
            link = Path(folder) / "link.jsonl"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("OS does not permit test symlink: " + str(exc.errno))
            with self.assertRaisesRegex(InputError, "nonregular_input"):
                with RolloutReader(link):
                    pass

    def test_reject_compressed_stdin_url_missing(self):
        for path in ("-", "https://example.invalid/input.jsonl", "unknown.jsonl.zst", "missing.jsonl"):
            with self.subTest(path=path), self.assertRaises(InputError):
                with RolloutReader(path):
                    pass

    def test_growing_snapshot_is_bounded_and_flagged(self):
        data = encode([meta()])
        with input_file(data) as path:
            with RolloutReader(path) as reader:
                with path.open("ab") as writer:
                    writer.write(encode([meta()]))
                items = list(reader)
            self.assertEqual(len(items), 1)
            self.assertEqual(reader.state.bytes_read, len(data))
            self.assertTrue(reader.state.input_changed)

    def test_shrinking_input_is_flagged(self):
        with input_file(encode([meta(), meta()])) as path:
            with RolloutReader(path) as reader:
                path.write_bytes(b"")
                self.assertEqual(list(reader), [])
            self.assertTrue(reader.state.input_changed)

    def test_replacement_detected(self):
        with input_file(encode([meta()])) as path:
            with RolloutReader(path) as reader:
                replacement = path.with_name("replacement.jsonl")
                replacement.write_bytes(encode([meta(id="other")]))
                try:
                    os.replace(replacement, path)
                except PermissionError:
                    self.skipTest("OS does not permit replacing this open descriptor")
                list(reader)
            self.assertTrue(reader.state.input_changed)

    def test_single_readonly_open_and_no_referenced_path(self):
        data = encode([meta(history_base={"path": "CANARY/never-open.jsonl"})])
        with input_file(data) as path:
            real_open = os.open
            calls = []
            def checked_open(name, flags, *args, **kwargs):
                calls.append((Path(name), flags))
                self.assertEqual(Path(name), path)
                self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_CREAT), 0)
                return real_open(name, flags, *args, **kwargs)
            with patch("agent_loop_audit.parser.os.open", side_effect=checked_open):
                with RolloutReader(path) as reader:
                    list(reader)
            self.assertEqual(len(calls), 1)

    def test_lifecycle_and_empty(self):
        reader, items = self.read(b"")
        self.assertEqual(items, [])
        with self.assertRaises(InputError):
            list(reader)
        with input_file(encode([meta()])) as path:
            with RolloutReader(path) as reader:
                next(iter(reader))
                with self.assertRaises(InputError):
                    list(reader)

    def test_timestamp_ordinal_and_diagnostic_ceiling(self):
        value = event("session_meta", {"id": "s"}, ordinal=3)
        value["timestamp"] = "CANARY"
        reader, items = self.read(encode([value]))
        self.assertEqual(items[0].ordinal, 3)
        self.assertIn("timestamp_unavailable", reader.diagnostics.items)
        diagnostics = Diagnostics(1)
        diagnostics.add("a", 1)
        diagnostics.add("a", 2)
        diagnostics.add("b", 3)
        self.assertEqual(diagnostics.items["a"].count, 2)
        self.assertEqual(diagnostics.omitted, 1)


if __name__ == "__main__":
    unittest.main()
