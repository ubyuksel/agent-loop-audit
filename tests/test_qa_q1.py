"""Independent Q1 oracles. All data and identifiers are invented here."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agent_loop_audit.models import Barrier, Envelope, Limits
from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import InputError, RolloutReader


def row(kind, **payload):
    return {"type": kind, "payload": payload}


def session(**extra):
    return row("session_meta", id="qa-thread", cwd="/invented", source="cli", **extra)


def request(cid="one", command="echo invented", **extra):
    return row("response_item", type="function_call", name="exec_command",
               call_id=cid, arguments=json.dumps({"cmd": command}), **extra)


def result(cid="one", text="invented", **extra):
    return row("response_item", type="function_call_output", call_id=cid,
               output=text, **extra)


def wire(records):
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


@contextmanager
def fixture(data):
    with tempfile.TemporaryDirectory(prefix="ala-q1-") as folder:
        path = Path(folder) / "fixture.jsonl"
        path.write_bytes(data)
        yield path


class IndependentFoundationQA(unittest.TestCase):
    def audit(self, records=None, data=None, limits=None):
        data = wire(records) if data is None else data
        with fixture(data) as path:
            before = hashlib.sha256(path.read_bytes()).digest()
            with RolloutReader(path, limits) as reader:
                n = Normalizer(limits)
                facts = list(n.facts(reader))
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
        return n, list(n.correlations()), facts, reader

    def test_line_endings_bom_tail_and_physical_lines(self):
        for ending in (b"\n", b"\r\n"):
            data = b"\xef\xbb\xbf" + wire([session()]).rstrip(b"\n") + ending * 2
            data += wire([request()]).rstrip(b"\n")
            n, rows, _, reader = self.audit(data=data)
            self.assertTrue(n.state.behavior_eligible)
            self.assertEqual(rows[0].call_line, 3)
            self.assertEqual(reader.state.blank, 1)

    def test_corruption_is_bounded_barrier_and_recovers(self):
        bad = [b"\xff", b'{"type":"x","payload":{"a":1,"a":2}}',
               b'{"type":"x","payload":{"n":NaN}}', b"null",
               b'{"type":"x","payload":{"n":' + b"["*70 + b"0" + b"]"*70 + b"}}"]
        n, rows, facts, reader = self.audit(data=wire([session()]) + b"\n".join(bad) + b"\n" + wire([request()]))
        self.assertEqual(reader.state.skipped, 5)
        self.assertEqual([f.line for f in facts if f.reason == "malformed_record"], list(range(2, 7)))
        self.assertEqual(rows[0].call_line, 7)
        _, _, _, tail = self.audit(data=wire([session()]) + b'{"secret":"QA_CANARY')
        self.assertIn("incomplete_tail", tail.diagnostics.items)
        self.assertNotIn("QA_CANARY", repr(tail.diagnostics))

    def test_oversize_drain_and_caps(self):
        data = b"x"*(2*1024*1024+1) + b"\n" + wire([session(), request()])
        _, rows, facts, reader = self.audit(data=data)
        self.assertEqual(reader.diagnostics.items["oversize_record"].count, 1)
        self.assertEqual(rows[0].call_line, 3)
        self.assertEqual(facts[0].reason, "oversize_record")
        n, rows, _, _ = self.audit([session(), request("a"), request("b")], limits=Limits(identities=1))
        self.assertEqual(len(rows), 1)
        self.assertTrue(n.state.analysis_truncated)
        self.assertFalse(n.state.behavior_eligible)
        n, _, _, reader = self.audit([session(), request()], limits=Limits(envelopes=1))
        self.assertTrue(reader.state.analysis_truncated)
        with fixture(wire([session()])) as path:
            with self.assertRaisesRegex(InputError, "input_too_large"):
                with RolloutReader(path, Limits(snapshot_bytes=1)):
                    pass

    def test_duplicate_records_are_not_distinct_requests(self):
        n, rows, _, _ = self.audit([session(), request(), result(), result(), request(), request()])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].duplicate_requests, 2)
        self.assertEqual(rows[0].duplicate_outputs, 1)
        _, rows, _, _ = self.audit([session(), *[request(str(i)) for i in range(3)]])
        self.assertEqual(len(rows), 3)

    def test_late_conflicts_revoke_all_complete_joins(self):
        for ending in (request(command="echo changed"), result(text="changed")):
            _, rows, _, _ = self.audit([session(), result(), request(), ending])
            self.assertTrue(rows[0].invalid)
            self.assertFalse(rows[0].complete)
            self.assertEqual(rows[0].status, "unknown")

    def test_result_before_call_and_missing_ids(self):
        n, rows, _, _ = self.audit([session(), result(), request(), request(None), result(None)])
        self.assertTrue(rows[0].complete)
        self.assertEqual(rows[0].output_line, 2)
        self.assertEqual(n.state.uncorrelated_requests, 1)
        self.assertEqual(n.state.orphan_outputs, 1)

    def test_unknown_epoch_ambiguity_and_explicit_turn_mismatch(self):
        records = [session(), request(), row("unknown_future", nested=[request()]), request(), result()]
        _, rows, facts, _ = self.audit(records)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.ambiguous and not r.complete for r in rows))
        self.assertIn("unknown_event", [f.reason for f in facts])
        _, rows, _, _ = self.audit([session(), row("turn_context", turn_id="alpha"), request(), result(turn_id="beta")])
        self.assertIsNone(rows[0].output_line)

    def test_siblings_embedded_history_and_discarded_content(self):
        call = request()
        call["metadata"] = {"payload": request("fake"), "secret": "QA_CANARY"}
        ignored = row("response_item", type="message", role="user", content=[{"type": "image", "data": "QA_CANARY"}])
        n, rows, facts, _ = self.audit([session(), ignored, call,
            row("compacted", history=[request("hidden")], encrypted="QA_CANARY")])
        self.assertEqual(len(rows), 1)
        self.assertNotIn("QA_CANARY", repr(n.__dict__) + repr(facts))
        _, rows, _, _ = self.audit([session(), request(), result(text=[{"type":"image", "data":"QA_CANARY"}])])
        self.assertFalse(rows[0].complete)

    def test_scope_indicators_and_conflicting_metadata(self):
        for fields in ({"parent_id":"invented"}, {"history_base":{"path":"/QA_CANARY"}},
                       {"source":{"subagent":{}}}, {"session_id":"parent"}):
            meta = session()
            meta["payload"].update(fields)
            n, _, _, _ = self.audit([meta, request()])
            self.assertFalse(n.state.behavior_eligible)
            self.assertTrue(n.state.inherited_scope)
        other = session()
        other["payload"]["id"] = "other"
        n, _, _, _ = self.audit([session(), request(), other])
        self.assertTrue(n.state.inconsistent_metadata)
        n, rows, _, _ = self.audit([session(), request(), session(), request()])
        self.assertTrue(n.state.behavior_eligible)
        self.assertEqual(len(rows), 1)

    def test_empty_and_non_codex(self):
        for data in (b"", b"\n", wire([row("future", text="invented")]), b'{}\n'):
            n, _, _, _ = self.audit(data=data)
            self.assertFalse(n.state.format_supported)
            self.assertIn("unsupported_format", n.diagnostics.items)

    def test_descriptor_reads_are_bounded_offline_and_readonly(self):
        with fixture(wire([session(history_base={"path":"/QA_CANARY"}), request(), result()])) as path:
            real_open = os.open
            calls = []
            def guarded(name, flags, *args, **kwargs):
                self.assertEqual(Path(name), path)
                self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC), 0)
                calls.append(name)
                return real_open(name, flags, *args, **kwargs)
            with patch("agent_loop_audit.parser.os.open", side_effect=guarded), \
                 patch.object(socket, "socket", side_effect=AssertionError("network")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
                with RolloutReader(path) as reader:
                    inner = reader._file
                    class Bounded:
                        def read(self, count):
                            self_outer.assertGreater(count, 0)
                            self_outer.assertLessEqual(count, 65536)
                            return inner.read(count)
                        def fileno(self): return inner.fileno()
                        def close(self): return inner.close()
                    self_outer = self
                    reader._file = Bounded()
                    n = Normalizer()
                    for _ in n.facts(reader): pass
            self.assertEqual(len(calls), 1)

    def test_append_and_shrink_are_partial_and_snapshot_bounded(self):
        for append in (True, False):
            data = wire([session(), request()])
            with fixture(data) as path:
                with RolloutReader(path) as reader:
                    if append:
                        with path.open("ab") as handle: handle.write(wire([request("late")]))
                    else:
                        path.write_bytes(b"")
                    n = Normalizer()
                    for _ in n.facts(reader): pass
                self.assertTrue(reader.state.input_changed)
                self.assertFalse(n.state.behavior_eligible)
                self.assertLessEqual(reader.state.bytes_read, len(data))

    def test_symlink_capability(self):
        with fixture(wire([session()])) as path:
            link = path.with_name("link.jsonl")
            try: link.symlink_to(path)
            except OSError as exc: self.skipTest("symlink creation unavailable: errno=" + str(exc.errno))
            with self.assertRaisesRegex(InputError, "nonregular_input"):
                with RolloutReader(link): pass

    def test_readonly_input_and_nonregular_directory(self):
        with fixture(wire([session(), request()])) as path:
            original_mode = path.stat().st_mode
            before = hashlib.sha256(path.read_bytes()).digest()
            try:
                path.chmod(0o444)
                with RolloutReader(path) as reader:
                    list(reader)
                self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
            finally:
                path.chmod(original_mode)
            directory = path.with_name("directory.jsonl")
            directory.mkdir()
            with self.assertRaisesRegex(InputError, "nonregular_input"):
                with RolloutReader(directory): pass

    def test_descriptor_replacement_capability(self):
        with fixture(wire([session()])) as path:
            replacement = path.with_name("replacement.jsonl")
            replacement.write_bytes(wire([session()]))
            with RolloutReader(path) as reader:
                try: os.replace(replacement, path)
                except PermissionError: self.skipTest("OS denies replacement of open descriptor")
                list(reader)
            self.assertTrue(reader.state.input_changed)
