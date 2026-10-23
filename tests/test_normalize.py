import builtins
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
import tracemalloc
import unittest
from unittest.mock import patch

from agent_loop_audit.models import Limits
from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import RolloutReader
from .support import call, encode, event, input_file, meta, normalize, output


class NormalizerTests(unittest.TestCase):
    def test_duplicate_identity_versus_distinct_requests(self):
        n, facts, correlations = normalize([meta(), call(), call(), call("c2"), call("c3")])
        self.assertEqual(len(correlations), 3)
        self.assertEqual(correlations[0].duplicate_requests, 1)
        self.assertEqual(sum(f.kind == "request" for f in facts), 3)
        self.assertTrue(n.state.behavior_eligible)

    def test_output_before_call_mirrors_and_late_conflict(self):
        n, facts, rows = normalize([meta(), output(), call(), output(), call(arguments='{"cmd":"changed"}')])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].output_line, 2)
        self.assertEqual(rows[0].duplicate_outputs, 1)
        self.assertTrue(rows[0].invalid)
        self.assertFalse(rows[0].complete)
        self.assertIn("invalidate", [f.kind for f in facts])

    def test_conflicting_outputs_invalidate_equality(self):
        _, _, rows = normalize([meta(), call(), output(), output(value="changed")])
        self.assertTrue(rows[0].invalid)
        self.assertFalse(rows[0].complete)

    def test_missing_ids_are_never_joined(self):
        n, facts, rows = normalize([meta(), call(None), output(None)])
        self.assertEqual(rows, [])
        self.assertEqual(n.state.uncorrelated_requests, 1)
        self.assertEqual(n.state.orphan_outputs, 1)

    def test_custom_and_structured_text_output(self):
        custom = event("response_item", {"type": "custom_tool_call", "name": "apply_patch", "call_id": "p", "input": "invented patch"})
        result = event("response_item", {"type": "custom_tool_call_output", "call_id": "p", "output": [{"type": "text", "text": "synthetic"}]})
        _, facts, rows = normalize([meta(), custom, result])
        self.assertEqual(next(f for f in facts if f.kind == "request").arguments, "invented patch")
        self.assertTrue(rows[0].complete)
        self.assertEqual(rows[0].status, "unknown")

    def test_image_missing_truncated_and_pending_outputs(self):
        values = [None, [{"type": "image", "data": "invented"}],
                  "Warning: truncated output\nsynthetic", "Process running with session ID 123"]
        for value in values:
            with self.subTest(value=value):
                _, _, rows = normalize([meta(), call(), output(value=value)])
                self.assertFalse(rows[0].complete)
        _, _, rows = normalize([meta(), call(), output(value="arbitrary error failed exit 1")])
        self.assertEqual(rows[0].status, "unknown")

    def test_structured_terminal_status_and_neutral_search(self):
        for cmd, code, expected in [("python -m unittest", 1, "failure"), ("rg needle file", 1, "no_match"),
                                    ("opaque script", 1, "unknown"), ("opaque script", 0, "success")]:
            terminal = event("event_msg", {"type": "exec_command_end", "call_id": "c1", "exit_code": code, "status": "completed", "aggregated_output": "synthetic"})
            _, _, rows = normalize([meta(), call(arguments=json.dumps({"cmd": cmd})), output(), terminal])
            self.assertEqual(rows[0].status, expected)

    def test_text_structured_disagreement_and_declined(self):
        terminal = event("event_msg", {"type": "exec_command_end", "call_id": "c1", "exit_code": 1})
        wrapper = "Wall time: 0.1 seconds\nExit code: 0\nOutput:\ninvented"
        _, _, rows = normalize([meta(), call(), output(value=wrapper), terminal])
        self.assertTrue(rows[0].invalid)
        self.assertEqual(rows[0].status, "unknown")
        terminal["payload"]["status"] = "declined"
        _, _, rows = normalize([meta(), call(), output(), terminal])
        self.assertEqual(rows[0].status, "denied")

    def test_wrapper_grammar_is_anchored_and_only_for_known_shell_tools(self):
        legacy = "Wall time: 0.1 seconds\nExit code: 0\nOutput:\ninvented"
        current = "Chunk ID: synthetic\nWall time: 0.1 seconds\nProcess exited with code 0\nFinal output:\ninvented"
        for text in (legacy, current):
            _, _, rows = normalize([meta(), output(value=text), call(arguments='{"cmd":"cat example.txt"}')])
            self.assertEqual(rows[0].status, "success")
            self.assertTrue(rows[0].complete)
            _, _, rows = normalize([meta(), call(namespace="unknown"), output(value=text)])
            self.assertEqual(rows[0].status, "unknown")
            _, _, rows = normalize([meta(), call(), output(value="prefix\n" + text)])
            self.assertEqual(rows[0].status, "unknown")
        _, _, rows = normalize([meta(), call(), output(value={"body": "arbitrary data", "success": True})])
        self.assertEqual(rows[0].status, "unknown")
        self.assertFalse(rows[0].complete)

    def test_late_incomplete_mirror_never_upgrades_result(self):
        for copies in ([output(truncated=True), output()], [output(), output(truncated=True)]):
            _, _, rows = normalize([meta(), call(), *copies])
            self.assertFalse(rows[0].complete)
        _, _, rows = normalize([meta(), call(), output(), call(arguments=None)])
        self.assertTrue(rows[0].invalid)

    def test_explicit_and_unknown_turn_result_merge_is_order_independent(self):
        turn = event("turn_context", {"turn_id": "turn-a", "cwd": "/synthetic"})
        terminal = event("event_msg", {"type": "exec_command_end", "call_id": "c1", "turn_id": "turn-a", "exit_code": 0})
        for results in ([terminal, output()], [output(), terminal]):
            _, _, rows = normalize([meta(), turn, call(), *results])
            self.assertTrue(rows[0].complete)
            self.assertEqual(rows[0].status, "success")

    def test_output_text_cap_and_result_identity_cap(self):
        n, _, _ = normalize([meta(), call(), output(value="X"*400)], Limits(retained_text_bytes=200))
        self.assertTrue(n.state.analysis_truncated)
        self.assertFalse(n.state.behavior_eligible)
        n, _, _ = normalize([meta(), output("a"), output("b"), output("c")], Limits(identities=2))
        self.assertTrue(n.state.analysis_truncated)
        self.assertEqual(len(n._results), 2)

    def test_unknown_payload_types_are_safe_barriers(self):
        for value in (None, [], {}, 1, True):
            with input_file(encode([meta(), event("event_msg", {"type": value})])) as path:
                with RolloutReader(path) as reader:
                    n = Normalizer()
                    facts = list(n.facts(reader))
                self.assertIn("malformed_record", [f.reason for f in facts])
        n, facts, _ = normalize([meta(), event("response_item", {"type": "message", "role": []})])
        self.assertEqual(n.state.unknown_events, 1)
        self.assertIn("unknown_event", [f.reason for f in facts])

    def test_patch_and_mcp_outcomes_are_not_requests(self):
        for subtype, fields, expected in [("patch_apply_end", {"success": True, "status": "completed"}, "success"),
                ("mcp_tool_call_end", {"result": {"Ok": {"isError": True, "content": []}}}, "failure"),
                ("mcp_tool_call_end", {"result": {"Err": "invented failure"}}, "failure")]:
            _, facts, rows = normalize([meta(), call(), event("event_msg", {"type": subtype, "call_id": "c1", **fields})])
            self.assertEqual(len(rows), 1)
            self.assertEqual(sum(f.kind == "request" for f in facts), 1)
            self.assertEqual(rows[0].status, expected)

    def test_explicit_turn_mismatch_and_ambiguous_unknown_output(self):
        turn = lambda name: event("turn_context", {"turn_id": name, "cwd": "/synthetic"})
        n, _, rows = normalize([meta(), turn("a"), call(), output(turn_id="b")])
        self.assertIsNone(rows[0].output_line)
        self.assertEqual(n.state.orphan_outputs, 1)
        _, _, rows = normalize([meta(), turn("a"), call(), turn("b"), call(), output()])
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.ambiguous and not row.complete for row in rows))

    def test_scope_suppression_and_metadata_conflicts(self):
        indicators = [{"history_base": {"path": "CANARY/never-read"}}, {"forked_from_id": "parent"},
                      {"source": {"subagent": {"parent_thread_id": "parent"}}}, {"session_id": "root-other"}]
        for fields in indicators:
            n, _, _ = normalize([meta(**fields), call(), output()])
            self.assertFalse(n.state.behavior_eligible)
            self.assertTrue(n.state.inherited_scope)
        n, _, _ = normalize([meta(), call(), meta(id="different")])
        self.assertTrue(n.state.inconsistent_metadata)
        n, _, _ = normalize([meta(), call(), meta(history_base="later")])
        self.assertFalse(n.state.behavior_eligible)
        n, _, _ = normalize([meta(), meta(), call()])
        self.assertTrue(n.state.behavior_eligible)

    def test_metadata_mirror_preserves_identity_and_user_message_starts_epoch(self):
        _, _, rows = normalize([meta(), call(), meta(), call()])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].duplicate_requests, 1)
        turn = event("turn_context", {"turn_id": "known", "cwd": "/synthetic"})
        user = event("response_item", {"type": "message", "role": "user", "content": []})
        _, _, rows = normalize([meta(), turn, call(), user, call()])
        self.assertEqual(len(rows), 2)

    def test_unknown_and_user_content_are_barriers_only(self):
        unknown = event("response_item", {"type": "new_future_type", "secret": "CANARY"})
        message = event("response_item", {"type": "message", "role": "user", "content": "CANARY"})
        n, facts, _ = normalize([meta(), unknown, message, call()])
        self.assertEqual(n.state.unknown_events, 1)
        self.assertNotIn("CANARY", repr(facts) + repr(n.__dict__))
        self.assertIn("unknown_event", [f.reason for f in facts])

    def test_exact_arguments_context_and_sibling_metadata(self):
        first = call(arguments='{"cmd":"cat a", "workdir":"/a"}')
        second = call(arguments='{"workdir":"/a","cmd":"cat a"}')
        second["metadata"] = {"call_id": "not-another-call", "secret": "CANARY"}
        _, _, rows = normalize([meta(), first, second])
        self.assertFalse(rows[0].invalid)
        self.assertEqual(rows[0].duplicate_requests, 1)
        _, _, rows = normalize([meta(), first, call(arguments='{"cmd":"cat b", "workdir":"/a"}')])
        self.assertTrue(rows[0].invalid)
        _, _, rows = normalize([meta(), call(), event("turn_context", {"cwd": "/other"}), call()])
        self.assertNotEqual(rows[0].request_digest, rows[1].request_digest)

    def test_opaque_missing_nullable_inputs_and_text_budget(self):
        for extra in ({"arguments": None}, {"name": None}, {"namespace": []}):
            n, facts, rows = normalize([meta(), call(**extra)])
            self.assertEqual(rows, [])
            self.assertIn("opaque_request", [f.reason for f in facts])
        n, _, rows = normalize([meta(), call()], Limits(retained_text_bytes=4))
        self.assertEqual(rows, [])
        self.assertIn("retained_text_limit", n.diagnostics.items)

    def test_identity_cap_stops_without_eviction(self):
        n, _, rows = normalize([meta(), call("a"), call("b"), call("c")], Limits(identities=2))
        self.assertEqual(len(rows), 2)
        self.assertTrue(n.state.analysis_truncated)
        self.assertFalse(n.state.behavior_eligible)

    def test_usage_forwarding_is_top_level_and_numeric_only(self):
        usage = event("token_usage_record", {"thread_id": "synthetic-thread", "response_id": "r", "usage": {"input_tokens": 5, "output_tokens": True, "total_tokens": "CANARY"}, "model": "CANARY"})
        compacted = event("compacted", {"latest_token_usage_record": usage["payload"], "text": "CANARY"})
        n, facts, _ = normalize([meta(), usage, compacted, event("event_msg", {"type": "token_count", "info": None})])
        usages = [f for f in facts if f.kind == "usage"]
        self.assertEqual(len(usages), 2)
        self.assertIsNone(usages[0].usage["usage"]["output_tokens"])
        self.assertNotIn("CANARY", repr(usages[0].usage))

    def test_empty_non_codex_and_missing_metadata(self):
        for records in ([], [event("arbitrary", {})], [call()]):
            n, _, _ = normalize(records)
            self.assertFalse(n.state.format_supported)
            self.assertIn("unsupported_format", n.diagnostics.items)
        n, _, _ = normalize([meta()])
        self.assertTrue(n.state.format_supported)

    def test_streaming_memory_is_bounded_and_retains_no_commands(self):
        with input_file(b"") as path:
            with path.open("wb") as writer:
                writer.write(encode([meta()]))
                for i in range(50_000):
                    writer.write(encode([call(str(i), arguments='{"cmd":"CANARY command"}')]))
                    if i != 49_999:
                        writer.write(encode([output(str(i), "CANARY result")]))
            before = hashlib.sha256(path.read_bytes()).digest()
            tracemalloc.start()
            started = time.perf_counter()
            with RolloutReader(path) as reader:
                n = Normalizer()
                for _ in n.facts(reader):
                    pass
            _, peak = tracemalloc.get_traced_memory()
            elapsed = time.perf_counter() - started
            tracemalloc.stop()
            self.assertLessEqual(peak, 128 * 1024 * 1024)
            self.assertEqual(reader.state.parsed, 100_000)
            self.assertEqual(len(list(n.correlations())), 50_000)
            self.assertFalse(n.state.analysis_truncated)
            self.assertEqual(n.state.retained_raw_text_bytes, 0)
            self.assertNotIn("CANARY", repr(n._requests) + repr(n._results))
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
            print("synthetic_100000_peak_bytes=" + str(peak))
            print("synthetic_100000_seconds=" + format(elapsed, ".3f"))

    def test_runtime_has_no_network_subprocess_or_extra_opens(self):
        with input_file(encode([meta(history_base={"path": "CANARY"}), call(), output()])) as path:
            with RolloutReader(path) as reader:
                with patch.object(builtins, "open", side_effect=AssertionError("extra open")), \
                     patch.object(Path, "open", side_effect=AssertionError("extra path open")), \
                     patch.object(socket, "socket", side_effect=AssertionError("network")), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")):
                    n = Normalizer()
                    for _ in n.facts(reader):
                        pass
            self.assertTrue(n.state.inherited_scope)

    def test_fixtures(self):
        fixture_dir = Path(__file__).parent / "fixtures"
        for name, calls, inherited in [("legacy_root.jsonl", 2, False), ("current_root.jsonl", 2, False), ("inherited_scope.jsonl", 1, True)]:
            path = fixture_dir / name
            before = hashlib.sha256(path.read_bytes()).digest()
            with RolloutReader(path) as reader:
                n = Normalizer()
                for _ in n.facts(reader):
                    pass
            self.assertEqual(len(list(n.correlations())), calls)
            self.assertEqual(n.state.inherited_scope, inherited)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)


if __name__ == "__main__":
    unittest.main()
