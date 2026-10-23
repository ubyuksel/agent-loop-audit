"""Independent Q2 native-envelope oracles. Invented data and hand arithmetic only."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agent_loop_audit.fingerprint import fingerprint, read_like
from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import RolloutReader
from agent_loop_audit.rules import RuleEngine
from agent_loop_audit.tokens import TokenAccountant


def envelope(kind, **payload):
    return {"type": kind, "payload": payload}


def session(**extra):
    return envelope("session_meta", id="qa-thread", cwd="/qa", source="cli", **extra)


def request(identity, args=None, name="exec_command", **extra):
    return envelope("response_item", type="function_call", call_id=identity,
                    name=name, arguments=json.dumps(args or {"cmd": "python -m unittest"}), **extra)


def result(identity, text="qa output", code=2, structured=True, truncated=False):
    records = [envelope("response_item", type="function_call_output", call_id=identity,
                        output=text, truncated=truncated)]
    if structured:
        records.append(envelope("event_msg", type="exec_command_end", call_id=identity,
                                exit_code=code, aggregated_output=text))
    return records


def run_calls(count, args=None, code=2, text="qa output", name="exec_command"):
    records = [session()]
    for index in range(count):
        records += [request("q" + str(index), args, name)]
        records += result("q" + str(index), text, code)
    return records


def vector(total):
    return {"input_tokens": total, "output_tokens": 0, "total_tokens": total}


def legacy(total=None, **extra):
    info = {"total_token_usage": vector(total)} if total is not None else {}
    info.update(extra)
    return envelope("event_msg", type="token_count", info=info)


def ledger(identity="a", total=40, usage=None, **extra):
    payload = {"thread_id": "qa-thread", "response_id": identity,
               "usage": vector(total) if usage is None else usage}
    payload.update(extra)
    return {"type": "token_usage_record", "payload": payload}


def analyze(records, token_cap=50000, finding_cap=2000):
    data = b"".join(json.dumps(row).encode("utf-8") + b"\n" for row in records)
    with tempfile.TemporaryDirectory(prefix="ala-q2-") as folder:
        path = Path(folder) / "invented.jsonl"
        path.write_bytes(data)
        before = hashlib.sha256(data).digest()
        engine, accountant, normalizer = RuleEngine(finding_cap), TokenAccountant(token_cap), Normalizer()
        with RolloutReader(path) as reader:
            for fact in normalizer.facts(reader):
                engine.consume(fact)
                accountant.consume(fact)
        if hashlib.sha256(path.read_bytes()).digest() != before:
            raise AssertionError("synthetic input changed")
        findings = engine.finish(normalizer.correlations(), normalizer.state.behavior_eligible)
        accounting = accountant.finish(normalizer.state.thread, normalizer.state.root,
                                      inherited=normalizer.state.inherited_scope,
                                      unsupported=not normalizer.state.format_supported,
                                      truncated=normalizer.state.analysis_truncated)
        return findings, accounting


def rules(records):
    return [item.rule_id for item in analyze(records)[0]]


class IndependentRuleQA(unittest.TestCase):
    def test_thresholds_and_exact_evidence(self):
        for count in (2, 3, 4):
            with self.subTest(count=count):
                found = analyze(run_calls(count))[0]
                self.assertEqual([f.rule_id for f in found], [] if count == 2 else ["ALA002"])
                if found:
                    self.assertEqual(found[0].occurrences, count)
                    self.assertEqual(found[0].call_lines, [2 + 3 * i for i in range(count)])
                    self.assertEqual(found[0].outcome_lines, [3 + 3 * i for i in range(count)])
        for count in (2, 3, 4):
            with self.subTest(read_count=count):
                rows = run_calls(count, {"cmd": "cat 'a b'", "shell": "bash"}, code=0)
                self.assertEqual(rules(rows), [] if count == 2 else ["ALA004"])

    def test_single_identity_mirrors_do_not_make_repetition(self):
        rows = run_calls(1)
        self.assertEqual(rules(rows + copy.deepcopy(rows[1:]) * 3), [])
        # Distinct IDs with no complete status still form information only.
        self.assertEqual(rules([session()] + [request(str(i)) for i in range(3)]), ["ALA001"])

    def test_all_meaningful_arguments_and_context_remain_distinct(self):
        base = {"cmd": "cat a", "shell": "bash", "workdir": "/qa", "login": False,
                "env": {"X": "synthetic-secret-a"}, "sandbox_permissions": "use_default",
                "timeout_ms": 1000, "yield_time_ms": 100, "max_output_tokens": 100}
        variants = [dict(base, **change) for change in (
            {"cmd": "cat b"}, {"cmd": "cat 'a'"}, {"cmd": "cat A"},
            {"cmd": "cat .\\a"}, {"cmd": "cat ./a"}, {"shell": "zsh"},
            {"workdir": "/other"}, {"login": True}, {"env": {"X": "synthetic-secret-b"}},
            {"sandbox_permissions": "require_escalated"}, {"runas": "invented"},
            {"timeout_ms": 2000}, {"yield_time_ms": 200}, {"max_output_tokens": 200})]
        for variant in variants:
            with self.subTest(variant=variant):
                rows = [session(), request("a", base), request("b", base), request("c", variant)]
                self.assertEqual(rules(rows), [])
        for commands in (("rg 'a b' file", "rg 'a  b' file"), ("cat 1", "cat 2"),
                         ("cat C:/Foo", "cat c:/Foo")):
            rows = [session(), request("a", {"cmd": commands[0]}),
                    request("b", {"cmd": commands[0]}), request("c", {"cmd": commands[1]})]
            self.assertEqual(rules(rows), [])
        self.assertEqual(fingerprint((None, "exec_command"), '{"a":1,"b":2}', None),
                         fingerprint((None, "exec_command"), '{"b":2,"a":1}', None))
        self.assertNotEqual(fingerprint((None, "exec_command"), '{"a":[1,2]}', None),
                            fingerprint((None, "exec_command"), '{"a":[2,1]}', None))
        self.assertNotEqual(fingerprint((None, "exec_command"), '{}', None),
                            fingerprint((None, "exec_command"), '{}', "/qa"))

    def test_barriers_prevent_failed_repeat_and_reread_claims(self):
        barriers = [envelope("response_item", type="message", role="user", content=[]),
                    envelope("response_item", type="custom_tool_call", name="apply_patch",
                             call_id="patch", input="invented patch"),
                    envelope("turn_context", turn_id="next", cwd="/new"),
                    envelope("event_msg", type="turn_started", turn_id="next"),
                    envelope("future_shape", field="invented")]
        for args, code in ((None, 2), ({"cmd": "cat a", "shell": "bash"}, 0)):
            for barrier in barriers:
                with self.subTest(args=args, barrier=barrier["type"]):
                    rows = run_calls(3, args, code)
                    rows.insert(7, barrier)
                    self.assertEqual(rules(rows), [])

    def test_nonidentical_unknown_pending_and_truncated_results_are_not_warnings(self):
        for change in ("different", "pending", "truncated", "missing", "quoted"):
            with self.subTest(change=change):
                rows = run_calls(3)
                if change == "different":
                    rows[-2]["payload"]["output"] = "changed result"
                elif change == "pending":
                    rows[-2]["payload"]["output"] = "Process running with session ID invented"
                elif change == "truncated":
                    rows[-2]["payload"]["truncated"] = True
                elif change == "missing":
                    rows = rows[:-2]
                else:
                    rows = [session()]
                    for i in range(3):
                        rows += [request(str(i))] + result(str(i), 'quoted "Exit code: 2" error', structured=False)
                self.assertFalse(any(rule != "ALA001" for rule in rules(rows)))
        self.assertEqual(rules(run_calls(3, {"cmd": "rg needle file"}, code=1)), ["ALA001"])

    def test_late_result_and_request_conflicts_retract_prior_warning(self):
        for late in (request("q0", {"cmd": "changed"}),
                     envelope("response_item", type="function_call_output", call_id="q0", output="late conflict"),
                     envelope("event_msg", type="exec_command_end", call_id="q0", exit_code=0,
                              aggregated_output="qa output")):
            with self.subTest(late=late["type"]):
                self.assertEqual(rules(run_calls(3) + [late]), [])

    def test_poll_and_excluded_request_break_warning_adjacency(self):
        for name in ("wait", "write_stdin", "poll", "update_plan", "request_user_input", "list_tools"):
            self.assertFalse(any(rule != "ALA001" for rule in rules(run_calls(3, name=name))))
            rows = run_calls(3)
            rows.insert(7, request("interruption", name=name))
            self.assertFalse(any(rule != "ALA001" for rule in rules(rows)))

    def test_unknown_tools_get_only_private_information_labels(self):
        # E explicitly permits info observations for repeated opaque tool names.
        found = analyze(run_calls(3, name="qa_unknown_invented_private_tool"))[0]
        self.assertEqual([item.rule_id for item in found], ["ALA001"])
        self.assertEqual(found[0].tool_label, "tool_001")
        self.assertNotIn("qa_unknown", repr(found))

    def test_read_classifier_conservative_controls(self):
        for shell, cmd in (("bash", "cat a"), ("/bin/sh", "cat -- 'a b'"),
                           ("pwsh", "Get-Content -LiteralPath 'a''b' -Raw")):
            self.assertTrue(read_like((None, "exec_command"), json.dumps({"cmd": cmd, "shell": shell})))
        for shell, cmd in (("bash", "cat a; cat a"), ("bash", "cat $X"), ("bash", "cat *.py"),
                           ("bash", "rg a file"), ("bash", "cat a | head"), ("unknown", "cat a"),
                           ("bash", "python -c 'print(1)'"), ("pwsh", "Get-Content -Path 'a'")):
            self.assertFalse(read_like((None, "exec_command"), json.dumps({"cmd": cmd, "shell": shell})))

    def test_cycles_thresholds_overlap_and_interruption(self):
        for size in (2, 3, 4):
            for copies in (2, 3, 4):
                rows = [session()]
                for i in range(size * copies):
                    rows += [request(str(i), {"cmd": "python -m unittest case" + str(i % size)})]
                    rows += result(str(i))
                with self.subTest(size=size, copies=copies):
                    found = analyze(rows)[0]
                    self.assertEqual([f.rule_id for f in found], [] if copies == 2 else ["ALA003"])
                    if found:
                        self.assertEqual(found[0].occurrences, size * copies)
                        self.assertEqual(found[0].block_size, size)
                if copies == 3:
                    changed = copy.deepcopy(rows)
                    changed[-2]["payload"]["output"] = "different final outcome"
                    self.assertNotIn("ALA003", rules(changed))
                    rows.insert(1 + 3 * size, envelope("future_event", value="barrier"))
                    self.assertNotIn("ALA003", rules(rows))

    def test_maximal_run_and_inherited_suppression(self):
        found = analyze(run_calls(75))[0]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].occurrences, 75)
        self.assertEqual(len(found[0].call_lines), 20)
        self.assertTrue(found[0].evidence_truncated)
        rows = run_calls(3)
        rows[0] = session(history_base="invented")
        self.assertEqual(rules(rows), [])


class IndependentTokenQA(unittest.TestCase):
    def check_total(self, rows, expected, mode=None):
        result = analyze(rows)[1]
        observed = result["observed"]
        self.assertEqual(observed["total_tokens"] if observed is not None else None, expected)
        self.assertFalse(result["complete"])
        self.assertEqual(result["coverage"], "unavailable" if observed is None else "partial")
        if mode:
            self.assertEqual(result["mode"], mode)
        return result

    def test_t1_t2_t11_legacy_hand_arithmetic_and_lines(self):
        result = self.check_total([session()] + [legacy(x) for x in (100, 150, 150, 200)], 100)
        self.assertEqual(result["last_reported_counter"]["total_tokens"], 200)
        self.assertEqual(result["interval_lines"], [[2, 3], [3, 4], [4, 5]])
        self.assertIn("baseline_excluded", result["reason_codes"])
        result = self.check_total([session()] + [legacy(x) for x in (100, 150, 20, 60, 150)], 50)
        self.assertIn("ambiguous_reset", result["reason_codes"])
        self.assertEqual(result["observations"], 1)
        self.assertEqual(self.check_total([session(), legacy(0), legacy(0)], 0)["observations"], 1)

    def test_t3_t4_t10_gaps_last_only_compaction(self):
        self.check_total([session(), legacy(100), legacy(), legacy(170), legacy(200)], 30)
        self.check_total([session(), legacy(last_token_usage=vector(50)), legacy(last_token_usage=vector(50))], None)
        self.check_total([session(), legacy(100), envelope("compacted"), legacy(160), legacy(190)], None)

    def test_t5_t6_t7_dedup_conflict_and_mode_selection(self):
        result = self.check_total([session(), ledger(), ledger(), ledger("b", 60)], 100, "response_ledger")
        self.assertEqual(result["observations"], 2)
        self.assertEqual(result["interval_lines"], [[2, 2], [4, 4]])
        self.check_total([session(), ledger(), ledger(total=45)], None)
        self.check_total([session(), ledger(), ledger(total=45), ledger("b", 60)], 60)
        result = self.check_total([session(), legacy(100), legacy(200), ledger("b", 30)], 30, "response_ledger")
        self.assertIn("legacy_excluded", result["reason_codes"])

    def test_t8_t9_parent_and_nested_compaction_records(self):
        rows = [session(session_id="qa-root", history_base="invented"),
                ledger("parent", 900, thread_id="qa-parent"), ledger("child", 30, session_id="qa-root")]
        self.check_total(rows, 30)
        self.check_total([session(), envelope("compacted", latest_token_usage_record=ledger()["payload"]), ledger()], 40)

    def test_t12_t14_components_are_independent_and_never_added_twice(self):
        full = {"input_tokens": 100, "cached_input_tokens": 20, "output_tokens": 30,
                "reasoning_output_tokens": 10, "total_tokens": 130, "cache_write_input_tokens": 5}
        result = self.check_total([session(), ledger(usage=full)], 130)
        self.assertEqual(result["observed"], full)
        missing = dict(full)
        del missing["output_tokens"]
        result = self.check_total([session(), ledger(usage=full), ledger("b", usage=missing)], 260)
        self.assertIsNone(result["observed"]["output_tokens"])
        self.assertEqual(result["observed"]["input_tokens"], 200)
        self.assertEqual(result["observed"]["reasoning_output_tokens"], 20)

    def test_t13_strict_numeric_and_relational_validation(self):
        for invalid in (True, 1.25, "7", -1, 2**63):
            with self.subTest(invalid=invalid):
                bad = vector(40)
                bad["input_tokens"] = invalid
                self.check_total([session(), ledger(usage=bad)], None)
        for bad in ({"input_tokens": 4, "cached_input_tokens": 5, "total_tokens": 4},
                    {"output_tokens": 4, "reasoning_output_tokens": 5, "total_tokens": 4}):
            self.check_total([session(), ledger(usage=bad)], None)

    def test_t15_turn_root_session_and_ownership_conflicts(self):
        for field in ("turn_id", "root_turn_id", "session_id"):
            with self.subTest(field=field):
                self.check_total([session(), ledger(**{field: "one"}), ledger(**{field: "two"})], None)
        self.check_total([session(), ledger(thread_id="foreign")], None)
        self.check_total([session(), ledger(thread_id=None)], None)
        self.check_total([session(), ledger(response_id=None)], None)
        self.check_total([session(), ledger(session_id="foreign")], None)

    def test_t16_t17_no_fallback_and_component_change_rebaseline(self):
        self.check_total([session(), legacy(100), legacy(200), ledger(usage={"input_tokens": False})],
                         None, "response_ledger")
        changed = legacy(170)
        changed["payload"]["info"]["total_token_usage"]["cache_write_input_tokens"] = 5
        later = legacy(200)
        later["payload"]["info"]["total_token_usage"]["cache_write_input_tokens"] = 8
        result = self.check_total([session(), legacy(100), changed, later], 30)
        self.assertIn("component_set_changed", result["reason_codes"])
        self.assertEqual(result["interval_lines"], [[3, 4]])

    def test_identity_cap_cannot_keep_a_potentially_conflicting_total(self):
        result = analyze([session(), ledger(), ledger("b", 60), ledger(total=45)], token_cap=1)[1]
        self.assertIsNone(result["observed"])
        self.assertIn("analysis_truncated", result["reason_codes"])

    def test_legacy_scope_and_turn_boundaries(self):
        self.check_total([session(history_base="invented"), legacy(100), legacy(200)], None)
        self.check_total([session(), legacy(100), envelope("turn_context", turn_id="new", cwd="/qa"), legacy(200)], 100)


if __name__ == "__main__":
    unittest.main()
