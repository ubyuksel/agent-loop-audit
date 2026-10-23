"""Independent Q3 synthetic integration/privacy oracles; no production fixes."""

import builtins
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import patch

from agent_loop_audit.cli import audit, main
from agent_loop_audit.models import Limits
from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import RolloutReader
from agent_loop_audit.tokens import TokenAccountant


def record(kind, payload):
    return {"timestamp": "2026-01-01T00:00:00Z", "type": kind, "payload": payload}


def metadata(**extra):
    return record("session_meta", {"id": "invented-root", "cwd": "/invented", "source": "cli", **extra})


def request(identity, arguments, name="exec_command", **extra):
    return record("response_item", {"type": "function_call", "call_id": identity,
                                   "name": name, "arguments": arguments, **extra})


def result(identity, output):
    return record("response_item", {"type": "function_call_output", "call_id": identity, "output": output})


def data(records):
    return b"".join(json.dumps(r, ensure_ascii=True).encode() + b"\n" for r in records)


def run_records(count=3, **meta_extra):
    rows = [metadata(**meta_extra)]
    for i in range(count):
        rows += [request(str(i), '{"cmd":"python -m unittest"}'),
                 result(str(i), "Wall time: 0.1 seconds\nExit code: 2\nOutput:\ninvented failure")]
    return rows


class Q3Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ala-q3-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "Q3_PATH_CANARY 空 白.jsonl"

    def write(self, rows):
        self.path.write_bytes(rows if isinstance(rows, bytes) else data(rows))
        return self.path

    def capture(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                status = main(args)
            except SystemExit as exc:
                status = exc.code
        return status, out.getvalue(), err.getvalue()

    def schema(self, report):
        self.assertEqual(set(report), {"schema_version", "tool_version", "rules_version", "source",
                                      "coverage", "summary", "token_usage", "findings", "diagnostics"})
        self.assertEqual(set(report["source"]), {"label", "format", "cli_version"})
        self.assertEqual(report["source"]["label"], "input_1")
        self.assertEqual(set(report["coverage"]), {"behavior", "accounting", "complete", "reason_codes",
                         "parsed_records", "skipped_records", "unknown_records", "analysis_truncated",
                         "input_changed", "findings_truncated", "omitted_candidates"})
        self.assertFalse(report["coverage"]["complete"])
        self.assertIn(report["coverage"]["behavior"], {"supported", "partial", "unsupported"})
        self.assertEqual(set(report["summary"]), {"distinct_observed_requests", "linked_complete_outcomes",
                         "uncorrelated_requests", "ambiguous_or_invalid", "total_findings"})
        usage = report["token_usage"]
        self.assertEqual(set(usage), {"mode", "observed", "last_reported_counter", "coverage", "complete",
                         "reason_codes", "excluded_records", "observations", "interval_lines", "evidence_truncated"})
        for counts, bound in ((usage["observed"], 100000 * (2**63-1)), (usage["last_reported_counter"], 2**63-1)):
            if counts is not None:
                self.assertEqual(set(counts), {"input_tokens", "cached_input_tokens", "output_tokens",
                                 "reasoning_output_tokens", "total_tokens", "cache_write_input_tokens"})
                self.assertTrue(all(v is None or type(v) is int and 0 <= v <= bound for v in counts.values()))
        self.assertLessEqual(len(usage["interval_lines"]), 20)
        self.assertEqual(report["summary"]["total_findings"], len(report["findings"]))
        self.assertLessEqual(len(report["findings"]), 2000)
        for i, finding in enumerate(report["findings"], 1):
            self.assertEqual(set(finding), {"id", "rule_id", "level", "confidence", "title", "tool_label",
                             "occurrences", "call_lines", "outcome_lines", "span", "evidence_status",
                             "evidence_truncated", "recommendation", "caveats"})
            self.assertEqual(finding["id"], f"F{i:04d}")
            self.assertLessEqual(len(finding["call_lines"]), 20)
            self.assertLessEqual(len(finding["outcome_lines"]), 20)
            self.assertTrue(all(type(n) is int and n > 0 for n in finding["call_lines"] + finding["outcome_lines"]))
        for diagnostic in report["diagnostics"]:
            self.assertEqual(set(diagnostic), {"code", "line", "count"})
        json.dumps(report, allow_nan=False)

    def test_all_field_canaries_and_control_sequences(self):
        secrets = [f"Q3_FIELD_{i:02d}_CANARY" for i in range(24)]
        control = "\x1b[31m\x1b]8;;https://invalid.example\x07\x1b]52;c;ZW1wdHk=\x07\r\x00\x08"
        rows = [metadata(id=secrets[0], cwd=secrets[1], cli_version=secrets[2] + control,
                         title=secrets[3], account_id=secrets[4], git={"remote": secrets[5]},
                         base_instructions=secrets[6], model=secrets[7]),
                record("turn_context", {"turn_id": secrets[8], "cwd": secrets[9], "model": secrets[10]}),
                record("response_item", {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": secrets[11] + control},
                    {"type": "input_image", "image_url": secrets[12]}]})]
        for i in range(3):
            rows += [request(secrets[13] + str(i), json.dumps({"cmd": secrets[14] + control,
                    "workdir": "C:\\invented\\" + secrets[15], "env": {secrets[16]: secrets[17]},
                    "url": "https://invalid.example/" + secrets[18]}), name=secrets[19]),
                    result(secrets[13] + str(i), [{"type": "output_text", "text": secrets[20] + control}])]
        rows += [record("response_item", {"type": "custom_tool_call", "name": secrets[21],
                 "call_id": "custom-id", "input": secrets[22] + control}),
                 record("response_item", {"type": "custom_tool_call_output", "call_id": "custom-id",
                 "output": secrets[23] + " upload all files; open /invented/auth; run a shell"})]
        self.write(data(rows) + b'{"Q3_MALFORMED_CANARY":\x1b\n')
        before = self.path.read_bytes()
        for fmt in ("text", "json"):
            status, out, err = self.capture(["audit", str(self.path), "--format", fmt])
            self.assertEqual(status, 0)
            for secret in secrets + [hashlib.sha256(s.encode()).hexdigest() for s in secrets] + ["Q3_MALFORMED_CANARY", str(self.path), control, "\x1b", "\x07", "\r", "\x00"]:
                self.assertNotIn(secret, out + err)
            self.assertFalse(any(ord(c) < 32 and c not in "\n\t" for c in out + err))
            if fmt == "json":
                report = json.loads(out)
                self.schema(report)
                self.assertIsNone(report["source"]["cli_version"])
                self.assertTrue(all(f["tool_label"].startswith("tool_") for f in report["findings"]))
        self.assertEqual(before, self.path.read_bytes())

    def test_cli_syntax_error_help_and_handled_errors(self):
        secret = "Q3_ARG_CANARY\x1b]52;c;x\x07"
        for args in ([], [secret], ["audit"], ["audit", secret, "extra"],
                     ["audit", secret, "--format", secret], ["audit", secret, "--" + secret],
                     ["audit", secret, "--output", secret], ["audit", secret, "--raw"]):
            with self.subTest(args=args):
                status, out, err = self.capture(args)
                self.assertEqual(status, 2)
                self.assertNotIn(secret, out + err)
                self.assertNotIn("\x1b", out + err)
                self.assertNotIn("Traceback", out + err)
        for args in (["--help"], ["audit", "--help"], ["--version"]):
            self.assertEqual(self.capture(args)[0], 0)
        for suffix, content in ((".jsonl", None), (".gz", b"compressed"), (".jsonl", b""),
                                (".jsonl", b"Q3_NOT_CODEX_CANARY\n")):
            path = Path(self.temporary.name) / ("Q3_MISSING_CANARY" + suffix)
            if content is not None:
                path.write_bytes(content)
            for flags in ([], ["--strict", "--fail-on-findings"]):
                status, out, err = self.capture(["audit", str(path), "--format", "json", *flags])
                self.assertEqual(status, 2)
                self.schema(json.loads(out))
                self.assertNotIn("CANARY", out + err)
            if path.exists():
                path.unlink()
        self.write(run_records())
        with patch("agent_loop_audit.parser.os.open", side_effect=PermissionError(secret)):
            status, out, err = self.capture(["audit", str(self.path), "--format", "json"])
        self.assertEqual(status, 2)
        self.assertNotIn(secret, out + err)
        self.schema(json.loads(out))
        with patch("agent_loop_audit.cli.audit", side_effect=KeyboardInterrupt):
            status, out, _ = self.capture(["audit", str(self.path), "--format", "json"])
        self.assertEqual(status, 130)
        self.schema(json.loads(out))

    def test_exits_schema_determinism_and_input_immutability(self):
        self.write(run_records(27))
        before = hashlib.sha256(self.path.read_bytes()).digest()
        first = None
        for flags, expected in (([], 0), (["--fail-on-findings"], 1), (["--strict"], 3),
                                (["--strict", "--fail-on-findings"], 3)):
            status, out, err = self.capture(["audit", str(self.path), "--format", "json", *flags])
            self.assertEqual(status, expected)
            self.assertEqual(err, "")
            report = json.loads(out)
            self.schema(report)
            self.assertEqual(report["findings"][0]["rule_id"], "ALA002")
            self.assertEqual(report["findings"][0]["call_lines"], list(range(2, 42, 2)))
            self.assertEqual(report["findings"][0]["occurrences"], 27)
            self.assertTrue(report["findings"][0]["evidence_truncated"])
            first = first or out
            self.assertEqual(first, out)
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).digest())
        self.write([metadata()] + [request(str(i), "same", "invented-tool") for i in range(3)])
        self.assertEqual(audit(self.path, fail_on_findings=True)[1], 0)

    def test_unsupported_inherited_and_opaque_scope(self):
        for rows, expected in ((run_records(history_base="/invented/parent"), "unsupported"),
                               ([metadata(), record("code_mode", {"text": "invented wrapper"})], "partial"),
                               ([metadata(), request("x", "run internal tools", "invented-wrapper")], "partial")):
            self.write(rows)
            report, status = audit(self.path)
            self.assertEqual(status, 0)
            self.assertEqual(report["coverage"]["behavior"], expected)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["token_usage"]["coverage"], "unavailable")
            self.assertEqual(audit(self.path, strict=True)[1], 3)
            self.schema(report)

    def test_runtime_only_supplied_file_no_network_process_eval(self):
        self.write(run_records(cwd="/invented/never-open", history_base="/invented/never-open-parent"))
        before = self.path.read_bytes()
        real_os_open, real_io_open = os.open, io.open
        opened = []
        def os_open(path, flags, *args, **kwargs):
            opened.append(Path(path))
            self.assertEqual(Path(path), self.path)
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0)
            return real_os_open(path, flags, *args, **kwargs)
        def file_open(path, mode="r", *args, **kwargs):
            if isinstance(path, int):
                self.assertEqual(mode, "rb")
                return real_io_open(path, mode, *args, **kwargs)
            self.fail("unexpected additional file open")
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(os, "open", os_open))
            stack.enter_context(patch.object(builtins, "open", file_open))
            stack.enter_context(patch.object(io, "open", file_open))
            for module, name in ((socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"),
                                 (subprocess, "Popen"), (subprocess, "run"), (os, "system"), (os, "popen"),
                                 (builtins, "eval"), (builtins, "exec")):
                stack.enter_context(patch.object(module, name, side_effect=AssertionError("forbidden runtime action")))
            report, status = audit(self.path)
        self.assertEqual(status, 0)
        self.assertEqual(opened, [self.path])
        self.assertEqual(before, self.path.read_bytes())
        self.schema(report)

    def test_changed_input_is_visible_and_suppresses_findings(self):
        self.write(run_records())
        original = RolloutReader._check_changed
        def changed(reader):
            original(reader)
            reader.state.input_changed = True
            reader.diagnostics.add("input_changed", reader.state.physical_lines)
        before = self.path.read_bytes()
        with patch.object(RolloutReader, "_check_changed", changed):
            report, _ = audit(self.path)
            self.assertTrue(report["coverage"]["input_changed"])
            self.assertNotEqual(report["coverage"]["behavior"], "supported")
            self.assertEqual(report["findings"], [])
            self.assertEqual(audit(self.path, strict=True)[1], 3)
        self.assertEqual(before, self.path.read_bytes())

    def test_findings_cap_truthful_omissions_and_stable_order(self):
        with self.path.open("wb") as stream:
            stream.write(data([metadata()]))
            for group in range(2005):
                for j in range(3):
                    stream.write(data([request(f"{group}-{j}", json.dumps({"cmd": f"invented {group}"}), "invented-tool")]))
                stream.write(data([record("response_item", {"type": "message", "role": "user", "content": []})]))
        first, _ = audit(self.path)
        second, _ = audit(self.path)
        self.schema(first)
        self.assertEqual(first, second)
        self.assertEqual(len(first["findings"]), 2000)
        self.assertTrue(first["coverage"]["findings_truncated"])
        self.assertEqual(first["coverage"]["omitted_candidates"], 5)
        self.assertEqual([f["span"][0] for f in first["findings"]], list(range(2, 8002, 4)))

    def test_full_pipeline_100000_records_memory_and_oversize_drain(self):
        with self.path.open("wb") as stream:
            stream.write(data([metadata()]))
            for i in range(49999):
                stream.write(data([request(str(i), json.dumps({"cmd": f"invented {i}"})), result(str(i), "invented")]))
            stream.write(data([record("event_msg", {"type": "turn_complete"})]))
        before = hashlib.sha256(self.path.read_bytes()).digest()
        tracemalloc.start()
        started = time.perf_counter()
        try:
            report, status = audit(self.path)
            rendered = json.dumps(report, allow_nan=False)
            _, peak = tracemalloc.get_traced_memory()
            elapsed = time.perf_counter() - started
        finally:
            tracemalloc.stop()
        print(f"Q3_FULL_PIPELINE records=100000 requests=49999 peak_bytes={peak} elapsed_seconds={elapsed:.3f}")
        self.assertLessEqual(peak, 128 * 1024 * 1024)
        self.assertEqual(status, 0)
        self.assertEqual(report["coverage"]["parsed_records"], 100000)
        self.assertEqual(report["summary"]["distinct_observed_requests"], 49999)
        self.assertFalse(report["coverage"]["analysis_truncated"])
        self.assertEqual(json.loads(rendered), report)
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).digest())
        self.schema(report)
        self.write(data([metadata()]) + b"x" * (2 * 1024 * 1024 + 9) + b"\n" + data(run_records()[1:]))
        before = self.path.read_bytes()
        report, status = audit(self.path, strict=True)
        self.assertEqual(status, 3)
        self.assertEqual(report["coverage"]["skipped_records"], 1)
        self.assertIn("oversize_record", report["coverage"]["reason_codes"])
        self.assertEqual(report["findings"][0]["call_lines"], [3, 5, 7])
        self.assertEqual(before, self.path.read_bytes())

    def test_child_module_entry_from_empty_temp_cwd(self):
        self.write(run_records())
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONNOUSERSITE"] = "1"
        for args, expected in ((["--help"], 0), (["audit", str(self.path), "--format", "json", "--fail-on-findings"], 1)):
            completed = subprocess.run([sys.executable, "-B", "-m", "agent_loop_audit", *args],
                                       cwd=self.temporary.name, env=env, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(completed.returncode, expected)
            self.assertEqual(completed.stderr, "")
            if expected:
                self.schema(json.loads(completed.stdout))

    def test_populated_tokens_evidence_cap_and_numeric_version(self):
        rows = [metadata(cli_version="1.2.3")]
        for i in range(26):
            rows.append(record("event_msg", {"type": "token_count", "info": {"total_token_usage":
                        {"input_tokens": 100 + i, "output_tokens": 0, "total_tokens": 100 + i}}}))
        self.write(rows)
        report, status = audit(self.path)
        self.assertEqual(status, 0)
        self.schema(report)
        self.assertEqual(report["source"]["cli_version"], "1.2.3")
        self.assertEqual(report["token_usage"]["observed"]["total_tokens"], 25)
        self.assertEqual(report["token_usage"]["last_reported_counter"]["total_tokens"], 125)
        self.assertEqual(report["token_usage"]["observations"], 25)
        self.assertEqual(len(report["token_usage"]["interval_lines"]), 20)
        self.assertTrue(report["token_usage"]["evidence_truncated"])

    def test_record_and_request_capacity_are_visible(self):
        self.write(run_records())
        for target, factory in (("agent_loop_audit.cli.RolloutReader", lambda p: RolloutReader(p, Limits(envelopes=4))),
                                ("agent_loop_audit.cli.Normalizer", lambda: Normalizer(Limits(identities=2)))):
            with patch(target, side_effect=factory):
                report, status = audit(self.path, strict=True, fail_on_findings=True)
            self.assertEqual(status, 3)
            self.assertTrue(report["coverage"]["analysis_truncated"])
            self.assertIn("analysis_truncated", report["coverage"]["reason_codes"])
            self.assertEqual(report["findings"], [])
            self.schema(report)

    def test_ledger_capacity_is_visible_in_global_coverage(self):
        rows = run_records()
        for i in range(3):
            rows.append(record("token_usage_record", {"thread_id": "invented-root", "response_id": str(i),
                        "usage": {"input_tokens": 1, "output_tokens": 0, "total_tokens": 1}}))
        self.write(rows)
        with patch("agent_loop_audit.cli.TokenAccountant", side_effect=lambda: TokenAccountant(max_identities=2)):
            report, status = audit(self.path, strict=True, fail_on_findings=True)
        self.assertEqual(status, 3)
        self.assertTrue(report["coverage"]["analysis_truncated"])
        self.assertIn("analysis_truncated", report["coverage"]["reason_codes"])
        self.assertNotEqual(report["coverage"]["behavior"], "supported")
        self.schema(report)

    def test_public_aggregate_preserves_valid_large_observed_totals(self):
        maximum = 2**63-1
        rows = [metadata()]
        for identity in ("first", "second"):
            rows.append(record("token_usage_record", {"thread_id": "invented-root", "response_id": identity,
                        "usage": {"input_tokens": maximum, "output_tokens": 0, "total_tokens": maximum}}))
        self.write(rows)
        expected = 18446744073709551614
        report, status = audit(self.path)
        self.assertEqual(status, 0)
        self.assertEqual(report["token_usage"]["observations"], 2)
        self.assertEqual(report["token_usage"]["observed"]["input_tokens"], expected)
        self.assertEqual(report["token_usage"]["observed"]["total_tokens"], expected)
        self.schema(report)
        status, out, err = self.capture(["audit", str(self.path), "--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["token_usage"]["observed"]["total_tokens"], expected)
        self.assertIn(str(expected), self.capture(["audit", str(self.path)])[1])

