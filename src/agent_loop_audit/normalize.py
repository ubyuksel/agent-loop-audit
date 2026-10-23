"""Streaming native facts and bounded digest-only correlation, with EOF finality."""

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Iterator

from .models import Barrier, Correlation, Diagnostics, Envelope, Fact, Key, Limits, Status
from .parser import RolloutReader, strict_json


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _id(value: Any) -> str | None:
    return digest(value) if isinstance(value, str) and value else None


def _arguments(text: str, limits: Limits) -> Any:
    try:
        return ["json", strict_json(text, limits)]
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        return ["literal", text]


_LEGACY_SHELL = re.compile(
    r"\AWall time: [0-9]+(?:\.[0-9]+)? seconds\r?\nExit code: (-?[0-9]{1,10})\r?\nOutput:\r?\n[\s\S]*\Z")
_CURRENT_SHELL = re.compile(
    r"\AChunk ID: [A-Za-z0-9_-]{1,80}\r?\nWall time: [0-9]+(?:\.[0-9]+)? seconds\r?\n"
    r"Process exited with code (-?[0-9]{1,10})\r?\nFinal output:\r?\n[\s\S]*\Z")


def _output(value: Any, truncated: bool, shell_tool: bool) -> tuple[str, bool, Status, int | None]:
    status: Status = "unknown"
    body = value
    complete = isinstance(body, str)
    if isinstance(body, list):
        complete = bool(body) and all(
            isinstance(item, dict) and isinstance(item.get("type"), str)
            and item.get("type") in {"text", "input_text", "output_text"}
            and isinstance(item.get("text"), str)
            and not item.get("truncated") for item in body)
    # Known truncation markers, not a claim to recognize every wrapper dialect.
    text = body if isinstance(body, str) else ""
    if re.search(r"(?im)^(?:Warning: truncated output|Output truncated|\[output truncated\]|Original token count:)", text):
        truncated = True
    if re.search(r"(?m)^Process running with session ID \S+\s*$", text):
        status, truncated = "pending", True
    exit_code = None
    if shell_tool and isinstance(body, str):
        match = _LEGACY_SHELL.fullmatch(body) or _CURRENT_SHELL.fullmatch(body)
        if match:
            exit_code = int(match[1])
            if exit_code == 0:
                status = "success"
    return digest(value), complete and not truncated, status, exit_code


def _text_size(value: Any, limit: int) -> int:
    """Count transient text bytes without serializing or retaining the tree."""
    total, stack = 0, [value]
    while stack and total <= limit:
        item = stack.pop()
        if isinstance(item, str):
            total += len(item.encode("utf-8"))
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return total


@dataclass(slots=True)
class _Result:
    line: int
    output_digest: str | None = None
    structured_digest: str | None = None
    text_status: Status = "unknown"
    structured_status: Status = "unknown"
    complete: bool = False
    conflict: bool = False
    mirrors: int = 0
    exit_code: int | None = None
    text_exit_code: int | None = None
    shell_wrapper_status: Status = "unknown"


@dataclass(slots=True)
class NormalizationState:
    thread: str | None = field(default=None, repr=False)
    root: str | None = field(default=None, repr=False)
    cli_version: str | None = None
    inherited_scope: bool = False
    inconsistent_metadata: bool = False
    analysis_truncated: bool = False
    finished: bool = False
    recognized_events: int = 0
    native_events: int = 0
    unknown_events: int = 0
    uncorrelated_requests: int = 0
    orphan_outputs: int = 0
    peak_transient_text_bytes: int = 0
    retained_raw_text_bytes: int = 0

    @property
    def behavior_eligible(self) -> bool:
        return (self.finished and self.thread is not None and not self.inherited_scope
                and not self.inconsistent_metadata and not self.analysis_truncated)

    @property
    def format_supported(self) -> bool:
        return self.thread is not None and not self.inconsistent_metadata


class Normalizer:
    """One-shot consumer. Facts are provisional; correlations are final at EOF.

    Consumers must honor final behavior_eligible, barriers and invalidations.
    Unknown-turn results are resolved only at EOF, never by nearest timestamp.
    Maps retain hashes, enums and bounded line/count summaries, never commands.
    """

    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self.state = NormalizationState()
        self.diagnostics = Diagnostics(self.limits.diagnostic_codes)
        self._requests: dict[Key, Correlation] = {}
        self._results: dict[Key, _Result] = {}
        self._index: dict[tuple[str | None, str], list[Key]] = {}
        self._turn: str | None = None
        self._epoch = 0
        self._context = digest(["unknown_context"])
        self._meta_signature = None
        self._started = False

    def _barrier(self, line: int, reason: str, ordinal: int | None = None) -> Fact:
        if self._turn is None:
            self._epoch += 1
        return Fact("barrier", line, ordinal, reason=reason)

    def _capacity(self, line: int, result: bool = False) -> bool:
        table = self._results if result else self._requests
        if len(table) < self.limits.identities:
            return True
        self.state.analysis_truncated = True
        self.diagnostics.add("analysis_truncated", line)
        return False

    def _scope(self, payload: dict, result: bool = False) -> str:
        explicit = _id(payload.get("turn_id"))
        if explicit:
            return "t:" + explicit
        if result:
            return "?"
        return "t:" + self._turn if self._turn else "e:" + str(self._epoch)

    def _session(self, env: Envelope) -> Fact:
        p = env.payload
        thread, root = _id(p.get("id")), _id(p.get("session_id"))
        if thread is None:
            self.state.inconsistent_metadata = True
            self.diagnostics.add("invalid_session_metadata", env.line)
            return self._barrier(env.line, "invalid_session_metadata", env.ordinal)
        signature = digest([thread, root, p.get("cwd"), p.get("source")])
        if self._meta_signature is not None and self._meta_signature != signature:
            self.state.inconsistent_metadata = True
            self.diagnostics.add("inconsistent_session_metadata", env.line)
        self._meta_signature = signature
        if self.state.thread is None:
            self.state.thread, self.state.root = thread, root
        indicators = ("forked_from_id", "forked_from", "parent_thread_id", "parent_session_id",
                      "parent_id", "history_base", "inherited_history", "is_subagent")
        source = p.get("source")
        inherited = any(p.get(key) is not None and p.get(key) is not False for key in indicators)
        inherited |= isinstance(source, dict) or source in ("subagent", "fork", "inherited")
        inherited |= root is not None and root != thread
        if inherited:
            self.state.inherited_scope = True
            self.diagnostics.add("unsupported_inherited_scope", env.line)
        version = p.get("cli_version")
        if isinstance(version, str) and re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-[a-z]{1,10}[0-9]{0,4})?", version):
            self.state.cli_version = version
        if p.get("cwd") is not None and not isinstance(p["cwd"], str):
            self.diagnostics.add("unknown_context", env.line)
        self._context = digest(["cwd", p.get("cwd") if isinstance(p.get("cwd"), str) else None])
        # A repeated metadata record is not a new unknown-turn epoch.
        return Fact("barrier", env.line, env.ordinal, reason="session_metadata")

    def _call(self, env: Envelope) -> Fact:
        p = env.payload
        name, namespace = p.get("name"), p.get("namespace")
        custom = p["type"] == "custom_tool_call"
        text = p.get("input" if custom else "arguments")
        if (not isinstance(name, str) or not name or not isinstance(text, str)
                or (namespace is not None and not isinstance(namespace, str))):
            self.diagnostics.add("opaque_request", env.line)
            opaque_id = _id(p.get("call_id"))
            for prior_key in self._index.get((self.state.thread, opaque_id), ()):
                self._requests[prior_key].invalid = True
            return self._barrier(env.line, "opaque_request", env.ordinal)
        text_bytes = len(text.encode("utf-8")) + len(name.encode("utf-8"))
        if namespace is not None:
            text_bytes += len(namespace.encode("utf-8"))
        if text_bytes > self.limits.retained_text_bytes:
            self.diagnostics.add("retained_text_limit", env.line)
            self.state.analysis_truncated = True
            return self._barrier(env.line, "opaque_request", env.ordinal)
        self.state.peak_transient_text_bytes = max(self.state.peak_transient_text_bytes, text_bytes)
        semantic = ["custom", text] if custom else _arguments(text, self.limits)
        request_digest = digest([namespace, name, semantic, self._context])
        call_id = _id(p.get("call_id"))
        key = (self.state.thread, self._scope(p), call_id) if call_id else None
        if key is not None:
            prior = self._requests.get(key)
            if prior is not None:
                if prior.request_digest == request_digest:
                    prior.duplicate_requests += 1
                    self.diagnostics.add("duplicate_request_record", env.line)
                    return Fact("duplicate_request", env.line, env.ordinal, key=key)
                prior.invalid = True
                self.diagnostics.add("conflicting_request_identity", env.line)
                return Fact("invalidate", env.line, env.ordinal, key=key, reason="conflicting_request_identity")
            if not self._capacity(env.line):
                return self._barrier(env.line, "analysis_truncated", env.ordinal)
            shell_tools = {(ns, tool) for ns in (None, "functions")
                           for tool in ("exec_command", "shell_command", "shell")}
            family = "shell" if not custom and (namespace, name) in shell_tools else None
            # Exact, tiny command families solely for neutral exit-1 classification.
            if not custom and isinstance(semantic[1], dict):
                cmd = semantic[1].get("cmd", semantic[1].get("command"))
                if family and isinstance(cmd, str):
                    if re.fullmatch(r"(?:rg|grep) [\w ./-]+", cmd):
                        family = "search"
                    elif re.fullmatch(r"(?:python -m (?:unittest|pytest)|pytest)(?: [\w ./-]+)?", cmd):
                        family = "test"
            self._requests[key] = Correlation(key, call_line=env.line, request_digest=request_digest,
                                                 command_family=family)
            self._index.setdefault((self.state.thread, call_id), []).append(key)
        else:
            self.state.uncorrelated_requests += 1
            self.diagnostics.add("missing_call_identity", env.line)
        known = {(ns, tool) for ns in (None, "functions") for tool in
                 ("exec_command", "shell_command", "shell", "apply_patch", "read_file", "write_stdin", "wait")}
        opaque = (namespace, name) not in known
        if name == "apply_patch" or opaque:
            # Fact itself still exposes a single observation; barrier precedes it.
            reason = "opaque_operation" if opaque else "patch_operation"
        else:
            reason = None
        return Fact("request", env.line, env.ordinal, key, (namespace, name), text,
                    self._context, request_digest, reason=reason)

    def _result(self, env: Envelope, structured: bool) -> Fact:
        p = env.payload
        retained = _text_size(p, self.limits.retained_text_bytes)
        if retained > self.limits.retained_text_bytes:
            self.diagnostics.add("retained_text_limit", env.line)
            # Equality is no longer trustworthy for this ID, even if prior output
            # was complete. Stop rather than forgetting a potential late conflict.
            self.state.analysis_truncated = True
            return self._barrier(env.line, "retained_text_limit", env.ordinal)
        self.state.peak_transient_text_bytes = max(self.state.peak_transient_text_bytes, retained)
        call_id = _id(p.get("call_id"))
        if call_id is None:
            self.state.orphan_outputs += 1
            self.diagnostics.add("orphan_output", env.line)
            return self._barrier(env.line, "orphan_output", env.ordinal)
        key = (self.state.thread, self._scope(p, True), call_id)
        result = self._results.get(key)
        if result is None:
            if not self._capacity(env.line, result=True):
                return self._barrier(env.line, "analysis_truncated", env.ordinal)
            result = self._results[key] = _Result(env.line)
        status: Status = "unknown"
        complete = False
        if structured:
            subtype = p["type"]
            code = p.get("exit_code")
            if subtype == "exec_command_end":
                if type(code) is int and -(2**31) <= code < 2**31:
                    result.exit_code = code
                    if code == 0 and p.get("status") != "failed":
                        status = "success"
                    elif code == 0 and p.get("status") == "failed":
                        result.conflict = True
                    # Nonzero statuses depend on the command family at EOF.
                if p.get("status") == "declined":
                    status = "denied"
                structured_value = [subtype, p.get("status"), code, p.get("stdout"), p.get("stderr"), p.get("aggregated_output")]
            elif subtype == "patch_apply_end":
                if type(p.get("success")) is bool:
                    status = "success" if p["success"] else "failure"
                    if ((p.get("status") == "failed" and p["success"])
                            or (p.get("status") == "completed" and not p["success"])):
                        result.conflict = True
                if p.get("status") == "declined":
                    status = "denied"
                structured_value = [subtype, p.get("status"), p.get("success"), p.get("stdout"), p.get("stderr")]
            else:  # MCP Result is encoded as {Ok: ...} or {Err: ...}.
                value = p.get("result")
                if isinstance(value, dict) and set(value) == {"Ok"}:
                    ok = value["Ok"]
                    if isinstance(ok, dict):
                        if ok.get("isError") is True:
                            status = "failure"
                        elif ok.get("isError") is False or "isError" not in ok:
                            status = "success"
                elif isinstance(value, dict) and set(value) == {"Err"}:
                    status = "failure"
                structured_value = [subtype, value]
            value_digest = digest(structured_value)
            old = result.structured_digest
            if old is not None and old != value_digest:
                result.conflict = True
            if old == value_digest:
                result.mirrors += 1
            result.structured_digest, result.structured_status = value_digest, status
        else:
            value = p.get("output")
            # Request may arrive later: preserve only a potential wrapper status,
            # and apply it only for a verified shell tool in final correlation.
            value_digest, complete, status, text_code = _output(value, bool(p.get("truncated")), True)
            old = result.output_digest
            if old is not None and old != value_digest:
                result.conflict = True
            if old == value_digest:
                result.mirrors += 1
                self.diagnostics.add("duplicate_output_record", env.line)
            result.complete = complete if old is None else result.complete and complete
            result.output_digest = value_digest
            result.shell_wrapper_status = status
            result.text_exit_code = text_code
            # Text is provisional and not a known outcome until the tool joins.
            status = "pending" if status == "pending" else "unknown"
            result.text_status = status
        if result.conflict:
            self.diagnostics.add("conflicting_output_identity", env.line)
        return Fact("outcome", env.line, env.ordinal, key=key, digest=value_digest,
                    status=status, complete=complete, reason="structured" if structured else "output")

    def _usage(self, env: Envelope) -> Fact:
        # Select numeric fields only; never retain model/rate-limit/free-text fields.
        p = env.payload
        def counters(value: Any) -> Any:
            if value is None:
                return None
            if not isinstance(value, dict):
                return {"invalid": True}
            keys = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens",
                    "total_tokens", "cache_write_input_tokens")
            return {key: (value[key] if type(value[key]) is int and 0 <= value[key] <= 2**63-1 else None)
                    for key in keys if key in value}
        if env.kind == "token_usage_record":
            usage = {key: _id(p.get(key)) for key in ("thread_id", "session_id", "turn_id", "response_id", "root_turn_id")}
            usage["usage"] = counters(p.get("usage"))
            reason = "response_ledger"
        else:
            info = p.get("info")
            usage = ({"total_token_usage": counters(info.get("total_token_usage")),
                      "last_token_usage": counters(info.get("last_token_usage"))}
                     if isinstance(info, dict) else {"info": None})
            reason = "legacy"
        return Fact("usage", env.line, env.ordinal, usage=usage, reason=reason)

    def _adapt(self, env: Envelope) -> Iterator[Fact]:
        p, kind = env.payload, env.kind
        if any(p.get(key) is not None and p.get(key) is not False for key in
               ("history_base", "forked_from_id", "parent_thread_id", "parent_session_id", "is_subagent")):
            self.state.inherited_scope = True
            self.diagnostics.add("unsupported_inherited_scope", env.line)
        if kind == "session_meta":
            yield self._session(env)
            return
        if self.state.thread is None:
            self.state.inconsistent_metadata = True
            self.diagnostics.add("missing_session_metadata", env.line)
        if kind == "turn_context":
            self._turn = _id(p.get("turn_id"))
            self._context = digest(["cwd", p.get("cwd") if isinstance(p.get("cwd"), str) else None])
            yield self._barrier(env.line, "turn_context", env.ordinal)
        elif kind == "token_usage_record":
            yield self._usage(env)
        elif kind == "compacted":
            yield self._barrier(env.line, "compaction", env.ordinal)
        elif kind == "response_item" and p.get("type") in {"function_call", "custom_tool_call"}:
            fact = self._call(env)
            if fact.kind == "request" and fact.reason:
                yield self._barrier(env.line, fact.reason, env.ordinal)
            yield fact
        elif kind == "response_item" and p.get("type") in {"function_call_output", "custom_tool_call_output"}:
            yield self._result(env, False)
        elif (kind == "response_item" and p.get("type") == "message"
              and isinstance(p.get("role"), str)
              and p.get("role") in {"user", "assistant", "system", "developer"}):
            if p.get("role") == "user":
                self._turn = None
            yield self._barrier(env.line, "message_boundary", env.ordinal)
        elif kind == "response_item" and p.get("type") == "reasoning":
            yield self._barrier(env.line, "reasoning_boundary", env.ordinal)
        elif kind == "event_msg":
            subtype = p.get("type")
            if subtype == "token_count":
                yield self._usage(env)
            elif subtype in {"exec_command_end", "patch_apply_end", "mcp_tool_call_end"}:
                yield self._result(env, True)
                if subtype != "exec_command_end":
                    yield self._barrier(env.line, "state_change_or_opaque", env.ordinal)
            elif subtype in {"task_started", "turn_started", "task_complete", "turn_complete", "turn_aborted",
                             "user_message", "agent_message", "exec_command_begin", "patch_apply_begin", "mcp_tool_call_begin"}:
                if subtype in {"task_started", "turn_started"}:
                    self._turn = _id(p.get("turn_id"))
                elif subtype in {"task_complete", "turn_complete", "turn_aborted", "user_message"}:
                    self._turn = None
                yield self._barrier(env.line, "event_boundary", env.ordinal)
            else:
                self.state.unknown_events += 1
                self.diagnostics.add("unknown_event", env.line)
                yield self._barrier(env.line, "unknown_event", env.ordinal)
        else:
            self.state.unknown_events += 1
            self.diagnostics.add("unknown_event", env.line)
            yield self._barrier(env.line, "unknown_event", env.ordinal)

    def facts(self, reader: RolloutReader) -> Iterator[Fact]:
        if self._started:
            raise ValueError("normalizer_already_used")
        self._started = True
        for item in reader:
            if isinstance(item, Barrier):
                yield self._barrier(item.line, item.reason)
            else:
                unknown_before = self.state.unknown_events
                yield from self._adapt(item)
                if unknown_before == self.state.unknown_events:
                    self.state.recognized_events += 1
                    if item.kind != "session_meta":
                        self.state.native_events += 1
            if self.state.analysis_truncated:
                break
        self.state.analysis_truncated |= reader.state.analysis_truncated or not reader.state.finished
        if reader.state.input_changed:
            self.state.analysis_truncated = True
        self._finalize()
        if not self.state.format_supported:
            self.diagnostics.add("unsupported_format")
        elif not self.state.native_events:
            self.diagnostics.add("metadata_only")
        self.state.finished = True

    def _finalize(self) -> None:
        for key, outcome in self._results.items():
            thread, scope, call_id = key
            candidates = self._index.get((thread, call_id), [])
            if scope == "?":
                if len(candidates) != 1:
                    self.state.orphan_outputs += 1
                    if candidates:
                        for candidate in candidates:
                            self._requests[candidate].ambiguous = True
                        self.diagnostics.add("ambiguous_output_identity", outcome.line)
                    else:
                        self.diagnostics.add("orphan_output", outcome.line)
                    continue
                target = self._requests[candidates[0]]
            else:
                target = self._requests.get(key)
                if target is None:
                    self.state.orphan_outputs += 1
                    self.diagnostics.add("orphan_output", outcome.line)
                    continue
            if target.output_line is not None:
                # Explicit- and unknown-turn copies cannot upgrade completeness.
                if ((outcome.output_digest is not None and target.output_digest is not None
                     and outcome.output_digest != target.output_digest)
                    or (outcome.structured_digest is not None and target.structured_digest is not None
                        and outcome.structured_digest != target.structured_digest)):
                    target.invalid = True
            had_output = target.output_digest is not None
            target.output_line = min(target.output_line or outcome.line, outcome.line)
            target.output_digest = outcome.output_digest or target.output_digest
            target.structured_digest = outcome.structured_digest or target.structured_digest
            shell_request = target.command_family is not None
            # command_family has separate entries for ordinary shell operations.
            target.text_status = (outcome.shell_wrapper_status if shell_request and outcome.shell_wrapper_status != "unknown"
                                  else outcome.text_status if outcome.text_status != "unknown" else target.text_status)
            target.structured_status = outcome.structured_status if outcome.structured_status != "unknown" else target.structured_status
            if outcome.output_digest is not None:
                target.complete = target.complete and outcome.complete if had_output else outcome.complete
            target.invalid |= outcome.conflict
            target.duplicate_outputs += outcome.mirrors
            if outcome.exit_code is not None:
                target.exit_code = outcome.exit_code
            if shell_request and outcome.text_exit_code is not None:
                target.text_exit_code = outcome.text_exit_code
        for target in self._requests.values():
            if target.text_exit_code is not None and target.text_exit_code != 0:
                target.text_status = ("no_match" if target.text_exit_code == 1 and target.command_family == "search"
                                      else "failure" if target.command_family == "test" else "unknown")
            if target.exit_code is not None and target.exit_code != 0 and target.structured_status != "denied":
                target.structured_status = ("no_match" if target.exit_code == 1 and target.command_family == "search"
                                            else "failure" if target.command_family == "test" else "unknown")
            statuses = {s for s in (target.text_status, target.structured_status) if s != "unknown"}
            if len(statuses) > 1:
                target.invalid = True
                self.diagnostics.add("outcome_status_conflict", target.output_line or 0)
            target.status = next(iter(statuses)) if len(statuses) == 1 else "unknown"
            if target.invalid or target.ambiguous:
                target.status, target.complete = "unknown", False

    def correlations(self) -> Iterator[Correlation]:
        if not self.state.finished:
            raise ValueError("correlations_not_final")
        yield from self._requests.values()
