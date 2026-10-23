"""Bounded exact observation rules. Final outcome evidence is required for warnings."""

from collections import deque
from dataclasses import dataclass, field

from .fingerprint import EXCLUDED, read_like, tool_kind
from .models import Fact, Key
from .normalize import digest


@dataclass(slots=True)
class _Call:
    key: Key | None
    line: int
    segment: int
    fingerprint: str
    label: str
    warning: bool
    read: bool


@dataclass(slots=True)
class Finding:
    rule_id: str
    tool_label: str
    occurrences: int
    call_lines: list[int]
    outcome_lines: list[int]
    first: int
    last: int
    evidence_truncated: bool = False
    start_index: int = 0
    end_index: int = 0
    block_size: int = 1


class RuleEngine:
    def __init__(self, max_findings: int = 2000):
        self.max_findings = max_findings
        self._calls: list[_Call] = []
        self._segment = 0
        self._tools: dict[str, str] = {}
        self._unknown_count = 0
        self._pending_opaque = False
        self._last_opaque = False
        self.findings_truncated = False
        self.omitted = 0

    def consume(self, fact: Fact) -> None:
        if fact.kind == "barrier":
            if fact.reason == "opaque_operation":
                self._pending_opaque = True
            else:
                self._segment += 1
                self._pending_opaque = self._last_opaque = False
        elif fact.kind == "request":
            if self._pending_opaque:
                if not self._last_opaque or not self._calls or self._calls[-1].fingerprint != fact.digest:
                    self._segment += 1
                self._last_opaque = True
                self._pending_opaque = False
            elif self._last_opaque:
                self._segment += 1
                self._last_opaque = False
            kind = tool_kind(fact.tool)
            token = digest(fact.tool)
            if token not in self._tools:
                if kind is None:
                    self._unknown_count += 1
                self._tools[token] = kind or "tool_" + format(self._unknown_count, "03d")
            self._calls.append(_Call(fact.key, fact.line, self._segment, fact.digest or "",
                                     self._tools[token], bool(kind and kind not in EXCLUDED),
                                     read_like(fact.tool, fact.arguments or "")))

    def finish(self, correlations, eligible: bool) -> list[Finding]:
        if not eligible:
            return []
        outcomes = {row.key: row for row in correlations}
        window = deque(maxlen=64)
        retained: list[Finding] = []
        active: dict[tuple, Finding | None] = {}
        segment = None

        def candidate(rule, sequence, rows, block=1):
            key = (rule, sequence)
            old = active.get(key)
            if old is not None and rows[0][0] <= old.end_index:
                new = [r for r in rows if r[0] > old.end_index]
                old.occurrences += len(new)
                old.last, old.end_index = rows[-1][1].line, rows[-1][0]
                for _, call, outcome in new:
                    if len(old.call_lines) < 20:
                        old.call_lines.append(call.line)
                    if outcome and outcome.output_line and len(old.outcome_lines) < 20:
                        old.outcome_lines.append(outcome.output_line)
                old.evidence_truncated = old.occurrences > 20
                return
            if key in active and old is None:
                return
            if len(retained) >= self.max_findings:
                self.omitted += 1
                self.findings_truncated = True
                active[key] = None
                return
            new = Finding(rule, rows[0][1].label, len(rows), [r[1].line for r in rows[:20]],
                          [r[2].output_line for r in rows if r[2] and r[2].output_line][:20],
                          rows[0][1].line, rows[-1][1].line, len(rows) > 20,
                          rows[0][0], rows[-1][0], block)
            retained.append(new)
            active[key] = new

        def signature(row):
            call, outcome = row[1], row[2]
            if not call.warning or not outcome or not outcome.complete or outcome.invalid or outcome.ambiguous:
                return None
            if outcome.status not in {"success", "failure", "no_match"}:
                return None
            return (call.fingerprint, outcome.status, outcome.output_digest or "", outcome.structured_digest or "")

        for index, call in enumerate(self._calls):
            outcome = outcomes.get(call.key)
            if segment != call.segment:
                window.clear()
                active.clear()
                segment = call.segment
            if call.key is None or not outcome or outcome.invalid or outcome.ambiguous:
                window.clear()
                active.clear()
                continue
            window.append((index, call, outcome))
            rows = list(window)
            # Evict inactive candidate keys; all retained findings remain capped.
            active = {k: v for k, v in active.items() if v is None or v.end_index >= index - 64}
            same = [r for r in rows if r[1].fingerprint == call.fingerprint]
            if len(same) >= 3:
                candidate("ALA001", call.fingerprint, same)
            sig = signature(rows[-1])
            if sig is not None:
                run = []
                for row in reversed(rows):
                    if signature(row) != sig:
                        break
                    run.append(row)
                run.reverse()
                if len(run) >= 3 and outcome.status == "failure":
                    candidate("ALA002", sig, run)
                if len(run) >= 3 and outcome.status == "success" and all(r[1].read for r in run):
                    candidate("ALA004", sig, run)
            best = None
            for size in (2, 3, 4):
                if len(rows) < size * 3:
                    continue
                block = tuple(signature(r) for r in rows[-size:])
                if any(s is None for s in block) or not any(s[1] == "failure" for s in block):
                    continue
                if len({s[0] for s in block}) < 2:
                    continue
                count = size
                while count + size <= len(rows):
                    previous = tuple(signature(r) for r in rows[-count-size:-count])
                    if previous != block:
                        break
                    count += size
                if count >= size * 3 and (best is None or (count, -size) > (best[0], -best[1])):
                    best = count, size, block
            if best:
                count, size, block = best
                # Rotation-independent identity merges contiguous phases.
                canonical = min(tuple(block[i:] + block[:i]) for i in range(size))
                candidate("ALA003", canonical, rows[-count:], size)
        cycles = [f for f in retained if f.rule_id == "ALA003"]
        warnings = [f for f in retained if f.rule_id in {"ALA002", "ALA004"}]
        result = []
        for finding in retained:
            if finding.rule_id != "ALA003" and any(c.start_index <= finding.start_index and c.end_index >= finding.end_index for c in cycles):
                continue
            if finding.rule_id == "ALA001" and any((f.start_index, f.end_index, f.occurrences) ==
                    (finding.start_index, finding.end_index, finding.occurrences) for f in warnings):
                continue
            result.append(finding)
        priority = {"ALA002": 0, "ALA003": 1, "ALA004": 2, "ALA001": 3}
        return sorted(result, key=lambda f: (priority[f.rule_id], f.first, f.last))
