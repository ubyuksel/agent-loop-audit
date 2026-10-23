"""Fixed-schema public reports; raw facts and dataclasses are never serialized."""

from . import __version__
from .privacy import code, integer, tool_label, version
from .tokens import FIELDS

RULES = {
    "ALA001": ("Repeated requests observed", "Review whether each repetition answered a new question."),
    "ALA002": ("Repeated known failure review candidate", "Inspect the first failure and its prerequisite before repeating the same operation."),
    "ALA003": ("Exact cycle review candidate", "Review the repeated sequence and choose a different diagnostic step if its evidence is unchanged."),
    "ALA004": ("Repeated read result review candidate", "Reuse the earlier result if task state has not changed; narrow the next read to a new question."),
}


def _counts(value, maximum=2**63-1):
    if not isinstance(value, dict):
        return None
    return {name: value.get(name) if type(value.get(name)) is int and 0 <= value[name] <= maximum else None for name in FIELDS}


def usage_report(value):
    return {"mode": "response_ledger" if value.get("mode") == "response_ledger" else "legacy_observed_deltas",
            "observed": _counts(value.get("observed"), 100_000*(2**63-1)), "last_reported_counter": _counts(value.get("last_reported_counter")),
            "coverage": "partial" if value.get("observed") is not None else "unavailable", "complete": False,
            "reason_codes": sorted({code(c) for c in value.get("reason_codes", [])}),
            "excluded_records": integer(value.get("excluded_records")), "observations": integer(value.get("observations")),
            "interval_lines": [[integer(p[0]),integer(p[1])] for p in value.get("interval_lines", [])[:20]],
            "evidence_truncated": bool(value.get("evidence_truncated"))}


def make_report(reader=None, normalizer=None, engine=None, findings=(), usage=None, error=None, limitations=()):
    reasons = {code(value) for value in limitations}
    diagnostics = {}
    for collection in ((reader.diagnostics, normalizer.diagnostics) if reader and normalizer else ()):
        for item in collection.items.values():
            safe = code(item.code)
            if safe in diagnostics:
                diagnostics[safe]["count"] += integer(item.count)
            else:
                diagnostics[safe] = {"code": safe, "line": integer(item.line), "count": integer(item.count)}
    if error:
        safe = code(error)
        diagnostics[safe] = {"code": safe, "line": 0, "count": 1}
    reasons.update(diagnostics)
    state = normalizer.state if normalizer else None
    parsed = reader.state if reader else None
    supported = bool(state and state.format_supported)
    inherited = bool(state and state.inherited_scope)
    truncated = bool("analysis_truncated" in reasons or parsed and parsed.analysis_truncated or state and state.analysis_truncated)
    changed = bool(parsed and parsed.input_changed)
    if inherited:
        reasons.add("unsupported_inherited_scope")
    if truncated:
        reasons.add("analysis_truncated")
    if changed:
        reasons.add("input_changed")
    if engine and engine.findings_truncated:
        reasons.add("findings_truncated")
    public = []
    for finding in findings:
        if finding.rule_id not in RULES:
            continue
        title, recommendation = RULES[finding.rule_id]
        warning = finding.rule_id != "ALA001"
        public.append({"id": "F" + format(len(public)+1,"04d"), "rule_id": finding.rule_id,
                       "level": "warning" if warning else "info", "confidence": "review_candidate" if warning else "observation",
                       "title": title, "tool_label": tool_label(finding.tool_label),
                       "occurrences": integer(finding.occurrences), "call_lines": [integer(x) for x in finding.call_lines[:20]],
                       "outcome_lines": [integer(x) for x in finding.outcome_lines[:20]],
                       "span": [integer(finding.first), integer(finding.last)],
                       "evidence_status": "complete" if warning else "request_only",
                       "evidence_truncated": bool(finding.evidence_truncated), "recommendation": recommendation,
                       "caveats": ["Repetition does not establish waste.", "External state changes may be unlogged."]})
    rows = list(normalizer.correlations()) if normalizer and state.finished else []
    token = usage_report(usage or {})
    behavior = "unsupported" if not supported or inherited else "partial" if reasons else "supported"
    return {"schema_version": "1.0", "tool_version": version(__version__), "rules_version": "1.0.0",
            "source": {"label": "input_1", "format": "codex_rollout_jsonl" if supported else "unknown",
                       "cli_version": version(state.cli_version) if state else None},
            "coverage": {"behavior": behavior, "accounting": "observed_only" if token["observed"] is not None else "unavailable",
                         "complete": False, "reason_codes": sorted(reasons), "parsed_records": integer(parsed.parsed) if parsed else 0,
                         "skipped_records": integer(parsed.skipped) if parsed else 0, "unknown_records": integer(state.unknown_events) if state else 0,
                         "analysis_truncated": truncated, "input_changed": changed,
                         "findings_truncated": bool(engine and engine.findings_truncated),
                         "omitted_candidates": integer(engine.omitted) if engine else 0},
            "summary": {"distinct_observed_requests": len(rows), "linked_complete_outcomes": sum(r.complete for r in rows),
                        "uncorrelated_requests": integer(state.uncorrelated_requests) if state else 0,
                        "ambiguous_or_invalid": sum(r.invalid or r.ambiguous for r in rows), "total_findings": len(public)},
            "token_usage": token, "findings": public, "diagnostics": [diagnostics[k] for k in sorted(diagnostics)]}


def render_text(report):
    coverage = report["coverage"]
    lines = ["Agent Loop Audit", "Behavior coverage: " + coverage["behavior"],
             "Accounting: " + coverage["accounting"] + " (partial observations only)",
             "Distinct observed requests: " + str(report["summary"]["distinct_observed_requests"]),
             "Retained findings: " + str(len(report["findings"]))]
    for finding in report["findings"]:
        lines += [finding["id"] + " " + finding["rule_id"] + " " + finding["title"],
                  "  Tool: " + finding["tool_label"] + "; occurrences: " + str(finding["occurrences"]),
                  "  Call lines: " + ", ".join(map(str, finding["call_lines"])),
                  "  " + finding["recommendation"]]
    observed = report["token_usage"]["observed"]
    lines.append("Observed total tokens: " + (str(observed["total_tokens"]) if observed and observed["total_tokens"] is not None else "unavailable"))
    codes = sorted(set(coverage["reason_codes"]) | set(report["token_usage"]["reason_codes"]))
    if codes:
        lines.append("Coverage reasons: " + ", ".join(codes))
    lines.append("Repetition is an observation or review candidate, never proof of waste.")
    return "\n".join(lines) + "\n"
