"""Observed partial usage only. Ledger selection is global, never mixed with deltas."""

FIELDS = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens",
          "total_tokens", "cache_write_input_tokens")
GAPS = {"malformed_record", "incomplete_tail", "oversize_record", "unknown_event",
        "input_io_error", "invalid_session_metadata", "analysis_truncated"}


def validate(value):
    if not isinstance(value, dict) or not value or "invalid" in value:
        return None
    if any(key not in FIELDS or type(count) is not int or not 0 <= count <= 2**63-1
           for key, count in value.items()):
        return None
    if ("input_tokens" in value and value.get("cached_input_tokens", 0) > value["input_tokens"]
            or "output_tokens" in value and value.get("reasoning_output_tokens", 0) > value["output_tokens"]):
        return None
    return dict(value)


def aggregate(vectors):
    result = None
    count = 0
    for value in vectors:
        if result is None:
            result = {key: value.get(key) for key in FIELDS}
        else:
            for key in FIELDS:
                result[key] = (result[key] + value[key]
                               if result[key] is not None and key in value else None)
        count += 1
    return result, count


class TokenAccountant:
    def __init__(self, max_identities=50_000):
        self.max_identities = max_identities
        self.ledger_seen = False
        self.truncated = False
        self._ledger = {}
        self._conflicts = set()
        self._reasons = set()
        self._legacy_reasons = set()
        self._baseline = None
        self._baseline_line = None
        self._last = None
        self._sum = None
        self._intervals = []
        self._interval_count = 0
        self._suspended = False
        self._legacy_count = 0
        self._invalid = 0
        self._mirrors = 0

    def consume(self, fact):
        if fact.kind == "barrier":
            if fact.reason == "compaction":
                self._suspended = True
                self._legacy_reasons.add("compaction")
            elif fact.reason in GAPS:
                self._baseline = None
                self._legacy_reasons.add("coverage_gap")
            return
        if fact.kind != "usage":
            return
        observation = fact.usage or {}
        if fact.reason == "response_ledger":
            self.ledger_seen = True
            thread, response = observation.get("thread_id"), observation.get("response_id")
            if not thread or not response:
                self._invalid += 1
                self._reasons.add("missing_ownership_or_identity")
                return
            key = (thread, response)
            value = validate(observation.get("usage"))
            record = (observation.get("session_id"), observation.get("turn_id"),
                      observation.get("root_turn_id"), value)
            if key in self._ledger:
                if self._ledger[key][0] != record:
                    self._conflicts.add(key)
                    self._reasons.add("conflicting_response_identity")
                else:
                    self._mirrors += 1
            elif len(self._ledger) < self.max_identities:
                self._ledger[key] = (record, fact.line)
            else:
                self.truncated = True
                self._reasons.add("analysis_truncated")
            return
        self._legacy_count += 1
        value = validate(observation.get("total_token_usage"))
        if value is None or not {"input_tokens", "output_tokens", "total_tokens"} <= value.keys():
            self._baseline = None
            self._legacy_reasons.add("unsupported_usage")
            return
        self._last = value
        if self._suspended:
            return
        if self._baseline is not None and value.keys() != self._baseline.keys():
            self._baseline = None
            self._legacy_reasons.add("component_set_changed")
        if self._baseline is not None:
            delta = {key: value[key] - self._baseline[key] for key in value}
            if any(x < 0 for x in delta.values()):
                self._suspended = True
                self._legacy_reasons.add("ambiguous_reset")
            elif validate(delta) is not None:
                if self._sum is None:
                    self._sum = {key: delta.get(key) for key in FIELDS}
                else:
                    for key in FIELDS:
                        self._sum[key] = (self._sum[key] + delta[key]
                                          if self._sum[key] is not None and key in delta else None)
                self._interval_count += 1
                if len(self._intervals) < 20:
                    self._intervals.append([self._baseline_line, fact.line])
            else:
                self._legacy_reasons.add("inconsistent_delta")
        else:
            self._legacy_reasons.add("baseline_excluded")
        self._baseline, self._baseline_line = value, fact.line

    def finish(self, thread, root=None, *, inherited=False, unsupported=False, truncated=False):
        reasons = {"observed_only"}
        excluded = self._invalid
        if self.ledger_seen:
            reasons |= self._reasons
            included = []
            lines = []
            for (owner, response), (record, line) in self._ledger.items():
                session, turn, root_turn, value = record
                if (owner, response) in self._conflicts or value is None:
                    excluded += 1
                    reasons.add("invalid_or_conflicting_usage")
                elif unsupported or owner != thread or (session is not None and session != (root or thread)):
                    excluded += 1
                    reasons.add("nonowned_usage")
                else:
                    included.append(value)
                    if len(lines) < 20:
                        lines.append([line, line])
            observed, count = aggregate(included)
            if self.truncated:
                observed = None
            if self._legacy_count:
                reasons.add("legacy_excluded")
            mode, intervals, interval_count, last = "response_ledger", lines, count, None
            excluded += self._legacy_count + self._mirrors
        else:
            reasons |= self._legacy_reasons
            observed, last = self._sum, self._last
            if inherited or unsupported:
                observed = None
                reasons.add("unsupported_scope")
            mode, intervals, interval_count = "legacy_observed_deltas", self._intervals, self._interval_count
        if truncated or self.truncated:
            reasons.add("analysis_truncated")
        if observed is None:
            reasons.add("usage_unavailable")
        return {"mode": mode, "observed": observed, "last_reported_counter": last,
                "coverage": "partial" if observed is not None else "unavailable", "complete": False,
                "reason_codes": sorted(reasons), "excluded_records": excluded,
                "observations": interval_count, "interval_lines": intervals,
                "evidence_truncated": interval_count > 20}
