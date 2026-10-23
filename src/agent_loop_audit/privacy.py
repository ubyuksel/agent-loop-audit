"""Positive output allowlists. No regex-based redaction of arbitrary content."""

import re
from .fingerprint import KNOWN

CODES = frozenset({
    "unsupported_input", "nonregular_input", "input_changed", "input_too_large", "unreadable_input",
    "invalid_reader_lifecycle", "oversize_record", "incomplete_tail", "malformed_record",
    "analysis_truncated", "timestamp_unavailable", "input_io_error", "invalid_session_metadata",
    "inconsistent_session_metadata", "unsupported_inherited_scope", "unknown_context", "opaque_request",
    "retained_text_limit", "duplicate_request_record", "conflicting_request_identity", "missing_call_identity",
    "orphan_output", "duplicate_output_record", "conflicting_output_identity", "missing_session_metadata",
    "unknown_event", "unsupported_format", "metadata_only", "ambiguous_output_identity",
    "outcome_status_conflict", "observed_only", "coverage_gap", "compaction", "missing_ownership_or_identity",
    "conflicting_response_identity", "unsupported_usage", "component_set_changed", "ambiguous_reset",
    "inconsistent_delta", "baseline_excluded", "invalid_or_conflicting_usage", "nonowned_usage",
    "legacy_excluded", "unsupported_scope", "usage_unavailable", "audit_error", "interrupted",
    "findings_truncated", "partial_compatibility", "opaque_operation", "patch_operation", "state_change_or_opaque",
})


def integer(value, default=0):
    return value if type(value) is int and 0 <= value <= 2**63-1 else default


def code(value):
    return value if isinstance(value, str) and value in CODES else "audit_error"


def version(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:\.(?:dev)[0-9]{1,4})?", value) else None


def tool_label(value):
    if isinstance(value, str) and (value in KNOWN or re.fullmatch(r"tool_[0-9]{3,5}", value)):
        return value
    return "tool_001"
