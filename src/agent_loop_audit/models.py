"""Bounded internal types; no I/O and no public serialization API."""

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class Limits:
    snapshot_bytes: int = 256 * 1024 * 1024
    line_bytes: int = 2 * 1024 * 1024
    envelopes: int = 100_000
    identities: int = 50_000
    ledger_identities: int = 50_000
    retained_text_bytes: int = 8 * 1024 * 1024
    diagnostic_codes: int = 100
    json_depth: int = 64
    integer_digits: int = 128

    def __post_init__(self) -> None:
        if any(type(getattr(self, key)) is not int or getattr(self, key) < 1
               for key in self.__dataclass_fields__):
            raise ValueError("invalid_limits")


@dataclass(slots=True)
class Diagnostic:
    code: str
    line: int
    count: int = 1


@dataclass(slots=True)
class Diagnostics:
    limit: int = 100
    items: dict[str, Diagnostic] = field(default_factory=dict)
    omitted: int = 0

    def add(self, code: str, line: int = 0) -> None:
        if code in self.items:
            self.items[code].count += 1
        elif len(self.items) < self.limit:
            self.items[code] = Diagnostic(code, line)
        else:
            self.omitted += 1


@dataclass(frozen=True, slots=True)
class Envelope:
    line: int
    kind: str
    payload: dict[str, Any] = field(repr=False)
    ordinal: int | None = None


@dataclass(frozen=True, slots=True)
class Barrier:
    line: int
    reason: str


@dataclass(slots=True)
class ParseState:
    physical_lines: int = 0
    parsed: int = 0
    blank: int = 0
    skipped: int = 0
    bytes_read: int = 0
    input_changed: bool = False
    analysis_truncated: bool = False
    finished: bool = False


Status = Literal["unknown", "success", "failure", "no_match", "pending", "denied", "aborted"]
Key = tuple[str | None, str, str]


@dataclass(frozen=True, slots=True)
class Fact:
    """Ephemeral consumer input. Never collect or serialize the raw text fields."""

    kind: str
    line: int
    ordinal: int | None = None
    key: Key | None = field(default=None, repr=False)
    tool: tuple[str | None, str] | None = field(default=None, repr=False)
    arguments: str | None = field(default=None, repr=False)
    context: str | None = field(default=None, repr=False)
    digest: str | None = field(default=None, repr=False)
    status: Status = "unknown"
    complete: bool = False
    reason: str | None = None
    usage: dict[str, Any] | None = field(default=None, repr=False)


@dataclass(slots=True)
class Correlation:
    """Digest/line summary only. Authoritative after normalizer completion."""

    key: Key = field(repr=False)
    call_line: int | None = None
    request_digest: str | None = field(default=None, repr=False)
    output_line: int | None = None
    output_digest: str | None = field(default=None, repr=False)
    structured_digest: str | None = field(default=None, repr=False)
    text_status: Status = "unknown"
    structured_status: Status = "unknown"
    status: Status = "unknown"
    complete: bool = False
    invalid: bool = False
    ambiguous: bool = False
    duplicate_requests: int = 0
    duplicate_outputs: int = 0
    exit_code: int | None = None
    text_exit_code: int | None = None
    command_family: str | None = None
