"""Single-descriptor snapshot reader. No log-referenced path is ever opened."""

import json
from datetime import datetime
import math
import os
from pathlib import Path
import stat
from typing import Iterator

from .models import Barrier, Diagnostics, Envelope, Limits, ParseState


class InputError(Exception):
    """Only a fixed code is exposed, never an OS exception or input path."""


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def strict_json(text: str, limits: Limits) -> object:
    """Reject ambiguous JSON before it can affect identity or fingerprints."""
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limits.json_depth:
                raise ValueError("json_depth")
        elif char in "]}":
            depth -= 1

    def integer(value: str) -> int:
        if len(value.lstrip("-")) > limits.integer_digits:
            raise ValueError("integer_size")
        return int(value)

    def floating(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite")
        return result

    def constant(_: str) -> object:
        raise ValueError("nonfinite")

    result = json.loads(text, object_pairs_hook=_pairs, parse_int=integer,
                        parse_float=floating, parse_constant=constant)
    # Python accepts lone escaped surrogates, but they are not valid UTF-8 text.
    stack = [result]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            value.encode("utf-8", "strict")
        elif isinstance(value, dict):
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return result


def _reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


class RolloutReader:
    """Use as a context manager; iterate once, consume each envelope immediately."""

    def __init__(self, path: str | os.PathLike, limits: Limits | None = None):
        self._path = Path(path)
        self.limits = limits or Limits()
        self.state = ParseState()
        self.diagnostics = Diagnostics(self.limits.diagnostic_codes)
        self._file = None
        self._started = False
        self._initial = None

    def __enter__(self) -> "RolloutReader":
        if self._path.suffix.lower() != ".jsonl":
            raise InputError("unsupported_input")
        fd = None
        try:
            before = self._path.lstat()
            if _reparse(before) or not stat.S_ISREG(before.st_mode):
                raise InputError("nonregular_input")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(self._path, flags)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or _reparse(info)
                    or _identity(info) != _identity(before)):
                raise InputError("input_changed")
            if info.st_size > self.limits.snapshot_bytes:
                raise InputError("input_too_large")
            self._initial = info
            self._file = os.fdopen(fd, "rb", buffering=0)
            fd = None
        except (OSError, ValueError):
            raise InputError("unreadable_input") from None
        finally:
            if fd is not None:
                os.close(fd)
        return self

    def _check_changed(self) -> None:
        try:
            current = os.fstat(self._file.fileno())
            path_now = self._path.lstat()
            old = self._initial
            changed = (current.st_size != old.st_size
                       or current.st_mtime_ns != old.st_mtime_ns
                       or _identity(path_now) != _identity(old) or _reparse(path_now))
        except OSError:
            changed = True
        if changed and not self.state.input_changed:
            self.state.input_changed = True
            self.diagnostics.add("input_changed", self.state.physical_lines)

    def __exit__(self, *args: object) -> None:
        if self._file is not None:
            self._check_changed()
            self._file.close()
            self._file = None

    def _lines(self) -> Iterator[tuple[bytes | None, bool]]:
        remaining = self._initial.st_size
        pending = bytearray()
        oversize = False
        while remaining:
            chunk = self._file.read(min(65536, remaining))
            if not chunk:
                self.state.input_changed = True
                self.diagnostics.add("input_changed", self.state.physical_lines)
                break
            remaining -= len(chunk)
            self.state.bytes_read += len(chunk)
            start = 0
            while start < len(chunk):
                end = chunk.find(b"\n", start)
                stop = len(chunk) if end < 0 else end + 1
                part = chunk[start:stop]
                if not oversize:
                    if len(pending) + len(part) > self.limits.line_bytes:
                        pending.clear()
                        oversize = True
                    else:
                        pending.extend(part)
                if end >= 0:
                    yield (None if oversize else bytes(pending)), False
                    pending.clear()
                    oversize = False
                start = stop
        if pending or oversize:
            yield (None if oversize else bytes(pending)), True

    def __iter__(self) -> Iterator[Envelope | Barrier]:
        if self._file is None or self._started:
            raise InputError("invalid_reader_lifecycle")
        self._started = True
        try:
            for raw, tail in self._lines():
                self.state.physical_lines += 1
                line = self.state.physical_lines
                if raw is None:
                    self.state.skipped += 1
                    self.diagnostics.add("oversize_record", line)
                    yield Barrier(line, "oversize_record")
                    continue
                if line == 1 and raw.startswith(b"\xef\xbb\xbf"):
                    raw = raw[3:]
                if not raw.strip():
                    self.state.blank += 1
                    continue
                try:
                    text = raw.decode("utf-8", "strict")
                    obj = strict_json(text, self.limits)
                except (UnicodeError, ValueError, RecursionError, OverflowError):
                    code = "incomplete_tail" if tail else "malformed_record"
                    self.state.skipped += 1
                    self.diagnostics.add(code, line)
                    yield Barrier(line, code)
                    continue
                if (not isinstance(obj, dict) or not isinstance(obj.get("type"), str)
                        or not isinstance(obj.get("payload"), dict)
                        or (obj.get("type") in {"response_item", "event_msg"}
                            and not isinstance(obj["payload"].get("type"), str))):
                    self.state.skipped += 1
                    self.diagnostics.add("malformed_record", line)
                    yield Barrier(line, "malformed_record")
                    continue
                ordinal = obj.get("ordinal")
                if ordinal is not None and (type(ordinal) is not int or not 0 <= ordinal <= 2**63 - 1):
                    self.state.skipped += 1
                    self.diagnostics.add("malformed_record", line)
                    yield Barrier(line, "malformed_record")
                    continue
                if self.state.parsed >= self.limits.envelopes:
                    self.state.analysis_truncated = True
                    self.diagnostics.add("analysis_truncated", line)
                    yield Barrier(line, "analysis_truncated")
                    break
                try:
                    timestamp = obj.get("timestamp")
                    if not isinstance(timestamp, str) or len(timestamp) > 64:
                        raise ValueError
                    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    self.diagnostics.add("timestamp_unavailable", line)
                self.state.parsed += 1
                yield Envelope(line, obj["type"], obj["payload"], ordinal)
                # Do not retain a previous envelope while asking for the next.
                del obj, text, raw
            self.state.finished = True
        except OSError:
            self.state.input_changed = True
            self.diagnostics.add("input_io_error", self.state.physical_lines)
            yield Barrier(self.state.physical_lines, "input_io_error")
        finally:
            self._check_changed()
