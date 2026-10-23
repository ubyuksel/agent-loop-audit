"""Invented schema-shaped data only; no discovery of real logs."""

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile

from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import RolloutReader


def event(kind, payload, **extra):
    return {"timestamp": "2026-01-01T00:00:00Z", "type": kind, "payload": payload, **extra}


def meta(**extra):
    return event("session_meta", {"id": "synthetic-thread", "cwd": "/synthetic", "source": "cli", **extra})


def call(identity="c1", arguments='{"cmd":"python -m unittest"}', **extra):
    return event("response_item", {"type": "function_call", "call_id": identity,
                                  "name": "exec_command", "arguments": arguments, **extra})


def output(identity="c1", value="invented result", **extra):
    return event("response_item", {"type": "function_call_output", "call_id": identity,
                                  "output": value, **extra})


def encode(records):
    return b"".join(json.dumps(record, ensure_ascii=True).encode() + b"\n" for record in records)


@contextmanager
def input_file(data):
    with tempfile.TemporaryDirectory(prefix="ala-test-") as folder:
        path = Path(folder) / "synthetic.jsonl"
        path.write_bytes(data)
        yield path


def normalize(records, limits=None):
    with input_file(encode(records)) as path:
        before = hashlib.sha256(path.read_bytes()).digest()
        with RolloutReader(path, limits) as reader:
            normalizer = Normalizer(limits)
            facts = list(normalizer.facts(reader))  # Small synthetic cases only.
        assert hashlib.sha256(path.read_bytes()).digest() == before
        return normalizer, facts, list(normalizer.correlations())
