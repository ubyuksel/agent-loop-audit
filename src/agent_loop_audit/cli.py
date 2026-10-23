"""Single-file offline command line. The audit path has no subprocess/network use."""

import argparse
import io
import json
import sys

from . import __version__
from .normalize import Normalizer
from .parser import InputError, RolloutReader
from .report import make_report, render_text
from .rules import RuleEngine
from .tokens import TokenAccountant


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "agent-loop-audit: invalid_arguments\n")


def audit(path, *, strict=False, fail_on_findings=False):
    reader, normalizer, engine, tokens = None, None, RuleEngine(), TokenAccountant()
    limitations = set()
    try:
        with RolloutReader(path) as reader:
            normalizer = Normalizer()
            for fact in normalizer.facts(reader):
                if fact.reason in {"opaque_operation", "opaque_request", "state_change_or_opaque"}:
                    limitations.add(fact.reason)
                engine.consume(fact)
                tokens.consume(fact)
        state = normalizer.state
        eligible = state.behavior_eligible and not reader.state.input_changed and not tokens.truncated
        findings = engine.finish(normalizer.correlations(), eligible)
        usage = tokens.finish(state.thread, state.root, inherited=state.inherited_scope,
                              unsupported=not state.format_supported,
                              truncated=state.analysis_truncated or reader.state.input_changed)
        if tokens.truncated:
            limitations.add("analysis_truncated")
        report = make_report(reader, normalizer, engine, findings, usage, limitations=limitations)
        if not state.format_supported or "input_io_error" in reader.diagnostics.items:
            return report, 2
        if strict and (report["coverage"]["behavior"] != "supported" or usage["coverage"] != "complete"):
            return report, 3
        if fail_on_findings and any(f["level"] == "warning" for f in report["findings"]):
            return report, 1
        return report, 0
    except InputError as exc:
        return make_report(error=str(exc)), 2
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        return make_report(error="audit_error"), 2


def main(argv=None):
    parser = _Parser(prog="agent-loop-audit", description="Inspect one Codex rollout offline; repetition is not proof of waste.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    cmd = sub.add_parser("audit", help="Audit one explicit uncompressed JSONL input")
    cmd.add_argument("path")
    cmd.add_argument("--format", choices=("text", "json"), default="text")
    cmd.add_argument("--strict", action="store_true")
    cmd.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args(argv)
    try:
        report, status = audit(args.path, strict=args.strict, fail_on_findings=args.fail_on_findings)
    except KeyboardInterrupt:
        report, status = make_report(error="interrupted"), 130
    try:
        text = json.dumps(report, ensure_ascii=True, allow_nan=False, sort_keys=True) + "\n" if args.format == "json" else render_text(report)
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        sys.stdout = io.StringIO()
        return 0
    return status
