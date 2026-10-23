import json
import unittest
from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import RolloutReader
from agent_loop_audit.rules import RuleEngine
from .support import call, output, meta, event, encode, input_file


def detect(records, cap=2000):
    with input_file(encode(records)) as path:
        engine = RuleEngine(cap)
        with RolloutReader(path) as reader:
            n = Normalizer()
            for fact in n.facts(reader):
                engine.consume(fact)
        return engine, engine.finish(n.correlations(), n.state.behavior_eligible)


def repeats(count=3, code=1, cmd="python -m unittest", **options):
    records = [meta()]
    for i in range(count):
        records += [call(str(i), json.dumps({"cmd": cmd, **options})),
                    output(str(i), f"Wall time: 0.1 seconds\nExit code: {code}\nOutput:\ninvented result")]
    return records


class RuleTests(unittest.TestCase):
    def test_failure_threshold_and_overlap(self):
        self.assertEqual(detect(repeats(2))[1], [])
        rows = detect(repeats())[1]
        self.assertEqual([r.rule_id for r in rows], ["ALA002"])
        self.assertEqual(rows[0].call_lines, [2, 4, 6])
        self.assertEqual(rows[0].outcome_lines, [3, 5, 7])

    def test_read_and_info_changed_results(self):
        self.assertEqual([r.rule_id for r in detect(repeats(code=0, cmd="cat a", shell="bash"))[1]], ["ALA004"])
        self.assertEqual([r.rule_id for r in detect(repeats(code=1, cmd="rg needle file"))[1]], ["ALA001"])
        data = repeats()
        data[-1]["payload"]["output"] += " changed"
        self.assertEqual([r.rule_id for r in detect(data)[1]], ["ALA001"])

    def test_barriers_conflicts_and_inherited(self):
        data = repeats()
        data.insert(4, event("response_item", {"type": "message", "role": "user", "content": []}))
        self.assertEqual(detect(data)[1], [])
        self.assertEqual(detect(repeats() + [call("0", '{"cmd":"changed"}')])[1], [])
        data = repeats()
        data[0] = meta(history_base="synthetic")
        self.assertEqual(detect(data)[1], [])

    def test_exact_cycle(self):
        data = [meta()]
        for i in range(6):
            cmd = "python -m unittest" if i % 2 == 0 else "pytest unit"
            data += [call(str(i), json.dumps({"cmd": cmd})), output(str(i), "Wall time: 0.1 seconds\nExit code: 1\nOutput:\nsynthetic")]
        rows = detect(data)[1]
        self.assertEqual([r.rule_id for r in rows], ["ALA003"])
        self.assertEqual(rows[0].occurrences, 6)

    def test_long_runs_and_evidence_cap(self):
        rows = detect(repeats(80))[1]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].occurrences, 80)
        self.assertEqual(len(rows[0].call_lines), 20)
        self.assertTrue(rows[0].evidence_truncated)

    def test_poll_unknown_and_pending_are_not_warnings(self):
        for cmd in ("opaque command", "rg needle file"):
            self.assertFalse(any(f.rule_id != "ALA001" for f in detect(repeats(cmd=cmd))[1]))
        data = repeats()
        for r in data:
            if r["payload"].get("type") == "function_call_output":
                r["payload"]["output"] = "Process running with session ID 123"
        self.assertEqual([r.rule_id for r in detect(data)[1]], ["ALA001"])

    def test_unknown_information_and_seeded_negative_variations(self):
        import random
        rng = random.Random(20261023)
        for _ in range(8):
            data = repeats()
            for row in data:
                if row["payload"].get("type") == "function_call":
                    row["payload"]["name"] = "invented_unknown_tool"
            findings = detect(data)[1]
            self.assertEqual([(f.rule_id,f.tool_label) for f in findings], [("ALA001","tool_001")])
            selected = rng.choice([1,3,5])
            data[selected]["payload"]["arguments"] += " " + str(rng.randrange(10000))
            self.assertEqual(detect(data)[1], [])
