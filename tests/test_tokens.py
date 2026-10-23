import unittest
from agent_loop_audit.normalize import Normalizer
from agent_loop_audit.parser import RolloutReader
from agent_loop_audit.tokens import TokenAccountant
from .support import encode, input_file, meta, event


def vector(total):
    return {"input_tokens": total, "output_tokens": 0, "total_tokens": total}


def legacy(total):
    return event("event_msg", {"type": "token_count", "info": {"total_token_usage": vector(total)}})


def ledger(identity, total, **extra):
    return event("token_usage_record", {"thread_id": "synthetic-thread", "response_id": identity,
                                         "usage": vector(total), **extra})


def account(records):
    with input_file(encode(records)) as path:
        with RolloutReader(path) as reader:
            n, t = Normalizer(), TokenAccountant()
            for fact in n.facts(reader):
                t.consume(fact)
        return t.finish(n.state.thread, n.state.root, inherited=n.state.inherited_scope,
                        unsupported=not n.state.format_supported)


class TokenTests(unittest.TestCase):
    def test_hand_calculated_legacy_oracles(self):
        for values, expected in [([100,150,150,200],100), ([100,150,20,60,150],50), ([0,0],0), ([100],None)]:
            result = account([meta()] + [legacy(v) for v in values])
            self.assertEqual(result["observed"]["total_tokens"] if result["observed"] else None, expected)
            self.assertFalse(result["complete"])

    def test_gap_compaction_and_last_only(self):
        bad = event("event_msg", {"type":"token_count", "info":None})
        result = account([meta(), legacy(100), bad, legacy(170), legacy(200)])
        self.assertEqual(result["observed"]["total_tokens"], 30)
        self.assertIsNone(account([meta(),legacy(100),event("compacted",{}),legacy(160),legacy(190)])["observed"])
        last = event("event_msg", {"type":"token_count", "info":{"last_token_usage":vector(50)}})
        self.assertIsNone(account([meta(), last, last])["observed"])

    def test_dedup_conflict_and_late_mode_selection(self):
        result = account([meta(), ledger("a",40),ledger("a",40),ledger("b",60)])
        self.assertEqual(result["observed"]["total_tokens"],100)
        self.assertEqual(result["observations"],2)
        self.assertIsNone(account([meta(),ledger("a",40),ledger("a",45)])["observed"])
        result = account([meta(),legacy(100),legacy(200),ledger("b",30)])
        self.assertEqual(result["observed"]["total_tokens"],30)
        self.assertEqual(result["mode"],"response_ledger")

    def test_invalid_and_missing_components(self):
        for invalid in (True, 1.0, "1", -1, 2**64):
            row = ledger("a",40)
            row["payload"]["usage"]["input_tokens"] = invalid
            self.assertIsNone(account([meta(),row])["observed"])
        row = ledger("b",60)
        del row["payload"]["usage"]["output_tokens"]
        result = account([meta(),ledger("a",40),row])
        self.assertIsNone(result["observed"]["output_tokens"])
        self.assertEqual(result["observed"]["total_tokens"],100)

    def test_owned_inherited_nested_and_component_relations(self):
        result = account([meta(session_id="root",history_base="synthetic"),ledger("p",900,thread_id="parent"),ledger("c",30,session_id="root")])
        self.assertEqual(result["observed"]["total_tokens"],30)
        row = ledger("a",130)
        row["payload"]["usage"] = {"input_tokens":100,"cached_input_tokens":20,"output_tokens":30,"reasoning_output_tokens":10,"total_tokens":130}
        result = account([meta(),event("compacted",{"latest_token_usage_record":row["payload"]}),row])
        self.assertEqual(result["observed"]["total_tokens"],130)
        row["payload"]["usage"]["cached_input_tokens"] = 101
        self.assertIsNone(account([meta(),row])["observed"])
