import json
import unittest

from nvg_scanner.checks.firewall_checks import run
from nvg_scanner.collectors import Context
from tests.fixtures import config, FakeCollector


def fixture(extra=None, policy="drop"):
    cfg = config()
    cfg["firewall"] = {"enabled": True, "require_ipv6": True, "require_default_deny": True, "accept_justifications": {}}
    records = [{"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "type": "filter", "policy": policy}}]
    records += extra or []
    return Context(cfg, FakeCollector(commands={"nft": json.dumps({"nftables": records}),
                                                "ss": "tcp LISTEN 0 128 127.0.0.1:9050 0.0.0.0:*\n"}))


def rule(*expressions):
    return {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": list(expressions)}}


class FirewallTests(unittest.TestCase):
    def test_drop_policy_covers_socket(self):
        results = list(run(fixture()))
        self.assertTrue(results)
        self.assertTrue(all(r.status == "pass" for r in results))
        self.assertEqual(next(r for r in results if ".socket." in r.id).evidence["source"], "chain_policy")

    def test_accept_without_justification_and_socket_fails(self):
        self.assertTrue(all(r.status == "fail" for r in run(fixture(policy="accept"))))

    def test_reject_is_rule_verdict_not_chain_policy(self):
        self.assertTrue(all(r.status == "pass" for r in run(fixture([rule({"reject": None})], "accept"))))
        results = list(run(fixture(policy="reject")))
        self.assertTrue(all(r.status == "warning" for r in results))
        self.assertIn("policy", results[0].reason)

    def test_excess_accept_even_without_socket(self):
        item = rule({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8332}}, {"accept": None})
        context = fixture([item]); context.collector.commands["ss"] = ""
        results = list(run(context))
        self.assertTrue(any(".allow." in r.id and r.status == "fail" for r in results))

    def test_unknown_constructions_never_produce_protection_pass(self):
        cases = [
            ([{"chain": {"family": "ip", "table": "nat", "name": "pre", "type": "nat", "hook": "prerouting"}}], "NAT"),
            ([{"set": {"flags": ["dynamic"]}}], "dinâmico"),
            ([{"chain": {"family": "ip", "table": "other", "name": "in", "type": "filter", "hook": "input", "policy": "drop"}}], "múltiplas"),
            ([rule({"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "established"}}, {"accept": None})], "conntrack"),
            ([rule({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": None})], "interface"),
            ([rule({"jump": {"target": "other"}})], "jump"),
            ([rule({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "@ports"}}, {"accept": None})], "set"),
            ([{"table": {"family": "inet", "name": "filter", "flags": ["dormant"]}}], "dormant"),
        ]
        for records, reason in cases:
            with self.subTest(reason=reason):
                results = list(run(fixture(records)))
                self.assertTrue(results)
                self.assertTrue(all(r.status == "warning" for r in results))
                self.assertTrue(any(reason in r.reason for r in results))

    def test_missing_tool_is_inconclusive(self):
        context = fixture(); context.collector.commands.pop("nft")
        self.assertEqual(next(run(context)).status, "warning")

    def test_missing_ipv6_chain_fails(self):
        context = fixture()
        doc = json.loads(context.collector.commands["nft"])
        doc["nftables"][0]["chain"]["family"] = "ip"
        context.collector.commands["nft"] = json.dumps(doc)
        self.assertTrue(any(r.id == "firewall.ip6.input" and r.status == "fail" for r in run(context)))

    def test_shared_socket_snapshot(self):
        from nvg_scanner.checks.network_checks import run as network_run
        context = fixture()
        list(run(context)); list(network_run(context))
        self.assertEqual(sum(c[0] == "command" and c[1][0] == "ss" for c in context.collector.calls), 1)
