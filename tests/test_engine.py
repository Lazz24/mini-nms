"""Test suite for the network engine (stdlib unittest only).

Run from the project root:  python -m unittest discover tests
"""

import os
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # `python -m` already adds the cwd; this covers other launchers
    sys.path.insert(0, str(ROOT))

from engine import monitor  # noqa: E402
from engine.audit import run_audit  # noqa: E402
from engine.model import NetworkModel  # noqa: E402
from engine.parser import parse_config  # noqa: E402
from engine.troubleshoot import diagnose  # noqa: E402

CONFIG_DIR = ROOT / "configs"
LIVE_CONFIGS = ["r1.cfg", "r2.cfg", "sw1.cfg", "sw2.cfg", "fw1.cfg"]
ALL_CONFIGS = LIVE_CONFIGS + ["golden/r1.cfg"]

_RESULT = None  # the shared TestResult, captured so tearDownModule can print a summary


class EngineTestCase(unittest.TestCase):
    def run(self, result=None):
        global _RESULT
        result = super().run(result)
        _RESULT = result
        return result


def tearDownModule():
    if _RESULT is None:
        return
    bad = len(_RESULT.failures) + len(_RESULT.errors)
    skipped = len(_RESULT.skipped)
    passed = _RESULT.testsRun - bad - skipped
    print(f"\nSUMMARY: {passed}/{_RESULT.testsRun} tests passed"
          + (f", {bad} FAILED/ERRORED" if bad else "") + (f", {skipped} skipped" if skipped else ""))


def _parse_text(text):
    """Parse config text by way of a temp file (parse_config takes a path)."""
    fd, path = tempfile.mkstemp(suffix=".cfg")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        return parse_config(path)
    finally:
        os.remove(path)


def _root_layer(diagnosis):
    rc = diagnosis["root_cause"]
    return rc["layer"] if rc else None


# -- 1. Parser ----------------------------------------------------------------


class TestParser(EngineTestCase):
    MEANINGFUL = ("ip address", "switchport", "vlan", "access-list", "snmp-server community",
                  "transport input", "access-class")

    @classmethod
    def setUpClass(cls):
        cls.parsed = {name: parse_config(CONFIG_DIR / name) for name in ALL_CONFIGS}

    def test_all_configs_parse(self):
        """All 5 live configs and the golden r1 parse to a dict with a hostname (no exception)."""
        self.assertEqual(len(self.parsed), 6)
        for name, cfg in self.parsed.items():
            with self.subTest(config=name):
                self.assertIsInstance(cfg, dict)
                self.assertTrue(cfg["hostname"])

    def test_no_meaningful_config_left_unparsed(self):
        """Config that matters (addresses, VLANs, ACLs, SNMP, vty) is never silently dropped
        into _unparsed; only boilerplate may be there."""
        for name, cfg in self.parsed.items():
            for line in cfg["_unparsed"]:
                with self.subTest(config=name, line=line):
                    self.assertFalse(any(k in line.lower() for k in self.MEANINGFUL),
                                     f"meaningful line left unparsed: {line!r}")

    def test_r1_vty_transport_is_telnet(self):
        """The seeded r1 telnet flaw is read back correctly from the vty block."""
        self.assertEqual(self.parsed["r1.cfg"]["vty"]["transport_input"], "telnet")

    def test_r2_has_public_community(self):
        """r2's weak SNMP community 'public' is parsed into snmp_communities."""
        communities = [c["community"] for c in self.parsed["r2.cfg"]["snmp_communities"]]
        self.assertIn("public", communities)

    def test_sw1_access_port_vlan(self):
        """sw1 Fa0/10 (SERVER-APP-1) is parsed as an access port in VLAN 20."""
        sw = self.parsed["sw1.cfg"]["interfaces"]["FastEthernet0/10"]["switchport"]
        self.assertEqual(sw["access_vlan"], 20)

    def test_sw1_trunk_allowed(self):
        """sw1's uplink trunk allowed list is parsed as [10] (the seeded VLAN mismatch)."""
        sw = self.parsed["sw1.cfg"]["interfaces"]["GigabitEthernet0/1"]["switchport"]
        self.assertEqual(sw["mode"], "trunk")
        self.assertEqual(sw["trunk_allowed"], [10])

    def test_fw1_dmz_ip(self):
        """fw1's DMZ interface carries the address that overlaps r2's server subnet."""
        self.assertEqual(self.parsed["fw1.cfg"]["interfaces"]["GigabitEthernet0/2"]["ip_address"],
                         "10.20.20.1")

    def test_empty_input_does_not_raise(self):
        """An empty file parses to a well-formed dict instead of crashing."""
        cfg = _parse_text("")
        self.assertIsInstance(cfg, dict)
        self.assertIn("_unparsed", cfg)
        self.assertEqual(cfg["interfaces"], {})

    def test_whitespace_only_input_does_not_raise(self):
        """A whitespace-only file parses to a well-formed dict instead of crashing."""
        cfg = _parse_text("   \n\t\n  \n")
        self.assertIsInstance(cfg, dict)
        self.assertEqual(cfg["_unparsed"], [])

    def test_garbage_input_is_reported_unparsed(self):
        """Non-IOS text does not crash the parser and is surfaced in _unparsed, not dropped."""
        garbage = "@@@ this is not ios ###\nthe quick brown fox\n  indented junk\ninterface\nvlan\n{\"json\": true}\n"
        cfg = _parse_text(garbage)
        self.assertIsInstance(cfg, dict)
        self.assertTrue(cfg["_unparsed"])
        self.assertIn("the quick brown fox", cfg["_unparsed"])

    def test_malformed_ios_lines_do_not_raise(self):
        """Truncated/malformed known commands fall through to _unparsed rather than raising."""
        text = ("hostname\nip address\ninterface Gi0/0\n ip address 1.2.3\n switchport trunk allowed vlan x,y\n"
                " encapsulation dot1Q\nsnmp-server community\nrouter ospf\nline vty 0 4\n transport input\n")
        cfg = _parse_text(text)
        self.assertIsInstance(cfg, dict)
        self.assertTrue(cfg["_unparsed"])


# -- shared model -------------------------------------------------------------


class ModelCase(EngineTestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = NetworkModel(CONFIG_DIR)


# -- 2. Model -----------------------------------------------------------------


class TestModel(ModelCase):
    def test_builds_five_devices_with_expected_roles(self):
        """The model finds 5 devices (golden/ excluded) and infers 2 routers, 2 switches, 1 firewall."""
        self.assertEqual(len(self.model.devices), 5)
        roles = Counter(d["role"] for d in self.model.devices.values())
        self.assertEqual(roles, Counter(router=2, switch=2, firewall=1))

    def test_four_links_after_dedupe(self):
        """Duplicate subnet/description views of one physical link collapse to exactly 4 links."""
        self.assertEqual(len(self.model.links), 4)
        pairs = sorted(tuple(link["devices"]) for link in self.model.links)
        self.assertEqual(pairs, [("fw1", "r1"), ("r1", "r2"), ("r1", "sw1"), ("r2", "sw2")])

    def test_switch_router_links_merge_both_methods(self):
        """r1-sw1 and r2-sw2 are each found by subnet AND description and merged into one entry."""
        by_pair = {tuple(link["devices"]): link for link in self.model.links}
        for pair in (("r1", "sw1"), ("r2", "sw2")):
            with self.subTest(pair=pair):
                self.assertEqual(by_pair[pair]["methods"], ["subnet", "description"])
                self.assertEqual(len(by_pair[pair]["endpoints"]), 2)

    def test_exactly_one_subnet_overlap_conflict(self):
        """The fw1/r2 overlap is reported as a conflict on 10.20.20.0/24 and never as a link."""
        self.assertEqual(len(self.model.conflicts), 1)
        conflict = self.model.conflicts[0]
        self.assertEqual(conflict["type"], "subnet_overlap")
        self.assertEqual(conflict["network"], "10.20.20.0/24")
        self.assertEqual({k.split(":")[0] for k in conflict["interfaces"]}, {"fw1", "r2"})
        self.assertNotIn(("fw1", "r2"), [tuple(link["devices"]) for link in self.model.links])


# -- 3. Audit -----------------------------------------------------------------


class TestAudit(ModelCase):
    REQUIRED_KEYS = {"severity", "category", "rule", "device", "object", "finding", "why", "fix"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.findings = run_audit(cls.model)
        cls.counts = Counter((f["rule"], f["device"]) for f in cls.findings)

    def test_finding_count(self):
        """The seeded network yields exactly 11 findings (no extras, none missing)."""
        self.assertEqual(len(self.findings), 11, [(f["rule"], f["device"]) for f in self.findings])

    def test_each_seeded_flaw_is_reported(self):
        """Every deliberately seeded flaw is caught, attributed to the right device."""
        expected = {
            ("vty-telnet", "r1"): 1, ("vty-no-acl", "r1"): 1,
            ("snmp-weak-community", "r2"): 1, ("snmp-no-acl", "r2"): 1,
            ("vlan-not-on-trunk", "sw1"): 1, ("subnet-overlap", "fw1 / r2"): 1,
            ("interface-down-with-host", "sw2"): 1, ("config-drift", "r1"): 3,
        }
        for key, count in expected.items():
            with self.subTest(finding=key):
                self.assertEqual(self.counts[key], count)

    def test_no_enable_secret_false_positive(self):
        """Every device has an enable secret, so no-enable-secret must never fire."""
        self.assertEqual([f for f in self.findings if f["rule"] == "no-enable-secret"], [])

    def test_weak_snmp_only_on_r2(self):
        """Strong communities on r1/sw1/sw2/fw1 must not trigger snmp-weak-community; only r2's 'public' does."""
        self.assertEqual([f["device"] for f in self.findings if f["rule"] == "snmp-weak-community"], ["r2"])

    def test_findings_are_well_formed(self):
        """Every finding has all required keys, a valid severity and non-empty text/fix fields."""
        for f in self.findings:
            with self.subTest(rule=f["rule"], device=f["device"]):
                self.assertTrue(self.REQUIRED_KEYS <= set(f), self.REQUIRED_KEYS - set(f))
                self.assertIn(f["severity"], ("HIGH", "MEDIUM", "LOW"))
                for key in ("finding", "why", "fix"):
                    self.assertTrue(f[key].strip())


# -- 4. Troubleshooter (config-only) -----------------------------------------


class TestTroubleshoot(ModelCase):
    def _diag(self, source, dest):
        return diagnose(self.model, {"type": "no_connectivity", "source": source, "dest": dest})

    def test_vlan_not_on_trunk_is_l2_on_sw1(self):
        """A server in a VLAN the trunk doesn't carry is diagnosed as an L2 fault on sw1."""
        d = self._diag("SERVER-APP-1", "gateway")
        self.assertEqual(_root_layer(d), "L2")
        self.assertEqual(d["root_cause"]["device"], "sw1")

    def test_shutdown_port_is_l1(self):
        """An admin-shutdown host port is diagnosed at L1, before any later layer."""
        d = self._diag("SERVER-DB-1", "gateway")
        self.assertEqual(_root_layer(d), "L1")
        self.assertEqual(d["root_cause"]["device"], "sw2")

    def test_subnet_overlap_is_l3(self):
        """A destination inside the fw1/r2 overlap is diagnosed as ambiguous at L3."""
        self.assertEqual(_root_layer(self._diag("USER-PC-4", "10.20.20.10")), "L3")

    def test_healthy_path_has_no_root_cause(self):
        """A working path yields root_cause None instead of an invented fault."""
        d = self._diag("USER-PC-1", "gateway")
        self.assertIsNone(d["root_cause"])
        self.assertIn("healthy", d["summary"])

    def test_nonexistent_source_fails_gracefully(self):
        """An unknown source returns a diagnosis with a recorded resolve failure and no exception."""
        d = self._diag("NOPE-999", "gateway")
        self.assertIsInstance(d, dict)
        self.assertIsNone(d["root_cause"])
        self.assertTrue(any(t["layer"] == "RESOLVE" and t["result"] == "FAIL" for t in d["trace"]))
        self.assertIn("resolve", d["summary"].lower())

    def test_nonexistent_dest_fails_gracefully(self):
        """An unknown destination is reported as a resolve failure too, not a crash."""
        d = self._diag("USER-PC-1", "NOPE-999")
        self.assertTrue(any(t["layer"] == "RESOLVE" and t["result"] == "FAIL" for t in d["trace"]))

    def test_missing_source_key(self):
        """A symptom with no 'source' key returns a graceful error diagnosis."""
        d = diagnose(self.model, {"type": "no_connectivity", "dest": "gateway"})
        self.assertIsInstance(d, dict)
        self.assertIsNone(d["root_cause"])
        self.assertTrue(any(t["result"] == "FAIL" for t in d["trace"]))

    def test_missing_dest_key(self):
        """A symptom with no 'dest' key returns a graceful error diagnosis."""
        d = diagnose(self.model, {"type": "no_connectivity", "source": "USER-PC-1"})
        self.assertIsInstance(d, dict)
        self.assertIsNone(d["root_cause"])
        self.assertTrue(any(t["result"] == "FAIL" for t in d["trace"]))

    def test_empty_symptom(self):
        """An empty symptom dict is rejected with an explanatory diagnosis, not an exception."""
        d = diagnose(self.model, {})
        self.assertIsInstance(d, dict)
        self.assertIsNone(d["root_cause"])
        self.assertTrue(d["summary"])

    def test_unsupported_symptom_type(self):
        """An unknown symptom type is reported as unsupported instead of being walked."""
        d = diagnose(self.model, {"type": "high_latency", "source": "USER-PC-1", "dest": "gateway"})
        self.assertIsNone(d["root_cause"])
        self.assertIn("Unsupported", d["summary"])


# -- 5. Troubleshooter with live state -----------------------------------------


class TestTroubleshootLive(ModelCase):
    SYMPTOM = {"type": "no_connectivity", "source": "USER-PC-4", "dest": "10.10.10.50"}
    CORE = "r1:GigabitEthernet0/0"

    def test_injected_core_link_down_is_l1(self):
        """With r1 Gi0/0 down in live state, the inter-router path fails at L1 on the r1<->r2 link."""
        state = monitor.poll(self.model)
        monitor.inject_interface_down(state, self.CORE)
        d = diagnose(self.model, self.SYMPTOM, live_state=state)
        self.assertEqual(_root_layer(d), "L1")
        rc = d["root_cause"]
        self.assertEqual(rc["device"], "r1")
        self.assertTrue(rc["object"].startswith("GigabitEthernet0/0"))
        self.assertRegex(rc["summary"], r"r[12]↔r[12] link")
        self.assertFalse(any(t["check"] == "Route to destination" and t["result"] == "PASS"
                             for t in d["trace"]), "a route out a dead interface must not PASS")

    def test_config_only_ignores_live_faults(self):
        """live_state=None falls back to config-only behavior: the same symptom is not an L1 fault."""
        state = monitor.poll(self.model)
        monitor.inject_interface_down(state, self.CORE)  # exists, but is not passed in
        d = diagnose(self.model, self.SYMPTOM)
        self.assertNotEqual(_root_layer(d), "L1")
        self.assertIsNone(d["root_cause"])

    def test_clear_faults_restores_healthy(self):
        """After clear_faults the live-state diagnosis returns to healthy (no L1 fault)."""
        state = monitor.poll(self.model)
        monitor.inject_interface_down(state, self.CORE)
        monitor.clear_faults(state)
        d = diagnose(self.model, self.SYMPTOM, live_state=state)
        self.assertIsNone(d["root_cause"])

    def test_flapping_link_is_l1_medium_confidence(self):
        """A flapping r1<->r2 link is an L1 fault reported with medium confidence."""
        state = monitor.poll(self.model)
        monitor.inject_link_flap(state, ("r1", "r2"))
        d = diagnose(self.model, self.SYMPTOM, live_state=state)
        self.assertEqual(_root_layer(d), "L1")
        self.assertEqual(d["confidence"], "medium")

    def test_inject_is_idempotent(self):
        """Injecting the same interface_down twice gives the same alerts and fault list as once."""
        once = monitor.poll(self.model)
        monitor.inject_interface_down(once, self.CORE)
        twice = monitor.poll(self.model)
        monitor.inject_interface_down(twice, self.CORE)
        monitor.inject_interface_down(twice, self.CORE)
        self.assertEqual(len(monitor.get_alerts(twice)), len(monitor.get_alerts(once)))
        self.assertEqual(twice["faults"], once["faults"])
        self.assertEqual(len(twice["faults"]), 1)

    def test_inject_unknown_interface_raises_keyerror(self):
        """Injecting a fault on a nonexistent interface fails loudly with KeyError (the API maps it to 400)."""
        state = monitor.poll(self.model)
        with self.assertRaises(KeyError):
            monitor.inject_interface_down(state, "zz9:Nope0/0")


# -- 6. Monitor ---------------------------------------------------------------


class TestMonitor(ModelCase):
    def test_poll_covers_all_devices(self):
        """poll() returns state for all 5 devices, each with interface entries, and marks itself simulated."""
        state = monitor.poll(self.model)
        self.assertTrue(state["simulated"])
        self.assertEqual(set(state["devices"]), {"fw1", "r1", "r2", "sw1", "sw2"})
        for host, dev in state["devices"].items():
            with self.subTest(device=host):
                self.assertEqual(dev["status"], "up")
                self.assertTrue(dev["interfaces"])

    def test_shutdown_port_is_oper_down(self):
        """sw2 Fa0/2, shut down in config, shows oper_status down in the baseline state."""
        state = monitor.poll(self.model)
        self.assertEqual(state["interfaces"]["sw2:FastEthernet0/2"]["oper_status"], "down")
        self.assertEqual(state["interfaces"]["sw2:FastEthernet0/1"]["oper_status"], "up")

    def test_utilization_is_deterministic(self):
        """Two polls of two freshly built models give identical utilization and error numbers."""
        a = monitor.poll(NetworkModel(CONFIG_DIR))["interfaces"]
        b = monitor.poll(NetworkModel(CONFIG_DIR))["interfaces"]
        self.assertEqual({k: (v["utilization_pct"], v["errors"]) for k, v in a.items()},
                         {k: (v["utilization_pct"], v["errors"]) for k, v in b.items()})
        for v in a.values():
            self.assertTrue(5 <= v["utilization_pct"] <= 98)

    def test_baseline_alerts_include_down_server_port(self):
        """Baseline alerts warn about the shut-down SERVER-DB-1 port on sw2."""
        alerts = monitor.get_alerts(monitor.poll(self.model))
        match = [a for a in alerts if a["object"] == "sw2:FastEthernet0/2"]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0]["severity"], "warning")
        self.assertIn("SERVER-DB-1", match[0]["message"])

    def test_ping_reflects_injected_fault(self):
        """ping() is reachable at baseline and unreachable across an injected-down transit link."""
        state = monitor.poll(self.model)
        self.assertTrue(monitor.ping(self.model, state, "r1", "r2")["reachable"])
        monitor.inject_interface_down(state, "r1:GigabitEthernet0/0")
        self.assertFalse(monitor.ping(self.model, state, "r1", "r2")["reachable"])
        self.assertFalse(monitor.ping(self.model, state, "r1", "nope")["reachable"])


if __name__ == "__main__":
    unittest.main()
