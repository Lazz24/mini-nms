"""Run a ruleset over the network model and golden configs, returning findings."""

import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from .model import NetworkModel
    from .parser import parse_config
except ImportError:  # run directly as a script (python engine/audit.py)
    from model import NetworkModel
    from parser import parse_config

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
WEAK_COMMUNITIES = {"public", "private", "cisco", "admin"}
MIN_COMMUNITY_LEN = 8
HOST_DESC_KEYWORDS = ("PC", "SERVER", "HOST", "USER")


def _finding(severity, category, rule, device, obj, finding, why, fix):
    return {
        "severity": severity,
        "category": category,
        "rule": rule,
        "device": device,
        "object": obj,
        "finding": finding,
        "why": why,
        "fix": fix,
    }


def load_golden(golden_dir):
    """Parse every golden/*.cfg into {hostname: parsed_config}."""
    golden = {}
    for path in sorted(Path(golden_dir).glob("*.cfg")):
        parsed = parse_config(path)
        golden[parsed["hostname"] or path.stem] = parsed
    return golden


def _configs(model):
    for hostname, device in sorted(model.devices.items()):
        yield hostname, device["config"]


def _vty_configured(vty):
    return any(v is not None for v in vty.values())


# -- Security ---------------------------------------------------------------


def rule_vty_telnet(model):
    findings = []
    for host, cfg in _configs(model):
        transport = (cfg["vty"]["transport_input"] or "").split()
        if "telnet" in transport or "all" in transport:
            findings.append(_finding(
                "HIGH", "Security", "vty-telnet", host, "line vty 0 4",
                "VTY lines allow telnet (cleartext remote access).",
                "Telnet sends the login and every command in cleartext, so anyone on the "
                "path can capture credentials and take over the device.",
                "line vty 0 4\n transport input ssh",
            ))
    return findings


def rule_vty_no_acl(model):
    findings = []
    for host, cfg in _configs(model):
        vty = cfg["vty"]
        if _vty_configured(vty) and vty["access_class"] is None:
            findings.append(_finding(
                "MEDIUM", "Security", "vty-no-acl", host, "line vty 0 4",
                "VTY lines have no access-class restricting who can connect.",
                "The management plane is open to any source IP that can reach the device, "
                "so the only barrier is the login itself.",
                "access-list <N> permit <mgmt-subnet> <wildcard>\n"
                "line vty 0 4\n access-class <N> in",
            ))
    return findings


def rule_snmp_weak_community(model):
    findings = []
    for host, cfg in _configs(model):
        for snmp in cfg["snmp_communities"]:
            name = snmp["community"]
            if name.lower() in WEAK_COMMUNITIES:
                reason = "is a well-known default"
            elif len(name) < MIN_COMMUNITY_LEN:
                reason = f"is shorter than {MIN_COMMUNITY_LEN} characters"
            else:
                continue
            findings.append(_finding(
                "HIGH", "Security", "snmp-weak-community", host,
                f"snmp-server community {name}",
                f"SNMP community '{name}' ({snmp['access']}) {reason}.",
                "SNMP v1/v2c communities act as passwords; a guessable one lets anyone "
                "read device configuration and topology (or change it, if RW).",
                f"no snmp-server community {name}\n"
                f"snmp-server community <strong-random-string> {snmp['access']}"
                + (f" {snmp['acl']}" if snmp["acl"] else " <acl>"),
            ))
    return findings


def rule_snmp_no_acl(model):
    findings = []
    for host, cfg in _configs(model):
        for snmp in cfg["snmp_communities"]:
            if snmp["acl"] is None:
                name = snmp["community"]
                findings.append(_finding(
                    "MEDIUM", "Security", "snmp-no-acl", host,
                    f"snmp-server community {name}",
                    f"SNMP community '{name}' is not bound to an ACL.",
                    "SNMP is reachable from any source address, so anyone who learns or "
                    "guesses the community can poll the device.",
                    f"snmp-server community {name} {snmp['access']} <acl>",
                ))
    return findings


def rule_no_enable_secret(model):
    findings = []
    for host, cfg in _configs(model):
        if not cfg["enable_secret"]:
            findings.append(_finding(
                "HIGH", "Security", "no-enable-secret", host, "enable secret",
                "No enable secret is configured.",
                "Privileged EXEC is not protected by a hashed secret, so anyone who "
                "reaches the CLI may get full control of the device.",
                "enable secret <strong-password>",
            ))
    return findings


def rule_no_password_encryption(model):
    findings = []
    for host, cfg in _configs(model):
        if not cfg["services"]["password_encryption"]:
            findings.append(_finding(
                "LOW", "Security", "no-password-encryption", host,
                "service password-encryption",
                "service password-encryption is not enabled.",
                "Type 0 passwords in the config (line, local user) are stored in "
                "cleartext and readable by anyone who sees the config or a backup.",
                "service password-encryption",
            ))
    return findings


# -- Correctness ------------------------------------------------------------


def rule_vlan_not_on_trunk(model):
    findings = []
    for host, device in sorted(model.devices.items()):
        if device["role"] != "switch":
            continue
        ifaces = [i for i in model.interfaces.values() if i["device"] == host]
        trunks = [i for i in ifaces if (i["switchport"] or {}).get("mode") == "trunk"]
        # A trunk with no allowed list carries every VLAN, so nothing can be stranded.
        if not trunks or any(t["switchport"]["trunk_allowed"] is None for t in trunks):
            continue
        allowed = set().union(*(t["switchport"]["trunk_allowed"] for t in trunks))
        for port in ifaces:
            sw = port["switchport"] or {}
            vlan = sw.get("access_vlan")
            if vlan is None or sw.get("mode") == "trunk" or vlan in allowed:
                continue
            trunk = trunks[0]["name"]
            names = ", ".join(t["name"] for t in trunks)
            findings.append(_finding(
                "HIGH", "Correctness", "vlan-not-on-trunk", host, port["name"],
                f"Access port {port['name']} is in VLAN {vlan}, but trunk {names} "
                f"does not allow VLAN {vlan}.",
                "Traffic from the attached host is dropped at the trunk, so the host "
                "is isolated from its gateway and the rest of the network.",
                f"interface {trunk}\n switchport trunk allowed vlan add {vlan}",
            ))
    return findings


def rule_subnet_overlap(model):
    findings = []
    for conflict in model.conflicts:
        if conflict["type"] != "subnet_overlap":
            continue
        a, b = conflict["interfaces"]
        devices = sorted({a.split(":", 1)[0], b.split(":", 1)[0]})
        findings.append(_finding(
            "HIGH", "Correctness", "subnet-overlap", " / ".join(devices),
            f"{a} <-> {b}",
            f"{a} and {b} both claim {conflict['network']}.",
            "Two devices own the same subnet, so routing is ambiguous: traffic for "
            "these hosts may be blackholed or delivered to the wrong device.",
            f"interface {b.split(':', 1)[1]}\n ip address <unique-subnet-address> <mask>"
            f"   ! on {b.split(':', 1)[0]}; re-IP one side onto a unique subnet",
        ))
    return findings


def rule_interface_down_with_host(model):
    findings = []
    for key, iface in sorted(model.interfaces.items()):
        if not iface["shutdown"]:
            continue
        desc = (iface["description"] or "").upper()
        access_vlan = (iface["switchport"] or {}).get("access_vlan")
        if not (any(k in desc for k in HOST_DESC_KEYWORDS) or access_vlan is not None):
            continue
        clue = f"description '{iface['description']}'" if iface["description"] else ""
        if access_vlan is not None:
            clue = (clue + " and " if clue else "") + f"access VLAN {access_vlan}"
        findings.append(_finding(
            "MEDIUM", "Correctness", "interface-down-with-host", iface["device"],
            iface["name"],
            f"{iface['name']} is administratively shut down but has {clue}.",
            "The port looks like it should be serving a host, but it is admin-down, "
            "so whatever is attached has no connectivity.",
            f"interface {iface['name']}\n no shutdown",
        ))
    return findings


def rule_desc_subnet_mismatch(model):
    findings = []
    for link in model.links:
        if link["desc_confirmed"] is not False:
            continue
        pairs = "; ".join(" <-> ".join(str(e) for e in p) for p in link["endpoints"])
        findings.append(_finding(
            "LOW", "Correctness", "desc-subnet-mismatch",
            " / ".join(link["devices"]), pairs,
            "Interface description and subnet disagree about the neighbor.",
            "The description names one neighbor but the addressing puts a different "
            "device on the link, so either the label or the IP plan is wrong.",
            "Correct the interface description or address so they agree",
        ))
    return findings


# -- Drift ------------------------------------------------------------------


def _drift_fix(field, golden_value):
    if field == "services.password_encryption":
        return "service password-encryption" if golden_value else "no service password-encryption"
    if field == "vty.transport_input":
        if golden_value is None:
            return "line vty 0 4\n no transport input"
        return f"line vty 0 4\n transport input {golden_value}"
    if golden_value is None:
        return "line vty 0 4\n no access-class"
    return f"line vty 0 4\n access-class {golden_value} in"


def rule_config_drift(model, golden):
    findings = []
    for host, cfg in _configs(model):
        if host not in golden:
            continue
        gold = golden[host]
        checks = [
            ("services.password_encryption",
             cfg["services"]["password_encryption"], gold["services"]["password_encryption"]),
            ("vty.transport_input",
             cfg["vty"]["transport_input"], gold["vty"]["transport_input"]),
            ("vty.access_class",
             cfg["vty"]["access_class"], gold["vty"]["access_class"]),
        ]
        for field, live, approved in checks:
            if live == approved:
                continue
            findings.append(_finding(
                "MEDIUM", "Drift", "config-drift", host, field,
                f"{field} is {live!r} on the live config but {approved!r} in the "
                f"golden (approved) config.",
                "The running config has drifted from the approved baseline, so the "
                "device no longer matches the standard it was audited against.",
                _drift_fix(field, approved),
            ))
    return findings


# -- Runner -----------------------------------------------------------------

MODEL_RULES = [
    rule_vty_telnet,
    rule_vty_no_acl,
    rule_snmp_weak_community,
    rule_snmp_no_acl,
    rule_no_enable_secret,
    rule_no_password_encryption,
    rule_vlan_not_on_trunk,
    rule_subnet_overlap,
    rule_interface_down_with_host,
    rule_desc_subnet_mismatch,
]
GOLDEN_RULES = [rule_config_drift]


def run_audit(model, golden_dir=None):
    golden = load_golden(golden_dir or model.config_dir / "golden")
    findings = []
    for rule in MODEL_RULES:
        findings.extend(rule(model))
    for rule in GOLDEN_RULES:
        findings.extend(rule(model, golden))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["device"], f["rule"]))
    return findings


def _print_report(findings):
    print(f"Findings: {len(findings)}")
    by_sev = Counter(f["severity"] for f in findings)
    by_cat = Counter(f["category"] for f in findings)
    print("  By severity: " + ", ".join(f"{s}={by_sev.get(s, 0)}" for s in SEVERITY_ORDER))
    print("  By category: " + ", ".join(f"{c}={n}" for c, n in sorted(by_cat.items())))

    by_device = defaultdict(list)
    for f in findings:
        by_device[f["device"]].append(f)
    for device in sorted(by_device):
        print(f"\n{'=' * 70}\n{device}\n{'=' * 70}")
        for f in by_device[device]:
            print(f"\n[{f['severity']}] {f['rule']}  ({f['category']})  -  {f['object']}")
            print(f"  Finding: {f['finding']}")
            print(f"  Why:     {f['why']}")
            fix_lines = f["fix"].split("\n")
            print(f"  Fix:     {fix_lines[0]}")
            for line in fix_lines[1:]:
                print(f"           {line}")


if __name__ == "__main__":
    model = NetworkModel(*sys.argv[1:2])
    _print_report(run_audit(model))
