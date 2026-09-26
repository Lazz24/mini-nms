"""Parse a Cisco IOS running-config into a structured dict (stdlib only)."""

import json
import sys


def _to_int(text):
    try:
        return int(text)
    except ValueError:
        return text


def _parse_vlan_list(text, existing=None):
    """Parse '10,20,30-32' (optionally 'add ...') into a list of ints.

    Returns None if the text contains anything that is not a number or range.
    """
    tokens = text.split()
    result = list(existing or [])
    if tokens and tokens[0] == "add":
        tokens = tokens[1:]
    else:
        result = []
    for chunk in "".join(tokens).split(","):
        if chunk.isdigit():
            result.append(int(chunk))
        elif "-" in chunk and all(p.isdigit() for p in chunk.split("-", 1)):
            lo, hi = (int(p) for p in chunk.split("-", 1))
            result.extend(range(lo, hi + 1))
        else:
            return None
    return sorted(set(result))


def _acl_type_for_number(number):
    n = int(number) if number.isdigit() else -1
    if 1 <= n <= 99 or 1300 <= n <= 1999:
        return "standard"
    return "extended"


def _new_interface():
    return {
        "description": None,
        "ip_address": None,
        "mask": None,
        "encapsulation_vlan": None,
        "shutdown": False,
        "access_group": None,
        "ospf_network_type": None,
    }


def _new_config():
    return {
        "hostname": None,
        "version": None,
        "services": {"password_encryption": False},
        "enable_secret": False,
        "ssh_version": None,
        "interfaces": {},
        "vlans": {},
        "ospf": None,
        "access_lists": {},
        "snmp_communities": [],
        "default_gateway": None,
        "static_routes": [],
        "vty": {"transport_input": None, "access_class": None, "login": None},
        "_unparsed": [],
    }


def _parse_interface_line(iface, line):
    """Apply one indented interface sub-command. Returns True if recognized."""
    words = line.split()
    if line.startswith("description "):
        iface["description"] = line[len("description "):]
    elif words[:2] == ["ip", "address"] and len(words) >= 4:
        iface["ip_address"], iface["mask"] = words[2], words[3]
    elif words == ["no", "ip", "address"]:
        iface["ip_address"], iface["mask"] = None, None
    elif words[:2] == ["encapsulation", "dot1Q"] and len(words) >= 3:
        iface["encapsulation_vlan"] = _to_int(words[2])
    elif line == "shutdown":
        iface["shutdown"] = True
    elif line == "no shutdown":
        iface["shutdown"] = False
    elif words[:2] == ["ip", "access-group"] and len(words) >= 4:
        iface["access_group"] = {"name": words[2], "dir": words[3]}
    elif words[:3] == ["ip", "ospf", "network"] and len(words) >= 4:
        iface["ospf_network_type"] = " ".join(words[3:])
    elif words[0] == "switchport":
        return _parse_switchport(iface, words[1:])
    else:
        return False
    return True


def _parse_switchport(iface, words):
    sw = iface.setdefault(
        "switchport",
        {"mode": None, "access_vlan": None, "trunk_allowed": None, "trunk_encap": None,
         "native_vlan": None},
    )
    if words[:1] == ["mode"] and len(words) == 2:
        sw["mode"] = words[1]
    elif words[:2] == ["access", "vlan"] and len(words) == 3:
        sw["access_vlan"] = _to_int(words[2])
    elif words[:3] == ["trunk", "allowed", "vlan"] and len(words) >= 4:
        parsed = _parse_vlan_list(" ".join(words[3:]), sw["trunk_allowed"])
        if parsed is None:
            return False
        sw["trunk_allowed"] = parsed
    elif words[:2] == ["trunk", "encapsulation"] and len(words) == 3:
        sw["trunk_encap"] = words[2]
    elif words[:3] == ["trunk", "native", "vlan"] and len(words) == 4 and words[3].isdigit():
        sw["native_vlan"] = int(words[3])
    else:
        # Don't leave an empty switchport dict behind for an unrecognized line.
        if all(v is None for v in sw.values()):
            del iface["switchport"]
        return False
    return True


def _parse_ospf_line(ospf, line):
    words = line.split()
    if words[0] == "router-id" and len(words) == 2:
        ospf["router_id"] = words[1]
    elif words[0] == "passive-interface" and len(words) == 2:
        ospf["passive_interfaces"].append(words[1])
    elif words[0] == "network" and len(words) == 5 and words[3] == "area":
        ospf["networks"].append(
            {"network": words[1], "wildcard": words[2], "area": _to_int(words[4])}
        )
    elif words[:2] == ["default-information", "originate"]:
        ospf["default_information_originate"] = True
    else:
        return False
    return True


def _parse_vty_line(vty, line):
    words = line.split()
    if words[:2] == ["transport", "input"] and len(words) >= 3:
        vty["transport_input"] = " ".join(words[2:])
    elif words[0] == "access-class" and len(words) >= 2:
        vty["access_class"] = words[1]
    elif words[0] == "login":
        vty["login"] = " ".join(words[1:]) or "line"
    else:
        return False
    return True


def _parse_snmp(cfg, words):
    """'snmp-server community STR [view V] RO|RW [ACL]'."""
    if len(words) < 3:
        return False
    access_idx = next(
        (i for i, w in enumerate(words[3:], 3) if w.upper() in ("RO", "RW")), None
    )
    if access_idx is None:
        return False
    acl = words[access_idx + 1] if len(words) > access_idx + 1 else None
    cfg["snmp_communities"].append(
        {"community": words[2], "access": words[access_idx].upper(), "acl": acl}
    )
    return True


def _parse_top_level(cfg, line):
    """Handle a non-indented line.

    Returns (recognized, new_context). Context is (kind, object) or None.
    """
    words = line.split()

    if words[0] == "hostname" and len(words) == 2:
        cfg["hostname"] = words[1]
    elif words[0] == "version" and len(words) == 2:
        cfg["version"] = words[1]
    elif line == "service password-encryption":
        cfg["services"]["password_encryption"] = True
    elif line == "no service password-encryption":
        cfg["services"]["password_encryption"] = False
    elif words[:2] == ["enable", "secret"]:
        cfg["enable_secret"] = True
    elif words[:3] == ["ip", "ssh", "version"] and len(words) == 4:
        cfg["ssh_version"] = _to_int(words[3])
    elif words[0] == "interface" and len(words) >= 2:
        iface = cfg["interfaces"].setdefault(" ".join(words[1:]), _new_interface())
        return True, ("interface", iface)
    elif words[0] == "vlan" and len(words) == 2 and words[1].isdigit():
        vid = int(words[1])
        cfg["vlans"].setdefault(vid, None)
        return True, ("vlan", vid)
    elif words[:2] == ["router", "ospf"] and len(words) == 3:
        if cfg["ospf"] is None:
            cfg["ospf"] = {
                "process_id": _to_int(words[2]),
                "router_id": None,
                "passive_interfaces": [],
                "networks": [],
                "default_information_originate": False,
            }
        return True, ("ospf", cfg["ospf"])
    elif words[:2] == ["line", "vty"]:
        return True, ("vty", cfg["vty"])
    elif (
        words[:2] == ["ip", "access-list"]
        and len(words) == 4
        and words[2] in ("standard", "extended")
    ):
        acl = cfg["access_lists"].setdefault(
            words[3], {"type": words[2], "rules": []}
        )
        return True, ("acl", acl)
    elif words[0] == "access-list" and len(words) >= 3:
        acl = cfg["access_lists"].setdefault(
            words[1], {"type": _acl_type_for_number(words[1]), "rules": []}
        )
        acl["rules"].append(" ".join(words[2:]))
    elif words[:2] == ["snmp-server", "community"]:
        return _parse_snmp(cfg, words), None
    elif words[0] == "ip" and len(words) == 3 and words[1] == "default-gateway":
        cfg["default_gateway"] = words[2]
    elif words[:2] == ["ip", "route"] and len(words) >= 5:
        cfg["static_routes"].append(
            {"dest": words[2], "mask": words[3], "next_hop": words[4]}
        )
    else:
        return False, None
    return True, None


def _parse_block_line(cfg, ctx, line):
    """Handle an indented line inside a block. Returns True if recognized."""
    kind, obj = ctx
    if kind == "interface":
        return _parse_interface_line(obj, line)
    if kind == "ospf":
        return _parse_ospf_line(obj, line)
    if kind == "vty":
        return _parse_vty_line(obj, line)
    if kind == "acl":
        obj["rules"].append(line)
        return True
    if kind == "vlan":
        if line.startswith("name ") and len(line.split()) >= 2:
            cfg["vlans"][obj] = line[len("name "):]
            return True
    return False


def parse_config(path):
    cfg = _new_config()
    ctx = None

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.rstrip()
            stripped = raw.strip()
            if not stripped:
                continue
            indented = raw[0].isspace()

            if stripped.startswith("!"):
                if not indented:
                    ctx = None
                continue

            if not indented:
                if stripped == "end":  # config terminator, not configuration
                    ctx = None
                    continue
                recognized, ctx = _parse_top_level(cfg, stripped)
                if not recognized:
                    cfg["_unparsed"].append(raw)
                continue

            if ctx is None or not _parse_block_line(cfg, ctx, stripped):
                cfg["_unparsed"].append(raw)

    return cfg


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python parser.py <config-file>")
    print(json.dumps(parse_config(sys.argv[1]), indent=2))
