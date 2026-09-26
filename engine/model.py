"""Assemble a network model (devices, interfaces, links, conflicts) from parsed configs."""

import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

try:
    from .parser import parse_config
except ImportError:  # run directly as a script (python engine/model.py)
    from parser import parse_config

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "configs"

# Matches link-style descriptions: LINK-TO-R2, TRUNK-TO-SW1, UPLINK-TO-FW1, INSIDE-TO-R1 ...
_DESC_PEER = re.compile(r"(?:^|-)TO-(\w+)$", re.IGNORECASE)
_SVI = re.compile(r"^Vlan(\d+)$", re.IGNORECASE)


def _desc_peer(description):
    """Return the lower-cased device name a description points at, or None."""
    if not description:
        return None
    match = _DESC_PEER.search(description.strip())
    return match.group(1).lower() if match else None


def _infer_role(hostname, parsed):
    ifaces = parsed["interfaces"]
    if hostname.lower().startswith("fw") or any(
        "OUTSIDE" in (i["description"] or "").upper() for i in ifaces.values()
    ):
        return "firewall"
    has_l3 = any(
        i["ip_address"] and not name.lower().startswith(("loopback", "vlan"))
        for name, i in ifaces.items()
    )
    if parsed["ospf"] and has_l3:
        return "router"
    if parsed["vlans"] and any("switchport" in i for i in ifaces.values()):
        return "switch"
    return "unknown"


def _interface_vlan(name, iface):
    if iface["encapsulation_vlan"] is not None:
        return iface["encapsulation_vlan"]
    svi = _SVI.match(name)
    if svi:
        return int(svi.group(1))
    return (iface.get("switchport") or {}).get("access_vlan")


def _flatten_interface(hostname, name, iface):
    network = None
    prefix_len = None
    if iface["ip_address"] and iface["mask"]:
        try:
            net = ipaddress.ip_interface(f"{iface['ip_address']}/{iface['mask']}").network
            network, prefix_len = str(net), net.prefixlen
        except ValueError:
            pass
    return {
        "device": hostname,
        "name": name,
        "description": iface["description"],
        "ip": iface["ip_address"],
        "mask": iface["mask"],
        "network": network,
        "prefix_len": prefix_len,
        "vlan": _interface_vlan(name, iface),
        "shutdown": iface["shutdown"],
        "access_group": iface["access_group"],
        "switchport": iface.get("switchport"),
    }


def _is_gateway_address(iface):
    """True if the interface holds the first host address (.1) of its network."""
    net = ipaddress.ip_network(iface["network"])
    return ipaddress.ip_address(iface["ip"]) == net.network_address + 1


def _desc_agreement(a, b):
    """Compare link descriptions with the devices actually joined.

    True  = at least one description names the right peer and none name a wrong one.
    False = some description names a different device.
    None  = neither side has a link-style description, so there is nothing to check.
    """
    checks = [(_desc_peer(a["description"]), b["device"].lower()),
              (_desc_peer(b["description"]), a["device"].lower())]
    named = [(got, want) for got, want in checks if got is not None]
    if not named:
        return None
    return all(got == want for got, want in named)


class NetworkModel:
    def __init__(self, config_dir=DEFAULT_CONFIG_DIR):
        self.config_dir = Path(config_dir)
        self.devices = {}
        self.interfaces = {}
        self.links = []
        self.conflicts = []
        self._build()

    # -- assembly -----------------------------------------------------------

    def _build(self):
        # Non-recursive on purpose: golden/ is a subfolder and is not read here.
        for path in sorted(self.config_dir.glob("*.cfg")):
            parsed = parse_config(path)
            hostname = parsed["hostname"] or path.stem
            self.devices[hostname] = {
                "hostname": hostname,
                "role": _infer_role(hostname, parsed),
                "config": parsed,
            }
            for name, iface in parsed["interfaces"].items():
                self.interfaces[f"{hostname}:{name}"] = _flatten_interface(hostname, name, iface)

        self._infer_subnet_links()
        self._infer_trunk_links()
        self.links = self._dedupe_links(self.links)

    @staticmethod
    def _dedupe_links(raw_links):
        """Merge entries joining the same unordered pair of devices into one link."""
        merged = {}
        for link in raw_links:
            hosts = [e.split(":", 1)[0] if e else None for e in (link["a"], link["b"])]
            devices = sorted((h for h in hosts if h), key=str)
            entry = merged.setdefault(
                tuple(devices),
                {
                    "devices": devices,
                    "endpoints": [],
                    "methods": [],
                    "network": None,
                    "desc_confirmed": None,
                },
            )
            entry["endpoints"].append([link["a"], link["b"]])
            if link["method"] not in entry["methods"]:
                entry["methods"].append(link["method"])
            if entry["network"] is None:
                entry["network"] = link["network"]
            # True if any entry confirmed; otherwise False if any disagreed; else None.
            if link["desc_confirmed"] is True:
                entry["desc_confirmed"] = True
            elif link["desc_confirmed"] is False and entry["desc_confirmed"] is None:
                entry["desc_confirmed"] = False
        return list(merged.values())

    def _infer_subnet_links(self):
        by_network = defaultdict(list)
        for key, iface in self.interfaces.items():
            # /32s (loopbacks) can never form a link.
            if iface["network"] and iface["prefix_len"] < 32:
                by_network[iface["network"]].append((key, iface))

        for network, members in sorted(by_network.items()):
            for (ka, a), (kb, b) in combinations(sorted(members, key=lambda m: m[0]), 2):
                if a["device"] == b["device"]:
                    continue
                if _is_gateway_address(a) and _is_gateway_address(b):
                    # Both claim to be the gateway (.1): not a link, an overlap.
                    self.conflicts.append(
                        {"type": "subnet_overlap", "interfaces": [ka, kb], "network": network}
                    )
                    continue
                self.links.append(
                    {
                        "a": ka,
                        "b": kb,
                        "network": network,
                        "method": "subnet",
                        "desc_confirmed": _desc_agreement(a, b),
                    }
                )

    def _infer_trunk_links(self):
        for key, iface in sorted(self.interfaces.items()):
            device = self.devices[iface["device"]]
            sw = iface["switchport"]
            if device["role"] != "switch" or not sw or sw["mode"] != "trunk":
                continue
            peer_name = _desc_peer(iface["description"])
            if peer_name is None:
                continue
            peer_key = self._find_trunk_peer(peer_name, iface["device"])
            confirmed = False
            if peer_key:
                back = _desc_peer(self.interfaces[peer_key]["description"])
                confirmed = back == iface["device"].lower()
            self.links.append(
                {
                    "a": key,
                    "b": peer_key,
                    "network": None,
                    "method": "description",
                    "desc_confirmed": confirmed,
                }
            )

    def _find_trunk_peer(self, peer_name, this_device):
        """Find the interface on device `peer_name` that faces `this_device`."""
        target = next((h for h in self.devices if h.lower() == peer_name), None)
        if target is None:
            return None
        candidates = [
            k for k, i in self.interfaces.items()
            if i["device"] == target and _desc_peer(i["description"]) == this_device.lower()
        ]
        if not candidates:
            # Fall back to a router-style parent interface that carries subinterfaces.
            candidates = [
                k for k, i in self.interfaces.items()
                if i["device"] == target and "." not in i["name"]
                and any(o["device"] == target and o["name"].startswith(i["name"] + ".")
                        for o in self.interfaces.values())
            ]
        return candidates[0] if len(candidates) == 1 else None

    # -- output -------------------------------------------------------------

    def summary(self):
        roles = Counter(d["role"] for d in self.devices.values())
        print(f"Devices: {len(self.devices)}")
        for role, count in sorted(roles.items()):
            print(f"  {role}: {count}")
        print(f"Interfaces: {len(self.interfaces)}")
        print(f"Links: {len(self.links)}")
        for link in self.links:
            print(
                f"  {' <-> '.join(link['devices'])}: {'+'.join(link['methods'])}"
                f", {len(link['endpoints'])} endpoint pair(s)"
            )
        print(f"Conflicts: {len(self.conflicts)}")
        for c in self.conflicts:
            print(f"  {c['type']}: {' <-> '.join(c['interfaces'])} on {c['network']}")


if __name__ == "__main__":
    model = NetworkModel(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_DIR)
    model.summary()
    print()
    print(json.dumps({"links": model.links, "conflicts": model.conflicts}, indent=2))
