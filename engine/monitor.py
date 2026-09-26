"""SIMULATED live monitoring state for the modeled network.

This is a simulator, not a monitor of real devices: nothing is polled over SNMP/SSH.
State is derived from the parsed configs (admin shutdown, links) plus deterministic
pseudo-random utilization/error figures hashed from each interface key, and can be
altered by injecting faults into the live state (never into the configs).
"""

import copy
import hashlib
import sys
from collections import deque

try:
    from .model import NetworkModel
except ImportError:  # run directly as a script (python engine/monitor.py)
    from model import NetworkModel

HOST_DESC_KEYWORDS = ("PC", "SERVER", "HOST", "USER")
BACKBONE_DESC_KEYWORDS = ("TRUNK", "UPLINK", "LINK")
HIGH_UTIL_PCT = 90


def _hash(key, salt=""):
    return int(hashlib.md5(f"{salt}{key}".encode()).hexdigest(), 16)


def _base_utilization(key, description):
    util = 5 + _hash(key) % 81  # 5..85
    if any(k in (description or "").upper() for k in BACKBONE_DESC_KEYWORDS):
        util += 15
    return min(util, 98)


def _base_errors(key):
    h = _hash(key, "err")
    return 1 + (h // 7) % 40 if h % 7 == 0 else 0


def _uptime(device):
    h = _hash(device, "up")
    return f"{5 + h % 200}d {h // 200 % 24}h"


def _is_physical(key):
    name = key.split(":", 1)[1]
    return not (name.lower().startswith(("vlan", "loopback")) or "." in name)


def _refresh_link_status(state):
    """Recompute link_status for every interface from oper_status, peers and flaps."""
    ifaces = state["interfaces"]
    for key, i in ifaces.items():
        peers = state["_peers"].get(key, ())
        if peers and (i["oper_status"] == "down" or any(ifaces[p]["oper_status"] == "down" for p in peers)):
            i["link_status"] = "down"
        elif key in state["_flapping"]:
            i["link_status"] = "flapping"
        else:
            i["link_status"] = "up"


def poll(model):
    """Return a full state snapshot derived from the model's configs."""
    interfaces = {}
    for key, iface in sorted(model.interfaces.items()):
        interfaces[key] = {
            "device": iface["device"],
            "name": iface["name"],
            "description": iface["description"],
            "oper_status": "down" if iface["shutdown"] else "up",
            "link_status": "up",
            "utilization_pct": _base_utilization(key, iface["description"]),
            "errors": _base_errors(key),
        }

    peers = {}
    links = []
    for link in model.links:
        links.append({"devices": list(link["devices"]), "endpoints": [list(p) for p in link["endpoints"]]})
        for a, b in link["endpoints"]:
            if a and b:
                peers.setdefault(a, set()).add(b)
                peers.setdefault(b, set()).add(a)

    state = {
        "simulated": True,
        "devices": {
            host: {
                "status": "up",
                "uptime": _uptime(host),
                "interfaces": sorted(k for k, i in interfaces.items() if i["device"] == host),
            }
            for host in sorted(model.devices)
        },
        "interfaces": interfaces,
        "faults": [],
        "_peers": {k: sorted(v) for k, v in peers.items()},
        "_links": links,
        "_flapping": set(),
    }
    _refresh_link_status(state)
    state["_baseline"] = copy.deepcopy({k: v for k, v in state.items() if k != "_baseline"})
    return state


# -- Reachability -------------------------------------------------------------


def _device_of(name):
    return name.split(":", 1)[0]


def _hop_ok(state, link):
    """A hop is up if some physical interface pair has both ends oper+link up."""
    pairs = [p for p in link["endpoints"] if all(p)]
    physical = [p for p in pairs if all(_is_physical(k) for k in p)] or pairs
    ifaces = state["interfaces"]
    for a, b in physical:
        if all(ifaces[k]["oper_status"] == "up" and ifaces[k]["link_status"] == "up" for k in (a, b)):
            return True, None
    detail = "; ".join(
        f"{k} oper={ifaces[k]['oper_status']} link={ifaces[k]['link_status']}"
        for a, b in physical for k in (a, b)
        if ifaces[k]["oper_status"] != "up" or ifaces[k]["link_status"] != "up"
    )
    return False, detail or "no interface pair on this hop"


def ping(model, state, source, dest):
    """Physical reachability only (interface/link state); ACLs and VLANs are not considered."""
    src, dst = _device_of(source), _device_of(dest)
    unknown = [d for d in (src, dst) if d not in state["devices"]]
    if unknown:
        return {"reachable": False, "path": [], "reason": f"unknown device(s): {', '.join(unknown)}"}
    if src == dst:
        return {"reachable": True, "path": [src], "reason": "same device"}

    # Shortest path over the structural topology (ignoring current health).
    graph = {}
    for link in state["_links"]:
        if len(link["devices"]) == 2:
            a, b = link["devices"]
            graph.setdefault(a, {}).setdefault(b, link)
            graph.setdefault(b, {}).setdefault(a, link)
    prev = {src: None}
    queue = deque([src])
    while queue:
        cur = queue.popleft()
        for nxt in graph.get(cur, {}):
            if nxt not in prev:
                prev[nxt] = cur
                queue.append(nxt)
    if dst not in prev:
        return {"reachable": False, "path": [], "reason": f"no modeled path from {src} to {dst}"}
    path = []
    node = dst
    while node is not None:
        path.append(node)
        node = prev[node]
    path.reverse()

    for a, b in zip(path, path[1:]):
        ok, detail = _hop_ok(state, graph[a][b])
        if not ok:
            return {"reachable": False, "path": path, "reason": f"hop {a} -> {b} is down ({detail})"}
    return {"reachable": True, "path": path, "reason": "all interfaces on the path are up"}


# -- Fault injection ----------------------------------------------------------


def _require(state, key):
    if key not in state["interfaces"]:
        raise KeyError(f"no such interface: {key}")
    return state["interfaces"][key]


def _record_fault(state, kind, target, text):
    """Record a fault once per (kind, target): re-injecting replaces rather than stacks."""
    prefix = f"{kind} {target}"
    state["faults"] = [f for f in state["faults"] if f != prefix and not f.startswith(prefix + " ")]
    state["faults"].append(text)


def inject_interface_down(state, key):
    _require(state, key)["oper_status"] = "down"
    _record_fault(state, "interface_down", key, f"interface_down {key}")
    _refresh_link_status(state)


def inject_link_flap(state, device_pair):
    wanted = set(device_pair)
    hit = False
    for link in state["_links"]:
        if set(link["devices"]) == wanted:
            for pair in link["endpoints"]:
                state["_flapping"].update(k for k in pair if k)
            hit = True
    if not hit:
        raise KeyError(f"no modeled link between {' and '.join(device_pair)}")
    pair = "<->".join(sorted(wanted))
    _record_fault(state, "link_flap", pair, f"link_flap {pair}")
    _refresh_link_status(state)


def inject_high_util(state, key, pct):
    _require(state, key)["utilization_pct"] = pct
    _record_fault(state, "high_util", key, f"high_util {key} {pct}%")


def clear_faults(state):
    """Reset live state to the config-derived baseline."""
    baseline = copy.deepcopy(state["_baseline"])
    state.clear()
    state.update(baseline)
    state["_baseline"] = copy.deepcopy(baseline)


# -- Alerts -------------------------------------------------------------------


def get_alerts(state):
    alerts = []
    for key, i in sorted(state["interfaces"].items()):
        desc = i["description"] or ""
        if i["oper_status"] == "down" and any(k in desc.upper() for k in HOST_DESC_KEYWORDS):
            alerts.append({"severity": "warning", "device": i["device"], "object": key,
                           "message": f"Interface {i['name']} down — {desc}"})
        if i["link_status"] in ("down", "flapping"):
            peers = ", ".join(state["_peers"].get(key, ()))
            alerts.append({"severity": "critical", "device": i["device"], "object": key,
                           "message": f"Link {i['link_status']} on {i['name']}"
                                      + (f" (peer {peers})" if peers else "")})
        if i["utilization_pct"] > HIGH_UTIL_PCT:
            alerts.append({"severity": "warning", "device": i["device"], "object": key,
                           "message": f"High utilization on {i['name']}: {i['utilization_pct']}%"})
    alerts.sort(key=lambda a: (a["severity"] != "critical", a["device"], a["object"]))
    return alerts


# -- CLI ----------------------------------------------------------------------


def _print_state(state):
    print(f"[SIMULATED STATE - derived from configs, not polled from devices]")
    for host, dev in state["devices"].items():
        print(f"\n{host}  status={dev['status']}  uptime={dev['uptime']}")
        width = max((len(state["interfaces"][k]["name"]) for k in dev["interfaces"]), default=9)
        print(f"  {'interface':<{width}}  {'oper':<5} {'link':<9} {'util%':>5} {'errors':>6}")
        for key in dev["interfaces"]:
            i = state["interfaces"][key]
            print(f"  {i['name']:<{width}}  {i['oper_status']:<5} {i['link_status']:<9} "
                  f"{i['utilization_pct']:>5} {i['errors']:>6}")


def _print_alerts(alerts, known=None):
    if not alerts:
        print("  (no alerts)")
    for a in alerts:
        new = " NEW" if known is not None and (a["object"], a["message"]) not in known else ""
        print(f"  [{a['severity'].upper():<8}] {a['device']:<4} {a['message']}{new}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # alert messages contain an em dash
    net_model = NetworkModel(*sys.argv[1:2])
    state = poll(net_model)
    _print_state(state)

    print("\n=== Alerts (baseline) ===")
    baseline = get_alerts(state)
    _print_alerts(baseline)
    print("  ping r1 -> r2:", ping(net_model, state, "r1", "r2")["reason"])

    print("\n=== Injecting fault: r1:GigabitEthernet0/0 down ===")
    inject_interface_down(state, "r1:GigabitEthernet0/0")
    print("  ping r1 -> r2:", ping(net_model, state, "r1", "r2")["reason"])
    print("  Alerts:")
    _print_alerts(get_alerts(state), {(a["object"], a["message"]) for a in baseline})

    clear_faults(state)
    print("\n=== After clear_faults ===")
    print(f"  alerts: {len(get_alerts(state))} (baseline was {len(baseline)})")
