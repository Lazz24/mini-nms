"""Symptom-driven troubleshooter over the network model (stdlib only).

diagnose(model, symptom) resolves the symptom's source and destination to concrete
points in the model, then walks the path bottom-up -- L1 (interface state), L2 (VLANs
and trunks), L3 (addressing, overlaps, routing both ways), L4/ACL (interface ACLs in
the direction traffic crosses them) -- and stops at the first fault.

Symptom fields:
  type      "no_connectivity" (the only type supported)
  source    host description (e.g. "SERVER-APP-1"), an IP, or "device:interface"
  dest      same forms, or "gateway" (the source's own default gateway)
  protocol  optional: "tcp" / "udp" / "icmp" -- narrows ACL matching
  port      optional: destination port, used with tcp/udp
"""

import ipaddress
import re
import sys
import textwrap
from collections import deque

try:
    from .model import NetworkModel
except ImportError:  # run directly as a script (python engine/troubleshoot.py)
    from model import NetworkModel

LAYER_ORDER = ["L1", "L2", "L3", "L4/ACL"]
HOST_KINDS = ("host_port", "host_ip", "svi")
ANY_NET = ipaddress.ip_network("0.0.0.0/0")

_SVI = re.compile(r"^Vlan(\d+)$", re.IGNORECASE)
_IFNAME = re.compile(r"^([a-z-]+)\s*([\d/.:]+)$")

# ACL match strengths: a flow can match a rule not at all, only partly (the rule
# narrows protocol/port/address beyond what the flow specifies), or entirely.
NONE, PARTIAL, FULL = 0, 1, 2
PROTO_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp"}
PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "telnet": 23, "smtp": 25, "domain": 53, "bootps": 67,
    "bootpc": 68, "tftp": 69, "www": 80, "pop3": 110, "ntp": 123, "snmp": 161,
    "bgp": 179, "syslog": 514,
}
IGNORED_ACL_OPTIONS = {"log", "log-input"}


# -- Topology helpers ---------------------------------------------------------


def _new_ep(text, kind, **fields):
    ep = {
        "input": text, "kind": kind, "device": None, "interface": None,
        "description": None, "ip": None, "network": None, "vlan": None,
        "switch": None, "access_port": None, "trunk": None, "router_port": None,
        "gateway": None, "gateway_candidates": [], "ambiguous": False,
    }
    ep.update(fields)
    return ep


def _parent(key):
    """'r1:Gi0/1.10' -> 'r1:Gi0/1'; None for a non-subinterface."""
    return key.rsplit(".", 1)[0] if "." in key.split(":", 1)[1] else None


def _route(net, ad, cost, kind, egress, next_device=None, next_ingress=None, owner=None, via=None):
    return {
        "net": net, "ad": ad, "cost": cost, "kind": kind, "egress": egress,
        "next_device": next_device, "next_ingress": next_ingress, "owner": owner, "via": via,
    }


def _hop(device, ingress, egress, via, detail):
    return {"device": device, "ingress": ingress, "egress": egress, "via": via, "detail": detail}


class _Topo:
    """Read-only lookups over a NetworkModel: endpoints, OSPF adjacency, forwarding."""

    def __init__(self, model, live_state=None):
        self.model = model
        self.live = live_state
        self.ifaces = model.interfaces
        self.adjacency, self.down_adjacencies = self._ospf_adjacency()
        self.advertised = {dev: [] for dev in model.devices}
        for key, i in sorted(self.ifaces.items()):
            if i["network"] and not i["shutdown"] and self.ospf_statement(key):
                self.advertised[i["device"]].append((key, ipaddress.ip_network(i["network"])))
        self.default_originators = {
            host for host, d in model.devices.items()
            if (d["config"]["ospf"] or {}).get("default_information_originate")
        }

    def cfg(self, device):
        return self.model.devices[device]["config"]

    def role(self, device):
        return self.model.devices[device]["role"]

    def is_trunk(self, key):
        return (self.ifaces[key]["switchport"] or {}).get("mode") == "trunk"

    def is_access(self, key):
        sw = self.ifaces[key]["switchport"] or {}
        return sw.get("mode") != "trunk" and sw.get("access_vlan") is not None

    def label(self, key):
        desc = self.ifaces[key]["description"]
        return f"{key} ({desc})" if desc else key

    def down_reason(self, key):
        """Why an interface can't pass traffic, or None if it is up.

        'admin' = shutdown in config. With live state: 'oper' = oper_status down,
        'link' = link_status down, 'flapping' = link_status flapping.
        """
        if self.ifaces[key]["shutdown"]:
            return "admin"
        live = (self.live or {}).get("interfaces", {}).get(key)
        if live:
            if live["oper_status"] == "down":
                return "oper"
            if live["link_status"] == "down":
                return "link"
            if live["link_status"] == "flapping":
                return "flapping"
        return None

    def link_peer(self, key):
        """The interface at the other end of this interface's modeled link, or None."""
        for link in self.model.links:
            for a, b in link["endpoints"]:
                if a == key and b:
                    return b
                if b == key and a:
                    return a
        return None

    # -- endpoint resolution ------------------------------------------------

    def resolve(self, value, source=None):
        """Return (endpoint, None) or (None, error message)."""
        text = str(value).strip() if value is not None else ""
        if not text:
            return None, "no value given"
        if text.lower() == "gateway":
            if source is None:
                return None, "'gateway' only makes sense as the destination (the source's own gateway)"
            gw = source["gateway"]
            ep = _new_ep(text, "gateway", interface=gw, gateway=gw, network=source["network"],
                         gateway_candidates=list(source["gateway_candidates"]),
                         ambiguous=source["ambiguous"])
            if gw:
                i = self.ifaces[gw]
                ep.update(device=i["device"], ip=i["ip"], description=i["description"])
            return ep, None
        if ":" in text:
            key = self.find_interface(text)
            if key is None:
                return None, f"no interface in the model matches '{text}'"
            return self._interface_ep(text, key), None
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return self._description_ep(text)
        return self._ip_ep(text, ip)

    def find_interface(self, text):
        """Match 'device:interface', allowing IOS abbreviations like r1:Gi0/0."""
        dev, _, name = text.partition(":")
        dev, name = dev.strip().lower(), name.strip().lower()
        on_dev = {k: i for k, i in self.ifaces.items() if i["device"].lower() == dev}
        for key, i in on_dev.items():
            if i["name"].lower() == name:
                return key
        want = _IFNAME.match(name)
        if not want:
            return None
        hits = []
        for key, i in on_dev.items():
            have = _IFNAME.match(i["name"].lower())
            if have and have.group(1).startswith(want.group(1)) and have.group(2) == want.group(2):
                hits.append(key)
        return hits[0] if len(hits) == 1 else None

    def _interface_ep(self, text, key):
        i = self.ifaces[key]
        base = {"device": i["device"], "interface": key, "description": i["description"]}
        if self.is_access(key):
            ep = _new_ep(text, "host_port", access_port=key, switch=i["device"],
                         vlan=i["switchport"]["access_vlan"], **base)
            self._attach_uplink(ep)
            return ep
        if self.role(i["device"]) == "switch" and _SVI.match(i["name"]):
            ep = _new_ep(text, "svi", ip=i["ip"], network=i["network"], switch=i["device"],
                         vlan=i["vlan"], **base)
            self._attach_uplink(ep)
            return ep
        return _new_ep(text, "interface", ip=i["ip"], network=i["network"], vlan=i["vlan"],
                       gateway=key, gateway_candidates=[key], **base)

    def _ip_ep(self, text, ip):
        exact = sorted(k for k, i in self.ifaces.items() if i["ip"] == str(ip))
        if len(exact) == 1:
            return self._interface_ep(text, exact[0]), None
        if len(exact) > 1:
            # The same address configured on several interfaces: an overlap.
            return _new_ep(text, "interface", ip=str(ip), network=self.ifaces[exact[0]]["network"],
                           gateway_candidates=exact, ambiguous=True), None
        candidates = sorted(
            k for k, i in self.ifaces.items()
            if i["network"] and i["prefix_len"] < 32 and self.role(i["device"]) != "switch"
            and ip in ipaddress.ip_network(i["network"])
        )
        if not candidates:
            return None, f"{ip} is not inside any routed interface's subnet"
        ep = _new_ep(text, "host_ip", ip=str(ip), network=self.ifaces[candidates[0]]["network"],
                     gateway_candidates=candidates, ambiguous=len(candidates) > 1)
        if len(candidates) == 1:
            gw = candidates[0]
            gi = self.ifaces[gw]
            ep.update(gateway=gw, device=gi["device"])
            if gi["vlan"] is not None and _parent(gw):
                switch, trunk = self.switch_behind(_parent(gw))
                ep.update(vlan=gi["vlan"], router_port=_parent(gw), switch=switch, trunk=trunk)
                if switch:
                    ep["device"] = switch
        return ep, None

    def _description_ep(self, text):
        needle = text.lower()
        described = sorted((k, (i["description"] or "").lower()) for k, i in self.ifaces.items())
        matches = [k for k, d in described if d == needle] or [k for k, d in described if needle in d]
        matches = [k for k in matches if self.is_access(k)] or matches
        if not matches:
            return None, f"'{text}' is not a device:interface, an IP, or any interface description"
        if len(matches) > 1:
            return None, f"'{text}' matches several interface descriptions: {', '.join(matches)}"
        return self._interface_ep(text, matches[0]), None

    def _attach_uplink(self, ep):
        ep["trunk"], ep["router_port"] = self.uplink(ep["switch"])
        if ep["router_port"] and ep["vlan"] is not None:
            gw = self.subif_for_vlan(ep["router_port"], ep["vlan"])
            if gw:
                ep["gateway"], ep["gateway_candidates"] = gw, [gw]
                ep["network"] = ep["network"] or self.ifaces[gw]["network"]

    def uplink(self, switch):
        """(switch trunk key, router-side key) for the switch's trunk toward a router."""
        found = []
        for link in self.model.links:
            if switch not in link["devices"]:
                continue
            for pair in link["endpoints"]:
                for mine, peer in (pair, pair[::-1]):
                    if mine and mine.split(":", 1)[0] == switch and self.is_trunk(mine):
                        found.append((mine, peer))
        found.sort(key=lambda t: t[1] is None)
        if found:
            return found[0]
        trunks = sorted(k for k, i in self.ifaces.items() if i["device"] == switch and self.is_trunk(k))
        return (trunks[0], None) if trunks else (None, None)

    def switch_behind(self, router_port):
        """(switch, switch trunk key) linked to a router's trunk-facing port."""
        for link in self.model.links:
            for pair in link["endpoints"]:
                if router_port in pair:
                    other = pair[1] if pair[0] == router_port else pair[0]
                    if other and self.is_trunk(other):
                        return self.ifaces[other]["device"], other
        return None, None

    def subif_for_vlan(self, router_port, vlan):
        device, name = router_port.split(":", 1)
        for key, i in sorted(self.ifaces.items()):
            if i["device"] == device and i["name"].startswith(name + ".") and i["vlan"] == vlan:
                return key
        return None

    # -- OSPF ---------------------------------------------------------------

    def ospf_statement(self, key):
        """The 'network ... area N' statement covering this interface, or None."""
        i = self.ifaces[key]
        ospf = self.cfg(i["device"])["ospf"]
        if not ospf or not i["ip"]:
            return None
        ip = int(ipaddress.ip_address(i["ip"]))
        for stmt in ospf["networks"]:
            wildcard = int(ipaddress.ip_address(stmt["wildcard"]))
            if ip & ~wildcard == int(ipaddress.ip_address(stmt["network"])) & ~wildcard:
                return stmt
        return None

    def _passive(self, key):
        i = self.ifaces[key]
        return i["name"] in (self.cfg(i["device"])["ospf"] or {}).get("passive_interfaces", [])

    def _ospf_adjacency(self):
        """Neighbors per device, plus would-be adjacencies broken by a shutdown interface."""
        adjacency = {dev: [] for dev in self.model.devices}
        down = []
        for link in self.model.links:
            for a, b in link["endpoints"]:
                if not a or not b:
                    continue
                ia, ib = self.ifaces[a], self.ifaces[b]
                if not ia["network"] or ia["network"] != ib["network"]:
                    continue
                sa, sb = self.ospf_statement(a), self.ospf_statement(b)
                if not sa or not sb or sa["area"] != sb["area"] or self._passive(a) or self._passive(b):
                    continue
                if ia["shutdown"] or ib["shutdown"]:
                    down.append((a, b))
                    continue
                adjacency[ia["device"]].append((ib["device"], a, b))
                adjacency[ib["device"]].append((ia["device"], b, a))
        return adjacency, down

    def _ospf_bfs(self, start):
        """{device: (hops, first-hop device, egress key, first-hop ingress key)}.

        Hop count stands in for OSPF cost (all links here are equal-speed).
        """
        seen = {start: (0, None, None, None)}
        queue = deque([start])
        while queue:
            device = queue.popleft()
            dist, first, egress, ingress = seen[device]
            for peer, local, remote in self.adjacency.get(device, []):
                if peer not in seen:
                    seen[peer] = (dist + 1, first or peer, egress or local, ingress or remote)
                    queue.append(peer)
        return seen

    # -- forwarding ---------------------------------------------------------

    def best_routes(self, device, dest_net):
        """All routes on `device` tied for best (longest prefix, then AD, then cost)."""
        candidates = []
        for key, i in sorted(self.ifaces.items()):
            if i["device"] == device and i["network"] and not i["shutdown"]:
                net = ipaddress.ip_network(i["network"])
                if dest_net.subnet_of(net):
                    candidates.append(_route(net, 0, 0, "connected", key, owner=key))

        cfg = self.cfg(device)
        statics = list(cfg["static_routes"])
        if cfg["default_gateway"]:
            statics.append({"dest": "0.0.0.0", "mask": "0.0.0.0", "next_hop": cfg["default_gateway"]})
        for route in statics:
            net = ipaddress.ip_network(f"{route['dest']}/{route['mask']}", strict=False)
            if not dest_net.subnet_of(net):
                continue
            next_hop = ipaddress.ip_address(route["next_hop"])
            egress = next(
                (k for k, i in sorted(self.ifaces.items())
                 if i["device"] == device and i["network"] and not i["shutdown"]
                 and next_hop in ipaddress.ip_network(i["network"])),
                None,
            )
            if egress is None:
                continue  # next hop not reachable on a connected interface: route not installed
            nxt = next((k for k, i in sorted(self.ifaces.items())
                        if i["ip"] == route["next_hop"] and not i["shutdown"]), None)
            candidates.append(_route(
                net, 1, 0, "static", egress, self.ifaces[nxt]["device"] if nxt else None, nxt,
                owner=f"static via {next_hop}", via=str(next_hop),
            ))

        if cfg["ospf"]:
            for dev, (dist, first, egress, ingress) in self._ospf_bfs(device).items():
                if dev == device:
                    continue
                for key, net in self.advertised[dev]:
                    if dest_net.subnet_of(net):
                        candidates.append(_route(net, 110, dist, "ospf", egress, first, ingress,
                                                 owner=key, via=dev))
                if dev in self.default_originators:
                    candidates.append(_route(ANY_NET, 110, dist, "ospf default", egress, first,
                                             ingress, owner=f"default from {dev}", via=dev))

        if not candidates:
            return []
        rank = lambda r: (-r["net"].prefixlen, r["ad"], r["cost"])  # noqa: E731
        candidates.sort(key=rank)
        return [r for r in candidates if rank(r) == rank(candidates[0])]

    def route_text(self, r):
        out = self.ifaces[r["egress"]]["name"]
        if r["kind"] == "connected":
            return f"connected {r['net']} out {out}"
        if r["kind"] == "static":
            return f"static {r['net']} via {r['via']} out {out}"
        if r["kind"] == "ospf default":
            return f"OSPF default route from {r['via']}, next hop {r['next_device']} out {out}"
        return f"OSPF {r['net']} from {r['via']}, next hop {r['next_device']} out {out}"

    def forward(self, start, ingress, dest_net, dest_iface=None, expect_egress=None, max_hops=16):
        """Walk routing tables hop by hop from `start` toward `dest_net`.

        dest_iface: the destination is this device interface (router/switch address).
        expect_egress: the destination is a host behind this gateway interface.
        """
        hops = []
        device = start
        seen = set()

        def fail(kind, reason, owners=()):
            return {"ok": False, "kind": kind, "device": device, "reason": reason,
                    "hops": hops, "owners": list(owners), "dest_net": dest_net}

        while True:
            if device in seen or len(hops) >= max_hops:
                return fail("loop", f"routing loop: traffic for {dest_net} returns to {device}")
            seen.add(device)
            if dest_iface and self.ifaces[dest_iface]["device"] == device:
                hops.append(_hop(device, ingress, None, "local", f"{device} owns {dest_iface}"))
                return {"ok": True, "hops": hops}
            winners = self.best_routes(device, dest_net)
            if not winners:
                return fail("no_route", f"{device} has no route to {dest_net}")
            owners = sorted({r["owner"] for r in winners})
            if len(owners) > 1:
                return fail(
                    "ambiguous",
                    f"{device} has {len(owners)} equally good routes to {dest_net} that lead to "
                    f"different places ({', '.join(owners)})",
                    owners,
                )
            r = winners[0]
            hops.append(_hop(device, ingress, r["egress"], r["kind"], self.route_text(r)))
            if r["kind"] == "connected":
                if dest_iface:
                    di = self.ifaces[dest_iface]
                    if di["network"] == self.ifaces[r["egress"]]["network"]:
                        hops.append(_hop(di["device"], dest_iface, None, "local",
                                         f"{di['device']} owns {dest_iface}"))
                        return {"ok": True, "hops": hops}
                    return fail("misdelivered",
                                f"{device} delivers {dest_net} onto {r['egress']}, not to {dest_iface}",
                                [r["egress"], dest_iface])
                if expect_egress and r["egress"] != expect_egress:
                    return fail(
                        "misdelivered",
                        f"{device} delivers {dest_net} onto its own {r['egress']}, not to "
                        f"{expect_egress} where the destination lives",
                        [r["egress"], expect_egress],
                    )
                return {"ok": True, "hops": hops}
            if r["next_device"] is None:
                return fail("exits", f"{device}'s best route to {dest_net} is {self.route_text(r)}, "
                                     f"which leaves the modeled network")
            device, ingress = r["next_device"], r["next_ingress"]


# -- ACL evaluation -----------------------------------------------------------


def _is_ip(token):
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _parse_addr(tokens, i, needs_wildcard):
    token = tokens[i]
    if token == "any":
        return ANY_NET, i + 1
    if token == "host":
        return ipaddress.ip_network(f"{tokens[i + 1]}/32"), i + 2
    address = ipaddress.ip_address(token)
    if i + 1 < len(tokens) and _is_ip(tokens[i + 1]):
        wildcard, nxt = tokens[i + 1], i + 2
    elif needs_wildcard:
        raise ValueError(f"missing wildcard after {token}")
    else:
        wildcard, nxt = "0.0.0.0", i + 1  # standard ACL: bare address means host
    mask = ipaddress.ip_address(int(ipaddress.ip_address(wildcard)) ^ 0xFFFFFFFF)
    # Raises ValueError for non-contiguous wildcards, which we don't model.
    return ipaddress.ip_network(f"{address}/{mask}", strict=False), nxt


def _parse_ports(tokens, i):
    if i < len(tokens) and tokens[i] in ("eq", "neq", "lt", "gt", "range"):
        op = tokens[i]
        count = 2 if op == "range" else 1
        values = [int(v) if v.isdigit() else PORT_NAMES.get(v) for v in tokens[i + 1:i + 1 + count]]
        return (op, values), i + 1 + count
    return None, i


def _parse_rule(tokens, standard):
    """tokens start at permit/deny. Raises ValueError/IndexError if not understood."""
    action = tokens[0]
    if standard:
        src, i = _parse_addr(tokens, 1, needs_wildcard=False)
        return {"action": action, "proto": "ip", "src": src, "sport": None, "dst": ANY_NET,
                "dport": None, "extras": [t for t in tokens[i:] if t not in IGNORED_ACL_OPTIONS]}
    proto = PROTO_NUMBERS.get(tokens[1], tokens[1])
    src, i = _parse_addr(tokens, 2, needs_wildcard=True)
    sport, i = _parse_ports(tokens, i)
    dst, i = _parse_addr(tokens, i, needs_wildcard=True)
    dport, i = _parse_ports(tokens, i)
    return {"action": action, "proto": proto, "src": src, "sport": sport, "dst": dst,
            "dport": dport, "extras": [t for t in tokens[i:] if t not in IGNORED_ACL_OPTIONS]}


def _match_net(flow_net, rule_net):
    if flow_net.subnet_of(rule_net):
        return FULL
    return PARTIAL if flow_net.overlaps(rule_net) else NONE


def _match_port(condition, port):
    if condition is None:
        return FULL
    op, values = condition
    if port is None or None in values:
        return PARTIAL
    hit = {
        "eq": lambda: port == values[0],
        "neq": lambda: port != values[0],
        "lt": lambda: port < values[0],
        "gt": lambda: port > values[0],
        "range": lambda: values[0] <= port <= values[1],
    }[op]()
    return FULL if hit else NONE


def _match_rule(rule, flow):
    parts = [_match_net(flow["src"], rule["src"]), _match_net(flow["dst"], rule["dst"])]
    if rule["proto"] != "ip":
        if flow["proto"] is None:
            parts.append(PARTIAL)
        else:
            parts.append(FULL if flow["proto"] == rule["proto"] else NONE)
    parts += [_match_port(rule["sport"], flow["sport"]), _match_port(rule["dport"], flow["dport"])]
    if rule["extras"]:  # established, icmp types, etc: only some packets match
        parts.append(PARTIAL)
    return min(parts)


def evaluate_acl(acl, flow):
    """First-match-wins evaluation of one parsed ACL against a flow.

    Returns the rule that matches the whole flow (or the implicit deny), plus any
    earlier rules that match only part of it (e.g. 'permit tcp ... eq 443' when the
    flow's protocol is unspecified) -- those carve out exceptions before the verdict.
    """
    standard = acl["type"] == "standard"
    exceptions, seqs, default_numbered = [], [], False
    for position, text in enumerate(acl["rules"], 1):
        tokens = text.split()
        if tokens and tokens[0].isdigit():
            seq, tokens = int(tokens[0]), tokens[1:]
        else:
            seq, default_numbered = position * 10, True
        if not tokens or tokens[0] not in ("permit", "deny"):
            continue  # remark
        seqs.append(seq)
        body = " ".join(tokens)
        try:
            rule = _parse_rule(tokens, standard)
        except (ValueError, IndexError):
            exceptions.append({"seq": seq, "action": "unparsed", "rule": body})
            continue
        strength = _match_rule(rule, flow)
        if strength == FULL:
            return {"action": rule["action"], "seq": seq, "rule": body, "exceptions": exceptions,
                    "seqs": seqs, "default_numbered": default_numbered}
        if strength == PARTIAL:
            exceptions.append({"seq": seq, "action": rule["action"], "rule": body})
    return {"action": "deny", "seq": None, "rule": "implicit deny any", "exceptions": exceptions,
            "seqs": seqs, "default_numbered": default_numbered}


def _acl_addr(net):
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    if net.prefixlen == 0:
        return "any"
    return f"{net.network_address} {net.hostmask}"


def _acl_fix(name, acl, verdict, flow):
    if acl["type"] == "standard":
        line = f"permit {_acl_addr(flow['src'])}"
    else:
        proto = flow["proto"] or "ip"
        ports = proto in ("tcp", "udp")
        line = f"permit {proto} {_acl_addr(flow['src'])}"
        if ports and flow["sport"] is not None:
            line += f" eq {flow['sport']}"
        line += f" {_acl_addr(flow['dst'])}"
        if ports and flow["dport"] is not None:
            line += f" eq {flow['dport']}"

    seqs = sorted(verdict["seqs"])
    lines = []
    deny_seq = verdict["seq"]
    if deny_seq is None:
        new_seq = (seqs[-1] if seqs else 0) + 10
        lines.append(f"! Nothing in {name} permits this traffic; add a permit if it should be allowed.")
    else:
        prev = max((s for s in seqs if s < deny_seq), default=0)
        if deny_seq - prev < 2:
            lines.append(f"ip access-list resequence {name} 10 10")
            index = seqs.index(deny_seq)
            prev, deny_seq = index * 10, (index + 1) * 10
        new_seq = prev + (deny_seq - prev) // 2
        lines.append(f"! Only if this traffic should be allowed: seq {deny_seq} is an explicit deny, "
                     f"so this may be intended policy.")
    lines += [f"ip access-list {acl['type']} {name}", f" {new_seq} {line}"]
    if verdict["default_numbered"]:
        lines.append("! (sequence numbers assume IOS default numbering: 10, 20, 30, ...)")
    return "\n".join(lines)


def _net_text(net):
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def _flow_text(flow):
    text = f"{flow['proto'] or 'any IP traffic'} from {_net_text(flow['src'])} to {_net_text(flow['dst'])}"
    if flow["dport"] is not None:
        text += f" (dst port {flow['dport']})"
    if flow["sport"] is not None:
        text += f" (src port {flow['sport']})"
    return text


def _exceptions_text(verdict):
    parts = []
    for e in verdict["exceptions"]:
        if e["action"] == "unparsed":
            parts.append(f"seq {e['seq']} could not be parsed ('{e['rule']}')")
        else:
            parts.append(f"seq {e['seq']} {e['action']}s only part of it ('{e['rule']}')")
    return f" Earlier partial matches: {'; '.join(parts)}." if parts else ""


# -- Diagnostic walk ----------------------------------------------------------


class _Walk:
    def __init__(self):
        self.trace = []
        self.root_cause = None
        self.fix = None
        self.confidence = None

    def add(self, layer, check, result, detail):
        self.trace.append({"layer": layer, "check": check, "result": result, "detail": detail})

    def ok(self, layer, check, detail):
        self.add(layer, check, "PASS", detail)

    def info(self, layer, check, detail):
        self.add(layer, check, "INFO", detail)

    def fault(self, layer, check, detail, summary, device, obj, fix, confidence="high"):
        self.add(layer, check, "FAIL", detail)
        self.root_cause = {"layer": layer, "summary": summary, "device": device, "object": obj}
        self.fix = fix
        self.confidence = confidence


def _who(ep):
    if ep["kind"] == "host_port":
        desc = f" ({ep['description']})" if ep["description"] else ""
        return f"the host on {ep['access_port']}{desc}"
    if ep["kind"] == "host_ip":
        return f"host {ep['ip']}"
    return ep["interface"] or f"'{ep['input']}'"


def _describe(ep):
    if ep["ambiguous"]:
        return (f"'{ep['input']}' is AMBIGUOUS: {ep['network']} is claimed by "
                f"{', '.join(ep['gateway_candidates'])}.")
    kind = ep["kind"]
    if kind == "host_port":
        return (f"'{ep['input']}' -> access port {ep['access_port']} (VLAN {ep['vlan']}); "
                f"gateway {ep['gateway'] or 'not found'}.")
    if kind == "host_ip":
        behind = f", VLAN {ep['vlan']} behind {ep['switch']}" if ep["switch"] else ""
        return f"{ep['ip']} -> host in {ep['network']}{behind}; gateway {ep['gateway']}."
    if kind == "svi":
        return (f"'{ep['input']}' -> SVI {ep['interface']} ({ep['ip']}), VLAN {ep['vlan']}; "
                f"gateway {ep['gateway'] or 'not found'}.")
    if kind == "gateway":
        return f"'gateway' -> the source's gateway, {ep['gateway'] or 'not found (see L2)'}."
    return f"'{ep['input']}' -> interface {ep['interface']} ({ep['ip'] or 'no IP'})."


def _view(ep):
    return {k: v for k, v in ep.items() if k != "input" and v not in (None, [], False)}


def _endpoints(ctx):
    return (("Source", ctx["src"]), ("Destination", ctx["dst"]))


# L1 ----------------------------------------------------------------------------


def _segment(ep, local_l2):
    """Interfaces an endpoint's traffic must cross to reach its gateway, bottom-up."""
    items = []
    if ep["kind"] == "host_port":
        items.append(("access port", ep["access_port"]))
    elif ep["kind"] == "host_ip" and ep["switch"]:
        items.append(("access port", None))  # host's exact port is unknown
    elif ep["kind"] == "svi":
        items.append(("SVI", ep["interface"]))
    elif ep["interface"]:
        if _parent(ep["interface"]):
            items.append(("parent interface", _parent(ep["interface"])))
        items.append(("interface", ep["interface"]))
    if ep["kind"] in HOST_KINDS and not local_l2:
        items += [("uplink trunk", ep["trunk"]), ("router trunk port", ep["router_port"]),
                  ("gateway interface", ep["gateway"])]
    return items


def _check_up(topo, w, label, what, key):
    """L1 check of one interface: config shutdown, plus live oper/link state if present."""
    i = topo.ifaces[key]
    check = f"{label} {what} up"
    reason = topo.down_reason(key)
    if reason is None:
        live = "; live oper/link up" if topo.live is not None else ""
        w.ok("L1", check, f"{topo.label(key)} is up (no shutdown{live}).")
        return False
    impact = ("the attached host has no link to the network" if what == "access port"
              else "traffic has no path through it")
    if reason == "admin":
        source = " (config)" if topo.live is not None else ""
        w.fault(
            "L1", check, f"{topo.label(key)} is administratively down (shutdown){source}.",
            summary=f"The {label.lower()}'s {what} {topo.label(key)} is administratively shut down, "
                    f"so {impact}.",
            device=i["device"], obj=f"{i['name']} ({what})", fix=f"interface {i['name']}\n no shutdown",
        )
        return True
    _live_fault(topo, w, check, key, reason, what, impact)
    return True


def _live_fault(topo, w, check, key, reason, what, impact):
    """FAIL for an interface that is up in config but down/flapping in live state."""
    a = _down_analysis(topo, key, reason, what)
    if reason == "flapping":
        impact = "traffic across it is dropped intermittently while the link bounces"
    w.fault(
        "L1", check, f"{topo.label(key)} {a['state']}{a['link_clause']}.",
        summary=f"{topo.label(a['culprit'])} is {a['cause']}{a['taking']}, so {impact}.",
        device=a["device"], obj=a["object"], fix=a["fix"], confidence=a["confidence"],
    )


def _down_analysis(topo, key, reason, what):
    """Explain a down interface: its state, the link it breaks, which end to blame, the fix."""
    i = topo.ifaces[key]
    state = {"admin": "is administratively shut down (config)", "oper": "is operationally DOWN (live)",
             "link": "link is DOWN (live)", "flapping": "link is FLAPPING (live)"}[reason]
    link_word = "flapping" if reason == "flapping" else "down"
    link_name = None

    # If only the link is down, the fault usually sits on the far end: blame that end.
    culprit, culprit_reason, culprit_what = key, reason, what
    peer = topo.link_peer(key)
    link_clause = ""
    if peer:
        pi = topo.ifaces[peer]
        link_name = f"{i['device']}↔{pi['device']}"
        link_clause = f" — the {link_name} link is {link_word}"
        peer_reason = topo.down_reason(peer)
        if reason == "link" and peer_reason in ("admin", "oper"):
            culprit, culprit_reason, culprit_what = peer, peer_reason, f"link to {i['device']}"
            peer_state = ("administratively shut down (config)" if peer_reason == "admin"
                          else "operationally down (live)")
            link_clause += f": peer {topo.label(peer)} is {peer_state}"

    c = topo.ifaces[culprit]
    name = c["name"]
    if culprit_reason == "admin":
        fix = f"! On {c['device']}:\ninterface {name}\n no shutdown"
        cause = "administratively shut down"
    elif culprit_reason == "flapping":
        fix = (f"! On {c['device']}: the link is up in config but flapping; find the physical cause\n"
               f"show interfaces {name} | include line protocol|resets|CRC|carrier\n"
               f"show logging | include {name}\n"
               f"! Check cabling/optics/duplex on both ends; optionally damp flaps while fixing:\n"
               f"interface {name}\n dampening")
        cause = "flapping"
    else:
        far = f" and the far end ({peer if culprit == key else key})" if peer else ""
        fix = (f"! On {c['device']}: {name} is not shut down in config, so the fault is physical/operational\n"
               f"show interfaces {name}\n"
               f"show logging | include {name}\n"
               f"! Check cabling/optics{far}; if the port is err-disabled, bounce it:\n"
               f"interface {name}\n shutdown\n no shutdown")
        cause = "operationally down (live)" if culprit_reason == "oper" else "link-down (live)"
    taking = f", taking down the {link_name} link" if peer and reason != "flapping" else ""
    if reason == "flapping":
        taking = f" on the {link_name} link" if peer else ""
    return {
        "state": state, "link_clause": link_clause, "link_name": link_name, "culprit": culprit,
        "cause": cause, "taking": taking, "device": c["device"], "object": f"{name} ({culprit_what})",
        "fix": fix, "confidence": "medium" if reason == "flapping" else "high",
    }


def _check_unknown_port(topo, w, label, ep):
    switch, vlan = ep["switch"], ep["vlan"]
    check = f"{label} access port up"
    ports = sorted(k for k, i in topo.ifaces.items()
                   if i["device"] == switch and topo.is_access(k)
                   and i["switchport"]["access_vlan"] == vlan)
    if not ports:
        w.info("L1", check, f"{ep['ip']} was resolved by IP and {switch} has no access ports in "
                            f"VLAN {vlan}, so the host's port can't be checked.")
        return False
    states = ", ".join(f"{topo.ifaces[p]['name']} {'DOWN' if topo.down_reason(p) else 'up'}"
                       for p in ports)
    if all(topo.down_reason(p) for p in ports):
        names = [topo.ifaces[p]["name"] for p in ports]
        w.fault(
            "L1", check, f"Every VLAN {vlan} access port on {switch} is shut down ({states}).",
            summary=f"Host {ep['ip']} is in VLAN {vlan} on {switch}, and every access port in that "
                    f"VLAN is administratively shut down, so the host most likely has no link.",
            device=switch, obj=", ".join(names),
            fix="\n".join(f"interface {n}\n no shutdown" for n in names), confidence="medium",
        )
        return True
    w.info("L1", check, f"{ep['ip']} was resolved by IP, so its exact port is unknown. "
                        f"VLAN {vlan} access ports on {switch}: {states}.")
    return False


def _layer_l1(topo, w, ctx):
    checked = set()
    for label, ep in _endpoints(ctx):
        if ep["ambiguous"]:
            w.info("L1", f"{label} interface state",
                   f"'{ep['input']}' can't be pinned to one interface "
                   f"({', '.join(ep['gateway_candidates'])} all claim it); see L3.")
            continue
        new = 0
        for what, key in _segment(ep, ctx["local_l2"]):
            if what == "access port" and key is None:
                new += 1
                if _check_unknown_port(topo, w, label, ep):
                    return
                continue
            if key is None or key in checked:
                continue
            checked.add(key)
            new += 1
            if _check_up(topo, w, label, what, key):
                return
        if not new:
            w.info("L1", f"{label} interface state", "Same interfaces as the source's path; checked above.")

    # Config-only runs keep their original behavior: a shutdown transit interface is
    # already excluded from routing, so L3 reports it. Live faults don't change the
    # configured routes, so the transit hops must be checked physically here.
    if topo.live is not None:
        _check_transit(topo, w, ctx, checked)


def _check_transit(topo, w, ctx, checked):
    """L1-check every interface the routed path crosses (both directions), using live state."""
    src, dst = ctx["src"], ctx["dst"]
    if src["ambiguous"] or dst["ambiguous"] or src["network"] == dst["network"]:
        return False
    if any(ep["kind"] in HOST_KINDS and not ep["gateway"] for ep in (src, dst)):
        w.info("L1", "Transit path", "The routed path can't be computed until the gateway is "
                                     "identified (see L2).")
        return False
    for direction, frm, to in (("Forward", src, dst), ("Return", dst, src)):
        route = topo.forward(**_forward_args(topo, frm, to))
        if not route["ok"]:
            w.info("L1", f"{direction} transit path",
                   f"No configured route to check yet ({route['reason']}); L3 examines routing.")
            return False
        todo = []
        for hop in route["hops"]:
            for role, key in (("ingress", hop["ingress"]), ("egress", hop["egress"])):
                if not key:
                    continue
                for k, what in ((_parent(key), f"hop {hop['device']} {role} parent"),
                                (key, f"hop {hop['device']} {role}")):
                    if k is not None and k not in checked and k not in (t[0] for t in todo):
                        todo.append((k, what))
        crosses = " -> ".join(h["device"] for h in route["hops"])
        w.info("L1", f"{direction} transit path",
               f"Configured path crosses {crosses}; " +
               ("checking each hop's interfaces against live state." if todo
                else "all of its interfaces were already checked above."))
        for k, what in todo:
            checked.add(k)
            if _check_up(topo, w, f"{direction} path", what, k):
                return True
    return False


# L2 ----------------------------------------------------------------------------


def _no_switch_text(ep):
    if ep["kind"] == "gateway":
        return (f"The destination is the source's own gateway ({ep['gateway']}); its L2 path is "
                f"the source VLAN checked above.")
    if ep["kind"] == "host_ip" and ep["vlan"] is not None:
        return (f"{ep['ip']} sits behind {ep['router_port']} (dot1Q {ep['vlan']}), but no switch in "
                f"the model connects there; the L2 path beyond the router can't be checked.")
    if ep["kind"] == "host_ip":
        return f"{ep['ip']} sits on routed interface {ep['gateway']}; no modeled switch in the path."
    return f"{ep['interface']} is a routed interface on {ep['device']}; no switching on this side."


def _check_vlan_path(topo, w, label, ep, local_l2):
    switch, vlan = ep["switch"], ep["vlan"]
    vlans = topo.cfg(switch)["vlans"]
    if ep["kind"] == "host_port":
        where = f"{topo.label(ep['access_port'])} is an access port in VLAN {vlan}."
    elif ep["kind"] == "svi":
        where = f"{ep['interface']} is the SVI for VLAN {vlan}."
    else:
        where = (f"{ep['ip']} is in VLAN {vlan} (gateway {ep['gateway']} uses dot1Q {vlan}), "
                 f"carried to {switch} over {ep['trunk']}.")
    w.info("L2", f"{label} VLAN", where)

    check = f"VLAN {vlan} defined on {switch}"
    if vlan not in vlans:
        defined = ", ".join(str(v) for v in sorted(vlans)) or "none"
        w.fault("L2", check, f"{switch} has no 'vlan {vlan}' (defined: {defined}).",
                summary=f"VLAN {vlan} is not defined on {switch}, so {switch} does not forward "
                        f"traffic for {_who(ep)}.",
                device=switch, obj=f"vlan {vlan}", fix=f"vlan {vlan}\n name <NAME>")
        return True
    w.ok("L2", check, f"VLAN {vlan} ({vlans[vlan] or 'unnamed'}) is defined.")

    if local_l2:
        w.info("L2", "Trunk toward gateway", f"Both endpoints are in VLAN {vlan} on {switch}; "
                                             f"traffic is switched locally and never crosses the trunk.")
        return False

    trunk = ep["trunk"]
    if trunk is None:
        w.fault("L2", f"Uplink trunk on {switch}", f"{switch} has no trunk interface.",
                summary=f"{switch} has no trunk toward a router, so VLAN {vlan} has no path to a gateway.",
                device=switch, obj="uplink trunk (missing)",
                fix=f"interface <uplink>\n switchport trunk encapsulation dot1q\n switchport mode trunk\n"
                    f" switchport trunk allowed vlan add {vlan}",
                confidence="medium")
        return True
    t = topo.ifaces[trunk]
    allowed = t["switchport"]["trunk_allowed"]
    peer = ep["router_port"] or "its router"
    check = f"Trunk {trunk} carries VLAN {vlan}"
    if allowed is None:
        w.ok("L2", check, f"{trunk} has no allowed-VLAN list, so it carries all VLANs.")
    elif vlan in allowed:
        w.ok("L2", check, f"{trunk} (toward {peer}) allows VLAN(s) {','.join(map(str, allowed))}, "
                          f"including {vlan}.")
    else:
        gateway = f" {ep['gateway']}" if ep["gateway"] else ""
        peer_device = ep["router_port"].split(":", 1)[0] if ep["router_port"] else "its router"
        w.fault(
            "L2", check,
            f"{trunk} (toward {peer}) allows only VLAN(s) {','.join(map(str, allowed)) or 'none'}; "
            f"VLAN {vlan} is not carried.",
            summary=f"{switch}'s trunk {t['name']} toward {peer_device} does not allow VLAN {vlan}, so "
                    f"{_who(ep)} (VLAN {vlan}) is cut off from its gateway{gateway}: its frames are "
                    f"dropped at the trunk.",
            device=switch, obj=f"{t['name']} (trunk)",
            fix=f"interface {t['name']}\n switchport trunk allowed vlan add {vlan}",
        )
        return True

    router_port = ep["router_port"]
    if router_port is None:
        w.fault(
            "L2", f"Router at far end of {trunk}",
            f"Could not identify which router interface {trunk} connects to.",
            summary=f"The router side of {switch}'s trunk {t['name']} can't be identified, so no "
                    f"gateway for VLAN {vlan} was found.",
            device=switch, obj=f"{t['name']} (trunk)",
            fix=f"! Fix the trunk description (TRUNK-TO-<router>) or cabling; the router needs:\n"
                f"interface <router-port>.{vlan}\n encapsulation dot1Q {vlan}\n"
                f" ip address <gateway-ip> <mask>",
            confidence="medium",
        )
        return True
    router, port_name = router_port.split(":", 1)
    check = f"Gateway subinterface for VLAN {vlan} on {router}"
    gateway = ep["gateway"]
    if gateway is None:
        w.fault(
            "L2", check, f"{router_port} has no subinterface with 'encapsulation dot1Q {vlan}'.",
            summary=f"{router} has no subinterface for VLAN {vlan} on {port_name}, so hosts in "
                    f"VLAN {vlan} have no gateway.",
            device=router, obj=f"{port_name}.{vlan} (missing)",
            fix=f"interface {port_name}.{vlan}\n encapsulation dot1Q {vlan}\n ip address <gateway-ip> <mask>",
        )
        return True
    g = topo.ifaces[gateway]
    w.ok("L2", check, f"{gateway} (dot1Q {vlan}, {g['ip']}/{g['prefix_len']}) is the gateway for VLAN {vlan}.")
    return False


def _layer_l2(topo, w, ctx):
    seen = set()
    for label, ep in _endpoints(ctx):
        if ep["ambiguous"]:
            w.info("L2", f"{label} L2 path", f"'{ep['input']}' is ambiguous (see L3); its L2 path "
                                             f"can't be determined.")
            continue
        if not ep["switch"]:
            w.info("L2", f"{label} L2 path", _no_switch_text(ep))
            continue
        path = (ep["switch"], ep["vlan"], ep["trunk"])
        if path in seen:
            w.info("L2", f"{label} L2 path", f"Same VLAN {ep['vlan']} on {ep['switch']} as the source; "
                                             f"checked above.")
            continue
        seen.add(path)
        if _check_vlan_path(topo, w, label, ep, ctx["local_l2"]):
            return


# L3 ----------------------------------------------------------------------------


def _overlap_fix(topo, keys):
    # Renumbering a side with no VLAN of hosts behind it touches fewer devices.
    keys = sorted(keys, key=lambda k: (topo.ifaces[k]["vlan"] is not None, k))
    pick = topo.ifaces[keys[0]]
    cheaper = pick["vlan"] is None and any(topo.ifaces[k]["vlan"] is not None for k in keys[1:])
    reason = "it has no VLAN of hosts behind it, so it's the cheaper side" if cheaper else "either side works"
    lines = [f"! Re-IP one side onto a unique subnet ({reason}). On {pick['device']}:",
             f"interface {pick['name']}", " ip address <unique-ip> <mask>"]
    stmt = topo.ospf_statement(keys[0])
    if stmt:
        pid = topo.cfg(pick["device"])["ospf"]["process_id"]
        lines += [f"router ospf {pid}",
                  f" no network {stmt['network']} {stmt['wildcard']} area {stmt['area']}",
                  f" network <unique-network> <wildcard> area {stmt['area']}"]
    return "\n".join(lines)


def _no_route_fix(topo, result, target):
    """(fix, explanation, confidence) for a missing route."""
    owner = target["gateway"] or target["interface"]
    if owner:
        oi = topo.ifaces[owner]
        ospf = topo.cfg(oi["device"])["ospf"]
        if ospf and topo.ospf_statement(owner) is None:
            net = ipaddress.ip_network(oi["network"])
            area = ospf["networks"][0]["area"] if ospf["networks"] else 0
            return (f"! On {oi['device']}:\nrouter ospf {ospf['process_id']}\n"
                    f" network {net.network_address} {net.hostmask} area {area}",
                    f"{oi['device']} never advertises {net} into OSPF (no network statement covers {owner})",
                    "high")
    if topo.down_adjacencies:
        a, b = topo.down_adjacencies[0]
        shut = topo.ifaces[a] if topo.ifaces[a]["shutdown"] else topo.ifaces[b]
        return (f"! On {shut['device']}:\ninterface {shut['name']}\n no shutdown",
                f"the OSPF link {a} <-> {b} is shut down, splitting the routing domain",
                "medium")
    net = result["dest_net"]
    return (f"! On {result['device']} (or bring it into the OSPF domain that carries {net}):\n"
            f"ip route {net.network_address} {net.netmask} <next-hop>",
            "no connected, static, or OSPF route covers it",
            "medium")


def _route_fault(topo, w, check, result, target):
    device = result["device"]
    path = " -> ".join(f"{h['device']} [{h['detail']}]" for h in result["hops"])
    detail = (f"Path so far: {path}. " if path else "") + f"Then {result['reason']}."
    kind = result["kind"]
    if kind in ("ambiguous", "misdelivered"):
        overlap = [o for o in result["owners"] if o in topo.ifaces]
        w.fault(
            "L3", check, detail,
            summary=f"{result['reason'][0].upper()}{result['reason'][1:]}: the subnet overlap between "
                    f"{' and '.join(overlap)} means traffic is split or delivered to the wrong device.",
            device=device, obj=" <-> ".join(overlap) or "routing table",
            fix=_overlap_fix(topo, overlap) if len(overlap) >= 2
            else "! Remove the conflicting route so only one path to the destination remains",
        )
    elif kind == "no_route":
        fix, why, confidence = _no_route_fix(topo, result, target)
        w.fault("L3", check, detail,
                summary=f"{device} has no route to {result['dest_net']}: {why}.",
                device=device, obj="routing table", fix=fix, confidence=confidence)
    else:
        w.fault("L3", check, detail, summary=f"{result['reason'][0].upper()}{result['reason'][1:]}.",
                device=device, obj="routing table",
                fix=f"! Advertise {result['dest_net']} into OSPF on the device that owns it, or add a "
                    f"specific route on {device} toward it",
                confidence="medium")


def _route_links_dead(topo, w, check, hops, dest_net):
    """Refuse to pass a route that egresses a dead interface.

    Routes are computed from config, which can't see live faults. Before a route is
    declared healthy, every hop's egress interface and the next hop's ingress on the same
    link (plus parents of subinterfaces) must be up under the combined config+live rule.
    A dead one is a physical failure surfacing during path computation: reported as L1.
    Config-only runs skip this (the forwarder already excludes shutdown interfaces).
    """
    if topo.live is None:
        return False
    for n, hop in enumerate(hops):
        if not hop["egress"]:
            continue
        next_ingress = hops[n + 1]["ingress"] if n + 1 < len(hops) else None
        for key in (hop["egress"], next_ingress):
            for k in (_parent(key), key) if key else ():
                reason = topo.down_reason(k) if k else None
                if not reason:
                    continue
                a = _down_analysis(topo, k, reason, f"route egress on {topo.ifaces[k]['device']}")
                role = "egresses" if key == hop["egress"] else "enters the next hop at"
                link = f" — the {a['link_name']} link is {'flapping' if reason == 'flapping' else 'down'}" \
                    if a["link_name"] else ""
                that = {"admin": "that interface is administratively shut down (config)",
                        "oper": "that interface is operationally DOWN (live)",
                        "link": "that interface's link is DOWN (live)",
                        "flapping": "that interface's link is FLAPPING (live)"}[reason]
                verdict = "intermittently unusable" if reason == "flapping" else "not usable"
                w.fault(
                    "L1", f"{check}: transit link up",
                    f"{hop['device']} [{hop['detail']}], but {topo.label(k)} {a['state']}"
                    f"{a['link_clause']}.",
                    summary=f"The route from {hop['device']} to {dest_net} {role} {k}, but {that}{link}, "
                            f"so the route is {verdict}.",
                    device=a["device"], obj=a["object"], fix=a["fix"], confidence=a["confidence"],
                )
                return True
    return False


def _ep_net(ep):
    return ipaddress.ip_network(f"{ep['ip']}/32") if ep["ip"] else ipaddress.ip_network(ep["network"])


def _forward_args(topo, frm, to):
    if frm["kind"] in HOST_KINDS:
        start, ingress = topo.ifaces[frm["gateway"]]["device"], frm["gateway"]
    else:
        start, ingress = frm["device"], None  # traffic originates on the device itself
    return {
        "start": start, "ingress": ingress, "dest_net": _ep_net(to),
        "dest_iface": to["interface"] if to["kind"] in ("interface", "gateway") else None,
        "expect_egress": to["gateway"] if to["kind"] in HOST_KINDS else None,
    }


def _layer_l3(topo, w, ctx):
    src, dst = ctx["src"], ctx["dst"]
    for label, ep in _endpoints(ctx):
        if ep["ambiguous"]:
            candidates = ep["gateway_candidates"]
            devices = sorted({topo.ifaces[k]["device"] for k in candidates})
            what = ep["ip"] or f"'{ep['input']}'"
            w.fault(
                "L3", f"{label} subnet is unambiguous",
                f"{what} falls in {ep['network']}, which is claimed by {' and '.join(candidates)}.",
                summary=f"{ep['network']} is configured on both {' and '.join(devices)} (subnet overlap), "
                        f"so the network can't tell which one {what} lives behind; traffic to it is "
                        f"misrouted or blackholed.",
                device=" / ".join(devices), obj=" <-> ".join(candidates),
                fix=_overlap_fix(topo, candidates),
            )
            return

    same = src["network"] == dst["network"]
    if same:
        w.ok("L3", "Same subnet", f"Both endpoints are in {src['network']}; no routing is needed "
                                  f"(the L2 path was checked above).")
    else:
        w.info("L3", "Same subnet", f"Source is in {src['network']}, destination in {dst['network']}; "
                                    f"traffic must be routed.")

    touched = False
    for conflict in topo.model.conflicts:
        cnet = ipaddress.ip_network(conflict["network"])
        for label, ep in _endpoints(ctx):
            if ep["network"] and ipaddress.ip_network(ep["network"]).overlaps(cnet):
                touched = True
                note = ("local traffic is unaffected" if same
                        else "checking whether routing still reaches the right device")
                w.info("L3", "Subnet overlap",
                       f"{label} subnet {ep['network']} overlaps conflict {conflict['network']} "
                       f"({' vs '.join(conflict['interfaces'])}); {note}.")
    if not touched:
        w.ok("L3", "Subnet overlap", "Neither endpoint's subnet is part of an overlap conflict.")

    if same:
        # No routing; only a device interface that is itself an endpoint sees the traffic.
        def local(ep):
            if ep["kind"] in HOST_KINDS:
                return []
            return [_hop(ep["device"], ep["interface"], None, "local", f"{ep['device']} owns {ep['interface']}")]
        ctx["paths"] = [("forward", local(dst), False), ("return", local(src), False)]
        return

    forward_args = _forward_args(topo, src, dst)
    forward = topo.forward(**forward_args)
    if not forward["ok"]:
        _route_fault(topo, w, "Route to destination", forward, dst)
        return
    if _route_links_dead(topo, w, "Route to destination", forward["hops"], forward_args["dest_net"]):
        return
    w.ok("L3", "Route to destination", " -> ".join(f"{h['device']} [{h['detail']}]" for h in forward["hops"]))
    back_args = _forward_args(topo, dst, src)
    back = topo.forward(**back_args)
    if not back["ok"]:
        _route_fault(topo, w, "Return route to source", back, src)
        return
    if _route_links_dead(topo, w, "Return route to source", back["hops"], back_args["dest_net"]):
        return
    w.ok("L3", "Return route to source", " -> ".join(f"{h['device']} [{h['detail']}]" for h in back["hops"]))
    ctx["paths"] = [
        ("forward", forward["hops"], src["kind"] not in HOST_KINDS),
        ("return", back["hops"], dst["kind"] not in HOST_KINDS),
    ]


# L4 / ACL ----------------------------------------------------------------------


def _checkpoints(hops, locally_originated):
    """(interface, direction) pairs the traffic crosses. IOS does not apply outbound
    ACLs to traffic the router generates itself."""
    points = []
    for n, hop in enumerate(hops):
        if hop["ingress"]:
            points.append((hop["ingress"], "in"))
        if hop["egress"] and not (n == 0 and locally_originated):
            points.append((hop["egress"], "out"))
    return points


def _layer_acl(topo, w, ctx):
    symptom = ctx["symptom"]
    proto = (symptom.get("protocol") or "").lower() or None
    port = symptom.get("port")
    forward_flow = {"src": _ep_net(ctx["src"]), "dst": _ep_net(ctx["dst"]), "proto": proto,
                    "sport": None, "dport": int(port) if port is not None else None}
    return_flow = {"src": forward_flow["dst"], "dst": forward_flow["src"], "proto": proto,
                   "sport": forward_flow["dport"], "dport": None}

    all_points, applied = [], 0
    for direction, hops, local in ctx["paths"]:
        flow = forward_flow if direction == "forward" else return_flow
        for key, way in _checkpoints(hops, local):
            all_points.append(f"{key} {way}")
            i = topo.ifaces[key]
            group = i["access_group"]
            if not group or group["dir"] != way:
                continue
            applied += 1
            name = group["name"]
            check = f"ACL {name} {way} on {key} ({direction} traffic)"
            acl = topo.cfg(i["device"])["access_lists"].get(name)
            if acl is None:
                w.info("L4/ACL", check, f"{key} references ACL {name}, which is not defined; IOS passes "
                                        f"all traffic through an undefined ACL.")
                continue
            verdict = evaluate_acl(acl, flow)
            if verdict["action"] == "permit":
                w.ok("L4/ACL", check, f"{_flow_text(flow)} is permitted by seq {verdict['seq']} "
                                      f"('{verdict['rule']}').{_exceptions_text(verdict)}")
                continue
            where = (f"seq {verdict['seq']} ('{verdict['rule']}')" if verdict["seq"]
                     else "the implicit 'deny any' at the end")
            partial_permits = [e for e in verdict["exceptions"] if e["action"] == "permit"]
            summary = (f"ACL {name} applied {way} on {key} denies {direction} traffic "
                       f"({_flow_text(flow)}) at {where}.")
            if partial_permits:
                allowed = ", ".join(f"'{e['rule']}'" for e in partial_permits)
                summary += (f" Only traffic matching {allowed} gets through before that, so if that "
                            f"traffic fails too, look elsewhere.")
            w.fault(
                "L4/ACL", check,
                f"{_flow_text(flow)} is denied by {where}.{_exceptions_text(verdict)}",
                summary=summary, device=i["device"], obj=f"{i['name']} ip access-group {name} {way}",
                fix=_acl_fix(name, acl, verdict, flow),
                confidence="medium" if partial_permits else "high",
            )
            return

    if applied:
        return
    if not all_points:
        detail = ("Traffic stays inside one VLAN, so no routed interface (and no interface ACL) is in "
                  "the path. VLAN ACLs are not modeled.")
    else:
        detail = (f"No interface on the path has an ip access-group in the direction traffic crosses "
                  f"it ({', '.join(all_points)}).")
    w.ok("L4/ACL", "Interface ACLs on path", detail)


LAYERS = {"L1": _layer_l1, "L2": _layer_l2, "L3": _layer_l3, "L4/ACL": _layer_acl}


# -- Entry point -------------------------------------------------------------


def diagnose(model, symptom, live_state=None):
    """Diagnose a symptom against the model.

    live_state: optional monitor.poll(...) snapshot (possibly with injected faults).
    When given, L1 treats an interface as down if it is shut down in config OR is
    oper/link down or flapping in the live state, and also checks every interface the
    routed path crosses. When None, only config (admin) state is used.
    """
    topo = _Topo(model, live_state)
    w = _Walk()
    result = {"symptom": dict(symptom), "trace": w.trace, "root_cause": None, "summary": None,
              "fix": None, "confidence": None}

    if symptom.get("type") != "no_connectivity":
        w.add("RESOLVE", "Symptom type", "FAIL",
              f"Unsupported symptom type {symptom.get('type')!r}; only 'no_connectivity' is handled.")
        result["summary"] = "Unsupported symptom type; nothing was walked."
        return result

    src, error = topo.resolve(symptom.get("source"))
    if src:
        dst, error = topo.resolve(symptom.get("dest"), source=src)
        which, value = "destination", symptom.get("dest")
    else:
        which, value = "source", symptom.get("source")
    if error:
        w.add("RESOLVE", f"Resolve {which}", "FAIL", f"Could not resolve {which} {value!r}: {error}.")
        result["summary"] = (f"Could not resolve the {which} {value!r} to anything in the model "
                             f"({error}), so no path could be walked.")
        return result

    result["symptom"]["resolved"] = {"source": _view(src), "dest": _view(dst)}
    w.info("RESOLVE", "Source", _describe(src))
    w.info("RESOLVE", "Destination", _describe(dst))
    if live_state is not None:
        faults = live_state.get("faults") or []
        w.info("RESOLVE", "Live state",
               "Using live monitor state for L1 (simulated); injected faults: "
               + (", ".join(faults) if faults else "none") + ".")

    ctx = {
        "symptom": symptom, "src": src, "dst": dst, "paths": [],
        "local_l2": bool(src["kind"] in HOST_KINDS and dst["kind"] in HOST_KINDS and src["switch"]
                         and src["switch"] == dst["switch"] and src["vlan"] == dst["vlan"]),
    }
    for n, layer in enumerate(LAYER_ORDER):
        LAYERS[layer](topo, w, ctx)
        if w.root_cause:
            rest = LAYER_ORDER[n + 1:]
            found = w.root_cause["layer"]
            where = found if found == layer else f"{found} (discovered during {layer} path computation)"
            w.info(layer, "Walk stopped",
                   f"Root cause found at {where}; " +
                   (f"not evaluated: {', '.join(rest)}." if rest
                    else "remaining checkpoints on the path were not evaluated."))
            break

    if w.root_cause:
        result.update(root_cause=w.root_cause, summary=w.root_cause["summary"], fix=w.fix,
                      confidence=w.confidence)
    else:
        result["summary"] = (
            f"All modeled checks passed: the configured path from {src['input']!r} to "
            f"{dst['input']!r} is healthy"
            + (" and every interface on it is up in the live state" if live_state is not None else "")
            + ". The problem is likely outside the modeled config: "
            f"physical cabling or optics, the host's own IP/mask/gateway or firewall, or something upstream."
        )
    return result


def _print_diagnosis(d):
    s = d["symptom"]
    extra = "".join(f"  {k}={s[k]}" for k in ("protocol", "port") if s.get(k) is not None)
    print("=" * 100)
    print(f"Symptom: {s.get('type')}  {s.get('source')} -> {s.get('dest')}{extra}")
    print("=" * 100)
    print("Trace:")
    for n, step in enumerate(d["trace"], 1):
        print(f"{n:4}. [{step['layer']:<7}] {step['result']:<4}  {step['check']}")
        print(textwrap.fill(step["detail"], width=100, initial_indent=" " * 22, subsequent_indent=" " * 22))
    print()
    rc = d["root_cause"]
    if rc:
        print(f"Root cause  [{rc['layer']}]  {rc['device']}  -  {rc['object']}")
        print(textwrap.fill(rc["summary"], width=100, initial_indent="  ", subsequent_indent="  "))
        print(f"Confidence: {d['confidence']}")
        print("Fix:")
        for line in d["fix"].split("\n"):
            print(f"    {line}")
    else:
        print("Root cause: none found")
        print(textwrap.fill(d["summary"], width=100, initial_indent="  ", subsequent_indent="  "))
    print()


BUILTIN_SYMPTOMS = [
    {"type": "no_connectivity", "source": "SERVER-APP-1", "dest": "gateway"},
    {"type": "no_connectivity", "source": "SERVER-DB-1", "dest": "gateway"},
    {"type": "no_connectivity", "source": "10.10.10.50", "dest": "10.10.20.10"},
    # Users -> r1's own VLAN 20 address: no switch in the dest path, so the ACL is reached.
    {"type": "no_connectivity", "source": "10.10.10.50", "dest": "10.10.20.1", "protocol": "icmp"},
    # Healthy multi-hop path over OSPF (r2 -> r1): no fault should be invented.
    {"type": "no_connectivity", "source": "USER-PC-4", "dest": "10.10.10.50"},
    # Destination inside the fw1/r2 overlap.
    {"type": "no_connectivity", "source": "USER-PC-4", "dest": "10.20.20.10"},
]


if __name__ == "__main__":
    try:
        from . import monitor
    except ImportError:  # run directly as a script
        import monitor

    sys.stdout.reconfigure(encoding="utf-8")  # live-fault wording uses '↔'
    net_model = NetworkModel(*sys.argv[1:2])
    for sym in BUILTIN_SYMPTOMS:
        _print_diagnosis(diagnose(net_model, sym))

    print("#" * 100)
    print("# LIVE-STATE TESTS (simulated monitor state with injected faults)")
    print("#" * 100 + "\n")
    inter_router = {"type": "no_connectivity", "source": "USER-PC-4", "dest": "10.10.10.50"}

    live = monitor.poll(net_model)
    print(">>> Baseline live state, no injected faults: expect a healthy path\n")
    _print_diagnosis(diagnose(net_model, inter_router, live_state=live))

    healthy = diagnose(net_model, inter_router, live_state=live)
    assert healthy["root_cause"] is None, healthy["root_cause"]

    monitor.inject_interface_down(live, "r1:GigabitEthernet0/0")
    print(">>> Injected r1:GigabitEthernet0/0 down: expect L1 FAIL on the r1<->r2 link\n")
    core_down = diagnose(net_model, inter_router, live_state=live)
    _print_diagnosis(core_down)
    rc = core_down["root_cause"]
    assert rc and rc["layer"] == "L1", rc
    assert rc["device"] == "r1" and rc["object"].startswith("GigabitEthernet0/0"), rc
    assert "r2↔r1 link" in rc["summary"] and core_down["confidence"] == "high", core_down
    assert not any(t["check"] == "Route to destination" and t["result"] == "PASS"
                   for t in core_down["trace"]), "route out a dead interface must not PASS"
    print("    [assert OK] L1 root cause on r1 GigabitEthernet0/0 (r1<->r2 link), no route PASS\n")

    # The routing layer must refuse the dead egress on its own, even if L1's transit
    # check were absent: disable it and confirm L3 path computation raises the L1 fault.
    print(">>> Same fault with the L1 transit check disabled: the L3 route check must catch it\n")
    _saved, _check_transit = _check_transit, lambda *a: False
    try:
        guarded = diagnose(net_model, inter_router, live_state=live)
    finally:
        _check_transit = _saved
    _print_diagnosis(guarded)
    rc = guarded["root_cause"]
    assert rc and rc["layer"] == "L1" and rc["device"] == "r1", rc
    assert any(t["check"] == "Route to destination: transit link up" and t["result"] == "FAIL"
               for t in guarded["trace"]), "L3 route guard did not fire"
    assert not any(t["check"] == "Route to destination" and t["result"] == "PASS" for t in guarded["trace"])
    print("    [assert OK] route out r2:GigabitEthernet0/0 rejected during L3 path computation\n")

    monitor.clear_faults(live)
    monitor.inject_link_flap(live, ("r1", "r2"))
    print(">>> Injected r1<->r2 link flap: expect L1 FAIL (flapping), medium confidence\n")
    _print_diagnosis(diagnose(net_model, inter_router, live_state=live))
