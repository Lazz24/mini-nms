# Mini-NMS — Network Operations Center

A working network management system that audits Cisco IOS configurations, monitors live device state, and troubleshoots connectivity faults by reasoning through the network layer by layer.

**Live demo:** [mini-nms.onrender.com](https://mini-nms.onrender.com)

*(Free-tier hosting — the first load after a period of inactivity takes ~30–60 seconds to wake up, then runs normally.)*

## What it does

Mini-NMS reads real Cisco IOS running-config files for a small network — two routers, two switches, and a firewall — and turns them into a live operations dashboard with three capabilities that mirror a network engineer's daily work:

**Audit.** Inspects every device and the topology as a whole against a ruleset covering security (telnet on VTY, weak SNMP communities, unprotected management access), correctness (VLAN/trunk mismatches, subnet overlaps, admin-down host ports), and configuration drift from an approved baseline. Each finding carries a severity, a plain-English explanation of why it matters, and the exact IOS commands to fix it.

**Monitor.** Produces live interface state — up/down, link status, utilization, errors — with an alerts feed, and supports fault injection so you can watch the network react to a failure in real time.

**Troubleshoot.** Given a symptom ("this server can't reach its gateway"), it walks the path bottom-up — physical → VLAN → routing → ACL — and stops at the first layer that's broken, reporting the root cause and the fix. It reads live monitor state, so an operationally-down link is caught even when the configuration looks correct.

## Architecture

The system is layered the way a real NMS is — a backend that computes, a frontend that displays:

```
IOS configs → parser → network model → engine → API → dashboard
                                          │
                        audit · monitor · troubleshoot
```

- `engine/parser.py` — turns raw IOS text into structured data; surfaces any line it doesn't recognize rather than dropping it silently.
- `engine/model.py` — assembles the parsed configs into one topology, inferring links by subnet and description, and flagging conflicts (e.g. two devices claiming the same subnet) rather than drawing a false connection.
- `engine/audit.py` — the ruleset; each rule inspects parsed fields, so it works on configs it has never seen, not just the sample network.
- `engine/troubleshoot.py` — the layer-by-layer diagnostic walk.
- `engine/monitor.py` — simulated live state and fault injection.
- `api.py` — a stdlib HTTP server exposing the engine as JSON and serving the dashboard.
- `dashboard/index.html` — the single-page operations UI.

**Design principle throughout:** the model computes, the output explains. Scores and diagnoses are deterministic and auditable; the reasoning is rendered in plain language on top.

## Running it locally

No dependencies — pure Python standard library (Python 3.11+).

```
git clone https://github.com/Lazz24/mini-nms.git
cd mini-nms
python api.py
```

Then open <http://localhost:8080>.

## Tests

```
python -m unittest discover tests
```

41 tests cover parsing (including malformed and empty input), topology inference, every audit rule, the troubleshooting walk at each layer, live-state correlation, and graceful handling of bad input.

## Note on the simulation

The network is simulated — the tool derives monitoring state from the device configs plus injectable faults rather than polling real hardware. The configuration analysis (parsing, audit, topology, layer-by-layer diagnosis) is real and works on any Cisco IOS config in the same format.
