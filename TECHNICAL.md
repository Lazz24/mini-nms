# Mini-NMS — Technical Documentation

## Purpose

Mini-NMS reads Cisco IOS configurations for a small network and provides three functions that mirror a network engineer's core work: auditing configuration, monitoring live state, and troubleshooting connectivity faults. This document covers the architecture, each component, the key design decisions, and the boundaries of the simulation.

## System architecture

The system separates computation from presentation, layered the way a production NMS is:

```
IOS configs (text)
      │
      ▼
  parser.py ──────► structured per-device data
      │
      ▼
  model.py ───────► unified topology (devices, links, conflicts)
      │
      ├──────────► audit.py ────────► findings
      ├──────────► monitor.py ──────► live state + alerts
      └──────────► troubleshoot.py ─► diagnosis (trace + fix)
                          │
                          ▼
                       api.py (stdlib HTTP, JSON + dashboard)
                          │
                          ▼
                   dashboard/index.html
```

Data flows one direction. The engine never depends on the API or dashboard; it can be driven directly from Python or the test suite. This is why the whole engine is testable in isolation and why the same code runs identically from the command line and behind the web server.

## Components

### Parser (`parser.py`)

Converts raw IOS running-config text into a structured dictionary per device: hostname, services, interfaces (with IPs, masks, VLANs, switchport config, ACLs applied), VLAN definitions, OSPF configuration, access lists, SNMP communities, static routes, and VTY line configuration.

Parsing is context-based: a line like `interface GigabitEthernet0/1` opens a block, and indented lines below it belong to that interface until the next unindented line. The same logic handles `router ospf`, `line vty`, `vlan`, and named ACL blocks.

**Design decision — fail loud, not silent.** Any line the parser doesn't recognize is appended verbatim to an `_unparsed` list rather than discarded. This matters because silently dropping valid configuration is the kind of latent fault that surfaces on a real device's config later, not on the sample. The test suite asserts that no meaningful line (addresses, VLANs, ACLs, SNMP, VTY) ever lands in `_unparsed`.

### Model (`model.py`)

Assembles the parsed per-device data into a single topology: devices (with inferred roles), interfaces flattened into addressable units, links, and conflicts.

Link inference uses two independent methods:

- **By subnet** — two interfaces on different devices whose IP/mask resolve to the same network are on the same link. This is the reliable method and mirrors how an engineer verifies a connection.
- **By description** — interface descriptions like `TRUNK-TO-R1` name the far end, which catches links that subnet-matching can't (a switch trunk port has no IP).

Where both methods identify the same physical link, the entries are merged into one, preserving both views. This prevents the topology from double-drawing a single cable.

**Design decision — a conflict is not a link.** When two interfaces on different devices claim the same subnet but both act as gateways (both hold the `.1` host address), the model does not record a link. Two devices fighting over one subnet is a misconfiguration, not a connection. It is recorded as a `subnet_overlap` conflict instead. A naive "same subnet → connected" heuristic would draw a cable that doesn't exist and hide a real fault.

### Audit (`audit.py`)

Runs a ruleset over the model and, for drift detection, against a golden reference configuration. Rules fall into three categories:

- **Security** — telnet on VTY lines, VTY lines without an access-class, weak or default SNMP community strings (a known-default set, or under eight characters), SNMP communities not bound to an ACL, missing enable secret, password encryption disabled.
- **Correctness** — an access port assigned to a VLAN its trunk does not carry, subnet overlaps, admin-down interfaces that serve a host, description/subnet mismatches on a link.
- **Drift** — differences between a live config and its approved golden baseline (password encryption, VTY transport, VTY access-class).

Each finding is a structured record: severity, category, rule id, device, object, the finding, why it matters, and the fix in IOS syntax.

**Design decision — rules are general, not hardcoded.** Each rule inspects parsed fields ("any VTY line with telnet"; "any community string in the weak set or under eight characters"), never specific hostnames or values. The audit therefore works on any config in the same format, not only the sample network — which is the difference between a tool and a demo rigged to its own inputs.

### Troubleshoot (`troubleshoot.py`)

Given a symptom (a source and destination, resolvable as a host description, an IP, a `device:interface`, or `gateway`), it produces a diagnosis: an ordered trace, a root cause, a fix, and a confidence level.

The diagnostic method is bottom-up, following the OSI layers, stopping at the first fault:

1. **L1 — physical/interface state.** Are the interfaces on the path up?
2. **L2 — VLAN/switching.** Is the source's VLAN defined and carried across the trunk to its gateway?
3. **L3 — addressing/routing.** Are source and destination routable to each other? Is either endpoint's subnet part of an overlap conflict?
4. **L4/ACL — filtering.** Does an ACL on the path deny the specific traffic, evaluated first-match-wins?

The walk stops at the first layer that fails, because that layer is the root cause and everything above it is a downstream symptom. This is the discipline that separates diagnosis from guessing.

**Design decision — live state overrides configuration at L1.** The troubleshooter accepts an optional live-state snapshot. When present, an interface is treated as down if the config shuts it down or the live state reports it operationally down or flapping — including transit links the computed route crosses. Without this, the tool could declare a path healthy over a link that is currently down, contradicting the monitor. With it, the monitor and the troubleshooter report one consistent truth. When no live state is supplied, the tool falls back to config-only analysis unchanged.

### Monitor (`monitor.py`)

Produces simulated live state derived from the configuration plus injectable faults: per-interface operational status, link status, utilization, and error counts, plus a device-level view and an alerts feed.

Utilization and error values are derived deterministically from a hash of the interface identifier, so they are stable across polls rather than random noise. Faults can be injected (interface down, link flap, high utilization) and cleared, which drives the live demo and, when passed to the troubleshooter, the live-state correlation described above.

### API (`api.py`)

A standard-library HTTP server. It exposes the engine as JSON — topology, status, alerts, audit, health, and a POST endpoint for troubleshooting and one for fault injection — and serves the dashboard at the root path. It reads the port from the environment for deployment, binds to all interfaces, handles CORS preflight, and wraps each handler so an error returns a JSON error response rather than crashing the server.

### Dashboard (`dashboard/index.html`)

A single self-contained page with no build step and no external libraries. It renders the topology (including the overlap conflict), a live status table refreshing on an interval, the alerts feed with fault-injection controls, the audit findings grouped by severity, and the troubleshooting panel that renders the layer-by-layer trace. It calls the API with relative URLs, so it works identically in local development and in deployment.

## Testing

The engine is covered by 41 automated tests (`python -m unittest discover tests`), grouped by component:

- **Parser** — every config parses; no meaningful line is dropped; empty, whitespace-only, and non-IOS input are handled without raising.
- **Model** — correct device roles, link count after deduplication, and exactly one recorded overlap conflict.
- **Audit** — every seeded flaw is caught and attributed correctly; no false positives (strong SNMP communities and present enable secrets do not trigger findings); every finding is well-formed.
- **Troubleshoot** — each layer's fault is diagnosed at the correct layer; a healthy path returns no fault; missing keys, empty symptoms, and unresolvable endpoints fail gracefully.
- **Live-state** — an injected core-link failure is caught at L1; config-only mode ignores live faults; clearing faults restores health; fault injection is idempotent.
- **Monitor** — all devices polled; a shutdown port reads down; utilization is deterministic; the baseline alerts include the down host port.

The suite tests both correct output on the sample network and graceful failure on bad input. No engine code is modified to make a test pass — a failing test is treated as a real finding.

## Scope and boundaries

The network is simulated. The monitor derives state from configuration and injected faults rather than polling hardware over SNMP, SSH, or ICMP. Routing is computed by comparing connected, static, and OSPF-derived routes by prefix length; OSPF cost is approximated by hop count. ACL matching honors first-match-wins on source and destination subnets and, when supplied, protocol and port, but does not model VLAN ACLs or non-contiguous wildcard masks.

The configuration analysis is real. Parsing, audit, topology inference, and the layer-by-layer diagnostic reasoning operate on any Cisco IOS configuration in the standard running-config format, not only the sample network.
