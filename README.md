# Yarisugi (やりすぎ)

A native Linux proxy toolchain manager designed for hostile network environments, massive node catalogs, and clean system routing.

---

## The Problem Space

Most desktop proxy frontends treat Linux as an afterthought—either running as web views inside heavy runtimes, or exposing local SOCKS5 loopbacks (`127.0.0.1:10808`) that leave half the system unproxied and leak DNS queries directly to the local ISP through `systemd-resolved`.

When users load high-volume public or scraped subscriptions (often thousands of entries), existing tools frequently freeze, choke on thread allocation, and produce misleading metrics.

Yarisugi is designed specifically for the Linux network stack and modern proxy cores (`sing-box`), guided by three operational realities:

### 1. The Latency Check Lie & Catalog Churn
A green ping number to `cp.cloudflare.com` or `gstatic.com/generate_204` proves almost nothing:
* **The Anycast Edge Fallacy:** Anycast CDNs resolve to the user's nearest physical edge PoP. A 20ms HTTP response from Cloudflare only confirms reachability to the local data center; it does not verify whether the upstream VPS can egress to the open internet.
* **Captive Portal & Middlebox Spoofing:** Deep Packet Inspection (DPI) equipment and captive portals routinely intercept port 80/443 traffic and inject `HTTP 200 OK` block pages or auth prompts. Naive HTTP checkers interpret any non-zero response as "alive."
* **Public List Attrition:** Publicly aggregated subscription lists consistently show baseline survival rates in the low single digits, with high rates of functional duplicates sharing identical server endpoints under cosmetic renames.
* **Probing Anomaly Signatures:** Blasting thousands of concurrent, unpadded HTTP pings with identical headers across dead endpoints creates obvious traffic-fingerprinting patterns for ISP DPI.

**How Yarisugi addresses this:** The architecture uses functional identity deduplication (matching endpoints and protocol hashes rather than names), cheap L4 preflight sweeps, and multi-operator quorum verification where both status codes and body signatures must match before a node is marked viable. See [We Don't Tell No Lies](#we-dont-tell-no-lies) for exactly what each tier is allowed to claim.

### 2. Protocol Semantics Matter to Middleboxes
Treating proxy nodes as generic `(ip, port, protocol)` tuples ignores how modern DPI middleboxes classify and degrade traffic:
* **The REALITY Decoy Trap:** Unauthorized client handshakes on an XTLS REALITY port are not dropped—they are transparently proxied to the server's configured fallback site (e.g., `apple.com`). Naive TLS probers complete the handshake, observe a valid third-party certificate, and report the node as operational despite authentication failure.
* **TLS-in-TLS Fingerprinting:** Encapsulating standard TLS payloads inside outer TLS tunnels exposes deterministic handshake packet-length sequences. Protocol enhancements like `xtls-rprx-vision` exist specifically to pad handshake boundaries and prevent heuristic classification.
* **UDP Throttling on QUIC:** Modern UDP-based protocols (Hysteria2, TUIC) excel on congested lines, but hostile ISPs frequently rate-limit or selectively drop high-entropy UDP on non-standard ports. A node with an impressive single-packet ping can stall under real load.

**How Yarisugi addresses this:** The design decouples raw reachability from active tunnel quality. The architecture incorporates in-kernel telemetry (`TCP_INFO` via Netlink `sock_diag`) to detect packet loss, retransmissions, and buffer stalls in real time without injecting synthetic test traffic.

### 3. Core Capabilities vs. Frontend Limitations
Modern cores like `sing-box` offer production-grade transparent routing (TPROXY), sniffing, multiplexing, and detour DNS routing. Most graphical frontends reduce this to loopback proxies or bury configuration behind brittle, manual JSON text fields.

**How Yarisugi addresses this:** Designed to generate explicit, isolated system routing configurations: dual-stack TPROXY, automatic `SO_MARK` loop prevention, and DNS interception that captures port 53 before local network bypasses can cause plaintext leaks.

---

## Architectural Principles

* **Unprivileged GUI + Privileged Daemon Separation:** The user interface runs unprivileged. A lightweight background daemon (`netd`) manages kernel routing rules over a framed UNIX domain socket with UID authorization.
* **Kernel Deadman's Switch:** If the controller crashes or the user session disconnects, the routing daemon automatically reverts all `nftables` rules and policy routes within 5 seconds.
* **Low-Allocation Data Layer:** The UI view runs on an immutable Structure-of-Arrays (SoA) model, rendering 50,000+ entries via a virtualized viewport without heap churn during high-frequency metric updates.
* **Direct Netlink Telemetry:** Inspects active tunnel health by querying kernel state directly (`INET_DIAG_REQ_V2`), avoiding cross-process file-descriptor workarounds.

---

## Current Repository Status

> **Notice:** The project is in active development. Features are implemented in discrete architectural phases to ensure safety at the kernel boundary before enabling host-level routing mutations.

| Subsystem | Status | Implementation Details |
| :--- | :--- | :--- |
| **Storage & IR Engine** | Active | Canonical node normalization, functional hash deduplication, SQLite persistence, and dense SoA snapshots. |
| **Virtual Viewport UI** | Active | Slint-based viewport supporting 50,000+ node models, background projection workers, and non-blocking search/sort. Benchmarked at 100k rows. |
| **Ingestion Engine** | Active | Line-delimited URI bundle parser and Clash/Mihomo YAML proxy reader. |
| **Routing Control Plane (`netd`)** | Active | IPC wire protocol, UID authentication, session ownership, and watchdog rollback engine. |
| **Network Backend** | Active | Dual-stack `nftables` TPROXY, `SO_MARK` loop prevention, policy routing, and DNS interception. |
| **Core Adapter & Supervisor** | Active | `sing-box` outbound configuration compilation, atomic config validation, and SIGHUP process management. |
| **Verification Ladder** | Active | L4 socket preflight (all nodes) → per-protocol egress quorum (finalists only). See *We Don't Tell No Lies* below. |
| **In-kernel Telemetry** | Active | `INET_DIAG_REQ_V2` via Netlink `sock_diag`, plus `pidfd_getfd` for supervised core sockets. |
| **Protocol handshake tier** | Planned | Per-protocol handshake probing; blocked on uTLS fingerprint replay, which stock `rustls` cannot reproduce. |

---

## We Don't Tell No Lies

This is the load-bearing design rule of the project. A proxy client that shows a
green ping for a node that cannot carry a single packet is worse than one that
shows nothing, because the user acts on it. Yarisugi therefore never collapses
"something answered" and "the tunnel works" into a single number.

### Two tiers, two different claims

| Tier | Scope | What it actually proves | What it cannot prove |
| :--- | :--- | :--- | :--- |
| **L4 socket preflight** | every node, cheap | The transport answered: a TCP connect completed, or a UDP datagram came back. Measures the **socket** round trip. | That the proxy protocol authenticates, or that traffic egresses. |
| **Egress quorum scatter** | finalists only | A real request through a real `sing-box` local SOCKS testbed returned the **expected status code *and* the expected body**. A quorum of independent operators must agree. | Anything about a node that never made the shortlist. |

The heavy tier exists precisely because the cheap tier cannot catch the
Anycast Edge Fallacy, captive portals that answer `HTTP 200` to everything, or
the REALITY decoy trap (where an unauthorized handshake is transparently
forwarded to the server's fallback site and returns a perfectly valid
third-party certificate). The heavy tier drives the **real core**, so a failed
authentication cannot masquerade as a success.

### Confidence is explicit, never inferred

`ProbeOutcome` carries a `ProbeConfidence` rather than a boolean:

```rust
pub enum ProbeConfidence {
    Confirmed,        // verified end-to-end by a real transcript
    SocketReachable,  // the transport answered; reachability only
    Unconfirmed,      // proved nothing either way (e.g. silent UDP)
    Unreachable,      // proven dead: refused, timed out, unresolvable
}
```

`Unconfirmed` is the variant that matters most. A UDP probe that gets no reply
has learned **nothing**: a hostile ISP silently dropping high-entropy UDP on a
non-standard port looks exactly like a healthy Hysteria2 server that ignores a
meaningless 1-byte datagram. Yarisugi refuses to score silence as success, and
refuses to call it failure either. It stays in the shortlist (sorting behind
anything actually measured) so the heavy tier can resolve it honestly, but the
UI never paints it as healthy.

### How this reaches the screen

* **Unconfirmed probes write no metric at all.** The row stays `—` (untested).
  Inventing a score would be the lie we are avoiding.
* **Socket-only health is capped** at 55, well below the verified ceiling of
  100, so "reachable" can never out-rank "works" no matter how good the round
  trip looked.
* **Socket-only readings render as `~40 ms`** in a neutral slate colour rather
  than a green `40 ms`. Verified readings drop the prefix and use the normal
  green/amber/red scale.
* **Every row carries a provenance badge** — `✓` for an egress-verified node,
  `≈` for socket reachability only, blank when nothing has been measured yet —
  with a legend beneath the viewport. The badge makes the tier legible at a
  glance so the distinction cannot be lost by ignoring the colour.
* **Every latency carries its provenance** (`MetricsArena::verified`) from the
  prober through the COW snapshot layer to the viewport, so the distinction
  survives a full catalog refresh instead of living only in a local variable.

---

## Development & Usage

### Prerequisites
* Linux (Kernel >= 5.6 recommended for modern `sock_diag` and `pidfd` features)
* Rust toolchain (stable)

### 1. Viewport Scale Demo
Run the unprivileged GUI with an in-memory fixture of 50,000 nodes to evaluate UI responsiveness, search performance, and sorting under simulated 30 Hz updates:

```bash
cargo run -p myproxy-gui -- --demo-nodes 50000
```

### 2. Control Plane Daemon
Run the routing daemon locally using a development socket override:

```bash
MYPROXY_NETD_SOCKET=/tmp/myproxy-netd.sock MYPROXY_NETD_ALLOWED_UID=$(id -u) cargo run -p myproxy-netd
```

### 3. Standalone Prober (L4 Preflight CLI)
Run the asynchronous L4 connectivity sweep directly on a subscription file:

```bash
cargo run -p myproxy-probe -- path/to/subscription.txt --concurrency 512
```

Every line reports one of three verdicts, and the tool prints a reminder that
none of them is a verified tunnel:

```text
[REACH ]    42ms  vless     @DE  🇩🇪 Frankfurt 01            socket answered
[UNKNWN]     --  hysteria2 @US  🇺🇸 Los Angeles (no reply)    no reply
[DEAD  ]     --  trojan    @NL  🇳🇱 Amsterdam 03            connection refused

3 reachable, 1 unconfirmed, 12 dead (of 40 scanned; 4 skipped, 6 duplicates)
```

`REACH` means the transport answered and nothing more. To turn a reachability
signal into a verified verdict, run the egress quorum instead (the
**Rescore egress** button in the GUI), which drives a real `sing-box` local
SOCKS testbed and requires a quorum of independent operators to agree on both
status code and response body.

---

## License

Licensed under the [MIT License](LICENSE).
```
