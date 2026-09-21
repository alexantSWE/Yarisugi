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

**How Yarisugi addresses this:** The architecture uses functional identity deduplication (matching endpoints and protocol hashes rather than names), cheap L4 preflight sweeps, and multi-operator quorum verification where both status codes and body signatures must match before a node is marked viable.

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
| **Virtual Viewport UI** | Active | Slint-based viewport supporting 50,000+ node models, background projection workers, and non-blocking search/sort. |
| **Ingestion Engine** | Active | Line-delimited URI bundle parser and Clash/Mihomo YAML proxy reader. |
| **Routing Control Plane (`netd`)** | Phase 1 (Stub) | IPC wire protocol, authentication, session ownership, and watchdog rollback engine. |
| **Network Backend** | In Progress | Transitioning from the development no-op backend to live dual-stack `nftables` TPROXY and policy routing. |
| **Core Adapter & Supervisor** | In Progress | `sing-box` outbound configuration compilation, atomic config validation, and SIGHUP process management. |

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

---

## License

Licensed under the [MIT License](LICENSE).
```

* **Memory Model Precision:** *"Zero-Allocation Data Layer"* $\to$ *"Low-Allocation Data Layer"*.
* **Prober Accurately Scoped:** Explicitly labeled as an *"L4 Preflight CLI"* rather than implying full L7 quorum checks are exposed in that command.
* **Kernel Note Refined:** Changed from a hard prerequisite to *"recommended for modern `sock_diag` and `pidfd` features"*.
