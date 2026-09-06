# Yarisugi

Linux-first proxy toolchain manager.

## Current status

The repository currently contains the Phase 0 control-plane slice:

- versioned length-delimited IPC protocol
- Unix socket peer-credential authorization
- one active controller session
- heartbeat watchdog and disconnect rollback
- validated routing requests
- replaceable network backend boundary
- canonical protocol-pure IR with versioned functional hashing
- typed transport, security, mux, and core-adapter contracts
- SQLite WAL persistence with canonical-node deduplication and subscription provenance
- dense in-memory metrics store with source-aware filtering and deterministic sorting
- atomic subscription refresh with protected empty snapshots and orphan garbage collection
- lock-free dense-store publication through immutable `ArcSwap` snapshots

The current backend is intentionally a no-op. It does not modify nftables, routes, DNS, or the host network yet.

The IR deliberately does not compile directly to a core's JSON dialect yet. Core adapters will be added after the identity and normalization rules are stable.

The storage layer keeps one row per canonical functional node and records subscription membership in a separate join table, so deduplication does not erase provenance. Diagnostic metrics and UI sorting fields are hydrated separately from the cold IR payload.

Subscription refreshes replace only that subscription's source links inside one transaction. Orphaned canonical nodes are then removed, while shared nodes and their diagnostics remain intact. Empty or entirely invalid reports require an explicit opt-in before they can clear an existing subscription.

## Running the daemon

The production socket path requires root and a configured allowed user:

```text
MYPROXY_NETD_ALLOWED_UID=1000 cargo run -p myproxy-netd
```

For local development, override the socket path:

```text
MYPROXY_NETD_SOCKET=/tmp/myproxy-netd.sock MYPROXY_NETD_ALLOWED_UID=$(id -u) cargo run -p myproxy-netd
```

The next implementation slice will add a disposable network-namespace test harness before any real kernel mutation is enabled.
