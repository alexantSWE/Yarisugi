//! Tier-3 egress validation: run a candidate node through a real sing-box
//! "mixed" (SOCKS5/HTTP) testbed on loopback and verify HTTP round trips to
//! health-check endpoints. This exercises the *entire* compiled stack -- TLS,
//! transport, and proxy protocol -- rather than just TCP reachability.
//!
//! Health checks are scatter-gather across independent operators
//! (`EGRESS_TARGETS`), each with an explicit expected status and, where the
//! operator designed one, an expected body, so captive portals and middleboxes
//! that answer `200` to everything are caught. A node only qualifies when a
//! quorum of distinct operators agree. To look like a browser session instead
//! of a fleet of health probes, a configurable number of real HTTPS sites
//! (`REAL_SITE_TARGETS`) is sampled at random into every trial; those sites
//! verify their TLS certificate chain against the configured trust anchors
//! (optional via rustls) and only assert a status code, so a single target can
//! never flunk a node on its own.
//!
//! The HTTP client is deliberately dependency-light (raw bytes, rustls for TLS
//! only, no reqwest) so tier-3 can scale without a full HTTP stack.

use anyhow::{bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::SingboxAdapter;
use crate::{compile_outbound, compile_routing};
use myproxy_ir::{CanonicalNode, CoreAdapter};

/// The quorum backbone: independent operators, each with an explicit expected
/// status and (where the operator designed a known body) body content, so a
/// captive portal or middlebox that answers `200` to everything is still
/// caught. Endpoints were verified live: every entry here answers as
/// documented. All are `quorum: true` -- only these count toward the pass
/// verdict.
pub const EGRESS_TARGETS: &[EgressTarget] = &[
    EgressTarget {
        tag: "cloudflare",
        host: "cp.cloudflare.com",
        path: "/generate_204",
        port: 80,
        tls: false,
        expect_status: 204,
        expect_body_contains: None,
        quorum: true,
    },
    EgressTarget {
        tag: "google",
        host: "www.gstatic.com",
        path: "/generate_204",
        port: 80,
        tls: false,
        expect_status: 204,
        expect_body_contains: None,
        quorum: true,
    },
    EgressTarget {
        tag: "microsoft",
        host: "www.msftconnecttest.com",
        path: "/connecttest.txt",
        port: 80,
        tls: false,
        expect_status: 200,
        expect_body_contains: Some("Microsoft Connect Test"),
        quorum: true,
    },
    EgressTarget {
        tag: "ubuntu",
        host: "connectivity-check.ubuntu.com",
        path: "/",
        port: 80,
        tls: false,
        expect_status: 204,
        expect_body_contains: None,
        quorum: true,
    },
    EgressTarget {
        tag: "debian",
        host: "network-test.debian.org",
        path: "/nm",
        port: 80,
        tls: false,
        expect_status: 200,
        expect_body_contains: Some("NetworkManager is online"),
        quorum: true,
    },
    EgressTarget {
        tag: "gnome",
        host: "nmcheck.gnome.org",
        path: "/check_network_status.txt",
        port: 80,
        tls: false,
        expect_status: 200,
        expect_body_contains: Some("NetworkManager is online"),
        quorum: true,
    },
    EgressTarget {
        tag: "apple",
        host: "captive.apple.com",
        path: "/hotspot-detect.html",
        port: 80,
        tls: false,
        expect_status: 200,
        expect_body_contains: Some("Success"),
        quorum: true,
    },
    EgressTarget {
        tag: "xiaomi",
        host: "connect.rom.miui.com",
        path: "/generate_204",
        port: 80,
        tls: false,
        expect_status: 204,
        expect_body_contains: None,
        quorum: true,
    },
    // HTTPS-only, so it had to wait for the TLS verifier. Useful precisely
    // because it cannot be answerable over plain HTTP: any success here ran a
    // real certificate chain validation through the node's tunnel.
    EgressTarget {
        tag: "firefox",
        host: "detectportal.firefox.com",
        path: "/success.txt",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: Some("success"),
        quorum: true,
    },
];

/// Real websites dragged into each trial as traffic-shape noise: a browser
/// session look, not a fleet of health probes. These are deliberately tolerant
/// -- status code only, no body assertions, because real sites churn content --
/// and never count toward the quorum, so one flaky frontend cannot sink a node.
/// Everything is TLS-verified, which also catches middleboxes doing TLS
/// interception on the far side.
pub const REAL_SITE_TARGETS: &[EgressTarget] = &[
    EgressTarget {
        tag: "wikipedia",
        host: "www.wikipedia.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "github",
        host: "github.com",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "rust-lang",
        host: "www.rust-lang.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "mozilla",
        host: "www.mozilla.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "python",
        host: "www.python.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "kernel",
        host: "www.kernel.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "archlinux",
        host: "archlinux.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
    EgressTarget {
        tag: "nginx",
        host: "www.nginx.org",
        path: "/",
        port: 443,
        tls: true,
        expect_status: 200,
        expect_body_contains: None,
        quorum: false,
    },
];

/// The legacy single-operator target, kept for compatibility and simple paths.
/// Plain HTTP on port 80: the verifier speaks raw HTTP/1.0 and cannot drive a
/// TLS handshake, and `www.gstatic.com:80/generate_204` answers 204 just like
/// its TLS twin.
pub const EGRESS_TARGET: &str = "www.gstatic.com:80";

/// A single health-check endpoint with an explicit expected response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressTarget {
    pub tag: &'static str,
    pub host: &'static str,
    pub path: &'static str,
    pub port: u16,
    /// Dial over TLS (SNI = `host`, ALPN http/1.1) and validate the
    /// certificate chain against the configured trust anchors before any HTTP
    /// byte is written. Catches far-side TLS interception that a plaintext
    /// probe would walk straight into.
    pub tls: bool,
    pub expect_status: u16,
    pub expect_body_contains: Option<&'static str>,
    /// Counts toward the quorum verdict. Operator reachability endpoints are
    /// quorum targets; real-site noise probes deliberately are not.
    pub quorum: bool,
}

impl EgressTarget {
    pub fn requires_body(&self) -> bool {
        self.expect_body_contains.is_some()
    }
}

/// Fully specifies one egress trial: which operator set forms the quorum
/// backbone, how many real sites to sprinkle in as traffic noise, the quorum
/// threshold, and the per-target timeout. Everything is engine-side
/// configurable; nothing about a hostile network gets hard-coded defaults
/// beyond a sane minimum.
#[derive(Debug, Clone)]
pub struct ScatterConfig {
    pub operators: &'static [EgressTarget],
    pub real_sites: &'static [EgressTarget],
    /// How many random real sites ride along on each trial as noise.
    pub real_count: usize,
    pub min_verified: usize,
    pub timeout: Duration,
    pub max_concurrency: usize,
}

impl Default for ScatterConfig {
    fn default() -> Self {
        Self {
            operators: EGRESS_TARGETS,
            real_sites: REAL_SITE_TARGETS,
            real_count: 2,
            min_verified: 2,
            timeout: Duration::from_secs(10),
            max_concurrency: 8,
        }
    }
}

/// Builds the concrete target list for a trial: every operator plus a random
/// sample of `real_count` real sites (distinct, order-preserving per pool).
/// Sampling happens per trial, so a node tested repeatedly against the same
/// operators still sees a different browser-shaped tail each time.
pub fn sample_targets(cfg: &ScatterConfig) -> Vec<EgressTarget> {
    let real_sample = sample_sites(cfg.real_sites, cfg.real_count);
    let mut targets = Vec::with_capacity(cfg.operators.len() + real_sample.len());
    targets.extend_from_slice(cfg.operators);
    targets.extend(real_sample);
    targets
}

/// xorshift64*: Marsaglia's xorshift64 for the core, then Vigna's multiplier
/// scrambles state into the output. The star step removes the well-known
/// weaknesses of plain xorshift -- the zero fixed point and the weak low bits
/// we would otherwise taste through `% (len - i)` -- while staying a couple of
/// instructions. Wrong for crypto, ideal for traffic-shape noise.
fn xorshift64_star(mut state: u64) -> u64 {
    state ^= state << 12;
    state ^= state >> 25;
    state ^= state << 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

/// Fisher-Yates partial shuffle without allocation pressure: picks
/// `count` distinct indices and maps them back to values.
fn shuffle_indices(len: usize, count: usize, mut seed: u64) -> Vec<usize> {
    if count == 0 || len == 0 {
        return Vec::new();
    }
    // Zero is a fixed point of xorshift; never start from it.
    seed = if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed };
    let count = count.min(len);
    let mut indices: Vec<usize> = (0..len).collect();
    for i in 0..count {
        seed = xorshift64_star(seed);
        let j = i + (seed as usize % (len - i));
        indices.swap(i, j);
    }
    indices[..count].to_vec()
}

/// Fisher-Yates partial shuffle: samples `count` distinct targets from `sites`
/// (the daily noise blend / scattered measurement set).
fn sample_sites(sites: &[EgressTarget], count: usize) -> Vec<EgressTarget> {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
        ^ std::process::id() as u64;
    shuffle_indices(sites.len(), count, seed)
        .into_iter()
        .map(|index| sites[index])
        .collect()
}

/// Result of one target check through the testbed tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCheck {
    pub tag: &'static str,
    /// True when the status **and** any required body matched.
    pub verified: bool,
    pub latency: Duration,
    /// HTTP status actually returned (0 when the exchange failed early).
    pub status: u16,
    /// Human-readable reason on failure.
    pub detail: String,
}

/// Aggregate of a scatter across egress targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScatterReport {
    pub checks: Vec<TargetCheck>,
    /// Number of targets that answered with the expected status and body
    /// (operators and real-site noise alike).
    pub verified: usize,
    /// Number of check targets actually attempted this trial.
    pub total: usize,
    /// Number of *quorum* operator checks that verified -- the number that
    /// decides the verdict.
    pub quorum_verified: usize,
    /// `true` when `quorum_verified >= min_verified`: a quorum of independent
    /// operators agrees the node egress really is on the open internet.
    pub passes: bool,
}

/// Outcome of a single egress round trip through the testbed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressReport {
    /// Wall-clock time including the SOCKS5 handshake and the HTTP exchange.
    pub round_trip: Duration,
    /// True when the status line was a 204 and the body was empty.
    pub verified: bool,
}

/// Assembles a lean testbed config: a loopback "mixed" listener plus the
/// candidate outbound. Unlike `compile_full_config` this has no tproxy/DNS
/// machinery -- the point is an isolated, reproducible stack trial.
pub fn compile_testbed_config(node: &CanonicalNode, socks5_port: u16) -> Result<serde_json::Value> {
    let outbound = compile_outbound(node)?;
    let tag = outbound
        .get("tag")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("proxy")
        .to_owned();
    Ok(json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": socks5_port
        }],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            outbound
        ],
        "route": compile_routing(&tag, 0, false)
    }))
}

/// A testbed variant that dials the operator endpoints **directly** (no node in
/// the path): a probe of the machine's *current* network egress, which is the
/// baseline a candidate node has to beat. Useful for quick "is it me or the
/// node?" triage when a node's scatter comes back poorly.
pub fn compile_direct_testbed_config(socks5_port: u16) -> serde_json::Value {
    json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": socks5_port
        }],
        "outbounds": [ { "type": "direct", "tag": "direct" } ],
        "route": compile_routing("direct", 0, false)
    })
}

/// A live sing-box process running a single-outbound testbed config.
pub struct Testbed {
    child: Child,
    port: u16,
    _config_path: PathBuf,
}

impl Testbed {
    /// Spawns `sing-box run -c <config>` on `socks5_port` and blocks until the
    /// listener accepts connections. Fails loudly (with stderr) if the binary
    /// is missing, the config is rejected, or the core never opens the
    /// listener.
    pub fn spawn(binary: &Path, node: &CanonicalNode, port: u16) -> Result<Self> {
        let config = compile_testbed_config(node, port)?;
        Self::spawn_with_config(binary, config, port)
    }

    /// Spawns the direct-egress testbed (no candidate node in the path) for
    /// measuring the current network's own connectivity baseline.
    pub fn spawn_direct(binary: &Path, port: u16) -> Result<Self> {
        Self::spawn_with_config(binary, compile_direct_testbed_config(port), port)
    }

    fn spawn_with_config(
        binary: &Path,
        config: serde_json::Value,
        port: u16,
    ) -> Result<Self> {
        SingboxAdapter
            .validate_config(binary, &serde_json::to_vec(&config)?)
            .with_context(|| format!("testbed config rejected by {}", binary.display()))?;

        let dir = std::env::temp_dir().join(format!("myproxy-testbed-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let config_path = dir.join(format!("{port}.json"));
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

        let child = Command::new(binary)
            .args(["run", "-c"])
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("could not launch sing-box; is {} a valid binary?", binary.display()))?;

        let mut testbed = Testbed {
            child,
            port,
            _config_path: config_path,
        };
        testbed.wait_until_ready(Duration::from_secs(10))?;
        Ok(testbed)
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), self.port)
    }

    fn wait_until_ready(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let addr: SocketAddr = format!("127.0.0.1:{}", self.port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait()? {
                bail!("sing-box testbed exited {status:?}: {}", self.take_stderr().trim());
            }
            if Instant::now() > deadline {
                bail!(
                    "sing-box testbed never opened the listener: {}",
                    self.take_stderr().trim()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn take_stderr(&mut self) -> String {
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        if stderr.is_empty() {
            "no stderr captured".into()
        } else {
            stderr
        }
    }
}

impl Drop for Testbed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Full tier-3 check: build + validate + boot the testbed, then run the
/// generate-204 round trip through it and tear it down.
pub fn test_egress(binary: &Path, node: &CanonicalNode, timeout: Duration) -> Result<EgressReport> {
    let testbed = Testbed::spawn(binary, node, ephemeral_loopback_port()?)?;
    generate_204_over_socks5(testbed.addr(), EGRESS_TARGET, timeout)
}

/// Scatter-gather egress validation: boots a single testbed, then checks the
/// configured targets (all operators plus the sampled real-site noise)
/// concurrently and reports how many answered exactly as expected. `passes`
/// requires a quorum of `min_verified` *operator* checks -- deliberately more
/// than one, because a single operator can be geo-filtered, route-peered
/// oddly, or middlebox-hijacked.
pub fn test_egress_scatter(
    binary: &Path,
    node: &CanonicalNode,
    cfg: &ScatterConfig,
) -> Result<ScatterReport> {
    let testbed = Testbed::spawn(binary, node, ephemeral_loopback_port()?)?;
    Ok(scatter_over_testbed(testbed.addr(), cfg))
}

/// Baseline scatter with **no node**: measures the machine's current network
/// egress directly through a real sing-box. Comparing this against
/// `test_egress_scatter` isolates "my network is the problem" from "the node is
/// the problem", which matters in filtered environments.
pub fn test_local_egress_scatter(
    binary: &Path,
    cfg: &ScatterConfig,
) -> Result<ScatterReport> {
    let testbed = Testbed::spawn_direct(binary, ephemeral_loopback_port()?)?;
    Ok(scatter_over_testbed(testbed.addr(), cfg))
}

/// Fans the trial's sampled targets out across up to `max_concurrency` worker
/// threads over an already-running testbed and folds the results into an
/// order-preserving report.
fn scatter_over_testbed(proxy: SocketAddr, cfg: &ScatterConfig) -> ScatterReport {
    let timeout = cfg.timeout;
    let min_verified = cfg.min_verified;
    let work: Arc<Vec<EgressTarget>> = Arc::new(sample_targets(cfg));
    let index = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::channel::<(usize, TargetCheck)>();
    let workers = work.len().clamp(1, cfg.max_concurrency);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let index = Arc::clone(&index);
        let work = Arc::clone(&work);
        let tx = tx.clone();
        handles.push(thread::spawn(move || loop {
            let i = index.fetch_add(1, Ordering::SeqCst);
            if i >= work.len() {
                break;
            }
            let check = check_target(proxy, &work[i], timeout);
            if tx.send((i, check)).is_err() {
                break;
            }
        }));
    }
    drop(tx);

    let mut ordered: Vec<Option<TargetCheck>> = vec![None; work.len()];
    for (i, check) in rx {
        ordered[i] = Some(check);
    }
    for handle in handles {
        handle.join().expect("egress worker panicked");
    }

    let checks: Vec<(usize, TargetCheck)> = ordered
        .into_iter()
        .enumerate()
        .map(|(i, check)| {
            (
                i,
                check.unwrap_or_else(|| panic!("missing egress check for {} at {i}", work[i].tag)),
            )
        })
        .collect();
    let verified = checks.iter().filter(|(_, check)| check.verified).count();
    let quorum_verified = checks
        .iter()
        .filter(|(index, check)| work[*index].quorum && check.verified)
        .count();
    ScatterReport {
        checks: checks.into_iter().map(|(_, check)| check).collect(),
        verified,
        total: work.len(),
        quorum_verified,
        passes: quorum_verified >= min_verified,
    }
}

/// Establishes a raw SOCKS5 CONNECT through `proxy` (no auth) to `target`
/// (`host:port`), issues an HTTP/1.0 `GET /generate_204`, and reports whether
/// the exchange was a `204` with an empty body plus how long the whole thing
/// took.
pub fn generate_204_over_socks5(
    proxy: SocketAddr,
    target: &str,
    timeout: Duration,
) -> Result<EgressReport> {
    let (host, port) = split_target(target)?;
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&proxy, timeout)
        .with_context(|| format!("cannot reach socks5 testbed at {proxy}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    socks5_connect(&mut stream, host, port)?;
    let request = format!("GET /generate_204 HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let exchange = read_http_exchange(&mut stream, &started, timeout)?;
    let verified = exchange.status == 204 && exchange.body.is_empty();
    Ok(EgressReport {
        round_trip: started.elapsed(),
        verified,
    })
}

/// Verifies a single target through an already-running testbed. Never fails the
/// caller: every outcome (including dead-on-arrival) is folded into a
/// `TargetCheck`.
fn check_target(proxy: SocketAddr, target: &EgressTarget, timeout: Duration) -> TargetCheck {
    check_target_with_roots(proxy, target, timeout, default_roots())
}

/// `check_target` with injectable trust anchors -- tests sign their own
/// certificate and verify the whole path (SOCKS5 CONNECT, TLS handshake,
/// certificate validation, HTTP exchange) end to end.
fn check_target_with_roots(
    proxy: SocketAddr,
    target: &EgressTarget,
    timeout: Duration,
    roots: &RootCertStore,
) -> TargetCheck {
    let started = Instant::now();
    let mut stream = match TcpStream::connect_timeout(&proxy, timeout) {
        Ok(stream) => stream,
        Err(error) => {
            return TargetCheck {
                tag: target.tag,
                verified: false,
                latency: started.elapsed(),
                status: 0,
                detail: format!("socks5 testbed unreachable: {error}"),
            }
        }
    };
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    if let Err(error) = socks5_connect(&mut stream, target.host, target.port) {
        return TargetCheck {
            tag: target.tag,
            verified: false,
            latency: started.elapsed(),
            status: 0,
            detail: format!("socks5 CONNECT failed: {error:#}"),
        };
    }
    let mut stream = match wrap_stream_with_roots(stream, target, roots) {
        Ok(stream) => stream,
        Err(error) => {
            return TargetCheck {
                tag: target.tag,
                verified: false,
                latency: started.elapsed(),
                status: 0,
                detail: format!("TLS setup failed: {error:#}"),
            }
        }
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target.path, target.host
    );
    if let Err(error) = stream.write_all(request.as_bytes()) {
        return TargetCheck {
            tag: target.tag,
            verified: false,
            latency: started.elapsed(),
            status: 0,
            detail: format!("write failed: {error}"),
        };
    }
    stream.flush().ok();
    let exchange = match read_http_exchange(&mut stream, &started, timeout) {
        Ok(exchange) => exchange,
        Err(error) => {
            return TargetCheck {
                tag: target.tag,
                verified: false,
                latency: started.elapsed(),
                status: 0,
                detail: error.to_string(),
            }
        }
    };
    let status = exchange.status;
    let verified = exchange.status == target.expect_status
        && target
            .expect_body_contains
            .map(|needle| exchange.body.as_str().contains(needle))
            .unwrap_or(true);
    let detail = if verified {
        "ok".into()
    } else if status != target.expect_status {
        format!("expected status {}, got {status}", target.expect_status)
    } else {
        format!(
            "expected body containing {:?}",
            target.expect_body_contains
        )
    };
    TargetCheck {
        tag: target.tag,
        verified,
        latency: started.elapsed(),
        status,
        detail,
    }
}

/// One dial is either a plain TCP stream or a rustls tunnel over it; wrapping
/// lets the HTTP layer talk to both uniformly.
enum PumpStream {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for PumpStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PumpStream::Tcp(stream) => stream.read(buffer),
            PumpStream::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for PumpStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            PumpStream::Tcp(stream) => stream.write(buffer),
            PumpStream::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            PumpStream::Tcp(stream) => stream.flush(),
            PumpStream::Tls(stream) => stream.flush(),
        }
    }
}

/// Trust anchors used for far-side verification. Defaults to the Mozilla set
/// (webpki-roots); tests inject their own store via `check_target_with_roots`.
fn default_roots() -> &'static RootCertStore {
    static ROOTS: OnceLock<RootCertStore> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots
    })
}

fn tls_client_config(roots: &RootCertStore) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    // ALPN http/1.1 only: the verifier writes raw HTTP/1.1 and never negotiates
    // h2, and most real sites still serve http/1.1 when offered.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

fn server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_owned())
            .map_err(|_| anyhow::anyhow!("invalid TLS SNI host {host:?}"))
    }
}

fn wrap_stream_with_roots(
    stream: TcpStream,
    target: &EgressTarget,
    roots: &RootCertStore,
) -> Result<PumpStream> {
    if !target.tls {
        return Ok(PumpStream::Tcp(stream));
    }
    let config = tls_client_config(roots);
    let connection = ClientConnection::new(Arc::new(config), server_name(target.host)?)?;
    Ok(PumpStream::Tls(Box::new(StreamOwned::new(connection, stream))))
}

struct HttpExchange {
    status: u16,
    body: String,
}

fn read_http_exchange<R: Read>(
    stream: &mut R,
    started: &Instant,
    timeout: Duration,
) -> Result<HttpExchange> {
    // Read until the header block is complete. A generate_204 endpoint answers
    // with `Content-Length: 0`, so a fully-received header block *is* the end
    // of the response -- waiting for EOF would hang forever on keep-alive
    // connections.
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => bail!("egress read failed: {error}"),
        }
        if response.len() > 64 * 1024 {
            bail!("egress response unexpectedly large ({} bytes)", response.len());
        }
        if started.elapsed() > timeout {
            bail!("egress round trip timed out after {timeout:?} waiting for headers");
        }
    }

    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("");
    let header_end = text
        .find("\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(text.len());
    let body = text[header_end..].to_string();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(HttpExchange { status, body })
}

/// Splits `host:port`, tolerating bare IPv4/IPv6 literals and an optional
/// `https://` scheme.
fn split_target(target: &str) -> Result<(&str, u16)> {
    let rest = target.strip_prefix("https://").unwrap_or(target);
    let (host, port) = match rest.rfind(':') {
        Some(colon) => {
            let host = &rest[..colon];
            let port: u16 = rest[colon + 1..]
                .parse()
                .with_context(|| format!("invalid target port in {target:?}"))?;
            (host.trim_start_matches('[').trim_end_matches(']'), port)
        }
        None => bail!("target {target:?} must be host:port"),
    };
    if host.is_empty() {
        bail!("target {target:?} has an empty host");
    }
    Ok((host, port))
}

/// Raw RFC 1928 client handshake (no auth, then CONNECT with the best-fitting
/// address type).
fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut greeting = [0u8; 2];
    read_exact(stream, &mut greeting)?;
    if greeting != [0x05, 0x00] {
        bail!("socks5 greeting rejected: {greeting:02x?}");
    }

    let mut request = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        request.push(0x01);
        request.extend(ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        request.push(0x04);
        request.extend(ip.octets());
    } else {
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend(host.as_bytes());
    }
    request.extend(port.to_be_bytes());
    stream.write_all(&request)?;

    let mut header = [0u8; 4];
    read_exact(stream, &mut header)?;
    if header[1] != 0x00 {
        bail!("socks5 CONNECT failed with reply {}", header[1]);
    }
    // Discard the bound address reported by the proxy.
    match header[3] {
        0x01 => read_exact(stream, &mut [0u8; 4])?,
        0x04 => read_exact(stream, &mut [0u8; 16])?,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len)?;
            let mut domain = vec![0u8; len[0] as usize];
            read_exact(stream, &mut domain)?;
        }
        other => bail!("socks5 reply with unknown address type {other}"),
    }
    read_exact(stream, &mut [0u8; 2])?;
    Ok(())
}

fn read_exact(stream: &mut TcpStream, bytes: &mut [u8]) -> Result<()> {
    stream
        .read_exact(bytes)
        .with_context(|| "short read during socks5 handshake")
}

fn ephemeral_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    thread::sleep(Duration::from_millis(10));
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use myproxy_ir::{
        CanonicalNode, EndpointTarget, NodeMetadata, ProtocolSpec, ShadowsocksCipher,
        ShadowsocksConfig, TransportSpec,
    };
    use rustls::pki_types::PrivateKeyDer;
    use std::net::TcpListener;

    fn node() -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, "egress-test", *b"US", 1).unwrap(),
            EndpointTarget::domain("egress.example.com", 443).unwrap(),
            ProtocolSpec::Shadowsocks(ShadowsocksConfig {
                method: ShadowsocksCipher::Chacha20IetfPoly1305,
                password: "pass".into(),
                plugin: None,
                plugin_opts: None,
            }),
            TransportSpec::Tcp,
            myproxy_ir::SecuritySpec::None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_succeeds_against_loopback_stub() {
        let target = spawn_204_server();
        let port = target.port();
        let proxy = spawn_socks5_stub(target.socket());

        let report =
            generate_204_over_socks5(proxy, &format!("127.0.0.1:{port}"), Duration::from_secs(5))
                .unwrap();
        assert!(report.verified, "stub must return a clean 204");
        assert!(report.round_trip < Duration::from_secs(5));
    }

    #[test]
    fn stub_rejections_are_reported() {
        let proxy = spawn_stub_that_rejects();
        let result = generate_204_over_socks5(proxy, "127.0.0.1:1", Duration::from_secs(2));
        assert!(result.is_err(), "a rejecting stub must surface as an error");
    }

    #[test]
    fn invalid_targets_are_rejected() {
        assert!(split_target("nope").is_err());
        assert!(split_target(":123").is_err());
        assert_eq!(
            split_target("https://example.com:443").unwrap(),
            ("example.com", 443)
        );
        assert_eq!(split_target("[::1]:53").unwrap(), ("::1", 53));
    }

    #[test]
    fn testbed_config_uses_mixed_listener() {
        let config = compile_testbed_config(&node(), 54321).unwrap();
        assert_eq!(config["inbounds"][0]["type"], "mixed");
        assert_eq!(config["inbounds"][0]["listen_port"], 54321);
        assert_eq!(config["outbounds"][0]["type"], "direct");
        assert_eq!(config["outbounds"][1]["type"], "shadowsocks");
        assert_eq!(config["route"]["default_mark"], 0);
        assert_eq!(config["route"]["auto_detect_interface"], false);
    }

    #[test]
    fn spawn_fails_loudly_without_binary() {
        let result = Testbed::spawn(Path::new("/nonexistent/sing-box"), &node(), 59999);
        let message = format!("{:#}", result.err().expect("missing binary must fail"));
        assert!(
            message.to_lowercase().contains("sing-box"),
            "error should name the missing binary: {message}"
        );
    }

    #[test]
    fn scatter_through_forwarding_stub() {
        let mut stubs = vec![];
        for (status, body) in [
            ("HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", b"".to_vec()),
            (
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 22\r\n\r\nMicrosoft Connect Test\n",
                b"Microsoft Connect Test".to_vec(),
            ),
            (
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 20\r\n\r\n<HTML><TITLE>Success</TITLE></HTML>",
                b"Success".to_vec(),
            ),
        ] {
            stubs.push(spawn_stub_http(status, body));
        }

        let targets = vec![
            EgressTarget {
                tag: "cloudflare-stub",
                host: "127.0.0.1",
                path: "/generate_204",
                port: stubs[0].port(),
                tls: false,
                expect_status: 204,
                expect_body_contains: None,
                quorum: true,
            },
            EgressTarget {
                tag: "microsoft-stub",
                host: "127.0.0.1",
                path: "/connecttest.txt",
                port: stubs[1].port(),
                tls: false,
                expect_status: 200,
                expect_body_contains: Some("Microsoft Connect Test"),
                quorum: true,
            },
            EgressTarget {
                tag: "apple-stub",
                host: "127.0.0.1",
                path: "/hotspot-detect.html",
                port: stubs[2].port(),
                tls: false,
                expect_status: 200,
                expect_body_contains: Some("Success"),
                quorum: true,
            },
        ];

        let proxy = spawn_forwarding_socks5_stub();
        let report = scatter_over_proxy(proxy, &targets, Duration::from_secs(10)).unwrap();
        assert_eq!(report.verified, 3, "all mock operators must verify: {report:?}");
        assert_eq!(report.total, 3);
        assert!(report.passes, "quorum of 2 must pass");
        assert!(report
            .checks
            .iter()
            .all(|check: &TargetCheck| check.verified && check.status > 0));
    }

    #[test]
    fn scatter_flags_hijacked_middlebox() {
        // Two honest operators plus one impostor that answers 200-with-login to
        // everything (captive portal behaviour).
        let honest_204 = spawn_stub_http("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", vec![]);
        let honest_msft = spawn_stub_http(
            "HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\nMicrosoft Connect Test\n",
            b"Microsoft Connect Test".to_vec(),
        );
        let hijacked =
            spawn_stub_http("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nPlease log in\n", vec![]);

        let target = |tag: &'static str, addr: TestServer, expect: u16, body: Option<&'static str>| EgressTarget {
            tag,
            host: "127.0.0.1",
            path: "/probe",
            port: addr.port(),
            tls: false,
            expect_status: expect,
            expect_body_contains: body,
            quorum: true,
        };
        let proxy = spawn_forwarding_socks5_stub();
        let report = scatter_over_proxy(
            proxy,
            &[
                target("cloudflare-stub", honest_204, 204, None),
                target(
                    "microsoft-stub",
                    honest_msft,
                    200,
                    Some("Microsoft Connect Test"),
                ),
                target("impostor", hijacked, 204, None),
            ],
            Duration::from_secs(10),
        )
        .unwrap();

        let impostor = report.checks.iter().find(|c| c.tag == "impostor").unwrap();
        assert!(!impostor.verified, "204-expected, 200-login impostor must fail");
        assert_eq!(impostor.status, 200);
        assert_eq!(report.verified, 2, "impostor must not count: {report:?}");
        assert!(report.passes, "2 of 3 honest operators still satisfy a quorum of 2");
    }

    #[test]
    fn scatter_supports_domain_targets() {
        // Guards the SOCKS5 ATYP 0x03 encoding (single-byte domain length):
        // loopback hosts ride 0x01, so a domain path bug would pass every other
        // test and only die against real endpoints.
        let msft = spawn_stub_http(
            "HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\nMicrosoft Connect Test\n",
            b"Microsoft Connect Test".to_vec(),
        );
        let proxy = spawn_forwarding_socks5_stub();
        let report = scatter_over_proxy(
            proxy,
            &[EgressTarget {
                tag: "microsoft-stub",
                host: "disguised.provider.invalid",
                path: "/connecttest.txt",
                port: msft.port(),
                tls: false,
                expect_status: 200,
                expect_body_contains: Some("Microsoft Connect Test"),
                quorum: true,
            }],
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(report.verified, 1, "domain-name SOCKS5 target must verify");
    }

    #[test]
    fn scatter_quorum_is_respected() {
        let honest_204 =
            spawn_stub_http("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", vec![]);
        let proxy = spawn_forwarding_socks5_stub();
        let report = scatter_over_proxy(
            proxy,
            &[EgressTarget {
                tag: "only-one",
                host: "127.0.0.1",
                path: "/probe",
                port: honest_204.port(),
                tls: false,
                expect_status: 204,
                expect_body_contains: None,
                quorum: true,
            }],
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(report.verified, 1);
        assert!(
            !report.passes,
            "a single operator must not satisfy a quorum of 2"
        );
    }

    #[test]
    fn tls_target_verifies_against_injected_roots() {
        // Full-path TLS check: SOCKS5 CONNECT through the forwarding stub, TLS
        // handshake with SNI + chain validation, HTTP/1.1 exchange -- all over
        // a certificate we trust because we injected it as the anchor.
        let (roots, port) = spawn_tls_server();
        let proxy = spawn_forwarding_socks5_stub();
        let target = EgressTarget {
            tag: "tls-stub",
            host: "localhost",
            path: "/probe",
            port,
            tls: true,
            expect_status: 200,
            expect_body_contains: Some("TLS OK"),
            quorum: true,
        };
        let check = check_target_with_roots(proxy, &target, Duration::from_secs(10), &roots);
        assert!(check.verified, "trusted TLS round trip must verify: {check:?}");
        assert_eq!(check.status, 200);
    }

    #[test]
    fn tls_target_rejects_untrusted_chain() {
        // The same server, but verified against the Mozilla store (defaults):
        // the self-signed chain must be rejected, proving verification is real
        // and not a `plaintext = trust` shortcut.
        let (_roots, port) = spawn_tls_server();
        let proxy = spawn_forwarding_socks5_stub();
        let target = EgressTarget {
            tag: "tls-untrusted",
            host: "localhost",
            path: "/probe",
            port,
            tls: true,
            expect_status: 200,
            expect_body_contains: None,
            quorum: true,
        };
        let check = check_target(proxy, &target, Duration::from_secs(10));
        assert!(
            !check.verified,
            "untrusted certificate must fail verification: {check:?}"
        );
        assert_eq!(check.status, 0);
    }

    #[test]
    fn sample_targets_carries_quorum_backbone_plus_noise() {
        let cfg = ScatterConfig::default();
        let sampled = sample_targets(&cfg);
        assert_eq!(
            sampled.iter().filter(|target| target.quorum).count(),
            EGRESS_TARGETS.len(),
            "every operator must always ride along"
        );
        assert_eq!(
            sampled.iter().filter(|target| !target.quorum).count(),
            cfg.real_count,
            "the configured number of noise sites must be sampled"
        );
        let mut tags = sampled.iter().map(|target| target.tag).collect::<Vec<_>>();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), sampled.len(), "no duplicate targets per trial");
    }

    #[test]
    fn xorshift64_star_is_deterministic_and_zero_stays_a_fixed_point() {
        // Zero *is* a fixed point even after the star multiply (0 * k = 0);
        // escaping it is the *sampler's* job (see shuffle_indices/map the
        // zero seed onto a constant). Pinning both behaviours here so nobody
        // "fixes" the wrong layer.
        assert_eq!(xorshift64_star(0), 0, "star does not escape zero on its own");
        let mut state = 1u64;
        for _ in 0..1_000 {
            state = xorshift64_star(state);
            assert_ne!(state, 0, "a nonzero state never collapses to zero");
        }
        // Same seed, same stream (the sampler relies on this being a pure
        // function of state).
        let a = (0..8).fold(0x1234_5678_9abc_def0u64, |s, _| xorshift64_star(s));
        let b = (0..8).fold(0x1234_5678_9abc_def0u64, |s, _| xorshift64_star(s));
        assert_eq!(a, b);
    }

    #[test]
    fn shuffle_indices_permutes_when_sampling_everything() {
        // Sampling all `len` must return every index exactly once.
        let mut picked = shuffle_indices(10, 10, 0xdead_beef);
        picked.sort_unstable();
        assert_eq!(picked, (0..10).collect::<Vec<_>>());
        // A partial sample yields distinct in-range indices...
        let picked = shuffle_indices(10, 3, 0x0123_4567);
        assert_eq!(picked.len(), 3);
        let mut dedup = picked.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), 3, "no repeats in a partial sample");
        assert!(picked.iter().all(|&index| index < 10));
        // A zero seed must be guarded off the fixed point: the first slot ends
        // up displaced (never j == i), which a broken guard would leave as 0.
        let picked = shuffle_indices(10, 3, 0);
        assert_ne!(picked[0], 0, "zero seed must be shuffled, never identity");
    }

    /// Boots a loopback TLS server serving a fixed 200 response over an
    /// rcgen-signed self-signed cert, and returns the matching root store plus
    /// the listener port.
    fn spawn_tls_server() -> (RootCertStore, u16) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let server_config = Arc::clone(&server_config);
                thread::spawn(move || {
                    let server = rustls::ServerConnection::new(server_config).expect("server config");
                    let mut tls = StreamOwned::new(server, stream);
                    let mut request = [0u8; 8192];
                    let mut used = 0;
                    loop {
                        let n = tls.read(&mut request[used..]).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        used += n;
                        if request[..used].windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if used >= request.len() {
                            break;
                        }
                    }
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 7\r\n\r\nTLS OK",
                    );
                    let _ = tls.flush();
                });
            }
        });
        (roots, port)
    }

    fn scatter_over_proxy(
        proxy: SocketAddr,
        targets: &[EgressTarget],
        timeout: Duration,
    ) -> Result<ScatterReport> {
        let mut checks = Vec::with_capacity(targets.len());
        for target in targets {
            checks.push(check_target(proxy, target, timeout));
        }
        let verified = checks.iter().filter(|check| check.verified).count();
        let quorum_verified = checks
            .iter()
            .zip(targets)
            .filter(|(check, target)| target.quorum && check.verified)
            .count();
        Ok(ScatterReport {
            checks,
            verified,
            total: targets.len(),
            quorum_verified,
            passes: quorum_verified >= 2,
        })
    }

    /// A SOCKS5 server that dials whatever host the client requested (loopback
    /// tests always carry 4-byte IP literals), instead of being pinned to one
    /// upstream like `spawn_socks5_stub`.
    fn spawn_forwarding_socks5_stub() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { break };
                thread::spawn(move || {
                    let mut greeting = [0u8; 2];
                    if client.read_exact(&mut greeting).is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; greeting[1] as usize];
                    if client.read_exact(&mut methods).is_err() {
                        return;
                    }
                    let _ = client.write_all(&[0x05, 0x00]);

                    let mut header = [0u8; 4];
                    if client.read_exact(&mut header).is_err() {
                        return;
                    }
                    // Domain atoms (ATYP 0x03) can't be resolved in tests, so any
                    // domain is dialed against loopback on the requested port.
                    let host: std::net::IpAddr = match header[3] {
                        0x01 => {
                            let mut ip = [0u8; 4];
                            if client.read_exact(&mut ip).is_err() {
                                return;
                            }
                            Ipv4Addr::from(ip).into()
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            if client.read_exact(&mut len).is_err() {
                                return;
                            }
                            let mut name = vec![0u8; len[0] as usize];
                            if client.read_exact(&mut name).is_err() {
                                return;
                            }
                            Ipv4Addr::LOCALHOST.into()
                        }
                        _ => return,
                    };
                    let mut port = [0u8; 2];
                    if client.read_exact(&mut port).is_err() {
                        return;
                    }
                    let Ok(mut upstream) =
                        TcpStream::connect(SocketAddr::new(host, u16::from_be_bytes(port)))
                    else {
                        let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    let _ = client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                    let mut client_reader = client.try_clone().unwrap();
                    let mut upstream_reader = upstream.try_clone().unwrap();
                    let forward = thread::spawn(move || {
                        let _ = std::io::copy(&mut client_reader, &mut upstream);
                    });
                    let _ = std::io::copy(&mut upstream_reader, &mut client);
                    let _ = forward.join();
                });
            }
        });
        addr
    }

    fn spawn_stub_http(status_line: &'static str, _expect_body: Vec<u8>) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                thread::spawn(move || {
                    let mut request = [0u8; 8192];
                    let mut used = 0;
                    loop {
                        let n = stream.read(&mut request[used..]).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        used += n;
                        if request[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let _ = stream.write_all(status_line.as_bytes());
                });
            }
        });
        TestServer { port, _handle: handle }
    }

    #[test]
    fn direct_testbed_config_routes_everything_to_direct() {
        let config = compile_direct_testbed_config(54321);
        assert_eq!(config["inbounds"][0]["type"], "mixed");
        assert_eq!(config["inbounds"][0]["listen_port"], 54321);
        assert_eq!(
            config["outbounds"].as_array().map(|outbounds| outbounds.len()),
            Some(1)
        );
        assert_eq!(config["outbounds"][0]["type"], "direct");
        assert_eq!(config["route"]["default_mark"], 0);
        assert_eq!(
            config["route"]["rules"][1]["outbound"], "direct",
            "route rule must pin egress to the direct outbound"
        );
    }

    #[test]
    #[ignore = "hits the network; run explicitly"]
    fn live_local_egress_scatter_through_real_singbox() {
        let binary = std::env::var_os("SING_BOX_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/bin/sing-box"));
        if !binary.exists() {
            eprintln!("skipping: no sing-box binary at {}", binary.display());
            return;
        }
        let report = test_local_egress_scatter(&binary, &ScatterConfig::default())
            .expect("direct testbed scatter must run");
        eprintln!(
            "live local egress: verified {}/{} passes={} through {}",
            report.verified,
            report.total,
            report.passes,
            binary.display()
        );
        let mut latencies = report
            .checks
            .iter()
            .filter(|check| check.verified)
            .map(|check| check.latency)
            .collect::<Vec<_>>();
        latencies.sort();
        let median = latencies.get(latencies.len() / 2);
        eprintln!("verified median latency: {median:?}");
        for check in &report.checks {
            eprintln!(
                "  {:12} status={:<3} verified={:<5} {:?} {}",
                check.tag, check.status, check.verified, check.latency, check.detail
            );
        }
        assert_eq!(
            report.total,
            EGRESS_TARGETS.len() + ScatterConfig::default().real_count,
            "every configured operator plus the sampled noise must be reported"
        );
        assert!(
            report.quorum_verified <= report.verified,
            "quorum successes are a subset of all successes"
        );
    }

    /// A tiny HTTP server answering `GET /generate_204` with a 204 and a
    /// zero-length body, exactly what the verifier must accept.
    fn spawn_204_server() -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                thread::spawn(move || {
                    let mut request = [0u8; 8192];
                    let mut used = 0;
                    loop {
                        let n = stream.read(&mut request[used..]).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        used += n;
                        if request[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let _ = stream.write_all(
                        b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    );
                });
            }
        });
        TestServer { port, _handle: handle }
    }

    /// A minimal in-process SOCKS5 server: no-auth handshake, CONNECT to
    /// whatever the client asked for, then pure byte relay to the target.
    fn spawn_socks5_stub(target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { break };
                thread::spawn(move || {
                    let mut greeting = [0u8; 2];
                    if client.read_exact(&mut greeting).is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; greeting[1] as usize];
                    if client.read_exact(&mut methods).is_err() {
                        return;
                    }
                    let _ = client.write_all(&[0x05, 0x00]);

                    let mut header = [0u8; 4];
                    if client.read_exact(&mut header).is_err() {
                        return;
                    }
                    let mut port = [0u8; 2];
                    match header[3] {
                        0x01 => {
                            let mut _host = [0u8; 4];
                            if client.read_exact(&mut _host).is_err() {
                                return;
                            }
                        }
                        0x04 => {
                            let mut _host = [0u8; 16];
                            if client.read_exact(&mut _host).is_err() {
                                return;
                            }
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            if client.read_exact(&mut len).is_err() {
                                return;
                            }
                            let mut host = vec![0u8; len[0] as usize];
                            if client.read_exact(&mut host).is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                    // Test traffic always targets loopback, so the requested
                    // destination is ignored in favour of the stub's server.
                    let _ = client.read_exact(&mut port);

                    let Ok(mut upstream) = TcpStream::connect(target) else {
                        let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    let _ = client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                    let mut client_reader = client.try_clone().unwrap();
                    let mut upstream_reader = upstream.try_clone().unwrap();
                    let forward =
                        thread::spawn(move || std::io::copy(&mut client_reader, &mut upstream));
                    let _ = std::io::copy(&mut upstream_reader, &mut client);
                    let _ = forward.join();
                });
            }
        });
        addr
    }

    fn spawn_stub_that_rejects() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut client) = stream else { break };
                let mut greeting = [0u8; 2];
                if client.read_exact(&mut greeting).is_err() {
                    continue;
                }
                let mut methods = vec![0u8; greeting[1] as usize];
                let _ = client.read_exact(&mut methods);
                let _ = client.write_all(&[0x05, 0x00]);
                let mut header = [0u8; 4];
                if client.read_exact(&mut header).is_err() {
                    continue;
                }
                let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            }
        });
        addr
    }

    struct TestServer {
        port: u16,
        _handle: thread::JoinHandle<()>,
    }

    impl TestServer {
        fn port(&self) -> u16 {
            self.port
        }

        fn socket(&self) -> SocketAddr {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), self.port)
        }
    }
}