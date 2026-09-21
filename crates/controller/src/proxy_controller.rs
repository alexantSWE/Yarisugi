//! The session orchestrator: owns persistence, the sing-box supervisor, and an
//! optional netd client, and exposes the higher-level operations the GUI (or
//! any future CLI) needs -- switching the active node, importing a
//! subscription, and loading probe targets with their persisted node ids.
//!
//! Everything is best-effort by design: a missing sing-box binary or an
//! absent netd daemon produce errors here (surfaced as status text), never a
//! panic, so the GUI keeps functioning as a pure catalog in those cases.

use anyhow::{Context, Result};
use myproxy_adapter::egress::{test_egress_scatter, test_local_egress_scatter, ScatterConfig, ScatterReport};
use myproxy_adapter::supervisor::Supervisor;
use myproxy_adapter::{compile_full_config, default_gateway_v4, DnsProvider, LocalDns};
use myproxy_ir::{CanonicalNode, CoreCapabilities};
use myproxy_netd_proto::{DEFAULT_SOCKET_PATH, PROTOCOL_VERSION};
use myproxy_storage::{
    open_database, DenseNodeStore, NodeRepository, SubscriptionRecord, SubscriptionRefresh,
    SubscriptionService,
};
use std::time::{Duration, Instant};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::netd_client::{NetdClient, RoutingSpec};

/// Single mark used for the whole tproxy pipeline (matching the netd ruleset);
/// the core's own sockets carry this mark and are exempted from interception.
pub const SINGLE_FW_MARK: u32 = 0x1;

/// Everything the controller needs to drive the system. Defaults are bare
/// minimums; surface every knob that could plausibly want tuning.
#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub tproxy_port: u16,
    pub fwmark: u32,
    pub table_id: u32,
    /// DoH resolver dialed through the node's tunnel (left untouched by the
    /// client's own network, so a local block on a provider is irrelevant while
    /// connected).
    pub dns_provider: DnsProvider,
    pub dns_ipv4: Option<Ipv4Addr>,
    pub core_uid: Option<u32>,
    pub bypass_subnets: &'static [&'static str],
    pub bypass_subnets_v6: &'static [&'static str],
    /// UDP resolver for traffic the tunnel does not carry (see
    /// `LocalDns`). Defaults to the default gateway discovered from
    /// `/proc/net/route`; in a network that blocks secure DNS from the
    /// machine itself, the LAN gateway/Pi-hole is the only reliable
    /// untunnelled resolver.
    pub local_dns: Option<LocalDns>,
    /// How many random real HTTPS sites ride along on each egress trial as
    /// traffic noise (they never count toward the quorum verdict).
    pub egress_real_count: usize,
    /// Per-target timeout for one egress check.
    pub egress_timeout: Duration,
    /// Quorum of operator checks required before a node counts as passing.
    pub egress_min_verified: usize,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            tproxy_port: 12345,
            fwmark: SINGLE_FW_MARK,
            table_id: 100,
            dns_provider: DnsProvider::default(),
            dns_ipv4: Some(Ipv4Addr::new(1, 1, 1, 1)),
            core_uid: None,
            bypass_subnets: &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            bypass_subnets_v6: &["fc00::/7"],
            local_dns: default_gateway_v4()
                .map(|ip| LocalDns::new(ip, 53)),
            egress_real_count: 2,
            egress_timeout: Duration::from_secs(10),
            egress_min_verified: 2,
        }
    }
}

impl ProxySettings {
    /// The scatter configuration derived from these settings.
    pub fn scatter_config(&self) -> ScatterConfig {
        ScatterConfig {
            real_count: self.egress_real_count,
            min_verified: self.egress_min_verified,
            timeout: self.egress_timeout,
            ..ScatterConfig::default()
        }
    }
}

pub struct ProxyController {
    db: Mutex<Connection>,
    supervisor: Mutex<Supervisor>,
    netd: Option<Arc<NetdClient>>,
    settings: Mutex<ProxySettings>,
    active_node: Mutex<Option<CanonicalNode>>,
    last_auto_switch: Mutex<Option<Instant>>,
    last_manual_switch: Mutex<Option<Instant>>,
    degraded: AtomicBool,
}

impl ProxyController {
    /// Opens (creating if needed) the SQLite database, boots a supervisor for
    /// `binary`, and connects to netd if it is reachable. netd is optional; a
    /// missing daemon just means routing operations error out later.
    pub fn open(
        db_path: &Path,
        binary: &Path,
        config_path: &Path,
        settings: ProxySettings,
    ) -> Result<Self> {
        let db = open_database(db_path)?;
        let supervisor = Supervisor::new(binary.to_path_buf(), config_path.to_path_buf());
        let netd = match NetdClient::new(DEFAULT_SOCKET_PATH, PROTOCOL_VERSION) {
            Ok(client) => Some(Arc::new(client)),
            Err(_) => None,
        };
        Ok(Self {
            db: Mutex::new(db),
            supervisor: Mutex::new(supervisor),
            netd,
            settings: Mutex::new(settings),
            active_node: Mutex::new(None),
            last_auto_switch: Mutex::new(None),
            last_manual_switch: Mutex::new(None),
            degraded: AtomicBool::new(false),
        })
    }

    /// A controller bound to an in-memory database (tests, demos) with no
    /// netd connection attempted.
    pub fn open_memory(binary: &Path, config_path: &Path) -> Result<Self> {
        let db = myproxy_storage::open_memory_database()?;
        Ok(Self {
            db: Mutex::new(db),
            supervisor: Mutex::new(Supervisor::new(binary.to_path_buf(), config_path.to_path_buf())),
            netd: None,
            settings: Mutex::new(ProxySettings::default()),
            active_node: Mutex::new(None),
            last_auto_switch: Mutex::new(None),
            last_manual_switch: Mutex::new(None),
            degraded: AtomicBool::new(false),
        })
    }

    pub fn settings(&self) -> ProxySettings {
        self.settings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn set_settings(&self, settings: ProxySettings) {
        *self
            .settings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = settings;
    }

    /// Materializes the current node catalog as a dense store.
    pub fn hydrate(&self) -> Result<DenseNodeStore> {
        let db = self.lock_db();
        DenseNodeStore::hydrate_from_db(&db).context("hydrate node catalog")
    }

    /// Builds the ordered list of probe targets the GUI needs to zip probe
    /// results back onto the model: `(persisted node id, decoded node)`.
    pub fn load_probe_targets(&self) -> Result<Vec<(u32, CanonicalNode)>> {
        let db = self.lock_db();
        let mut statement = db.prepare("SELECT id, raw_payload FROM nodes")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)? as u32, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut targets = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            let node = NodeRepository::decode_node_payload(&payload)
                .with_context(|| format!("corrupt node payload for id {id}"))?;
            targets.push((id, node));
        }
        Ok(targets)
    }

    /// Parses raw subscription bytes, persists them, and returns the refresh
    /// report. Refuses to clear an existing subscription with a junk payload
    /// (storage enforces that unless `allow_empty`).
    pub fn import_subscription(&self, raw: &[u8], name: &str, url: &str) -> Result<SubscriptionRefresh> {
        let db = self.lock_db();
        let next_id: i64 = db.query_row(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM subscriptions",
            [],
            |row| row.get(0),
        )?;
        let next_id = if next_id > u16::MAX as i64 {
            anyhow::bail!("too many subscriptions (id {next_id} exceeded u16)");
        } else {
            next_id as u16
        };
        let uuid = Uuid::new_v4().to_string();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let record = SubscriptionRecord {
            id: next_id,
            uuid: &uuid,
            name,
            url,
            last_updated: now_ms,
            auto_update_interval: 86400,
            etag: None,
        };
        SubscriptionService::refresh(&db, record, raw, false).context("import subscription")
    }

    /// Switches the live tunnel to `node`: compiles a full config stamped with
    /// the shared mark, writes it, hot-reloads (or cold-starts) the core, and
    /// (re)applies the netd routing ruleset for the new session. The swap is
    /// atomic: if the new config is rejected, the previous one is rolled back
    /// and the old node keeps serving -- essential with ephemeral subscription
    /// nodes that go stale mid-flight.
    ///
    /// `automatic` records *who* asked for the switch: the egress watchdog
    /// treats a recent manual switch as a do-not-interfere window, and clears
    /// the degraded-to-direct state when any switch succeeds.
    pub fn switch_node(&self, node: &CanonicalNode, automatic: bool) -> Result<String> {
        let settings = self.settings();
        let caps = CoreCapabilities {
            core_name: "sing-box".into(),
            version: "controller".into(),
            supported: BTreeSet::new(),
        };
        let config = compile_full_config(
            node,
            &caps,
            settings.tproxy_port,
            settings.fwmark,
            settings.dns_provider,
            settings.local_dns,
        )?;
        let rendered = serde_json::to_vec_pretty(&config)?;

        let mut supervisor = self.lock_supervisor();
        supervisor.apply_config(&rendered).context("apply core config")?;

        if let Some(netd) = &self.netd {
            let spec = RoutingSpec {
                tproxy_port: settings.tproxy_port,
                fwmark: settings.fwmark,
                table_id: settings.table_id,
                dns_ipv4: settings.dns_ipv4,
                bypass_subnets: settings
                    .bypass_subnets
                    .iter()
                    .map(|subnet| str::to_string(subnet))
                    .collect(),
                bypass_subnets_v6: settings
                    .bypass_subnets_v6
                    .iter()
                    .map(|subnet| str::to_string(subnet))
                    .collect(),
                core_uid: settings.core_uid,
            };
            netd.enable_routing(&spec).context("netd enable routing")?;
        }

        *self
            .active_node
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(node.clone());
        let now = Instant::now();
        if automatic {
            *self
                .last_auto_switch
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(now);
        } else {
            *self
                .last_manual_switch
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(now);
        }
        self.degraded.store(false, Ordering::SeqCst);

        Ok(format!("switched to {}", node.meta.label.as_ref()))
    }

    /// Tears the tunnel down: disable routing via netd, then stop the core.
    pub fn stop(&self) -> Result<()> {
        if let Some(netd) = &self.netd {
            let _ = netd.disable_routing();
        }
        let stopped = self.lock_supervisor().stop();
        *self
            .active_node
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        stopped
    }

    /// Drops the tunnel in place of direct internet. Only the egress watchdog
    /// calls this, and only after an active node has failed quorum repeatedly
    /// AND no other candidate could be confirmed: a dead tunnel is still worse
    /// than direct. A later cycle that finds a live candidate auto-heals back.
    pub fn degrade_to_direct(&self) {
        if let Some(netd) = &self.netd {
            let _ = netd.disable_routing();
        }
        let _ = self.lock_supervisor().stop();
        *self
            .active_node
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        self.degraded.store(true, Ordering::SeqCst);
    }

    /// The currently active node, if the core is up on one.
    pub fn active_node(&self) -> Option<CanonicalNode> {
        self.active_node
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Whether the watchdog has degraded to direct (tunnel down).
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    /// Age of the most recent manual or automatic switch.
    pub fn last_switch(&self) -> Option<Instant> {
        let manual = *self
            .last_manual_switch
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let auto = *self
            .last_auto_switch
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        manual.or(auto)
    }

    /// Stamps a manual switch time -- call this when a caller switches the
    /// core out-of-band (CLI, future GUI connect) so the watchdog holds off.
    pub fn note_manual_switch(&self) {
        *self
            .last_manual_switch
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
    }

    /// Stamps an automatic switch time (used by the watchdog, tests).
    pub fn note_auto_switch(&self) {
        *self
            .last_auto_switch
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
    }

    /// When the most recent manual switch happened (if ever).
    pub fn last_manual_switch(&self) -> Option<Instant> {
        *self
            .last_manual_switch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// When the most recent automatic watchdog switch happened (if ever).
    pub fn last_auto_switch(&self) -> Option<Instant> {
        *self
            .last_auto_switch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Kicks off a heartbeat thread keeping the netd watchdog fed. Safe to call
    /// only when `netd` connected at open time.
    pub fn start_netd_heartbeat(&self) -> Option<std::thread::JoinHandle<()>> {
        self.netd.as_ref().map(NetdClient::start_heartbeat)
    }

    fn lock_db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_supervisor(&self) -> std::sync::MutexGuard<'_, Supervisor> {
        self.supervisor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Egress health of a candidate node, measured through a fresh sing-box
/// testbed spun up for this check only (independent of the live core).
pub fn verify_node_egress(
    controller: &ProxyController,
    node: &CanonicalNode,
    cfg: &ScatterConfig,
) -> Result<ScatterReport> {
    let binary = controller.lock_supervisor().binary_path().to_path_buf();
    test_egress_scatter(&binary, node, cfg)
}

/// Baseline scatter with **no node**: the machine's current network egress
/// through a real sing-box, for comparing against `verify_node_egress` to
/// isolate "my network" problems from "the node" problems.
pub fn verify_local_egress(
    controller: &ProxyController,
    cfg: &ScatterConfig,
) -> Result<ScatterReport> {
    let binary = controller.lock_supervisor().binary_path().to_path_buf();
    test_local_egress_scatter(&binary, cfg)
}

/// Runs one trial per candidate (a fresh testbed spins down after each), so a
/// dead node cannot poison the others. Reports are `None` for trials that
/// failed to even boot.
pub fn run_egress_trials(
    binary: &Path,
    candidates: &[CanonicalNode],
    cfg: &ScatterConfig,
) -> Vec<Option<ScatterReport>> {
    candidates
        .iter()
        .map(|node| test_egress_scatter(binary, node, cfg).ok())
        .collect()
}

/// A single candidate's verdict after an egress trial report.
#[derive(Debug, Clone)]
pub struct CandidateScore {
    /// Index into the candidate slice the trial was run over (zip with the
    /// caller's persisted node ids).
    pub node_index: usize,
    pub label: String,
    /// Subscription the node came from (IR nodes don't carry their catalog id).
    pub sub_id: u16,
    /// Number of operators that answered exactly as expected.
    pub verified: usize,
    pub total: usize,
    pub passes: bool,
    /// Median latency across operators that verified (avoids one slow/fast
    /// operator dominating; None when nothing verified).
    pub median_latency: Option<Duration>,
}

/// Pure scoring over already-collected trial reports: quorum-passing candidates
/// first (fastest median among those), then the stragglers by verified count.
/// This is what makes "live ammunition" subscriptions usable -- pick the node
/// that is actually reachable right now, not the one that was last year.
pub fn rank_candidates(
    candidates: &[CanonicalNode],
    reports: &[Option<ScatterReport>],
    min_verified: usize,
) -> Vec<CandidateScore> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let report = reports.get(index).and_then(Option::as_ref);
            CandidateScore {
                node_index: index,
                label: node.meta.label.to_string(),
                sub_id: node.meta.sub_id,
                verified: report.map_or(0, |r| r.verified),
                total: report.map_or(0, |r| r.total),
                passes: report.map_or(false, |r| r.quorum_verified >= min_verified),
                median_latency: report.and_then(median_of_verified),
            }
        })
        .collect()
}

/// Median round-trip across the operators that verified (avoids one slow/fast
/// operator dominating); `None` when nothing verified.
fn median_of_verified(report: &ScatterReport) -> Option<Duration> {
    let mut latencies = report
        .checks
        .iter()
        .filter(|check| check.verified)
        .map(|check| check.latency)
        .collect::<Vec<_>>();
    latencies.sort();
    latencies.get(latencies.len() / 2).copied()
}

/// See `rank_candidates`: sorts a scored list into selection order.
fn sort_ranked(ranked: &mut [CandidateScore]) {
    ranked.sort_by(|a, b| {
        b.passes
            .cmp(&a.passes)
            .then_with(|| {
                a.median_latency
                    .unwrap_or(Duration::MAX)
                    .cmp(&b.median_latency.unwrap_or(Duration::MAX))
            })
            .then_with(|| b.verified.cmp(&a.verified))
            .then_with(|| a.node_index.cmp(&b.node_index))
    });
}

/// Computes a shortlist for `candidates`: fresh testbed per node, quorum-driven
/// scatter across the public operators, sorted into selection order. Dead or
/// mid-dial nodes simply don't pass; flaky ones sink because they fail quorum.
/// Truncated to `limit`.
pub fn score_egress_candidates(
    controller: &ProxyController,
    candidates: &[CanonicalNode],
    cfg: &ScatterConfig,
    limit: usize,
) -> Result<Vec<CandidateScore>> {
    let binary = controller.lock_supervisor().binary_path().to_path_buf();
    let reports = run_egress_trials(&binary, candidates, cfg);
    let mut ranked = rank_candidates(candidates, &reports, cfg.min_verified);
    sort_ranked(&mut ranked);
    ranked.truncate(limit);
    Ok(ranked)
}

// ---------------------------------------------------------------------------
// Tiered shortlist: cheap socket sweep, then heavy quorum scatter on the
// survivors. The whole point of the split is scale -- a subscription with
// thousands of nodes must not mean thousands of sing-box testbeds. Everyone
// gets one cheap socket probe (bounded concurrency); only the handful of
// fastest-alive finalists earn a full testbed trial.
// ---------------------------------------------------------------------------

/// Tuning for the cheap preflight tier of `tiered_shortlist`.
#[derive(Debug, Clone)]
pub struct PreflightConfig {
    /// Parallelism of the cheap socket sweep (kept modest: thousands of
    /// simultaneous dials out of a censored network is how you get your IP
    /// reputation burned by a firewall).
    pub concurrency: usize,
    /// Per-node dial deadline for the cheap tier.
    pub connect_timeout: Duration,
    /// How many fastest-alive candidates get promoted to the heavy tier.
    pub finalists: usize,
}

impl Default for PreflightConfig {
    fn default() -> Self {
        Self {
            concurrency: 512,
            connect_timeout: Duration::from_millis(800),
            finalists: 8,
        }
    }
}

/// One row of the cheap sweep, decoupled from the probe crate's types so the
/// sort is unit-testable offline. Position in the results vector is the
/// node index into the candidate slice.
#[derive(Debug, Clone, Copy)]
struct CheapOutcome {
    latency: Option<u16>,
    alive: bool,
}

/// The cheap tier: socket-level liveness for the whole catalog in one bounded
/// async sweep. No sing-box process is involved; this is a plain connect (and
/// UDP blast+reply-window for UDP protocols).
fn cheap_sweep(candidates: &[CanonicalNode], preflight: &PreflightConfig) -> Vec<CheapOutcome> {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(_) => return Vec::new(),
    };
    let engine = myproxy_probe::ProbeEngine::new(myproxy_probe::ProbeConfig {
        concurrency_limit: preflight.concurrency.max(1),
        connect_timeout: preflight.connect_timeout,
        ..Default::default()
    });
    runtime
        .block_on(myproxy_probe::probe_batch(
            &engine,
            candidates,
            myproxy_probe::ProbeDepth::L4Ping,
        ))
        .into_iter()
        .map(|outcome| CheapOutcome {
            latency: outcome.latency_ms,
            alive: outcome.alive,
        })
        .collect()
}

/// Pure decision over sweep rows: the fastest `finalists` that are alive
/// (UDP nodes with a live-but-wordless reply sort behind ones with a measured
/// latency). Off-by-one guarantees and wraparounds live here, not in the
/// async glue.
fn select_finalists(outcomes: &[CheapOutcome], finalists: usize) -> Vec<usize> {
    let mut order = (0..outcomes.len())
        .filter(|&index| outcomes[index].alive)
        .collect::<Vec<_>>();
    order.sort_by_key(|&index| outcomes[index].latency.unwrap_or(u16::MAX));
    order.truncate(finalists);
    order.sort_unstable();
    order
}

/// Two-tier shortlist: sweep everything cheaply, promote the fastest-alive
/// finalists to a full quorum scatter, and rank those. Bounded heavy load
/// regardless of catalog size. Returns `[]` untouched when the sweep finds
/// nothing alive (every candidate confirmed dead at the socket level).
pub fn tiered_shortlist(
    controller: &ProxyController,
    candidates: &[CanonicalNode],
    preflight: &PreflightConfig,
    heavy: &ScatterConfig,
    limit: usize,
) -> Vec<CandidateScore> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let outcomes = cheap_sweep(candidates, preflight);
    let finalists = select_finalists(&outcomes, preflight.finalists);
    if finalists.is_empty() {
        return Vec::new();
    }
    let finalist_nodes = finalists
        .iter()
        .map(|&index| candidates[index].clone())
        .collect::<Vec<_>>();
    let binary = controller.lock_supervisor().binary_path().to_path_buf();
    let reports = run_egress_trials(&binary, &finalist_nodes, heavy);

    let mut ranked = finalists
        .iter()
        .enumerate()
        .map(|(slot, &node_index)| {
            let report = reports.get(slot).and_then(Option::as_ref);
            CandidateScore {
                node_index,
                label: candidates[node_index].meta.label.to_string(),
                sub_id: candidates[node_index].meta.sub_id,
                verified: report.map_or(0, |r| r.verified),
                total: report.map_or(0, |r| r.total),
                passes: report.map_or(false, |r| r.quorum_verified >= heavy.min_verified),
                median_latency: report.and_then(median_of_verified),
            }
        })
        .collect::<Vec<_>>();
    sort_ranked(&mut ranked);
    ranked.truncate(limit);
    ranked
}

// ---------------------------------------------------------------------------
// Egress watchdog / paranoid auto-failover
//
// The signature style of this project: we do not care about being fast, we
// care about being *sure*. A node must fail quorum on consecutive cycles
// before anything happens; the replacement must pass a full scatter **and** an
// independent confirmation probe before we flip; and we drop to direct
// internet only when every candidate in the catalog is simultaneously dead --
// resurrecting nodes are picked back up the moment they pass again.
// ---------------------------------------------------------------------------

/// Timing and escalation knobs for the watchdog. Middle-ground defaults:
/// snappy enough to recover, conservative enough not to flap.
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Cadence of one watchdog cycle.
    pub interval: Duration,
    /// Failures (consecutive non-passing cycles) required before escalation.
    pub required_consecutive_failures: usize,
    /// Never auto-act while a manual switch is younger than this.
    pub min_time_since_manual_switch: Duration,
    /// Wait at least this long after an automatic switch before acting again.
    pub cooldown_after_auto_switch: Duration,
    /// How many candidates a rescore is allowed to trial (upper bound).
    pub rescore_limit: usize,
    /// Refresh the shortlist every N healthy cycles (0 = off). Keeps switch
    /// decisions running on fresh data instead of last-week's z-score.
    pub background_rescore_cycles: u32,
    /// Extra shortlist refresh during this UTC hour window, whatever the
    /// healthy cadence says (the "works at 1 AM" node phenomenon). Off = `None`.
    pub quiet_hours_utc: Option<(u8, u8)>,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(180),
            required_consecutive_failures: 2,
            min_time_since_manual_switch: Duration::from_secs(300),
            cooldown_after_auto_switch: Duration::from_secs(300),
            rescore_limit: 8,
            background_rescore_cycles: 4,
            quiet_hours_utc: None,
        }
    }
}

/// What one watchdog cycle decided (or failed to decide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverAction {
    /// Active node passed quorum; nothing to do.
    Healthy,
    /// Active failed but we have not reached enough consecutive failures yet.
    /// The shortlist gets pre-armed while we wait.
    Inspecting { failures: usize },
    /// Shortlist refreshed (background rescore or quiet-hours window).
    Rearmed { shortlist: usize },
    /// A different candidate passed a full scatter *and* an independent
    /// confirmation probe, and has been switched to automatically.
    Switched { label: String },
    /// Candidates existed and passed trials but failed the confirmation probe;
    /// we stay put rather than act on unconfirmed evidence.
    Unconfirmed,
    /// Every candidate in the catalog failed quorum and the active node is
    /// confirmed dead: dropped to direct internet, loudly.
    Degraded,
    /// Degraded earlier, but a resurrected candidate just passed trials and
    /// confirmation -- tunnel restored automatically.
    Healed { label: String },
    /// An active node failed, but we are inside the manual-switch courtesy
    /// window; hands off.
    ManualWindow,
    /// An automatic switch happened too recently to act again.
    Cooldown,
    /// No active node and not degraded: nothing to monitor.
    Idle,
    /// A cycle went wrong for a mechanical reason.
    Error(String),
}

impl FailoverAction {
    pub fn is_intervention(&self) -> bool {
        matches!(self, FailoverAction::Switched { .. } | FailoverAction::Degraded | FailoverAction::Healed { .. })
    }
}

/// The egress watchdog's public status, updated after every cycle.
#[derive(Debug, Clone, Default)]
pub struct FailoverStatus {
    pub active_node: Option<String>,
    pub degraded: bool,
    pub consecutive_failures: usize,
    pub last_action: Option<FailoverAction>,
    pub last_action_at: Option<Instant>,
    pub shortlist: Vec<CandidateScore>,
    /// Healthy cycles since the last shortlist refresh (resets on refresh).
    pub cycles_since_rescore: u32,
}

/// The operations a watchdog cycle may run. Injected for tests; `FailoverHooks::real`
/// wires the actual sing-box + netd machinery. Every hook receives the
/// controller, keeping the engine entirely testable without a binary or a
/// socket.
type ProbeHook =
    Box<dyn Fn(&ProxyController, &CanonicalNode, &ScatterConfig) -> Result<ScatterReport> + Send + Sync>;
type RescoreHook = Box<
    dyn Fn(&ProxyController, &[CanonicalNode], &ScatterConfig, usize) -> Result<Vec<CandidateScore>>
        + Send
        + Sync,
>;
type SwitchHook =
    Box<dyn Fn(&ProxyController, &CanonicalNode, bool) -> Result<String> + Send + Sync>;
type DegradeHook = Box<dyn Fn(&ProxyController) + Send + Sync>;

pub struct FailoverHooks {
    pub probe: ProbeHook,
    pub rescore: RescoreHook,
    pub switch_node: SwitchHook,
    pub degrade: DegradeHook,
}

impl FailoverHooks {
    /// The production wiring: real cheap preflight + egress scatter, real
    /// shortlisting, real atomic switch, real degrade-to-direct.
    pub fn real() -> Self {
        Self {
            probe: Box::new(verify_node_egress),
            rescore: Box::new(|controller, candidates, cfg, limit| {
                Ok(tiered_shortlist(
                    controller,
                    candidates,
                    &PreflightConfig::default(),
                    cfg,
                    limit,
                ))
            }),
            switch_node: Box::new(|controller, node, automatic| {
                controller.switch_node(node, automatic)
            }),
            degrade: Box::new(ProxyController::degrade_to_direct),
        }
    }
}

/// Drives exactly one watchdog cycle. Everything the cycle needs is injected
/// via `hooks`; the only controller state read directly is the active node,
/// the switch timestamps, and the degraded flag. Returns what happened so the
/// caller (a test, or the watchdog thread) can observe it.
pub fn run_failover_cycle(
    controller: &ProxyController,
    config: &FailoverConfig,
    hooks: &FailoverHooks,
    status: &mut FailoverStatus,
) -> FailoverAction {
    let settings = controller.settings();
    let cfg = settings.scatter_config();
    let active = controller.active_node();
    status.active_node = active.as_ref().map(|node| node.meta.label.to_string());
    status.degraded = controller.is_degraded();

    if controller.is_degraded() {
        return heal_or_stay_degraded(controller, config, hooks, &cfg, status);
    }

    let Some(active) = active else {
        status.shortlist = Vec::new();
        return FailoverAction::Idle;
    };

    if let Some(manual) = controller.last_manual_switch() {
        if manual.elapsed() < config.min_time_since_manual_switch {
            return FailoverAction::ManualWindow;
        }
    }

    match (hooks.probe)(controller, &active, &cfg) {
Ok(report) if report.passes => {
            status.consecutive_failures = 0;
            if should_refresh_shortlist(config, status) {
                return if let Some(len) = rescore(controller, hooks, config, &cfg, status) {
                    status.cycles_since_rescore = 0;
                    FailoverAction::Rearmed { shortlist: len }
                } else {
                    FailoverAction::Healthy
                };
            }
            FailoverAction::Healthy
        }
        Ok(_) | Err(_) => {
            let failures = status.consecutive_failures + 1;
            status.consecutive_failures = failures;
            if failures < config.required_consecutive_failures {
                // Pre-arm the shortlist while confidence builds, so the moment
                // we are sure the swap is instant.
                let _ = rescore(controller, hooks, config, &cfg, status);
                return FailoverAction::Inspecting { failures };
            }
            if let Some(auto) = controller.last_auto_switch() {
                if auto.elapsed() < config.cooldown_after_auto_switch {
                    return FailoverAction::Cooldown;
                }
            }
            escalate(controller, config, hooks, &cfg, status, &active)
        }
    }
}

fn rescore(
    controller: &ProxyController,
    hooks: &FailoverHooks,
    config: &FailoverConfig,
    cfg: &ScatterConfig,
    status: &mut FailoverStatus,
) -> Option<usize> {
    let candidates = candidate_nodes(controller).ok()?;
    let shortlist = (hooks.rescore)(controller, &candidates, cfg, config.rescore_limit).ok()?;
    let len = shortlist.len();
    status.shortlist = shortlist;
    Some(len)
}

/// Escalation: the active node has repeatedly failed quorum. Trialing all
/// candidates, confirm the best passing one independently before flipping, and
/// only degrade to direct when *nothing* in the catalog passes trials at all.
fn escalate(
    controller: &ProxyController,
    config: &FailoverConfig,
    hooks: &FailoverHooks,
    cfg: &ScatterConfig,
    status: &mut FailoverStatus,
    active: &CanonicalNode,
) -> FailoverAction {
    let candidates = match candidate_nodes(controller) {
        Ok(candidates) => candidates,
        Err(error) => return FailoverAction::Error(format!("catalog unavailable: {error:#}")),
    };
    let mut shortlist = match (hooks.rescore)(controller, &candidates, cfg, config.rescore_limit) {
        Ok(shortlist) => shortlist,
        Err(error) => return FailoverAction::Error(format!("rescore failed: {error:#}")),
    };
    shortlist.retain(|score| score.label != active.meta.label.as_ref());
    status.shortlist = shortlist.clone();

    for score in shortlist.iter().filter(|score| score.passes) {
        let candidate = &candidates[score.node_index];
        // Independent confirmation: the upgrade must pass the whole scatter a
        // second time before we trust it. Paranoid by design.
        match (hooks.probe)(controller, candidate, cfg) {
            Ok(report) if report.passes => {
                return match (hooks.switch_node)(controller, candidate, true) {
                    Ok(label) => {
                        status.consecutive_failures = 0;
                        FailoverAction::Switched { label }
                    }
                    Err(error) => FailoverAction::Error(format!("switch failed: {error:#}")),
                };
            }
            _ => continue,
        }
    }

    if shortlist.iter().any(|score| score.passes) {
        return FailoverAction::Unconfirmed;
    }
    // Nothing passed trials anywhere. Confident that this is truly dead.
    (hooks.degrade)(controller);
    status.consecutive_failures = 0;
    FailoverAction::Degraded
}

/// Keeps hunting for a resurrected candidate while degraded; auto-heals the
/// moment one survives trials and an independent confirmation.
fn heal_or_stay_degraded(
    controller: &ProxyController,
    config: &FailoverConfig,
    hooks: &FailoverHooks,
    cfg: &ScatterConfig,
    status: &mut FailoverStatus,
) -> FailoverAction {
    let candidates = match candidate_nodes(controller) {
        Ok(candidates) => candidates,
        Err(_) => return FailoverAction::Degraded,
    };
    let shortlist = match (hooks.rescore)(controller, &candidates, cfg, config.rescore_limit) {
        Ok(shortlist) => shortlist,
        Err(_) => return FailoverAction::Degraded,
    };
    status.shortlist = shortlist.clone();
    for score in shortlist.iter().filter(|score| score.passes) {
        let candidate = &candidates[score.node_index];
        if let Ok(report) = (hooks.probe)(controller, candidate, cfg) {
            if !report.passes {
                continue;
            }
            if let Ok(label) = (hooks.switch_node)(controller, candidate, true) {
                status.consecutive_failures = 0;
                return FailoverAction::Healed { label };
            }
        }
    }
    FailoverAction::Degraded
}

fn candidate_nodes(controller: &ProxyController) -> Result<Vec<CanonicalNode>> {
    Ok(controller
        .load_probe_targets()?
        .into_iter()
        .map(|(_, node)| node)
        .collect())
}

fn should_refresh_shortlist(config: &FailoverConfig, status: &mut FailoverStatus) -> bool {
    status.cycles_since_rescore += 1;
    let by_cadence = config.background_rescore_cycles > 0
        && status.cycles_since_rescore >= config.background_rescore_cycles;
    by_cadence || in_quiet_hours(config)
}

fn in_quiet_hours(config: &FailoverConfig) -> bool {
    match config.quiet_hours_utc {
        None => false,
        Some((start, end)) => {
            let hour = utc_hour();
            if start <= end {
                hour >= start && hour < end
            } else {
                // Wraparound window, e.g. (22, 4).
                hour >= start || hour < end
            }
        }
    }
}

fn utc_hour() -> u8 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    ((secs / 3600) % 24) as u8
}

/// A background thread that runs one `run_failover_cycle` every `interval`
/// until stopped. The status handle is what the GUI or any caller polls for
/// the current verdict, last action, and shortlist.
pub struct EgressWatchdog {
    stop: Arc<AtomicBool>,
    status: Arc<Mutex<FailoverStatus>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EgressWatchdog {
    pub fn start(
        controller: Arc<ProxyController>,
        config: FailoverConfig,
        hooks: FailoverHooks,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(FailoverStatus::default()));
        let thread_stop = Arc::clone(&stop);
        let thread_status = Arc::clone(&status);
        let handle = std::thread::spawn(move || loop {
            if thread_stop.load(Ordering::SeqCst) {
                break;
            }
            let mut guard = thread_status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let action = run_failover_cycle(&controller, &config, &hooks, &mut guard);
            guard.last_action = Some(action.clone());
            guard.last_action_at = Some(Instant::now());
            drop(guard);
            std::thread::sleep(config.interval);
        });
        Self {
            stop,
            status,
            handle: Some(handle),
        }
    }

    pub fn status(&self) -> Arc<Mutex<FailoverStatus>> {
        Arc::clone(&self.status)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EgressWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myproxy_adapter::egress::TargetCheck;
    use myproxy_ir::{
        EndpointTarget, NodeMetadata, ProtocolSpec, VlessConfig,
    };
    use std::collections::HashMap;

    const TEST_SUB: &[u8] =
        b"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=none#Alpha\n\
          vless://11111111-1111-1111-1111-111111111111@5.6.7.8:443?security=none#Beta";

    fn vless_node() -> CanonicalNode {
        CanonicalNode::try_new(
            NodeMetadata::new(1, "Alpha", *b"US", 1).unwrap(),
            EndpointTarget::Ip("1.2.3.4:443".parse().unwrap()),
            ProtocolSpec::Vless(VlessConfig {
                uuid: uuid::Uuid::nil(),
                flow: None,
            }),
            myproxy_ir::TransportSpec::Tcp,
            myproxy_ir::SecuritySpec::None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn import_then_probe_targets_round_trip() {
        let config = std::env::temp_dir().join("myproxy-controller-test.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        let refresh = controller
            .import_subscription(TEST_SUB, "Test sub", "https://example.invalid/sub")
            .unwrap();
        assert!(refresh.sync.inserted_nodes >= 1, "at least one node inserted");

        let targets = controller.load_probe_targets().unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].1.meta.label.as_ref(), "Alpha");
        assert!(targets.iter().all(|(id, _)| *id >= 1));
    }

    #[test]
    fn invalid_subscription_payload_is_rejected() {
        let config = std::env::temp_dir().join("myproxy-controller-test2.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        assert!(
            controller
                .import_subscription(b"this is definitely not a subscription", "bad", "https://x")
                .is_err()
        );
        assert!(controller.load_probe_targets().unwrap().is_empty());
    }

    #[test]
    fn switch_node_fails_without_a_real_binary() {
        let config = std::env::temp_dir().join("myproxy-controller-test3.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        let node = vless_node();
        let Err(error) = controller.switch_node(&node, false) else {
            panic!("switching without a binary must fail");
        };
        let message = format!("{error:#}");
        assert!(
            message.to_lowercase().contains("sing-box") || message.contains("No such file"),
            "error should blame the missing binary: {message}"
        );
    }

    #[test]
    fn hydrate_matches_imported_catalog() {
        let config = std::env::temp_dir().join("myproxy-controller-test4.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        controller.import_subscription(TEST_SUB, "Test sub", "https://example.invalid/sub").unwrap();
        let store = controller.hydrate().unwrap();
        assert_eq!(store.len(), 2);
        match controller.hydrate().unwrap().names[0].as_ref() {
            "Alpha" | "Beta" => {}
            other => panic!("unexpected first node {other:?}"),
        }
    }

    fn trial(verified: usize, total: usize, latencies_ms: &[u64]) -> Option<ScatterReport> {
        let checks = latencies_ms
            .iter()
            .map(|ms| TargetCheck {
                tag: "op",
                verified: true,
                latency: Duration::from_millis(*ms),
                status: 200,
                detail: "ok".into(),
            })
            .collect();
        Some(ScatterReport {
            checks,
            verified,
            total,
            quorum_verified: verified,
            passes: verified >= 2,
        })
    }

    #[test]
    fn rank_passes_only_on_quorum_not_total_verified() {
        let candidates = vec![vless_node()];
        let report = Some(ScatterReport {
            checks: Vec::new(),
            verified: 3, // plenty of noise sites answered 200...
            total: 9,
            quorum_verified: 1, // ...but only one operator agreed
            passes: false,
        });
        let ranked = rank_candidates(&candidates, std::slice::from_ref(&report), 2);
        assert!(
            !ranked[0].passes,
            "total-verified must not buy a pass; the quorum decides"
        );
        assert_eq!(ranked[0].verified, 3);
    }

    #[test]
    fn select_finalists_promotes_fastest_alive_only() {
        let outcomes = vec![
            CheapOutcome { latency: Some(900), alive: true },
            CheapOutcome { latency: Some(40), alive: true },
            CheapOutcome { latency: None, alive: false },
            CheapOutcome { latency: None, alive: true }, // UDP: alive, wordless
            CheapOutcome { latency: Some(120), alive: true },
        ];
        // Fastest three alive, ascending by node index for stable ordering.
        let finalists = select_finalists(&outcomes, 3);
        assert_eq!(finalists, vec![0, 1, 4]);
        // A lax cap promotes every live node.
        let finalists = select_finalists(&outcomes, 20);
        assert_eq!(finalists, vec![0, 1, 3, 4]);
        // Nothing alive, nothing promoted.
        let finalists = select_finalists(&outcomes[2..3], 3);
        assert!(finalists.is_empty());
    }

    #[test]
    fn tiered_shortlist_empty_catalog_is_immediate() {
        let config = std::env::temp_dir().join("myproxy-controller-tiered.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        let scores = tiered_shortlist(
            &controller,
            &[],
            &PreflightConfig::default(),
            &ScatterConfig::default(),
            10,
        );
        assert!(scores.is_empty(), "empty catalog must short-circuit, no network");
    }

    #[test]
    fn rank_favours_quorum_passing_then_fastest() {
        let candidates = vec![vless_node(), vless_node(), vless_node(), vless_node()];
        let reports = [
            trial(3, 8, &[50, 60, 70]),
            None,
            trial(0, 8, &[]),
            trial(3, 8, &[40, 45, 48]),
        ];
        let ranked = rank_candidates(&candidates, &reports, 2);
        let mut ranked = ranked;
        sort_ranked(&mut ranked);
        assert_eq!(ranked.len(), 4);
        // The two quorum-passing candidates lead, fastest median first.
        assert!(ranked[0].passes && ranked[1].passes);
        assert_eq!(ranked[0].median_latency, Some(Duration::from_millis(45)));
        assert_eq!(ranked[1].median_latency, Some(Duration::from_millis(60)));
        // Stragglers (including a fatal trial) sort behind the passing set.
        assert!(!ranked[2].passes && !ranked[3].passes);
        assert_eq!(ranked[2].verified, 0);
        assert_eq!(ranked[3].verified, 0);
    }

    #[test]
    fn rank_sinks_flaky_nodes_behind_fast_healthy_ones() {
        // Two passing nodes; the flaky one has the better single-operator TTFB
        // but a worse median, so it must lose the fast healthy node.
        let candidates = vec![vless_node(), vless_node()];
        let reports = [
            trial(3, 8, &[200, 210, 220]),
            trial(3, 8, &[90, 150, 430]),
        ];
        let ranked = rank_candidates(&candidates, &reports, 2);
        let mut ranked = ranked;
        sort_ranked(&mut ranked);
        assert!(ranked[0].median_latency <= ranked[1].median_latency);
    }

    #[test]
    fn scoring_without_binary_yields_nonpassing_shortlist() {
        let config = std::env::temp_dir().join("myproxy-controller-score.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        let cfg = ScatterConfig::default();
        let scores = score_egress_candidates(&controller, &[vless_node()], &cfg, 5).unwrap();
        assert_eq!(scores.len(), 1);
        assert!(!scores[0].passes);
        assert_eq!(scores[0].verified, 0);
        assert_eq!(scores[0].total, 0);
    }

    // --- Failover engine, driven with injected hooks so no binary runs. ---

    #[derive(Clone)]
    enum Muck {
        Pass,
        Fail,
        #[allow(dead_code)]
        Dead,
    }

    struct MockEgress {
        outcomes: HashMap<String, Muck>,
        rescore_passing: Vec<String>,
        probes: Vec<String>,
        switches: Vec<(String, bool)>,
        degrade_calls: usize,
    }

    impl MockEgress {
        fn new(outcomes: HashMap<String, Muck>) -> Self {
            Self {
                outcomes,
                rescore_passing: Vec::new(),
                probes: Vec::new(),
                switches: Vec::new(),
                degrade_calls: 0,
            }
        }
    }

    fn failover_controller() -> ProxyController {
        let config = std::env::temp_dir().join("myproxy-controller-failover.json");
        let controller =
            ProxyController::open_memory(Path::new("/nonexistent/sing-box"), &config).unwrap();
        controller
            .import_subscription(TEST_SUB, "Test sub", "https://example.invalid/sub")
            .unwrap();
        controller
    }

    fn fake_hooks(egress: Arc<Mutex<MockEgress>>) -> FailoverHooks {
        let probe_egress = Arc::clone(&egress);
        let rescore_egress = Arc::clone(&egress);
        let switch_egress = Arc::clone(&egress);
        let degrade_egress = Arc::clone(&egress);
        FailoverHooks {
            probe: Box::new(move |_controller, node, _cfg| {
                let mut egress = probe_egress.lock().unwrap();
                egress.probes.push(node.meta.label.to_string());
                match egress.outcomes.get(node.meta.label.as_ref()) {
                    Some(Muck::Pass) => Ok(trial(3, 8, &[50, 60]).unwrap()),
                    Some(Muck::Fail) => Ok(trial(0, 8, &[]).unwrap()),
                    Some(Muck::Dead) => Err(anyhow::anyhow!("no route to host")),
                    None => Err(anyhow::anyhow!("untracked node in mock probe")),
                }
            }),
            rescore: Box::new(move |_controller, candidates, _cfg, _limit| {
                let egress = rescore_egress.lock().unwrap();
                Ok(candidates
                    .iter()
                    .enumerate()
                    .map(|(index, node)| {
                        let passing = egress
                            .rescore_passing
                            .contains(&node.meta.label.to_string());
                        CandidateScore {
                            node_index: index,
                            label: node.meta.label.to_string(),
                            sub_id: node.meta.sub_id,
                            verified: if passing { 3 } else { 0 },
                            total: 8,
                            passes: passing,
                            median_latency: Some(Duration::from_millis(40)),
                        }
                    })
                    .collect())
            }),
            switch_node: Box::new(move |_controller, node, automatic| {
                switch_egress
                    .lock()
                    .unwrap()
                    .switches
                    .push((node.meta.label.to_string(), automatic));
                Ok(node.meta.label.to_string())
            }),
            degrade: Box::new(move |_controller| {
                degrade_egress.lock().unwrap().degrade_calls += 1;
            }),
        }
    }

    fn force_active(controller: &ProxyController, node: CanonicalNode) {
        *controller.active_node.lock().unwrap() = Some(node);
    }

    fn base_config() -> FailoverConfig {
        FailoverConfig {
            interval: Duration::from_secs(60),
            required_consecutive_failures: 2,
            min_time_since_manual_switch: Duration::from_secs(300),
            cooldown_after_auto_switch: Duration::from_secs(300),
            rescore_limit: 8,
            background_rescore_cycles: 0,
            quiet_hours_utc: None,
        }
    }

    #[test]
    fn failover_switches_only_after_two_failures_and_confirmation() {
        let controller = failover_controller();
        force_active(&controller, vless_node());
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([
            ("Alpha".into(), Muck::Fail),
            ("Beta".into(), Muck::Pass),
        ]))));
        egress.lock().unwrap().rescore_passing = vec!["Beta".into()];
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let first = run_failover_cycle(&controller, &base_config(), &hooks, &mut status);
        assert_eq!(first, FailoverAction::Inspecting { failures: 1 });
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(status.shortlist.len(), 2, "shortlist pre-armed while confidence builds");

        let second = run_failover_cycle(&controller, &base_config(), &hooks, &mut status);
        assert_eq!(second, FailoverAction::Switched { label: "Beta".into() });
        assert_eq!(status.consecutive_failures, 0);
        let guard = egress.lock().unwrap();
        assert_eq!(guard.switches.last(), Some(&("Beta".into(), true)));
        assert_eq!(guard.probes, vec!["Alpha", "Alpha", "Beta"]);
    }

    #[test]
    fn failover_respects_manual_switch_window() {
        let controller = failover_controller();
        force_active(&controller, vless_node());
        *controller.last_manual_switch.lock().unwrap() = Some(Instant::now());
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([(
            "Alpha".into(),
            Muck::Fail,
        )]))));
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let action = run_failover_cycle(&controller, &base_config(), &hooks, &mut status);
        assert_eq!(action, FailoverAction::ManualWindow);
        assert!(egress.lock().unwrap().probes.is_empty(), "hands off while the user drives");
    }

    #[test]
    fn failover_respects_cooldown_after_auto_switch() {
        let controller = failover_controller();
        force_active(&controller, vless_node());
        *controller.last_auto_switch.lock().unwrap() = Some(Instant::now());
        let mut config = base_config();
        config.required_consecutive_failures = 1;
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([(
            "Alpha".into(),
            Muck::Fail,
        )]))));
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let action = run_failover_cycle(&controller, &config, &hooks, &mut status);
        assert_eq!(action, FailoverAction::Cooldown);
        assert!(egress.lock().unwrap().switches.is_empty());
    }

    #[test]
    fn unconfirmed_candidate_blocks_switch_and_degrade() {
        let controller = failover_controller();
        force_active(&controller, vless_node());
        let mut config = base_config();
        config.required_consecutive_failures = 1;
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([
            ("Alpha".into(), Muck::Fail),
            ("Beta".into(), Muck::Fail), // passes trials, then fails confirmation
        ]))));
        egress.lock().unwrap().rescore_passing = vec!["Beta".into()];
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let action = run_failover_cycle(&controller, &config, &hooks, &mut status);
        assert_eq!(action, FailoverAction::Unconfirmed);
        let guard = egress.lock().unwrap();
        assert!(guard.switches.is_empty(), "no switch on unconfirmed evidence");
        assert_eq!(guard.degrade_calls, 0, "stay up rather than degrade");
    }

    #[test]
    fn degrade_only_when_nothing_passes_trials() {
        let controller = failover_controller();
        force_active(&controller, vless_node());
        let mut config = base_config();
        config.required_consecutive_failures = 1;
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([
            ("Alpha".into(), Muck::Fail),
            ("Beta".into(), Muck::Fail),
        ]))));
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let action = run_failover_cycle(&controller, &config, &hooks, &mut status);
        assert_eq!(action, FailoverAction::Degraded);
        let guard = egress.lock().unwrap();
        assert_eq!(guard.degrade_calls, 1);
        assert!(guard.switches.is_empty());
    }

    #[test]
    fn degraded_controller_heals_when_candidate_resurrects() {
        let controller = failover_controller();
        controller.degrade_to_direct();
        assert!(controller.is_degraded());
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([
            ("Beta".into(), Muck::Pass),
        ]))));
        egress.lock().unwrap().rescore_passing = vec!["Beta".into()];
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let action = run_failover_cycle(&controller, &base_config(), &hooks, &mut status);
        assert_eq!(action, FailoverAction::Healed { label: "Beta".into() });
        let guard = egress.lock().unwrap();
        assert_eq!(guard.switches.last(), Some(&("Beta".into(), true)));
        assert_eq!(guard.degrade_calls, 0);
    }

    #[test]
    fn healthy_cycles_keep_arranging_shortlist() {
        let controller = failover_controller();
        force_active(&controller, vless_node());
        let mut config = base_config();
        config.required_consecutive_failures = 99;
        config.background_rescore_cycles = 2;
        let egress = Arc::new(Mutex::new(MockEgress::new(HashMap::from([(
            "Alpha".into(),
            Muck::Pass,
        )]))));
        let hooks = fake_hooks(Arc::clone(&egress));

        let mut status = FailoverStatus::default();
        let first = run_failover_cycle(&controller, &config, &hooks, &mut status);
        assert_eq!(first, FailoverAction::Healthy);
        assert_eq!(status.consecutive_failures, 0);
        let second = run_failover_cycle(&controller, &config, &hooks, &mut status);
        assert_eq!(second, FailoverAction::Rearmed { shortlist: 2 });
        assert_eq!(status.shortlist.len(), 2);
        assert_eq!(status.cycles_since_rescore, 0);
    }
}