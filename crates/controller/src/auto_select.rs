//! Auto-selection: pick a node that actually works, and pick it well.
//!
//! Two rules define this module, and both are enforced in code rather than in
//! comments:
//!
//! 1. **Only verified nodes are eligible.** A candidate that failed the egress
//!    quorum is never selectable, no matter how good its socket latency looked.
//!    This is the "we don't tell no lies" floor expressed as a type-level
//!    guarantee: [`rank_working_nodes`] filters on [`CandidateScore::passes`]
//!    before any ranking happens.
//! 2. **Rank by stability, not by one latency number.** The fastest node is not
//!    the best node; the *most reliably* fast node is. Latency is smoothed into
//!    an EWMA, jitter is penalised separately, the quorum margin is rewarded,
//!    and recent failures decay over time rather than being erased by one good
//!    sample.
//!
//! Selection never *confirms* anything on its own. The quorum scatter remains
//! the only thing that can mark a node as working. Kernel telemetry
//! ([`tunnel_health`]) informs *when to look* and *how to rank*, never *whether
//! something is true* -- a tunnel the kernel has no socket for yields `None`,
//! which is "no evidence", never "dead".

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use myproxy_ir::CanonicalNode;
use myproxy_probe::socket_health::{
    health_grade, sock_diag::tcp_info_for_peer, HealthThresholds, TcpStats,
};

use crate::CandidateScore;

/// Default EWMA smoothing. Lower tracks history more heavily (more stable, less
/// responsive); the config exposes it for callers that want faster reaction.
const DEFAULT_ALPHA: f64 = 0.35;

/// Rolling reputation for a single node, accumulated across watchdog cycles.
///
/// Deliberately free of any I/O: every method is pure arithmetic over an
/// injected clock, which is what makes the whole selection algorithm testable
/// without a network, a database, or a sing-box binary.
#[derive(Debug, Clone, Default)]
pub struct NodeTrack {
    latency_ewma_ms: Option<f64>,
    spread_ewma_ms: Option<f64>,
    /// Raw failure weight, decayed at scoring time by [`AutoSelectConfig::failure_half_life`].
    failure_weight: f64,
    last_failure: Option<Instant>,
    consecutive_failures: u32,
    samples: u32,
}

impl NodeTrack {
    /// Folds a verified measurement into the track. A single success does *not*
    /// wipe the failure history; it only ages it.
    pub fn record_success(&mut self, median_ms: f64, spread_ms: f64, alpha: f64, now: Instant) {
        let alpha = alpha.clamp(0.0, 1.0);
        self.latency_ewma_ms = Some(match self.latency_ewma_ms {
            None => median_ms,
            Some(previous) => alpha * median_ms + (1.0 - alpha) * previous,
        });
        self.spread_ewma_ms = Some(match self.spread_ewma_ms {
            None => spread_ms,
            Some(previous) => alpha * spread_ms + (1.0 - alpha) * previous,
        });
        // A success halves the outstanding failure weight rather than clearing
        // it, so a node alternating pass/fail stays penalised.
        self.failure_weight *= 0.5;
        self.consecutive_failures = 0;
        self.samples = self.samples.saturating_add(1);
        let _ = now;
    }

    /// Records a failed verification (quorum not met).
    pub fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.failure_weight = (self.failure_weight + 1.0).min(4.0);
        self.last_failure = Some(now);
    }

    /// Failure weight decayed to zero with a half-life, so "failed twenty
    /// minutes ago" and "failed last Tuesday" are not the same node.
    pub fn decayed_failure(&self, half_life: Duration, now: Instant) -> f64 {
        let Some(last) = self.last_failure else {
            return 0.0;
        };
        let half_life = half_life.as_secs_f64().max(1.0);
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        self.failure_weight * 0.5f64.powf(elapsed / half_life)
    }

    pub fn latency_ewma_ms(&self) -> Option<f64> {
        self.latency_ewma_ms
    }

    pub fn spread_ewma_ms(&self) -> Option<f64> {
        self.spread_ewma_ms
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    /// True until the track has enough history to rank on. Used to report
    /// honestly that a cold node is being ranked on its latest measurement.
    pub fn is_cold(&self) -> bool {
        self.samples == 0
    }
}

/// Weights and tolerances for the selection cost. Every term is normalised so
/// the numbers are comparable and the defaults mean something readable.
#[derive(Debug, Clone, Copy)]
pub struct AutoSelectConfig {
    /// Weight on smoothed latency, expressed in units of [`Self::latency_scale`].
    pub w_latency: f64,
    /// Weight on latency spread (jitter).
    pub w_spread: f64,
    /// Weight on *disagreement* with the quorum: `1 - verified/total`.
    pub w_quorum: f64,
    /// Weight on the decayed failure penalty.
    pub w_failure: f64,
    /// Latency that saturates the latency term (ms).
    pub latency_scale: f64,
    /// A challenger must beat the incumbent by this much cost to trigger a
    /// switch. Without a margin, two nodes a millisecond apart swap forever.
    pub switch_margin: f64,
    /// Half-life of a recorded failure.
    pub failure_half_life: Duration,
    /// EWMA smoothing factor.
    pub alpha: f64,
}

impl Default for AutoSelectConfig {
    fn default() -> Self {
        Self {
            w_latency: 1.0,
            w_spread: 0.6,
            w_quorum: 0.5,
            w_failure: 1.2,
            latency_scale: 1000.0,
            switch_margin: 0.08,
            failure_half_life: Duration::from_secs(30 * 60),
            alpha: DEFAULT_ALPHA,
        }
    }
}

/// A verified candidate with its selection cost computed. Lower cost is better.
#[derive(Debug, Clone)]
pub struct RankedNode {
    /// Index into the candidate slice the scores were produced from.
    pub node_index: usize,
    pub cost: f64,
    /// Fraction of operators that agreed, in `0.0..=1.0`.
    pub quorum_margin: f64,
    pub track: NodeTrack,
}

impl RankedNode {
    /// True when this node is decisively better than `other`: strictly cheaper
    /// by more than `margin`.
    pub fn decisively_beats(&self, other: &RankedNode, margin: f64) -> bool {
        self.cost + margin < other.cost
    }
}

/// One ranked node's inputs.
#[derive(Debug, Clone, Copy)]
pub struct SelectionInput<'a> {
    pub score: &'a CandidateScore,
    pub track: &'a NodeTrack,
}

/// Ranks verified candidates into selection order.
///
/// **Hard gate:** candidates that did not pass quorum are dropped before any
/// arithmetic. A node that cannot be shown to work is not selectable, however
/// fast its socket was.
///
/// A candidate with no history yet is ranked on its own fresh measurement, so
/// a cold start still produces a usable ordering rather than refusing to choose.
pub fn rank_working_nodes(
    scores: &[CandidateScore],
    tracks: &HashMap<u32, NodeTrack>,
    ids: &[u32],
    config: &AutoSelectConfig,
    now: Instant,
) -> Vec<RankedNode> {
    let mut ranked: Vec<RankedNode> = scores
        .iter()
        .filter(|score| score.passes)
        .map(|score| {
            // The catalog index carried on the score, never the position in
            // `scores`: the shortlist is a sparse subset (the failed incumbent
            // is filtered out before escalation), so positional indexing would
            // silently point at the wrong node.
            let node_index = score.node_index;
            let track = ids
                .get(node_index)
                .and_then(|id| tracks.get(id))
                .cloned()
                .unwrap_or_default();
            let cost = selection_cost(score, &track, config, now);
            let quorum_margin = if score.total == 0 {
                0.0
            } else {
                score.verified as f64 / score.total as f64
            };
            RankedNode {
                node_index,
                cost,
                quorum_margin,
                track,
            }
        })
        .collect();
    ranked.sort_by(|a, b| {
        a.cost
            .partial_cmp(&b.cost)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.node_index.cmp(&b.node_index))
    });
    ranked
}

/// The composite cost. Lower is better.
///
/// Prefers the track's smoothed history when available and falls back to the
/// latest measurement for a cold node, so the very first selection is still
/// meaningful.
fn selection_cost(
    score: &CandidateScore,
    track: &NodeTrack,
    config: &AutoSelectConfig,
    now: Instant,
) -> f64 {
    let fresh_ms = score
        .median_latency
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(config.latency_scale * 2.0);
    let fresh_spread_ms = score
        .latency_spread
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);

    let latency_ms = track.latency_ewma_ms().unwrap_or(fresh_ms);
    let spread_ms = track.spread_ewma_ms().unwrap_or(fresh_spread_ms);
    let latency_term = (latency_ms / config.latency_scale).clamp(0.0, 4.0);
    let spread_term = (spread_ms / config.latency_scale).clamp(0.0, 4.0);
    let disagreement = if score.total == 0 {
        1.0
    } else {
        1.0 - (score.verified as f64 / score.total as f64)
    };
    let failure_term = track.decayed_failure(config.failure_half_life, now);

    config.w_latency * latency_term
        + config.w_spread * spread_term
        + config.w_quorum * disagreement
        + config.w_failure * failure_term
}

/// Applies the switch margin.
///
/// `challenger` must beat the `incumbent` by more than `margin` -- decisively,
/// not merely marginally. This single rule is what stops the classic two-node
/// oscillation where two nodes a millisecond apart swap forever.
///
/// The argument order is `(challenger, incumbent)`: callers get the direction
/// they intend rather than the one they assumed.
pub fn should_switch(challenger: &RankedNode, incumbent: &RankedNode, margin: f64) -> bool {
    challenger.decisively_beats(incumbent, margin)
}

/// What auto mode decided.
#[derive(Debug, Clone, PartialEq)]
pub enum AutoDecision {
    /// No active node and a verified candidate was adopted.
    Adopted {
        node_index: usize,
        label: String,
        cost: f64,
    },
    /// The incumbent is still the best choice by more than the switch margin.
    Kept { node_index: usize, reason: String },
    /// A challenger beat the incumbent by more than the margin.
    Switch {
        node_index: usize,
        label: String,
        cost: f64,
    },
    /// Nothing in the catalog passed quorum. Auto mode must not invent a
    /// winner; the caller degrades to direct instead.
    NoVerifiedNode,
}

/// Decides what to do with a freshly scored shortlist, given the current
/// incumbent (if any).
///
/// Pure: no I/O and no mutation. The caller performs the switch.
///
/// The margin is an explicit argument rather than a hidden default, because it
/// is the single most consequential knob in auto mode: too small and the tunnel
/// flaps between two similar nodes, too large and it clings to a bad one.
pub fn decide_with_margin(
    ranked: &[RankedNode],
    scores: &[CandidateScore],
    incumbent: Option<usize>,
    margin: f64,
) -> AutoDecision {
    let Some(best) = ranked.first() else {
        return AutoDecision::NoVerifiedNode;
    };
    let label = scores
        .get(best.node_index)
        .map(|score| score.label.clone())
        .unwrap_or_default();

    let Some(incumbent_index) = incumbent else {
        return AutoDecision::Adopted {
            node_index: best.node_index,
            label,
            cost: best.cost,
        };
    };

    // The incumbent missing from the ranking means it failed quorum this round.
    // Eligibility is checked before preference, so it is replaced outright --
    // no margin can save a node that is no longer demonstrably working.
    let Some(current) = ranked
        .iter()
        .find(|node| node.node_index == incumbent_index)
    else {
        return AutoDecision::Switch {
            node_index: best.node_index,
            label,
            cost: best.cost,
        };
    };

    if should_switch(best, current, margin) {
        AutoDecision::Switch {
            node_index: best.node_index,
            label,
            cost: best.cost,
        }
    } else {
        AutoDecision::Kept {
            node_index: incumbent_index,
            reason: if best.node_index == incumbent_index {
                "incumbent is the best verified node".into()
            } else {
                "challenger not decisively better".into()
            },
        }
    }
}

/// Stateful wrapper that owns the per-node tracks across cycles.
#[derive(Debug, Clone, Default)]
pub struct AutoSelector {
    config: AutoSelectConfig,
    tracks: HashMap<u32, NodeTrack>,
}

impl AutoSelector {
    pub fn new(config: AutoSelectConfig) -> Self {
        Self {
            config,
            tracks: HashMap::new(),
        }
    }

    pub fn config(&self) -> &AutoSelectConfig {
        &self.config
    }

    pub fn tracks(&self) -> &HashMap<u32, NodeTrack> {
        &self.tracks
    }

    /// Folds one full round of scores into the per-node tracks: verified nodes
    /// get their measurement smoothed in, everything else accrues failure
    /// weight.
    ///
    /// Indexes through [`CandidateScore::node_index`], which refers to the
    /// original catalog rather than to the shortlist's own position -- the
    /// shortlist is a sparse subset, so zipping positionally would corrupt the
    /// history.
    pub fn observe_round(&mut self, ids: &[u32], scores: &[CandidateScore], now: Instant) {
        for score in scores {
            let Some(id) = ids.get(score.node_index).copied() else {
                continue;
            };
            if score.passes {
                let median_ms = score
                    .median_latency
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                let spread_ms = score
                    .latency_spread
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                self.observe_verified(id, median_ms, spread_ms, now);
            } else {
                self.observe_failed(id, now);
            }
        }
    }

    pub fn track(&self, node_id: u32) -> Option<&NodeTrack> {
        self.tracks.get(&node_id)
    }

    pub fn track_mut(&mut self, node_id: u32) -> &mut NodeTrack {
        self.tracks.entry(node_id).or_default()
    }

    /// Folds a verified measurement into the node's track.
    pub fn observe_verified(
        &mut self,
        node_id: u32,
        median_ms: f64,
        spread_ms: f64,
        now: Instant,
    ) {
        let alpha = self.config.alpha;
        self.track_mut(node_id)
            .record_success(median_ms, spread_ms, alpha, now);
    }

    /// Folds a failed quorum into the node's track.
    pub fn observe_failed(&mut self, node_id: u32, now: Instant) {
        self.track_mut(node_id).record_failure(now);
    }

    /// Ranks the current scores, respecting the switch margin against
    /// `incumbent` if one is supplied.
    pub fn decide(
        &self,
        scores: &[CandidateScore],
        ids: &[u32],
        incumbent: Option<usize>,
        now: Instant,
    ) -> (AutoDecision, Vec<RankedNode>) {
        let ranked = rank_working_nodes(scores, &self.tracks, ids, &self.config, now);
        let decision = decide_with_margin(&ranked, scores, incumbent, self.config.switch_margin);
        (decision, ranked)
    }
}


// ---------------------------------------------------------------------------
// In-kernel tunnel telemetry (the Linux-native fast signal)
// ---------------------------------------------------------------------------

/// Live health of the tunnel to a node, sampled straight from the kernel.
#[derive(Debug, Clone, Copy)]
pub struct TunnelHealth {
    /// 0..=100 on the same scale as the storage layer's health scores.
    pub grade: u8,
    pub rtt_ms: u32,
    pub spread_ms: u32,
    pub retransmits: u32,
    pub connections: usize,
}

/// Samples `TCP_INFO` for the live connections to `node`'s server, over Netlink
/// `sock_diag`.
///
/// `sock_diag` reports process-wide socket state, so this sees the sing-box
/// child's tunnel without borrowing its file descriptors -- which is exactly
/// why the README prefers it to `dup_child_fd`.
///
/// `None` means **no evidence**: the kernel has no established socket to this
/// peer (the tunnel is down, or the node is simply not the active one). It is
/// never interpreted as failure -- only the quorum may declare a node dead.
pub fn tunnel_health(
    node: &CanonicalNode,
    thresholds: &HealthThresholds,
) -> Option<TunnelHealth> {
    let addresses = resolve_endpoint(node)?;
    let mut best: Option<TunnelHealth> = None;
    for address in addresses {
        let Ok(stats) = tcp_info_for_peer(address) else {
            continue;
        };
        if stats.is_empty() {
            continue;
        }
        // Several parallel streams to one peer are normal; the healthiest one
        // is what a fresh connection would actually get.
        if let Some(chosen) = aggregate(&stats, thresholds) {
            best = match best {
                Some(current) if current.grade >= chosen.grade => Some(current),
                _ => Some(chosen),
            };
        }
    }
    best
}

fn aggregate(stats: &[TcpStats], thresholds: &HealthThresholds) -> Option<TunnelHealth> {
    let best = stats
        .iter()
        .max_by_key(|sample| health_grade(sample, thresholds))?;
    Some(TunnelHealth {
        grade: health_grade(best, thresholds),
        rtt_ms: best.rtt_ms,
        spread_ms: best.rtt_var_ms,
        retransmits: best.total_retrans,
        connections: stats.len(),
    })
}

fn resolve_endpoint(node: &CanonicalNode) -> Option<Vec<SocketAddr>> {
    match &node.endpoint {
        myproxy_ir::EndpointTarget::Ip(address) => Some(vec![*address]),
        myproxy_ir::EndpointTarget::Domain { host, port } => (host.as_ref(), *port)
            .to_socket_addrs()
            .ok()
            .map(|addrs| addrs.collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn score(index: usize, passes: bool, verified: usize, total: usize, median_ms: u64) -> CandidateScore {
        CandidateScore {
            node_index: index,
            label: format!("node-{index}"),
            sub_id: 1,
            verified,
            total,
            passes,
            median_latency: Some(Duration::from_millis(median_ms)),
            latency_spread: Some(Duration::from_millis(median_ms / 10)),
        }
    }

    fn ids(n: usize) -> Vec<u32> {
        (1..=n as u32).collect()
    }

    #[test]
    fn only_quorum_passing_nodes_are_eligible() {
        // Node 0 is fast but never passed; node 1 is slower and verified.
        let scores = vec![score(0, false, 1, 9, 10), score(1, true, 5, 9, 200)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].node_index, 1, "a non-passing node must never be selectable");
    }

    #[test]
    fn empty_catalog_means_no_verified_node() {
        let scores = vec![score(0, false, 0, 9, 10)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(1),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        assert!(ranked.is_empty());
        assert_eq!(decide_with_margin(&ranked, &scores, None, 0.08), AutoDecision::NoVerifiedNode);
    }

    #[test]
    fn faster_verified_node_wins_when_both_verified() {
        let scores = vec![score(0, true, 5, 9, 100), score(1, true, 5, 9, 40)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        assert_eq!(ranked[0].node_index, 1);
    }

    #[test]
    fn jitter_is_penalised_over_uniform_slowdown() {
        // Same median, very different spread: the stable node must win.
        let mut steady = score(0, true, 5, 9, 100);
        steady.latency_spread = Some(Duration::from_millis(2));
        let mut jittery = score(1, true, 5, 9, 100);
        jittery.latency_spread = Some(Duration::from_millis(400));
        let scores = vec![steady, jittery];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        assert_eq!(ranked[0].node_index, 0, "a stable 100ms beats a jittery 100ms");
    }

    #[test]
    fn quorum_disagreement_is_penalised() {
        // Same latency and spread; the node fewer operators agreed on loses.
        let broad = score(0, true, 5, 9, 80);
        let narrow = score(1, true, 2, 9, 80);
        let scores = vec![broad, narrow];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        assert_eq!(ranked[0].node_index, 0, "a lopsided quorum is less trustworthy");
    }

    #[test]
    fn recent_failure_demotes_an_otherwise_equal_node() {
        let now = Instant::now();
        let scores = vec![score(0, true, 5, 9, 80), score(1, true, 5, 9, 80)];
        let mut tracks = HashMap::new();
        let mut failed = NodeTrack::default();
        failed.record_failure(now);
        tracks.insert(2u32, failed); // node_index 1 -> id 2
        let ranked = rank_working_nodes(
            &scores,
            &tracks,
            &ids(2),
            &AutoSelectConfig::default(),
            now,
        );
        assert_eq!(ranked[0].node_index, 0, "a node that just failed must not lead");
    }

    #[test]
    fn failure_penalty_decays_with_time() {
        let config = AutoSelectConfig::default();
        let now = Instant::now();
        let mut track = NodeTrack::default();
        track.record_failure(now);
        let fresh = track.decayed_failure(config.failure_half_life, now);
        let stale = track.decayed_failure(config.failure_half_life, now + Duration::from_secs(3600));
        assert!(fresh > stale, "the penalty must fade as the failure ages");
        assert!(stale > 0.0, "an hour is still within the half-life");
    }

    #[test]
    fn one_good_sample_does_not_erase_failure_history() {
        let now = Instant::now();
        let config = AutoSelectConfig::default();
        let mut track = NodeTrack::default();
        for _ in 0..3 {
            track.record_failure(now);
        }
        let before = track.decayed_failure(config.failure_half_life, now);
        track.record_success(50.0, 1.0, config.alpha, now);
        let after = track.decayed_failure(config.failure_half_life, now);
        assert!(
            after < before && after > 0.0,
            "a success should ease the penalty, not erase it"
        );
    }

    #[test]
    fn ewma_smooths_toward_the_recent_measurement() {
        let now = Instant::now();
        let config = AutoSelectConfig::default();
        let mut track = NodeTrack::default();
        track.record_success(200.0, 5.0, config.alpha, now);
        let after_first = track.latency_ewma_ms().unwrap();
        assert!((after_first - 200.0).abs() < 0.001);
        // A sudden fast sample pulls the EWMA down but not all the way.
        track.record_success(50.0, 5.0, config.alpha, now);
        let smoothed = track.latency_ewma_ms().unwrap();
        assert!(smoothed < after_first && smoothed > 50.0);
    }

    // -- switch margin ------------------------------------------------------

    #[test]
    fn marginal_improvement_does_not_trigger_a_switch() {
        // The classic oscillation: two nodes a hair apart must not thrash.
        let scores = vec![score(0, true, 5, 9, 100), score(1, true, 5, 9, 99)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        let decision = decide_with_margin(&ranked, &scores, Some(0), 0.08);
        assert!(
            matches!(decision, AutoDecision::Kept { .. }),
            "a ~1ms gain must not justify a switch, got {decision:?}"
        );
    }

    #[test]
    fn decisive_improvement_switches() {
        let scores = vec![score(0, true, 5, 9, 400), score(1, true, 5, 9, 40)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        let decision = decide_with_margin(&ranked, &scores, Some(0), 0.08);
        match decision {
            AutoDecision::Switch { node_index, .. } => assert_eq!(node_index, 1),
            other => panic!("expected a decisive switch, got {other:?}"),
        }
    }

    #[test]
    fn no_incumbent_adopts_the_best_verified_node() {
        let scores = vec![score(0, true, 5, 9, 300), score(1, true, 5, 9, 30)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        match decide_with_margin(&ranked, &scores, None, 0.08) {
            AutoDecision::Adopted { node_index, .. } => assert_eq!(node_index, 1),
            other => panic!("expected adoption on cold start, got {other:?}"),
        }
    }

    #[test]
    fn incumbent_that_fails_quorum_is_replaced() {
        // The incumbent is no longer eligible, so the best verified node wins
        // regardless of margin -- eligibility is checked before preference.
        let scores = vec![score(0, false, 1, 9, 10), score(1, true, 5, 9, 300)];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &ids(2),
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        match decide_with_margin(&ranked, &scores, Some(0), 0.08) {
            AutoDecision::Switch { node_index, .. } => assert_eq!(node_index, 1),
            other => panic!("a disqualified incumbent must be replaced, got {other:?}"),
        }
    }

    #[test]
    fn sparse_shortlist_resolves_catalog_indices_not_positions() {
        // Regression guard. `node_index` is a *catalog* index, not a position
        // in the slice: escalation filters the failed incumbent out before
        // ranking, so the two disagree. Indexing positionally would point at
        // the wrong node entirely -- and silently so.
        let scores = vec![score(2, true, 5, 9, 40), score(5, true, 5, 9, 900)];
        let catalog_ids = vec![10u32, 11, 12, 13, 14, 15];
        let ranked = rank_working_nodes(
            &scores,
            &HashMap::new(),
            &catalog_ids,
            &AutoSelectConfig::default(),
            Instant::now(),
        );
        assert_eq!(ranked[0].node_index, 2, "fastest catalog node must lead");
        assert_eq!(ranked[1].node_index, 5);
    }

    #[test]
    fn tracks_follow_the_catalog_index_too() {
        let now = Instant::now();
        let mut selector = AutoSelector::new(AutoSelectConfig::default());
        let catalog_ids = vec![10u32, 11, 12, 13, 14, 15];
        // Catalog index 5 (id 15) failed; catalog index 2 (id 12) did not.
        selector.observe_failed(15, now);
        let scores = vec![score(2, true, 5, 9, 40), score(5, true, 5, 9, 40)];
        let ranked = rank_working_nodes(
            &scores,
            selector.tracks(),
            &catalog_ids,
            selector.config(),
            now,
        );
        assert_eq!(
            ranked[0].node_index, 2,
            "history must attach to the right catalog node"
        );
    }

    #[test]
    fn observe_round_keys_history_by_catalog_index() {
        let now = Instant::now();
        let mut selector = AutoSelector::new(AutoSelectConfig::default());
        let catalog_ids = vec![10u32, 11, 12, 13, 14, 15];
        // A sparse shortlist: catalog indices 2 and 5, in that order.
        let scores = vec![score(2, true, 5, 9, 40), score(5, false, 0, 9, 0)];
        selector.observe_round(&catalog_ids, &scores, now);
        assert_eq!(selector.track(12).unwrap().samples(), 1, "id at index 2");
        assert_eq!(
            selector.track(15).unwrap().consecutive_failures(),
            1,
            "id at index 5"
        );
        assert!(
            selector.track(13).is_none(),
            "nodes outside the shortlist must not gain history"
        );
    }

    #[test]
    fn selector_remembers_history_across_cycles() {
        let now = Instant::now();
        let mut selector = AutoSelector::new(AutoSelectConfig::default());
        selector.observe_verified(1, 100.0, 5.0, now);
        selector.observe_verified(2, 120.0, 5.0, now);
        assert_eq!(selector.track(1).unwrap().samples(), 1);
        // A second cycle: node 1 stays fast, node 2 collapses.
        selector.observe_verified(1, 100.0, 5.0, now);
        selector.observe_verified(2, 800.0, 5.0, now);
        let scores = vec![score(0, true, 5, 9, 100), score(1, true, 5, 9, 800)];
        let (_, ranked) = selector.decide(&scores, &ids(2), None, now);
        assert_eq!(ranked[0].node_index, 0);
    }
}
