pub mod auto_select;
pub mod netd_client;
pub mod proxy_controller;

pub use auto_select::{
    decide_with_margin, rank_working_nodes, should_switch, tunnel_health, AutoDecision,
    AutoSelectConfig, AutoSelector, NodeTrack, RankedNode, TunnelHealth,
};
pub use myproxy_adapter::egress::ScatterConfig;
pub use netd_client::{NetdClient, RoutingSpec};
pub use proxy_controller::{
    rank_candidates, run_egress_trials, score_egress_candidates, tiered_shortlist,
    verify_local_egress, verify_node_egress, CandidateScore, EgressWatchdog, FailoverAction,
    FailoverConfig, FailoverHooks, FailoverStatus, PreflightConfig, ProxyController,
    ProxySettings, SINGLE_FW_MARK,
};