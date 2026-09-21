use anyhow::{bail, Result};
use myproxy_controller::{
    tiered_shortlist, EgressWatchdog, FailoverAction, FailoverConfig, FailoverHooks,
    PreflightConfig, ProxyController, ProxySettings, ScatterConfig,
};
use myproxy_probe::{probe_batch, ProbeConfig, ProbeDepth, ProbeEngine};
use myproxy_storage::{DenseNodeStore, StoreSnapshot, UNTESTED_LATENCY};
use slint::{ComponentHandle, ModelRc};
use std::path::{Path, PathBuf};
use std::{cell::RefCell, rc::Rc, sync::Arc};

mod dispatcher;
mod view_state;
mod virtual_model;

slint::include_modules!();

use dispatcher::{ProbeResult, UiDispatcher};
use view_state::ViewState;
use virtual_model::VirtualNodeModel;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let demo_requested = has_flag(&args, "--demo-nodes");
    let demo_count = flag_value(&args, "--demo-nodes")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    let db_path = flag_value(&args, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(default_db_path);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let singbox_binary = flag_value(&args, "--sing-box")
        .or_else(|| std::env::var("SING_BOX_BIN").ok())
        .unwrap_or_else(|| "/usr/bin/sing-box".into());
    let config_path = std::env::temp_dir().join("myproxy-gui-config.json");

    let controller = Arc::new(ProxyController::open(
        &db_path,
        Path::new(&singbox_binary),
        &config_path,
        ProxySettings::default(),
    )?);

    let watchdog_enabled = !has_flag(&args, "--no-egress-watchdog");
    let watchdog = (watchdog_enabled)
        .then(|| {
            EgressWatchdog::start(
                Arc::clone(&controller),
                FailoverConfig::default(),
                FailoverHooks::real(),
            )
        })
        .inspect(|_| eprintln!("egress watchdog: armed (failover middle-ground defaults)"));
    let _watchdog_guard = watchdog;

    let store = match controller.hydrate() {
        Ok(store) if !demo_requested && !store.is_empty() => store,
        _ => demo_store(demo_count),
    };

    let snapshots = Arc::new(StoreSnapshot::new(store));
    let initial_count = snapshots.load_full().len();
    let state = Rc::new(RefCell::new(ViewState::default()));
    let model = VirtualNodeModel::new(Arc::clone(&snapshots), &state.borrow());
    let app = MainWindow::new()?;
    app.set_nodes_model(ModelRc::new(model.clone()));
    app.set_total_nodes_count(initial_count as i32);
    app.set_status_text(initial_status(initial_count).into());

    let search_state = Rc::clone(&state);
    let search_model = model.clone();
    app.on_search_changed(move |query| {
        search_state.borrow_mut().search_text = query.to_string();
        search_model.refresh(&search_state.borrow());
    });

    let sort_state = Rc::clone(&state);
    let sort_model = model.clone();
    app.on_sort_changed(move |sort| {
        sort_state.borrow_mut().set_sort_name(sort.as_str());
        sort_model.refresh(&sort_state.borrow());
    });

    let selected_model = model.clone();
    let selected_app = app.as_weak();
    app.on_node_selected(move |node_id| {
        selected_model.select_node(node_id as u32);
        if let Some(app) = selected_app.upgrade() {
            app.set_active_node_name(selected_model.selected_name().into());
        }
    });

    let dispatcher = UiDispatcher::new(16_384);
    let burst_dispatcher = dispatcher.clone();
    let burst_store = Arc::clone(&snapshots);
    let burst_controller = Arc::clone(&controller);
    let burst_app = app.as_weak();
    app.on_probe_all_clicked(move || {
        let controller = Arc::clone(&burst_controller);
        let snapshots = Arc::clone(&burst_store);
        let sender = burst_dispatcher.clone();
        let weak = burst_app.clone();
        std::thread::spawn(move || {
            match controller.load_probe_targets() {
                Ok(targets) if !targets.is_empty() => {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build();
                    match runtime {
                        Ok(runtime) => {
                            let engine = ProbeEngine::new(ProbeConfig {
                                // The whole catalog at once; keep the socket
                                // barrage polite and below the firewall's
                                // attention threshold.
                                concurrency_limit: 512,
                                ..Default::default()
                            });
                            let nodes =
                                targets.iter().map(|(_, node)| node.clone()).collect::<Vec<_>>();
                            let outcomes = runtime
                                .block_on(probe_batch(&engine, &nodes, ProbeDepth::L4Ping));
                            for ((id, _node), outcome) in targets.iter().zip(outcomes.iter()) {
                                let latency_ms = outcome.latency_ms.unwrap_or(UNTESTED_LATENCY);
                                let health_score = probe_health(outcome.alive, outcome.latency_ms);
                                sender.enqueue(ProbeResult {
                                    node_id: *id,
                                    latency_ms,
                                    health_score,
                                });
                            }
                            if let Some(app) = weak.upgrade() {
                                app.set_status_text(
                                    format!("Probed {} nodes via socket health", targets.len())
                                        .into(),
                                );
                            }
                        }
                        Err(error) => {
                            if let Some(app) = weak.upgrade() {
                                app.set_status_text(format!("Probe runtime failed: {error}").into());
                            }
                        }
                    }
                }
                // No catalog (demo store): keep the burst visible rather than
                // silently doing nothing.
                _ => {
                    let ids = snapshots.load_full().node_ids.clone();
                    for id in ids {
                        let latency = 25 + ((id.wrapping_mul(37)) % 550) as u16;
                        sender.enqueue(ProbeResult {
                            node_id: id,
                            latency_ms: latency,
                            health_score: (100 - (latency / 8).min(90)) as u8,
                        });
                    }
                    if let Some(app) = weak.upgrade() {
                        app.set_status_text(
                            "Simulated burst (no persisted catalog; import a subscription)".into(),
                        );
                    }
                }
            }
        });
    });

    if let Some(watchdog) = &_watchdog_guard {
        let status_handle = watchdog.status();
        let poller_app = app.as_weak();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let Some(app) = poller_app.upgrade() else { break };
            let status = status_handle.lock().map(|guard| guard.clone()).unwrap_or_default();
            app.set_watchdog_status_text(watchdog_summary(&status).into());
            if let Some(active) = status.active_node.as_deref() {
                app.set_active_node_name(active.into());
            }
        });
    }

    let rescore_controller = Arc::clone(&controller);
    let rescore_snapshots = Arc::clone(&snapshots);
    let rescore_dispatcher = dispatcher.clone();
    let rescore_app = app.as_weak();
    app.on_rescore_egress_clicked(move || {
        let controller = Arc::clone(&rescore_controller);
        let snapshots = Arc::clone(&rescore_snapshots);
        let sender = rescore_dispatcher.clone();
        let weak = rescore_app.clone();
        std::thread::spawn(move || {
            let Some(app_up) = weak.upgrade() else { return };
            app_up.set_status_text("Rescoring egress (cheap sweep, then quorum scatter on finalists)...".into());
            let cfg = ScatterConfig::default();
            match controller.load_probe_targets() {
                Ok(targets) if !targets.is_empty() => {
                    let nodes = targets.iter().map(|(_, node)| node.clone()).collect::<Vec<_>>();
                    let ranked = tiered_shortlist(
                        &controller,
                        &nodes,
                        &PreflightConfig::default(),
                        &cfg,
                        10,
                    );
                    if !ranked.is_empty() {
                        let mut writes = 0;
                        for score in &ranked {
                            let Some((id, _node)) = targets.get(score.node_index) else {
                                continue;
                            };
                            let latency = score.median_latency.map(|d| d.as_millis() as u16);
                            sender.enqueue(ProbeResult {
                                node_id: *id,
                                latency_ms: latency.unwrap_or(UNTESTED_LATENCY),
                                health_score: probe_health(score.passes, latency),
                            });
                            writes += 1;
                        }
                        let passing = ranked.iter().filter(|s| s.passes).count();
                        let _ = snapshots;
                        if let Some(app) = weak.upgrade() {
                            app.set_status_text(
                                format!("Rescore: {passing}/{writes} candidates passed quorum").into(),
                            );
                        }
                    } else if let Some(app) = weak.upgrade() {
                        app.set_status_text(
                            "Rescore found nothing alive (all candidates dead at the socket level)".into(),
                        );
                    }
                }
                _ => {
                    if let Some(app) = weak.upgrade() {
                        app.set_status_text(
                            "Rescore needs a real subscription catalog, not demo nodes".into(),
                        );
                    }
                }
            }
        });
    });

    let import_controller = Arc::clone(&controller);
    let import_snapshots = Arc::clone(&snapshots);
    let import_model = model.clone();
    let import_state = Rc::clone(&state);
    let import_app = app.as_weak();
    app.on_import_subscription(move |raw| {
        let done = (|| -> Result<()> {
            if raw.trim().is_empty() {
                bail!("empty import payload");
            }
            let refresh = import_controller.import_subscription(raw.as_bytes(), "Imported", "clipboard")?;
            if refresh.report.successful_nodes.is_empty() {
                bail!("no supported nodes found in that payload");
            }
            import_snapshots.replace(import_controller.hydrate()?);
            import_model.refresh(&import_state.borrow());
            Ok(())
        })();
        if let Some(app) = import_app.upgrade() {
            match done {
                Ok(()) => app.set_status_text(
                    format!("Imported {} new node(s)", import_snapshots.load_full().len()).into(),
                ),
                Err(error) => {
                    app.set_status_text(format!("Import failed: {error:#}").into());
                }
            }
        }
    });

    let _dispatcher_timer = dispatcher.start(app.as_weak(), snapshots, model, state);
    app.run()?;
    Ok(())
}

fn probe_health(alive: bool, latency_ms: Option<u16>) -> u8 {
    if !alive {
        return 0;
    }
    match latency_ms {
        Some(latency) => (100 - (latency / 8).min(90)) as u8,
        // Reachable but silent (UDP without a transcript): healthy, unknown rtt.
        None => 100,
    }
}

fn watchdog_summary(status: &myproxy_controller::FailoverStatus) -> String {
    if status.degraded {
        return "Egress watchdog: DEGRADED to direct — hunting for a live node".into();
    }
    let active = status.active_node.as_deref().unwrap_or("no active node");
    let Some(action) = &status.last_action else {
        return format!("Egress watchdog: monitoring {active}");
    };
    match action {
        FailoverAction::Healthy => format!("Egress watchdog: {active} healthy"),
        FailoverAction::Inspecting { failures } => format!(
            "Egress watchdog: inspecting {active} ({failures} consecutive misses)"
        ),
        FailoverAction::Rearmed { shortlist } => format!(
            "Egress watchdog: shortlist refreshed ({shortlist} candidates)"
        ),
        FailoverAction::Switched { label } => {
            format!("Egress watchdog: auto-switched to {label}")
        }
        FailoverAction::Unconfirmed => format!(
            "Egress watchdog: candidate failed confirmation, staying on {active}"
        ),
        FailoverAction::Degraded => "Egress watchdog: degraded to direct".into(),
        FailoverAction::Healed { label } => {
            format!("Egress watchdog: healed, tunnel restored via {label}")
        }
        FailoverAction::ManualWindow => "Egress watchdog: deferring to manual control".into(),
        FailoverAction::Cooldown => "Egress watchdog: in post-switch cooldown".into(),
        FailoverAction::Idle => "Egress watchdog: idle (no active node)".into(),
        FailoverAction::Error(error) => format!("Egress watchdog: error — {error}"),
    }
}

fn initial_status(count: usize) -> String {
    if count == 0 {
        "Empty catalog — import a subscription to get started".into()
    } else {
        format!("{count} nodes from local catalog")
    }
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .unwrap_or_else(std::env::temp_dir);
    base.join("myproxy").join("myproxy.db")
}

fn demo_store(count: usize) -> DenseNodeStore {
    const COUNTRIES: &[[u8; 2]] = &[*b"DE", *b"US", *b"JP", *b"NL", *b"SG", *b"UN"];
    const PROTOCOLS: &[myproxy_storage::ProtocolKind] = &[
        myproxy_storage::ProtocolKind::Vless,
        myproxy_storage::ProtocolKind::Trojan,
        myproxy_storage::ProtocolKind::Shadowsocks,
        myproxy_storage::ProtocolKind::Hysteria2,
        myproxy_storage::ProtocolKind::Tuic,
    ];
    DenseNodeStore::from_hot_rows((0..count).map(|offset| {
        let id = (offset + 1) as u32;
        myproxy_storage::HotNodeRow {
            id,
            country_code: COUNTRIES[offset % COUNTRIES.len()],
            latency_ms: if offset % 7 == 0 {
                UNTESTED_LATENCY
            } else {
                30 + (offset % 600) as u16
            },
            health_score: (30 + (offset % 71)) as u8,
            name: format!("Demo node {id:05}").into_boxed_str(),
            protocol: PROTOCOLS[offset % PROTOCOLS.len()],
            source_sub_ids: vec![(offset % 3 + 1) as u16],
        }
    }))
}
