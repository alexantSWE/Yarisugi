use anyhow::Result;
use myproxy_storage::{DenseNodeStore, HotNodeRow, ProtocolKind, StoreSnapshot, UNTESTED_LATENCY};
use slint::{ComponentHandle, ModelRc};
use std::{cell::RefCell, rc::Rc, sync::Arc};

mod dispatcher;
mod view_state;
mod virtual_model;

slint::include_modules!();

use dispatcher::{ProbeResult, UiDispatcher};
use view_state::ViewState;
use virtual_model::VirtualNodeModel;

fn main() -> Result<()> {
    let count = demo_count();
    let snapshots = Arc::new(StoreSnapshot::new(demo_store(count)));
    let state = Rc::new(RefCell::new(ViewState::default()));
    let model = VirtualNodeModel::new(Arc::clone(&snapshots), &state.borrow());
    let app = MainWindow::new()?;
    app.set_nodes_model(ModelRc::new(model.clone()));
    app.set_total_nodes_count(count as i32);

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
            app.set_active_node_name(
                selected_model
                    .selected_name()
                    .unwrap_or_else(|| "No node selected".into())
                    .into(),
            );
        }
    });

    let dispatcher = UiDispatcher::new(16_384);
    let burst_dispatcher = dispatcher.clone();
    let burst_store = Arc::clone(&snapshots);
    let burst_app = app.as_weak();
    app.on_probe_all_clicked(move || {
        let ids = burst_store.load_full().node_ids.clone();
        let sender = burst_dispatcher.clone();
        std::thread::spawn(move || {
            for id in ids {
                let latency = 25 + ((id.wrapping_mul(37)) % 550) as u16;
                sender.enqueue(ProbeResult {
                    node_id: id,
                    latency_ms: latency,
                    health_score: (100 - (latency / 8).min(90)) as u8,
                });
            }
        });
        if let Some(app) = burst_app.upgrade() {
            app.set_status_text("Simulated metrics queued; network backend unavailable".into());
        }
    });

    let _dispatcher_timer = dispatcher.start(app.as_weak(), snapshots, model, state);
    app.run()?;
    Ok(())
}

fn demo_count() -> usize {
    std::env::args()
        .skip_while(|arg| arg != "--demo-nodes")
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000)
        .clamp(1, 100_000)
}

fn demo_store(count: usize) -> DenseNodeStore {
    const COUNTRIES: &[[u8; 2]] = &[*b"DE", *b"US", *b"JP", *b"NL", *b"SG", *b"UN"];
    const PROTOCOLS: &[ProtocolKind] = &[
        ProtocolKind::Vless,
        ProtocolKind::Trojan,
        ProtocolKind::Shadowsocks,
        ProtocolKind::Hysteria2,
        ProtocolKind::Tuic,
    ];
    DenseNodeStore::from_hot_rows((0..count).map(|offset| {
        let id = (offset + 1) as u32;
        HotNodeRow {
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
