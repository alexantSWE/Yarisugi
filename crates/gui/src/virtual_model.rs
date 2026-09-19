use crate::{view_state::ViewState, NodeRowData};
use arc_swap::ArcSwap;
use myproxy_storage::{DenseNodeStore, StoreSnapshot, UNTESTED_LATENCY};
use slint::{Color, Model, ModelNotify, ModelTracker, SharedString};
use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{mpsc, Arc},
};

/// Above this many on-screen metric changes a full reset is cheaper than a
/// flood of per-row notifications.
pub const POINT_UPDATE_LIMIT: usize = 2048;

struct Projection {
    store: Arc<DenseNodeStore>,
    indices: Vec<u32>,
}

/// A virtualized list model that renders a background-projected view of the
/// store. Projection requests are queued to a worker thread; completed
/// projections are swapped in atomically on the UI thread and destroyed rows
/// announce themselves with a single reset. The reverse map turns node ids
/// into rows without scanning the active list.
pub struct VirtualNodeModel {
    snapshots: Arc<StoreSnapshot>,
    projection: ArcSwap<Projection>,
    reverse: RefCell<HashMap<u32, usize>>,
    active_node_id: RefCell<Option<u32>>,
    active_name: RefCell<String>,
    desired_view: RefCell<ViewState>,
    request_tx: mpsc::Sender<ViewState>,
    result_rx: RefCell<mpsc::Receiver<Arc<Projection>>>,
    notify: ModelNotify,
}

impl VirtualNodeModel {
    pub fn new(snapshots: Arc<StoreSnapshot>, state: &ViewState) -> Rc<Self> {
        let store = snapshots.load_full();
        let metrics = snapshots.load_metrics();
        let indices = state.projection(&store, &metrics);
        let mut reverse = HashMap::with_capacity(indices.len());
        for (row, &dense_index) in indices.iter().enumerate() {
            reverse.insert(store.node_ids[dense_index as usize], row);
        }

        let (request_tx, request_rx) = mpsc::channel::<ViewState>();
        let (result_tx, result_rx) = mpsc::sync_channel::<Arc<Projection>>(4);
        let worker_snapshots = Arc::clone(&snapshots);
        std::thread::spawn(move || {
            while let Ok(mut view) = request_rx.recv() {
                while let Ok(newer) = request_rx.try_recv() {
                    view = newer;
                }
                let store = worker_snapshots.load_full();
                let metrics = worker_snapshots.load_metrics();
                let indices = view.projection(&store, &metrics);
                if result_tx
                    .send(Arc::new(Projection { store, indices }))
                    .is_err()
                {
                    break;
                }
            }
        });

        Rc::new(Self {
            snapshots,
            projection: ArcSwap::from(Arc::new(Projection { store, indices })),
            reverse: RefCell::new(reverse),
            active_node_id: RefCell::new(None),
            active_name: RefCell::new(String::from("No node selected")),
            desired_view: RefCell::new(state.clone()),
            request_tx,
            result_rx: RefCell::new(result_rx),
            notify: ModelNotify::default(),
        })
    }

    /// Commits the desired view and schedules a background recomputation.
    pub fn refresh(&self, state: &ViewState) {
        *self.desired_view.borrow_mut() = state.clone();
        self.request_latest();
    }

    fn request_latest(&self) {
        let view = self.desired_view.borrow().clone();
        let _ = self.request_tx.send(view);
    }

    /// Installs the newest completed projection if it still matches the store
    /// currently being served. Returns true when a full reset was emitted.
    pub fn apply_completed_projection(&self) -> bool {
        let projection = {
            let receiver = self.result_rx.borrow_mut();
            receiver.try_iter().last()
        };
        let Some(projection) = projection else {
            return false;
        };
        let current = self.snapshots.load_full();
        if !Arc::ptr_eq(&projection.store, &current) {
            self.request_latest();
            return false;
        }
        self.projection.store(Arc::clone(&projection));
        self.rebuild_reverse(&projection.indices);
        self.notify.reset();
        true
    }

    fn rebuild_reverse(&self, indices: &[u32]) {
        let projection = self.projection.load();
        let store = &projection.store;
        let mut reverse = HashMap::with_capacity(indices.len());
        for (row, &dense_index) in indices.iter().enumerate() {
            let dense_index = dense_index as usize;
            if dense_index >= store.len() {
                continue;
            }
            reverse.insert(store.node_ids[dense_index], row);
        }
        *self.reverse.borrow_mut() = reverse;
    }

    /// Announces metric-driven point updates for the given node ids, falling
    /// back to a full reset when too many rows changed at once.
    pub fn notify_metrics(&self, node_ids: &[u32]) -> bool {
        let reverse = self.reverse.borrow();
        let mut rows = Vec::new();
        for &id in node_ids {
            if let Some(&row) = reverse.get(&id) {
                rows.push(row);
            }
        }
        if rows.len() > POINT_UPDATE_LIMIT {
            self.notify.reset();
            return true;
        }
        for row in rows {
            self.notify.row_changed(row);
        }
        false
    }

    pub fn select_node(&self, node_id: u32) {
        let prior = self.active_node_id.replace(Some(node_id));
        self.refresh_active_name(node_id);
        let reverse = self.reverse.borrow();
        for changed in [prior, Some(node_id)].into_iter().flatten() {
            if let Some(&row) = reverse.get(&changed) {
                self.notify.row_changed(row);
            }
        }
    }

    fn refresh_active_name(&self, node_id: u32) {
        let projection = self.projection.load();
        let store = &projection.store;
        let name = projection
            .indices
            .iter()
            .map(|&dense_index| dense_index as usize)
            .find(|&index| index < store.len() && store.node_ids[index] == node_id)
            .map(|index| store.names[index].as_ref())
            .unwrap_or("No node selected");
        *self.active_name.borrow_mut() = name.to_owned();
    }

    pub fn selected_name(&self) -> String {
        self.active_name.borrow().clone()
    }
}

impl Model for VirtualNodeModel {
    type Data = NodeRowData;

    fn row_count(&self) -> usize {
        self.projection.load().indices.len()
    }

    fn row_data(&self, row: usize) -> Option<Self::Data> {
        let projection = self.projection.load();
        let dense_index = *projection.indices.get(row)? as usize;
        let store = &projection.store;
        if dense_index >= store.len() {
            return None;
        }
        let metrics = self.snapshots.load_metrics();
        let latency = metrics
            .latencies_ms
            .get(dense_index)
            .copied()
            .unwrap_or(UNTESTED_LATENCY);
        let (latency_text, latency_color) = latency_display(latency);
        let country = std::str::from_utf8(&store.country_codes[dense_index]).unwrap_or("UN");
        let node_id = store.node_ids[dense_index];
        Some(NodeRowData {
            id: node_id as i32,
            name: SharedString::from(store.names[dense_index].as_ref()),
            country: SharedString::from(country),
            protocol: SharedString::from(store.protocol_kinds[dense_index].label()),
            latency_text,
            latency_color,
            is_active: *self.active_node_id.borrow() == Some(node_id),
        })
    }

    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }
}

fn latency_display(latency: u16) -> (SharedString, Color) {
    if latency == UNTESTED_LATENCY {
        (SharedString::from("—"), Color::from_rgb_u8(113, 113, 122))
    } else if latency < 150 {
        (
            SharedString::from(format!("{latency} ms")),
            Color::from_rgb_u8(70, 167, 88),
        )
    } else if latency < 350 {
        (
            SharedString::from(format!("{latency} ms")),
            Color::from_rgb_u8(245, 166, 35),
        )
    } else {
        (
            SharedString::from(format!("{latency} ms")),
            Color::from_rgb_u8(229, 72, 77),
        )
    }
}