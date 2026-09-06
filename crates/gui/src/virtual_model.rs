use crate::{view_state::ViewState, NodeRowData};
use myproxy_storage::{DenseNodeStore, StoreSnapshot, UNTESTED_LATENCY};
use slint::{Color, Model, ModelNotify, ModelTracker, SharedString};
use std::{cell::RefCell, rc::Rc, sync::Arc};

pub struct VirtualNodeModel {
    snapshots: Arc<StoreSnapshot>,
    render_store: RefCell<Arc<DenseNodeStore>>,
    active_indices: RefCell<Vec<u32>>,
    active_node_id: RefCell<Option<u32>>,
    notify: ModelNotify,
}

impl VirtualNodeModel {
    pub fn new(snapshots: Arc<StoreSnapshot>, state: &ViewState) -> Rc<Self> {
        let store = snapshots.load_full();
        let indices = state.projection(&store);
        Rc::new(Self {
            snapshots,
            render_store: RefCell::new(store),
            active_indices: RefCell::new(indices),
            active_node_id: RefCell::new(None),
            notify: ModelNotify::default(),
        })
    }

    pub fn refresh(&self, state: &ViewState) {
        let store = self.snapshots.load_full();
        let indices = state.projection(&store);
        *self.render_store.borrow_mut() = store;
        *self.active_indices.borrow_mut() = indices;
        self.notify.reset();
    }

    pub fn select_node(&self, node_id: u32) {
        let prior = self.active_node_id.replace(Some(node_id));
        let indices = self.active_indices.borrow();
        for changed in [prior, Some(node_id)].into_iter().flatten() {
            if let Some(row) = indices
                .iter()
                .position(|&index| self.render_store.borrow().node_ids[index as usize] == changed)
            {
                self.notify.row_changed(row);
            }
        }
    }

    pub fn selected_name(&self) -> Option<String> {
        let selected = (*self.active_node_id.borrow())?;
        let store = self.render_store.borrow();
        store
            .node_ids
            .iter()
            .position(|&id| id == selected)
            .map(|index| store.names[index].to_string())
    }
}

impl Model for VirtualNodeModel {
    type Data = NodeRowData;

    fn row_count(&self) -> usize {
        self.active_indices.borrow().len()
    }

    fn row_data(&self, row: usize) -> Option<Self::Data> {
        let dense_index = *self.active_indices.borrow().get(row)? as usize;
        let store = self.render_store.borrow();
        if dense_index >= store.len() {
            return None;
        }

        let latency = store.latencies_ms[dense_index];
        let (latency_text, latency_color) = latency_display(latency);
        let country = std::str::from_utf8(&store.country_codes[dense_index]).unwrap_or("UN");
        Some(NodeRowData {
            id: store.node_ids[dense_index] as i32,
            name: SharedString::from(store.names[dense_index].as_ref()),
            country: SharedString::from(country),
            protocol: SharedString::from(store.protocol_kinds[dense_index].label()),
            latency_text,
            latency_color,
            is_active: *self.active_node_id.borrow() == Some(store.node_ids[dense_index]),
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
