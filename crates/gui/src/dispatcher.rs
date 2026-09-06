use crate::{view_state::ViewState, virtual_model::VirtualNodeModel, MainWindow};
use crossbeam_queue::ArrayQueue;
use myproxy_storage::{MetricUpdate, StoreSnapshot};
use slint::{Timer, TimerMode};
use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

pub const DISPATCH_INTERVAL: Duration = Duration::from_millis(33);

#[derive(Clone, Copy, Debug)]
pub struct ProbeResult {
    pub node_id: u32,
    pub latency_ms: u16,
    pub health_score: u8,
}

#[derive(Clone)]
pub struct UiDispatcher {
    queue: Arc<ArrayQueue<ProbeResult>>,
    dropped: Arc<AtomicU64>,
}

impl UiDispatcher {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Arc::new(ArrayQueue::new(capacity)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn enqueue(&self, result: ProbeResult) {
        if self.queue.push(result).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped_results(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn start(
        &self,
        ui: slint::Weak<MainWindow>,
        snapshots: Arc<StoreSnapshot>,
        model: Rc<VirtualNodeModel>,
        state: Rc<RefCell<ViewState>>,
    ) -> Timer {
        let dispatcher = self.clone();
        let timer = Timer::default();
        timer.start(TimerMode::Repeated, DISPATCH_INTERVAL, move || {
            let mut latest = HashMap::<u32, MetricUpdate>::new();
            while let Some(result) = dispatcher.queue.pop() {
                latest.insert(
                    result.node_id,
                    MetricUpdate {
                        node_id: result.node_id,
                        latency_ms: result.latency_ms,
                        health_score: result.health_score,
                    },
                );
            }
            if latest.is_empty() {
                return;
            }
            snapshots.update_metrics_batch(&latest.into_values().collect::<Vec<_>>());
            model.refresh(&state.borrow());
            if let Some(ui) = ui.upgrade() {
                ui.set_total_nodes_count(snapshots.load_full().len() as i32);
                let dropped = dispatcher.dropped_results();
                if dropped != 0 {
                    ui.set_status_text(format!("{dropped} demo updates dropped").into());
                }
            }
        });
        timer
    }
}
