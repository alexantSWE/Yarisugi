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
    time::{Duration, Instant},
};

pub const DISPATCH_INTERVAL: Duration = Duration::from_millis(33);
const METRIC_PUBLISH_INTERVAL: Duration = Duration::from_millis(150);
const RESORT_INTERVAL: Duration = Duration::from_secs(1);

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

    /// Spawns a metric worker thread that aggregates probe results and
    /// publishes them to the snapshot arena at a fixed cadence, then returns a
    /// timer that applies completed projections and point updates to the UI.
    pub fn start(
        &self,
        ui: slint::Weak<MainWindow>,
        snapshots: Arc<StoreSnapshot>,
        model: Rc<VirtualNodeModel>,
        state: Rc<RefCell<ViewState>>,
    ) -> Timer {
        let changed_ids = Arc::new(ArrayQueue::<Vec<u32>>::new(64));
        let metric_worker = self.clone();
        let metric_snapshots = Arc::clone(&snapshots);
        let metric_changes = Arc::clone(&changed_ids);
        let metric_exit = ui.clone();
        std::thread::spawn(move || {
            let mut accumulation = HashMap::<u32, MetricUpdate>::new();
            let mut next_publish = Instant::now() + METRIC_PUBLISH_INTERVAL;
            loop {
                std::thread::sleep(Duration::from_millis(10));
                while let Some(result) = metric_worker.queue.pop() {
                    accumulation.insert(
                        result.node_id,
                        MetricUpdate {
                            node_id: result.node_id,
                            latency_ms: result.latency_ms,
                            health_score: result.health_score,
                        },
                    );
                }
                if !accumulation.is_empty() && Instant::now() >= next_publish {
                    let updates = accumulation
                        .drain()
                        .map(|(_, update)| update)
                        .collect::<Vec<_>>();
                    let ids = updates.iter().map(|update| update.node_id).collect::<Vec<_>>();
                    metric_snapshots.publish_metrics(&updates);
                    let _ = metric_changes.push(ids);
                    next_publish = Instant::now() + METRIC_PUBLISH_INTERVAL;
                }
                if metric_exit.upgrade().is_none() {
                    break;
                }
            }
        });

        let timer = Timer::default();
        let last_resort = Rc::new(RefCell::new(Instant::now()));
        let dispatcher = self.clone();
        timer.start(TimerMode::Repeated, DISPATCH_INTERVAL, move || {
            model.apply_completed_projection();
            let mut ids = Vec::new();
            while let Some(batch) = changed_ids.pop() {
                ids.extend(batch);
            }
            if !ids.is_empty() {
                model.notify_metrics(&ids);
            }
            if last_resort.borrow().elapsed() >= RESORT_INTERVAL {
                let metric_sort = state.borrow().sort_is_metric_dependent();
                if metric_sort {
                    model.refresh(&state.borrow());
                }
                *last_resort.borrow_mut() = Instant::now();
            }
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