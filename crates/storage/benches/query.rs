use criterion::{criterion_group, criterion_main, Criterion};
use myproxy_storage::{
    query, query_with_metrics, DenseNodeStore, HotNodeRow, MetricUpdate, MetricsArena,
    ProtocolKind, SortCriteria, StoreSnapshot, UNTESTED_LATENCY,
};

fn demo_store(count: usize) -> DenseNodeStore {
    const COUNTRIES: &[[u8; 2]] = &[*b"DE", *b"US", *b"JP", *b"NL", *b"SG"];
    const PROTOCOLS: &[ProtocolKind] = &[
        ProtocolKind::Vless,
        ProtocolKind::Trojan,
        ProtocolKind::Shadowsocks,
        ProtocolKind::Hysteria2,
        ProtocolKind::Tuic,
    ];
    DenseNodeStore::from_hot_rows((0..count).map(|offset| HotNodeRow {
        id: (offset + 1) as u32,
        country_code: COUNTRIES[offset % COUNTRIES.len()],
        latency_ms: if offset % 7 == 0 {
            UNTESTED_LATENCY
        } else {
            30 + (offset % 600) as u16
        },
        health_score: (30 + (offset % 71)) as u8,
        name: format!("Demo node {offset:05}").into_boxed_str(),
        protocol: PROTOCOLS[offset % PROTOCOLS.len()],
        source_sub_ids: vec![(offset % 3 + 1) as u16],
    }))
}

fn live_metrics(store: &DenseNodeStore) -> MetricsArena {
    let mut arena = MetricsArena::from_store(store);
    for (index, latency) in arena.latencies_ms.iter_mut().enumerate() {
        *latency = ((index % 700) + 20) as u16;
    }
    arena
}

fn projection_100k(c: &mut Criterion) {
    let store = demo_store(100_000);
    let metrics = live_metrics(&store);
    let mut group = c.benchmark_group("projection_100k");
    group.bench_function("store_cold", |b| {
        b.iter(|| query(&store, "", None, None, SortCriteria::LatencyAsc));
    });
    group.bench_function("metrics_hot", |b| {
        b.iter(|| {
            query_with_metrics(&store, &metrics, "", None, None, SortCriteria::LatencyAsc);
        });
    });
    group.finish();
}

fn publish_metrics_cow_1000(c: &mut Criterion) {
    let snapshot = StoreSnapshot::new(demo_store(100_000));
    let updates = (0..1000u32)
        .map(|node_id| MetricUpdate {
            node_id,
            latency_ms: 40,
            health_score: 95,
        })
        .collect::<Vec<_>>();
    c.bench_function("publish_metrics_cow_1000", |b| {
        b.iter(|| snapshot.publish_metrics(&updates));
    });
}

criterion_group!(benches, projection_100k, publish_metrics_cow_1000);
criterion_main!(benches);