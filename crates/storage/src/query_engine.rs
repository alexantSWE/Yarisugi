use crate::soa_store::{DenseNodeStore, MetricsArena, UNTESTED_LATENCY};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCriteria {
    LatencyAsc,
    LatencyDesc,
    CountryAsc,
    NameAsc,
    HealthScoreDesc,
}

pub fn query(
    store: &DenseNodeStore,
    search_term: &str,
    country_filter: Option<[u8; 2]>,
    sub_filter: Option<u16>,
    sort: SortCriteria,
) -> Vec<u32> {
    run_query(
        store,
        search_term,
        country_filter,
        sub_filter,
        sort,
        |index| store.latencies_ms[index],
        |index| store.health_scores[index],
    )
}

/// Same projection as `query`, but latency and health readings come from the
/// hot metric arena so live probes are reflected in the ordering.
pub fn query_with_metrics(
    store: &DenseNodeStore,
    metrics: &MetricsArena,
    search_term: &str,
    country_filter: Option<[u8; 2]>,
    sub_filter: Option<u16>,
    sort: SortCriteria,
) -> Vec<u32> {
    run_query(
        store,
        search_term,
        country_filter,
        sub_filter,
        sort,
        |index| metrics.latencies_ms.get(index).copied().unwrap_or(UNTESTED_LATENCY),
        |index| metrics.health_scores.get(index).copied().unwrap_or(0),
    )
}

fn run_query(
    store: &DenseNodeStore,
    search_term: &str,
    country_filter: Option<[u8; 2]>,
    sub_filter: Option<u16>,
    sort: SortCriteria,
    metric_latency: impl Fn(usize) -> u16,
    metric_health: impl Fn(usize) -> u8,
) -> Vec<u32> {
    let search = search_term.to_lowercase();
    let mut indices = (0..store.len())
        .filter(|&index| {
            sub_filter.is_none_or(|sub_id| store.has_source(index, sub_id))
                && country_filter.is_none_or(|country| store.country_codes[index] == country)
                && (search.is_empty() || store.name_lower[index].contains(&search))
        })
        .map(|index| index as u32)
        .collect::<Vec<_>>();
    indices.sort_unstable_by(|&left, &right| {
        let a = left as usize;
        let b = right as usize;
        let ordering = match sort {
            SortCriteria::LatencyAsc => latency_order(metric_latency(a), metric_latency(b)),
            SortCriteria::LatencyDesc => latency_order(metric_latency(b), metric_latency(a)),
            SortCriteria::CountryAsc => store.country_codes[a].cmp(&store.country_codes[b]),
            SortCriteria::NameAsc => store.names[a].cmp(&store.names[b]),
            SortCriteria::HealthScoreDesc => metric_health(b).cmp(&metric_health(a)),
        };
        ordering.then_with(|| store.node_ids[a].cmp(&store.node_ids[b]))
    });
    indices
}

fn latency_order(left: u16, right: u16) -> Ordering {
    match (left == UNTESTED_LATENCY, right == UNTESTED_LATENCY) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => left.cmp(&right),
    }
}
