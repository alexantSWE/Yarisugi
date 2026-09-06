use crate::soa_store::{DenseNodeStore, UNTESTED_LATENCY};
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
            SortCriteria::LatencyAsc => latency_order(store.latencies_ms[a], store.latencies_ms[b]),
            SortCriteria::LatencyDesc => {
                latency_order(store.latencies_ms[b], store.latencies_ms[a])
            }
            SortCriteria::CountryAsc => store.country_codes[a].cmp(&store.country_codes[b]),
            SortCriteria::NameAsc => store.names[a].cmp(&store.names[b]),
            SortCriteria::HealthScoreDesc => store.health_scores[b].cmp(&store.health_scores[a]),
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
