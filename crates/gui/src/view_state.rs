use myproxy_storage::{query, DenseNodeStore, SortCriteria};

#[derive(Debug, Clone)]
pub struct ViewState {
    pub search_text: String,
    pub country_filter: Option<[u8; 2]>,
    pub subscription_filter: Option<u16>,
    pub sort: SortCriteria,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            search_text: String::new(),
            country_filter: None,
            subscription_filter: None,
            sort: SortCriteria::LatencyAsc,
        }
    }
}

impl ViewState {
    pub fn projection(&self, store: &DenseNodeStore) -> Vec<u32> {
        query(
            store,
            &self.search_text,
            self.country_filter,
            self.subscription_filter,
            self.sort,
        )
    }

    pub fn set_sort_name(&mut self, name: &str) {
        self.sort = match name {
            "country" => SortCriteria::CountryAsc,
            "name" => SortCriteria::NameAsc,
            "health" => SortCriteria::HealthScoreDesc,
            _ => SortCriteria::LatencyAsc,
        };
    }
}
