pub fn extract_country_code(label: &str) -> [u8; 2] {
    let indicators: Vec<u32> = label
        .chars()
        .filter_map(|character| {
            let value = character as u32;
            if (0x1F1E6..=0x1F1FF).contains(&value) {
                Some(value - 0x1F1E6)
            } else {
                None
            }
        })
        .collect();
    if indicators.len() >= 2 {
        [b'A' + indicators[0] as u8, b'A' + indicators[1] as u8]
    } else {
        *b"UN"
    }
}
