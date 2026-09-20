/// Extracts an ISO 3166-1 alpha-2 country code from a node label.
///
/// Priority: regional-indicator emoji pair > bracketed uppercase tag (`[DE]`,
/// `(US)`) > keyword dictionary (city/country names). Falls back to `UN` when
/// nothing is recognized.
pub fn extract_country_code(label: &str) -> [u8; 2] {
    if let Some(code) = emoji_code(label) {
        return code;
    }
    if let Some(code) = bracket_code(label) {
        return code;
    }
    let lowered = label.to_ascii_lowercase();
    for (keyword, code) in COUNTRY_KEYWORDS {
        if lowered.contains(keyword) {
            return *code;
        }
    }
    *b"UN"
}

fn emoji_code(label: &str) -> Option<[u8; 2]> {
    let indicators: Vec<u8> = label
        .chars()
        .filter_map(|character| {
            let value = character as u32;
            if (0x1F1E6..=0x1F1FF).contains(&value) {
                Some(b'A' + (value - 0x1F1E6) as u8)
            } else {
                None
            }
        })
        .collect();
    if indicators.len() >= 2 {
        Some([indicators[0], indicators[1]])
    } else {
        None
    }
}

fn bracket_code(label: &str) -> Option<[u8; 2]> {
    let bytes = label.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        let close_byte = match *byte {
            b'[' => b']',
            b'(' => b')',
            _ => continue,
        };
        let Some(rest) = bytes.get(index + 1..) else {
            continue;
        };
        if rest.len() > 6 {
            continue;
        }
        let Some(end) = rest.iter().position(|byte| *byte == close_byte) else {
            continue;
        };
        let candidate = &rest[..end];
        if candidate.len() == 2 && candidate.iter().all(u8::is_ascii_uppercase) {
            return Some([candidate[0], candidate[1]]);
        }
    }
    None
}

const COUNTRY_KEYWORDS: &[(&str, [u8; 2])] = &[
    ("tokyo", *b"JP"),
    ("osaka", *b"JP"),
    ("japan", *b"JP"),
    ("hong kong", *b"HK"),
    ("taiwan", *b"TW"),
    ("taipei", *b"TW"),
    ("singapore", *b"SG"),
    ("korea", *b"KR"),
    ("seoul", *b"KR"),
    ("frankfurt", *b"DE"),
    ("germany", *b"DE"),
    ("deutschland", *b"DE"),
    ("amsterdam", *b"NL"),
    ("netherlands", *b"NL"),
    ("paris", *b"FR"),
    ("france", *b"FR"),
    ("london", *b"GB"),
    ("united kingdom", *b"GB"),
    ("new york", *b"US"),
    ("los angeles", *b"US"),
    ("chicago", *b"US"),
    ("seattle", *b"US"),
    ("dallas", *b"US"),
    ("san jose", *b"US"),
    ("united states", *b"US"),
    ("usa", *b"US"),
    ("sydney", *b"AU"),
    ("australia", *b"AU"),
    ("bangkok", *b"TH"),
    ("thailand", *b"TH"),
    ("vietnam", *b"VN"),
    ("hanoi", *b"VN"),
    ("ho chi minh", *b"VN"),
    ("moscow", *b"RU"),
    ("russia", *b"RU"),
    ("mumbai", *b"IN"),
    ("india", *b"IN"),
    ("dubai", *b"AE"),
    ("istanbul", *b"TR"),
    ("turkey", *b"TR"),
    ("madrid", *b"ES"),
    ("spain", *b"ES"),
    ("helsinki", *b"FI"),
    ("finland", *b"FI"),
    ("stockholm", *b"SE"),
    ("sweden", *b"SE"),
    ("oslo", *b"NO"),
    ("norway", *b"NO"),
    ("copenhagen", *b"DK"),
    ("denmark", *b"DK"),
    ("warsaw", *b"PL"),
    ("poland", *b"PL"),
    ("prague", *b"CZ"),
    ("toronto", *b"CA"),
    ("vancouver", *b"CA"),
    ("montreal", *b"CA"),
    ("canada", *b"CA"),
    ("sao paulo", *b"BR"),
    ("brazil", *b"BR"),
    ("chile", *b"CL"),
    ("argentina", *b"AR"),
    ("kuala lumpur", *b"MY"),
    ("malaysia", *b"MY"),
    ("jakarta", *b"ID"),
    ("indonesia", *b"ID"),
    ("manila", *b"PH"),
    ("philippines", *b"PH"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_pair_wins_over_everything() {
        assert_eq!(extract_country_code("🇭🇰 Tokyo [DE]"), *b"HK");
        assert_eq!(extract_country_code("abc"), *b"UN");
    }

    #[test]
    fn explicit_bracket_tag_beats_dictionary() {
        assert_eq!(extract_country_code("Osaka [FR]"), *b"FR");
        assert_eq!(extract_country_code("tokyo (US)"), *b"US");
    }

    #[test]
    fn dictionary_lookup_for_common_cities() {
        assert_eq!(extract_country_code("Tokyo - 日本"), *b"JP");
        assert_eq!(extract_country_code("Hotspot Singapore 01"), *b"SG");
        assert_eq!(extract_country_code("Frankfurt 1"), *b"DE");
        assert_eq!(extract_country_code("Hong Kong V2"), *b"HK");
        assert_eq!(extract_country_code("Los Angeles 03"), *b"US");
        assert_eq!(extract_country_code("anything"), *b"UN");
    }

    #[test]
    fn non_ascii_bracket_tags_are_ignored() {
        assert_eq!(extract_country_code("Node (東京)"), *b"UN");
    }

    #[test]
    fn short_lowercase_tags_are_ignored() {
        assert_eq!(extract_country_code("wireguard de"), *b"UN");
    }
}