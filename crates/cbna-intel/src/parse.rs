//! Turn a feed's downloaded bytes into indicators.
//!
//! Each feed's bytes come from a third party over the network, so this is a
//! trust boundary: every function here must return normally on arbitrary input
//! — no panic, no unbounded work beyond the line count — and it is fuzzed
//! accordingly (see [`crate::fuzz`]). The extracted tokens are handed to
//! [`IocSet::insert_tagged`], which does its own classification and bounding.

use crate::feed::{Feed, Format};
use cbna_core::ioc::IocSet;

/// Parse `bytes` in `feed`'s format into `set`, tagging every indicator with
/// `feed.id` as its source. Returns how many indicators were added.
///
/// Unreadable rows are skipped, not fatal: a feed with one malformed line still
/// contributes the rest. `set`'s source label is set here, so a caller folding
/// in several feeds gets each one's provenance right.
pub fn parse_into(set: &mut IocSet, feed: &Feed, bytes: &[u8]) -> usize {
    set.set_source(feed.id);
    let before = set.len();

    for raw in bytes.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (token, tag) = match feed.format {
            Format::Lines => (line.to_string(), None),
            Format::Csv { value, tag } => {
                let fields = split_csv(line);
                match field(&fields, value) {
                    Some(v) => (v, tag.and_then(|t| field(&fields, t))),
                    None => continue,
                }
            }
            Format::UrlCsv { url, tag } => {
                let fields = split_csv(line);
                match field(&fields, url).and_then(|u| url_host(&u)) {
                    Some(host) => (host, tag.and_then(|t| field(&fields, t))),
                    None => continue,
                }
            }
        };

        // A per-row tag wins; otherwise the feed's default (if any) applies.
        let tag = tag
            .filter(|t| !t.is_empty() && t != "None")
            .or_else(|| feed.default_tag.map(str::to_string));

        // A full set stops the whole parse: nothing later will fit either.
        if set.insert_tagged(&token, tag).is_err() && set.len() >= IocSet::MAX_INDICATORS {
            break;
        }
    }

    set.len() - before
}

/// The `i`-th field, trimmed, or `None` if the row is too short or the field is
/// empty.
fn field(fields: &[String], i: usize) -> Option<String> {
    fields
        .get(i)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Split one CSV line into fields, honouring double-quoted fields (abuse.ch
/// quotes every field) and `""` as an escaped quote. Deliberately minimal — it
/// handles the fully-quoted rows these feeds emit and degrades to a plain comma
/// split on anything else, never erroring.
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// The host of a URL, lowercased. Strips an optional scheme, any `user@`
/// credential, and a trailing `:port`, path, query or fragment. Returns `None`
/// when nothing host-shaped remains.
fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    // Authority ends at the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop credentials, then the port.
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = hostport.split(':').next().unwrap_or("").trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::by_id;

    #[test]
    fn parses_feodo_line_list() {
        let feed = by_id("feodo").unwrap();
        let bytes = b"# Feodo Tracker\n203.0.113.7\n198.51.100.9\n\n";
        let mut set = IocSet::default();
        let n = parse_into(&mut set, feed, bytes);
        assert_eq!(n, 2);
        let hit = set.match_ip("203.0.113.7".parse().unwrap()).unwrap();
        assert_eq!(hit.source, "feodo");
        assert_eq!(hit.tag.as_deref(), Some("botnet-c2"));
    }

    #[test]
    fn parses_sslbl_ja3_csv_with_reason_tag() {
        let feed = by_id("sslbl").unwrap();
        // Real SSLBL layout: ja3_md5,Firstseen,Lastseen,Listingreason (unquoted).
        let bytes = b"# ja3_md5,Firstseen,Lastseen,Listingreason\n\
                      e7d705a3286e19ea42f587b344ee6865,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex\n";
        let mut set = IocSet::default();
        let n = parse_into(&mut set, feed, bytes);
        assert_eq!(n, 1);
        let hit = set.match_ja3("e7d705a3286e19ea42f587b344ee6865").unwrap();
        assert_eq!(hit.source, "sslbl");
        assert_eq!(hit.tag.as_deref(), Some("Dridex"));
    }

    #[test]
    fn parses_urlhaus_and_extracts_host() {
        let feed = by_id("urlhaus").unwrap();
        let bytes = b"# id,dateadded,url,url_status,last_online,threat,tags,link,reporter\n\
                      \"1\",\"2026-01-01\",\"http://bad.example:8080/payload.exe\",\"online\",\"\",\"malware_download\",\"\",\"\",\"x\"\n";
        let mut set = IocSet::default();
        let n = parse_into(&mut set, feed, bytes);
        assert_eq!(n, 1);
        let hit = set.match_domain("bad.example").unwrap();
        assert_eq!(hit.source, "urlhaus");
        assert_eq!(hit.tag.as_deref(), Some("malware_download"));
    }

    #[test]
    fn url_host_handles_scheme_creds_port_and_path() {
        assert_eq!(url_host("http://a.example/x").as_deref(), Some("a.example"));
        assert_eq!(
            url_host("https://user:pw@b.example:443/p?q#f").as_deref(),
            Some("b.example")
        );
        // No scheme, bare host.
        assert_eq!(url_host("c.example/path").as_deref(), Some("c.example"));
        assert_eq!(url_host("").as_deref(), None);
        assert_eq!(url_host("http://").as_deref(), None);
    }

    #[test]
    fn split_csv_handles_quotes_and_escapes() {
        assert_eq!(split_csv(r#""a","b","c""#), vec!["a", "b", "c"]);
        // An escaped quote inside a field, and a comma inside quotes.
        assert_eq!(split_csv(r#""a","x,y","z""z""#), vec!["a", "x,y", r#"z"z"#]);
        // Unquoted degrades to a plain split.
        assert_eq!(split_csv("a,b,c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn empty_feed_adds_nothing() {
        let feed = by_id("feodo").unwrap();
        let mut set = IocSet::default();
        assert_eq!(parse_into(&mut set, feed, b""), 0);
        assert!(set.is_empty());
    }
}
