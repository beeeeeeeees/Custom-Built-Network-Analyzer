//! The registry of built-in OSINT feeds and how to read each one.
//!
//! A [`Feed`] is a static description — id, human name, URL, wire format and
//! whether it needs an auth key. Nothing here fetches or parses; `fetch` pulls
//! the bytes and `parse` turns a feed's bytes into indicators. Adding a feed is
//! a row in [`BUILTIN`] plus, if its layout is new, a [`Format`] variant.

/// How to extract indicators from a feed's downloaded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One indicator per line; `#` starts a comment. (Feodo recommended list.)
    Lines,
    /// Quoted CSV: take column `value` as the indicator, and column `tag` — when
    /// present — as its label. (SSLBL JA3 list.)
    Csv { value: usize, tag: Option<usize> },
    /// Quoted CSV whose `url` column holds a URL; the host is extracted as a
    /// domain indicator, with column `tag` as its label. (URLhaus list.)
    UrlCsv { url: usize, tag: Option<usize> },
}

/// A downloadable indicator feed.
#[derive(Debug, Clone, Copy)]
pub struct Feed {
    /// Stable short id used on the CLI, as the source label, and as the cache
    /// file name.
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub format: Format,
    /// Whether the endpoint requires an `Auth-Key` header. abuse.ch is moving
    /// feeds behind a free key; the static blocklists below are still open.
    pub needs_auth: bool,
    /// Applied to every indicator when the feed carries no per-row label.
    pub default_tag: Option<&'static str>,
}

/// The feeds shipped in this cut. All three are permissively licensed abuse.ch
/// lists that map onto the three indicator kinds cbna matches. ThreatFox (a
/// zipped, auth-keyed export) is a deliberate fast-follow, not here yet.
pub const BUILTIN: &[Feed] = &[
    Feed {
        id: "feodo",
        name: "Feodo Tracker (botnet C2 IPs)",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        format: Format::Lines,
        needs_auth: false,
        default_tag: Some("botnet-c2"),
    },
    Feed {
        id: "sslbl",
        name: "SSLBL (malicious JA3 fingerprints)",
        url: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
        // # ja3_md5,Firstseen,Lastseen,Listingreason
        // Note: abuse.ch froze the JA3 blacklist in 2021; the fingerprints are
        // historical but still valid known-bad indicators.
        format: Format::Csv {
            value: 0,
            tag: Some(3),
        },
        needs_auth: false,
        default_tag: None,
    },
    Feed {
        id: "urlhaus",
        name: "URLhaus (malware distribution URLs)",
        url: "https://urlhaus.abuse.ch/downloads/csv_online/",
        // id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        format: Format::UrlCsv {
            url: 2,
            tag: Some(5),
        },
        needs_auth: false,
        default_tag: None,
    },
];

/// The built-in feed with this id, if any.
pub fn by_id(id: &str) -> Option<&'static Feed> {
    BUILTIN.iter().find(|f| f.id == id)
}
