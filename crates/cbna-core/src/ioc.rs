//! Threat-intelligence indicator matching.
//!
//! [`IocSet`] is the matcher: a normalised collection of indicators — IPs,
//! CIDR ranges, domains and JA3 hashes — that observed traffic is checked
//! against. It is pure data and does **no I/O**; the indicators are read and
//! parsed by a front-end (a local `--ioc` list in `cbna-capture`, or a fetched
//! OSINT feed in `cbna-intel`) which hands the finished set in here. That keeps
//! this crate on the no-I/O side of the line the whole analysis engine depends
//! on.
//!
//! Every indicator carries its **provenance** — the source that supplied it and
//! an optional tag (a malware family, a feed label) — so a match names the feed
//! that flagged it rather than just asserting "bad". Matching runs after a
//! capture is folded in, against the analyzer's existing indexes, so nothing
//! here touches the per-packet hot path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// What kind of indicator a token classified as. Returned by [`IocSet::insert`]
/// so a loader can report a per-category tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Ip,
    Cidr,
    Domain,
    Ja3,
}

/// Where an indicator came from and what it is called there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    /// Feed or list id, e.g. `feodo`, `sslbl`, `urlhaus`, `manual`.
    pub source: String,
    /// Optional label the source attached — a malware family, a category.
    pub tag: Option<String>,
}

/// A summary of one source that contributed indicators, for stamping into a
/// report so a run is reproducible against a known feed snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub source: String,
    /// When the snapshot was fetched (RFC 3339). `None` for a local list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    pub indicators: usize,
}

/// The result of a match: the indicator that fired plus its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocMatch {
    /// The indicator as it was listed (a CIDR keeps its slash form, a parent
    /// domain the parent it matched on).
    pub indicator: String,
    pub source: String,
    pub tag: Option<String>,
}

/// A CIDR range, kept alongside the text it was written as so a hit can name the
/// range the analyst put in their list rather than a re-serialised form.
#[derive(Debug, Clone)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
    text: String,
}

impl Cidr {
    /// True when `ip` falls inside the range. Same-family only — a v4 address is
    /// never contained by a v6 prefix or vice versa.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                prefix_eq(&base.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                prefix_eq(&base.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// True when `a` and `b` share their first `prefix` bits. A `prefix` of 0
/// matches everything; a prefix past the address width compares every bit.
fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    // Compare only the high `rem` bits of the next byte.
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// A normalised set of threat-intel indicators with per-indicator provenance.
#[derive(Debug, Clone)]
pub struct IocSet {
    ips: HashMap<IpAddr, Provenance>,
    cidrs: Vec<(Cidr, Provenance)>,
    /// Keys lowercase, trailing dot stripped.
    domains: HashMap<String, Provenance>,
    /// Keys lowercase 32-char hex.
    ja3: HashMap<String, Provenance>,
    /// Source applied to indicators inserted via [`IocSet::insert`]. A loader
    /// sets this once per feed; the default covers a hand-supplied list.
    current_source: String,
    /// One entry per contributing source, for reproducibility reporting.
    manifest: Vec<SourceInfo>,
}

impl Default for IocSet {
    fn default() -> Self {
        Self {
            ips: HashMap::new(),
            cidrs: Vec::new(),
            domains: HashMap::new(),
            ja3: HashMap::new(),
            // A hand-supplied `--ioc` list has no feed name; label it plainly so
            // its hits still read as sourced rather than blank.
            current_source: "manual".to_string(),
            manifest: Vec::new(),
        }
    }
}

impl IocSet {
    /// Cap on how many indicators one set holds. Feeds and lists are
    /// operator-chosen, so this is generous; it exists only so a malformed or
    /// hostile feed cannot grow the process without bound. Once reached, further
    /// indicators are rejected with [`IocError::Full`].
    pub const MAX_INDICATORS: usize = 4_000_000;

    /// Total indicators held across every category.
    pub fn len(&self) -> usize {
        self.ips.len() + self.cidrs.len() + self.domains.len() + self.ja3.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the source label applied to subsequently [`IocSet::insert`]ed
    /// indicators. Loaders call this once before folding in a feed's lines.
    pub fn set_source(&mut self, source: impl Into<String>) {
        self.current_source = source.into();
    }

    /// Record that a source contributed to this set, for the report's snapshot
    /// stamp. Called by a loader after inserting a feed's indicators.
    pub fn add_source_info(&mut self, info: SourceInfo) {
        self.manifest.push(info);
    }

    /// The per-source snapshot summary.
    pub fn sources(&self) -> &[SourceInfo] {
        &self.manifest
    }

    /// Absorb another set's indicators and source manifest, so a run can match
    /// against a local list and fetched feeds at once. Each indicator keeps the
    /// provenance it was inserted with; on a key collision the incoming one wins,
    /// matching [`IocSet::insert`]'s last-writer semantics. The per-category cap
    /// is a soft insert-time guard, so a merge can briefly exceed it.
    pub fn extend(&mut self, other: IocSet) {
        self.ips.extend(other.ips);
        self.cidrs.extend(other.cidrs);
        self.domains.extend(other.domains);
        self.ja3.extend(other.ja3);
        self.manifest.extend(other.manifest);
    }

    /// Classify a single token and add it under the current source with no tag.
    /// Whitespace must already be trimmed.
    ///
    /// Classification is unambiguous for the four supported kinds and is tried
    /// in order: a `/` makes it a CIDR, a bare address is an IP, 32 hex chars
    /// with no dot is a JA3 hash, and anything else containing a dot is a
    /// domain. A token that fits none is rejected rather than guessed at.
    pub fn insert(&mut self, token: &str) -> Result<IocKind, IocError> {
        self.insert_tagged(token, None)
    }

    /// Like [`IocSet::insert`], but attaches `tag` (a malware family or label the
    /// source carried) to the indicator.
    pub fn insert_tagged(&mut self, token: &str, tag: Option<String>) -> Result<IocKind, IocError> {
        if self.len() >= Self::MAX_INDICATORS {
            return Err(IocError::Full);
        }
        let meta = Provenance {
            source: self.current_source.clone(),
            tag,
        };
        if token.contains('/') {
            let cidr = parse_cidr(token).ok_or(IocError::Unrecognised)?;
            self.cidrs.push((cidr, meta));
            return Ok(IocKind::Cidr);
        }
        if let Ok(ip) = token.parse::<IpAddr>() {
            self.ips.insert(ip, meta);
            return Ok(IocKind::Ip);
        }
        if is_ja3(token) {
            self.ja3.insert(token.to_ascii_lowercase(), meta);
            return Ok(IocKind::Ja3);
        }
        if let Some(domain) = normalise_domain(token) {
            self.domains.insert(domain, meta);
            return Ok(IocKind::Domain);
        }
        Err(IocError::Unrecognised)
    }

    /// The indicator that matches `ip`, if any. An exact address wins over a
    /// range so the more specific hit is the one reported.
    pub fn match_ip(&self, ip: IpAddr) -> Option<IocMatch> {
        if let Some(meta) = self.ips.get(&ip) {
            return Some(meta.matched(ip.to_string()));
        }
        self.cidrs
            .iter()
            .find(|(c, _)| c.contains(ip))
            .map(|(c, meta)| meta.matched(c.text.clone()))
    }

    /// The indicator that matches `name`, if any. A domain indicator matches the
    /// name itself and any subdomain of it, so `evil.com` covers `c2.evil.com`.
    /// The most specific listed parent is returned. `name` need not be
    /// pre-normalised.
    pub fn match_domain(&self, name: &str) -> Option<IocMatch> {
        if self.domains.is_empty() {
            return None;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        // Walk the name and each parent suffix: a.b.evil.com, b.evil.com,
        // evil.com, com. O(labels) lookups rather than O(indicators).
        let mut hay = name.as_str();
        loop {
            if let Some(meta) = self.domains.get(hay) {
                return Some(meta.matched(hay.to_string()));
            }
            match hay.split_once('.') {
                Some((_, rest)) => hay = rest,
                None => return None,
            }
        }
    }

    /// The JA3 hash indicator matching `hash`, if any, matched
    /// case-insensitively.
    pub fn match_ja3(&self, hash: &str) -> Option<IocMatch> {
        if self.ja3.is_empty() {
            return None;
        }
        let h = hash.to_ascii_lowercase();
        self.ja3.get(&h).map(|meta| meta.matched(h))
    }
}

impl Provenance {
    fn matched(&self, indicator: String) -> IocMatch {
        IocMatch {
            indicator,
            source: self.source.clone(),
            tag: self.tag.clone(),
        }
    }
}

/// Why a token could not be added to an [`IocSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocError {
    /// The token matched none of the supported indicator shapes.
    Unrecognised,
    /// The set is already at [`IocSet::MAX_INDICATORS`].
    Full,
}

impl std::fmt::Display for IocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            IocError::Unrecognised => "not a recognised IP, CIDR, domain or JA3 hash",
            IocError::Full => "indicator limit reached",
        })
    }
}

/// A JA3 fingerprint is an MD5 digest: exactly 32 hexadecimal characters.
fn is_ja3(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Lowercase, strip a trailing dot, and require the shape of a hostname: at
/// least one dot and only letters, digits, hyphen and dot. Returns `None` for
/// anything that is not plausibly a domain, so junk lines are rejected rather
/// than stored as indicators that can never match.
fn normalise_domain(token: &str) -> Option<String> {
    let d = token.trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || !d.contains('.') {
        return None;
    }
    if !d
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(d)
}

/// Parse `base/prefix`. The prefix must fit the address family (0-32 for v4,
/// 0-128 for v6); anything else is rejected.
fn parse_cidr(token: &str) -> Option<Cidr> {
    let (base, prefix) = token.split_once('/')?;
    let base: IpAddr = base.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if base.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return None;
    }
    Some(Cidr {
        base,
        prefix,
        text: token.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_each_indicator_kind() {
        let mut set = IocSet::default();
        assert_eq!(set.insert("203.0.113.7").unwrap(), IocKind::Ip);
        assert_eq!(set.insert("198.51.100.0/24").unwrap(), IocKind::Cidr);
        assert_eq!(set.insert("evil.example").unwrap(), IocKind::Domain);
        assert_eq!(
            set.insert("e7d705a3286e19ea42f587b344ee6865").unwrap(),
            IocKind::Ja3
        );
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn rejects_unrecognised_tokens() {
        let mut set = IocSet::default();
        // No dot, not 32 hex, not an address.
        assert_eq!(set.insert("localhost"), Err(IocError::Unrecognised));
        // A hostname with an illegal character.
        assert_eq!(set.insert("bad_host.com"), Err(IocError::Unrecognised));
        assert!(set.is_empty());
    }

    #[test]
    fn matches_exact_ip_and_cidr() {
        let mut set = IocSet::default();
        set.insert("203.0.113.7").unwrap();
        set.insert("198.51.100.0/24").unwrap();

        assert_eq!(
            set.match_ip(ip("203.0.113.7")).unwrap().indicator,
            "203.0.113.7"
        );
        assert_eq!(
            set.match_ip(ip("198.51.100.42")).unwrap().indicator,
            "198.51.100.0/24"
        );
        assert_eq!(set.match_ip(ip("198.51.101.42")), None);
        assert_eq!(set.match_ip(ip("10.0.0.1")), None);
    }

    #[test]
    fn exact_ip_wins_over_covering_range() {
        let mut set = IocSet::default();
        set.insert("10.0.0.0/8").unwrap();
        set.insert("10.1.2.3").unwrap();
        // The specific address is the more useful hit to report.
        assert_eq!(set.match_ip(ip("10.1.2.3")).unwrap().indicator, "10.1.2.3");
        assert_eq!(
            set.match_ip(ip("10.9.9.9")).unwrap().indicator,
            "10.0.0.0/8"
        );
    }

    #[test]
    fn cidr_prefix_boundaries_are_exact() {
        let mut set = IocSet::default();
        set.insert("192.168.1.0/25").unwrap(); // .0-.127
        assert!(set.match_ip(ip("192.168.1.127")).is_some());
        assert!(set.match_ip(ip("192.168.1.128")).is_none());
    }

    #[test]
    fn ipv6_cidr_matches() {
        let mut set = IocSet::default();
        set.insert("2001:db8::/32").unwrap();
        assert!(set.match_ip(ip("2001:db8:dead:beef::1")).is_some());
        assert!(set.match_ip(ip("2001:db9::1")).is_none());
        // A v4 address is never inside a v6 prefix.
        assert!(set.match_ip(ip("203.0.113.7")).is_none());
    }

    #[test]
    fn zero_prefix_matches_the_whole_family() {
        let mut set = IocSet::default();
        set.insert("0.0.0.0/0").unwrap();
        assert!(set.match_ip(ip("8.8.8.8")).is_some());
        assert!(set.match_ip(ip("::1")).is_none());
    }

    #[test]
    fn domain_matches_itself_and_subdomains_only() {
        let mut set = IocSet::default();
        set.insert("evil.example").unwrap();

        assert_eq!(
            set.match_domain("evil.example").unwrap().indicator,
            "evil.example"
        );
        assert_eq!(
            set.match_domain("c2.evil.example").unwrap().indicator,
            "evil.example"
        );
        // Case and a trailing dot are normalised away.
        assert_eq!(
            set.match_domain("C2.Evil.Example.").unwrap().indicator,
            "evil.example"
        );
        // A sibling that merely ends in the same text is not a subdomain.
        assert_eq!(set.match_domain("notevil.example"), None);
        assert_eq!(set.match_domain("evil.example.org"), None);
    }

    #[test]
    fn most_specific_listed_parent_is_reported() {
        let mut set = IocSet::default();
        set.insert("example").ok(); // rejected: no dot, not stored
        set.insert("bad.example").unwrap();
        set.insert("worse.bad.example").unwrap();
        assert_eq!(
            set.match_domain("x.worse.bad.example").unwrap().indicator,
            "worse.bad.example"
        );
    }

    #[test]
    fn ja3_matches_case_insensitively() {
        let mut set = IocSet::default();
        set.insert("E7D705A3286E19EA42F587B344EE6865").unwrap();
        assert!(set.match_ja3("e7d705a3286e19ea42f587b344ee6865").is_some());
        assert!(set.match_ja3("00000000000000000000000000000000").is_none());
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = IocSet::default();
        assert!(set.match_ip(ip("8.8.8.8")).is_none());
        assert!(set.match_domain("evil.example").is_none());
        assert!(set.match_ja3("e7d705a3286e19ea42f587b344ee6865").is_none());
    }

    #[test]
    fn provenance_travels_with_the_indicator() {
        let mut set = IocSet::default();
        set.set_source("feodo");
        set.insert_tagged("203.0.113.7", Some("Emotet".into()))
            .unwrap();
        set.set_source("urlhaus");
        set.insert("bad.example").unwrap();

        let ip_hit = set.match_ip(ip("203.0.113.7")).unwrap();
        assert_eq!(ip_hit.source, "feodo");
        assert_eq!(ip_hit.tag.as_deref(), Some("Emotet"));

        let dom_hit = set.match_domain("x.bad.example").unwrap();
        assert_eq!(dom_hit.source, "urlhaus");
        assert_eq!(dom_hit.tag, None);
    }

    #[test]
    fn default_source_is_manual() {
        let mut set = IocSet::default();
        set.insert("203.0.113.7").unwrap();
        assert_eq!(set.match_ip(ip("203.0.113.7")).unwrap().source, "manual");
    }

    #[test]
    fn extend_merges_indicators_and_provenance() {
        let mut a = IocSet::default();
        a.set_source("manual");
        a.insert("203.0.113.7").unwrap();
        a.add_source_info(SourceInfo {
            source: "manual".into(),
            fetched_at: None,
            indicators: 1,
        });

        let mut b = IocSet::default();
        b.set_source("feodo");
        b.insert_tagged("198.51.100.9", Some("Emotet".into()))
            .unwrap();
        b.add_source_info(SourceInfo {
            source: "feodo".into(),
            fetched_at: Some("2026-08-15T00:00:00Z".into()),
            indicators: 1,
        });

        a.extend(b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.match_ip(ip("203.0.113.7")).unwrap().source, "manual");
        let feodo = a.match_ip(ip("198.51.100.9")).unwrap();
        assert_eq!(feodo.source, "feodo");
        assert_eq!(feodo.tag.as_deref(), Some("Emotet"));
        assert_eq!(a.sources().len(), 2);
    }
}
