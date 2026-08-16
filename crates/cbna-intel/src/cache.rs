//! On-disk feed cache and its manifest.
//!
//! `update` fetches feeds and writes each one's bytes to `<id>.data` next to a
//! `manifest.json` recording where it came from and when. `load` reads the cache
//! back into an [`IocSet`]. The split is deliberate: analysis reads the cache
//! offline and reproducibly, and refreshing it is a separate, network-touching
//! step — the same offline-first contract the rest of the tool keeps.

use crate::error::IntelError;
use crate::feed::{self, Feed};
use crate::parse::parse_into;
use cbna_core::ioc::{IocSet, SourceInfo};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Recorded state of one cached feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFeed {
    pub id: String,
    pub url: String,
    /// When the bytes were fetched, RFC 3339.
    pub fetched_at: String,
    pub bytes: usize,
    pub indicators: usize,
}

/// The cache index: one entry per feed with data on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub feeds: Vec<CachedFeed>,
}

impl Manifest {
    fn entry_mut(&mut self, id: &str) -> Option<&mut CachedFeed> {
        self.feeds.iter_mut().find(|f| f.id == id)
    }
}

/// What happened to one feed during an update.
#[derive(Debug)]
pub struct FeedResult {
    pub id: &'static str,
    /// `Ok(n)` — refreshed with `n` indicators; `Err(msg)` — fetch failed and
    /// the previous cache (if any) was left untouched.
    pub result: Result<usize, String>,
}

/// Resolve the cache directory: `CBNA_INTEL_CACHE` if set, else the platform
/// per-user cache dir, else a dot-dir in the working directory as a last resort.
pub fn default_cache_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CBNA_INTEL_CACHE") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(p).join("cbna").join("intel");
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(p) = std::env::var("XDG_CACHE_HOME") {
            return PathBuf::from(p).join("cbna").join("intel");
        }
        if let Ok(h) = std::env::var("HOME") {
            return PathBuf::from(h).join(".cache").join("cbna").join("intel");
        }
    }
    PathBuf::from(".cbna-intel")
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.json")
}

fn data_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.data"))
}

/// Read the manifest, or an empty one when the cache does not exist yet.
pub fn read_manifest(dir: &Path) -> Result<Manifest, IntelError> {
    match std::fs::read(manifest_path(dir)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Manifest::default()),
        Err(e) => Err(e.into()),
    }
}

fn write_manifest(dir: &Path, m: &Manifest) -> Result<(), IntelError> {
    let json = serde_json::to_vec_pretty(m)?;
    std::fs::write(manifest_path(dir), json)?;
    Ok(())
}

/// Load every cached feed into one [`IocSet`], tagging indicators with their
/// feed id and stamping each source's fetch time for the report. A missing
/// cache yields an empty set rather than an error, so the caller can tell the
/// user to run an update.
pub fn load(dir: &Path) -> Result<IocSet, IntelError> {
    let manifest = read_manifest(dir)?;
    let mut set = IocSet::default();

    for cached in &manifest.feeds {
        let Some(feed) = feed::by_id(&cached.id) else {
            // A cache written by a newer build may name a feed this one dropped;
            // skip it rather than fail the whole load.
            continue;
        };
        let bytes = match std::fs::read(data_path(dir, &cached.id)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let added = parse_into(&mut set, feed, &bytes);
        set.add_source_info(SourceInfo {
            source: cached.id.clone(),
            fetched_at: Some(cached.fetched_at.clone()),
            indicators: added,
        });
    }
    Ok(set)
}

/// The feeds an update should touch: a named subset, or all built-ins.
fn selected(only: Option<&[String]>) -> Result<Vec<&'static Feed>, IntelError> {
    match only {
        None => Ok(feed::BUILTIN.iter().collect()),
        Some(ids) => ids
            .iter()
            .map(|id| feed::by_id(id).ok_or_else(|| IntelError::UnknownFeed(id.clone())))
            .collect(),
    }
}

/// Count the indicators `bytes` would contribute, without disturbing a real set.
fn count_indicators(feed: &Feed, bytes: &[u8]) -> usize {
    let mut probe = IocSet::default();
    parse_into(&mut probe, feed, bytes)
}

/// Current time as an RFC 3339 string, via the core timestamp type.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    cbna_core::Timestamp::new(secs, 0).to_rfc3339()
}

/// Options for [`update`].
#[cfg(feature = "net")]
pub struct UpdateOptions<'a> {
    pub cache_dir: &'a Path,
    pub auth_key: Option<&'a str>,
    /// Restrict to these feed ids; `None` refreshes every built-in.
    pub only: Option<&'a [String]>,
}

/// Fetch the selected feeds into the cache. A feed that fails to fetch leaves
/// its previous cached copy in place and is reported as an error in its
/// [`FeedResult`]; the others still update. Only an unresolvable feed id or a
/// cache-directory I/O failure aborts the whole call.
#[cfg(feature = "net")]
pub fn update(opts: &UpdateOptions) -> Result<Vec<FeedResult>, IntelError> {
    let feeds = selected(opts.only)?;
    std::fs::create_dir_all(opts.cache_dir)?;
    let mut manifest = read_manifest(opts.cache_dir)?;
    let mut results = Vec::new();

    for feed in feeds {
        match crate::fetch::fetch(feed, opts.auth_key) {
            Ok(bytes) => {
                std::fs::write(data_path(opts.cache_dir, feed.id), &bytes)?;
                let indicators = count_indicators(feed, &bytes);
                let entry = CachedFeed {
                    id: feed.id.to_string(),
                    url: feed.url.to_string(),
                    fetched_at: now_rfc3339(),
                    bytes: bytes.len(),
                    indicators,
                };
                match manifest.entry_mut(feed.id) {
                    Some(e) => *e = entry,
                    None => manifest.feeds.push(entry),
                }
                results.push(FeedResult {
                    id: feed.id,
                    result: Ok(indicators),
                });
            }
            Err(e) => results.push(FeedResult {
                id: feed.id,
                result: Err(e.to_string()),
            }),
        }
    }

    write_manifest(opts.cache_dir, &manifest)?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cbna-intel-{tag}-{}", std::process::id()));
        p
    }

    #[test]
    fn missing_cache_loads_empty() {
        let dir = temp_dir("missing");
        let _ = std::fs::remove_dir_all(&dir);
        let set = load(&dir).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn round_trips_a_cached_feed_into_a_set() {
        let dir = temp_dir("roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Hand-write a Feodo cache entry and its data, then load it back.
        std::fs::write(data_path(&dir, "feodo"), b"203.0.113.7\n198.51.100.9\n").unwrap();
        let manifest = Manifest {
            feeds: vec![CachedFeed {
                id: "feodo".into(),
                url: feed::by_id("feodo").unwrap().url.into(),
                fetched_at: "2026-08-15T00:00:00Z".into(),
                bytes: 24,
                indicators: 2,
            }],
        };
        write_manifest(&dir, &manifest).unwrap();

        let set = load(&dir).unwrap();
        assert_eq!(set.len(), 2);
        let hit = set.match_ip("203.0.113.7".parse().unwrap()).unwrap();
        assert_eq!(hit.source, "feodo");
        // The snapshot time survives into the set for the report stamp.
        let src = set.sources().iter().find(|s| s.source == "feodo").unwrap();
        assert_eq!(src.fetched_at.as_deref(), Some("2026-08-15T00:00:00Z"));
        assert_eq!(src.indicators, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_feed_id_is_rejected() {
        let err = selected(Some(&["nope".to_string()])).unwrap_err();
        assert!(matches!(err, IntelError::UnknownFeed(_)));
    }
}
