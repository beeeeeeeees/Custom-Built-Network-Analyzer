//! Open-source threat-intel feed fetching and caching for cbna.
//!
//! This crate is the network front-end for [`cbna_core::ioc`]: it pulls OSINT
//! indicator feeds, caches them, and turns them into an [`IocSet`] the no-I/O
//! core matches traffic against. It never touches packets — it only produces the
//! indicator set the analyzer is handed.
//!
//! Fetching (the `net` feature, on by default) uses a blocking rustls client.
//! Parsing and cache loading do not need it, so the fuzz harness depends on this
//! crate without `net` and never builds the TLS stack.

pub mod cache;
pub mod error;
pub mod feed;
pub mod fuzz;
pub mod parse;

#[cfg(feature = "net")]
pub mod fetch;

pub use cache::{default_cache_dir, FeedResult};
pub use error::IntelError;
pub use feed::{Feed, Format, BUILTIN};

use cbna_core::ioc::IocSet;
use std::path::Path;

/// Load the cached feeds into a matchable set. A missing cache is an empty set,
/// not an error.
pub fn load(cache_dir: &Path) -> Result<IocSet, IntelError> {
    cache::load(cache_dir)
}

#[cfg(feature = "net")]
pub use cache::{update, UpdateOptions};

/// Fetch the selected feeds straight into a set without writing the cache — the
/// `--intel-live` path. Returns the set plus a per-feed outcome so a failed feed
/// is reported without sinking the run.
#[cfg(feature = "net")]
pub fn fetch_live(
    auth_key: Option<&str>,
    only: Option<&[String]>,
) -> Result<(IocSet, Vec<FeedResult>), IntelError> {
    use cbna_core::ioc::SourceInfo;

    let feeds: Vec<&Feed> = match only {
        None => feed::BUILTIN.iter().collect(),
        Some(ids) => ids
            .iter()
            .map(|id| feed::by_id(id).ok_or_else(|| IntelError::UnknownFeed(id.clone())))
            .collect::<Result<_, _>>()?,
    };

    let mut set = IocSet::default();
    let mut results = Vec::new();
    for feed in feeds {
        match fetch::fetch(feed, auth_key) {
            Ok(bytes) => {
                let added = parse::parse_into(&mut set, feed, &bytes);
                set.add_source_info(SourceInfo {
                    source: feed.id.to_string(),
                    fetched_at: Some(now_rfc3339()),
                    indicators: added,
                });
                results.push(FeedResult {
                    id: feed.id,
                    result: Ok(added),
                });
            }
            Err(e) => results.push(FeedResult {
                id: feed.id,
                result: Err(e.to_string()),
            }),
        }
    }
    Ok((set, results))
}

#[cfg(feature = "net")]
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    cbna_core::Timestamp::new(secs, 0).to_rfc3339()
}
