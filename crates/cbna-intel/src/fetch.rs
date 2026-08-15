//! Pull a feed's bytes over HTTPS, with the guards a network trust boundary
//! needs: TLS verification (rustls with the bundled Mozilla roots), connect and
//! overall timeouts, a bounded redirect chain, and a hard cap on the response
//! size so a hijacked or broken endpoint cannot exhaust memory.

use crate::error::IntelError;
use crate::feed::Feed;
use std::io::Read;
use std::time::Duration;

/// Largest response we will read into memory. URLhaus's online-URL dump is the
/// biggest of the shipped feeds at a few tens of MB; this leaves generous room
/// while still refusing a runaway download.
const MAX_BYTES: u64 = 128 * 1024 * 1024;

/// Fetch `feed`, returning its raw bytes. `auth_key` is sent as the `Auth-Key`
/// header when supplied; a feed that requires one and gets none fails fast
/// rather than fetching an error page.
pub fn fetch(feed: &Feed, auth_key: Option<&str>) -> Result<Vec<u8>, IntelError> {
    if feed.needs_auth && auth_key.is_none() {
        return Err(IntelError::AuthRequired {
            url: feed.url.to_string(),
        });
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .redirects(3)
        .user_agent(concat!("cbna-intel/", env!("CARGO_PKG_VERSION")))
        .build();

    let mut req = agent.get(feed.url);
    if let Some(key) = auth_key {
        req = req.set("Auth-Key", key);
    }

    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(status, _)) => {
            return Err(IntelError::Http {
                url: feed.url.to_string(),
                status,
            });
        }
        Err(ureq::Error::Transport(t)) => {
            return Err(IntelError::Network {
                url: feed.url.to_string(),
                msg: t.to_string(),
            });
        }
    };

    // Read one byte past the cap so a response sitting exactly on the limit is
    // still accepted while an over-limit one is caught.
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_BYTES {
        return Err(IntelError::TooLarge {
            url: feed.url.to_string(),
            cap: MAX_BYTES,
        });
    }
    Ok(buf)
}
