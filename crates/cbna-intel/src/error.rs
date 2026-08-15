//! One error type for fetching and caching feeds.

/// Anything that can go wrong pulling or reading a feed. The network variants
/// only arise under the `net` feature; the I/O and manifest variants are shared
/// with the always-available cache path.
#[derive(Debug, thiserror::Error)]
pub enum IntelError {
    #[error("HTTP {status} from {url}")]
    Http { url: String, status: u16 },

    #[error("network error for {url}: {msg}")]
    Network { url: String, msg: String },

    #[error("{url} requires an Auth-Key — pass --intel-auth-key or set CBNA_ABUSECH_AUTHKEY")]
    AuthRequired { url: String },

    #[error("response from {url} exceeded the {cap}-byte cap")]
    TooLarge { url: String, cap: u64 },

    #[error("unknown feed id: {0}")]
    UnknownFeed(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("cache manifest: {0}")]
    Json(#[from] serde_json::Error),
}
