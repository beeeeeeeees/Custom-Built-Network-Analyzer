//! HTTP/1.x start-line and header extraction.
//!
//! This is not a stream reassembler: it decodes headers that happen to start at
//! the beginning of a TCP segment, which covers the first request/response of
//! virtually every connection and is what artifact extraction needs.

use serde::{Deserialize, Serialize};

const METHODS: [&str; 9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// Header names we retain. Everything else is counted but discarded so a
/// long-running capture cannot grow unbounded from attacker-chosen headers.
const KEPT_HEADERS: [&str; 8] = [
    "host",
    "user-agent",
    "server",
    "content-type",
    "content-length",
    "location",
    "referer",
    "x-forwarded-for",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpKind {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessage {
    pub kind: HttpKind,
    pub version: String,
    /// Request only.
    pub method: Option<String>,
    pub uri: Option<String>,
    /// Response only.
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub location: Option<String>,
    pub referer: Option<String>,
    /// Credentials were present in the clear. The value itself is never stored.
    pub has_authorization: bool,
    pub has_cookie: bool,
    pub header_count: usize,
}

impl HttpMessage {
    /// `GET http://host/path` style label for reports.
    pub fn summary(&self) -> String {
        match self.kind {
            HttpKind::Request => format!(
                "{} {}{}",
                self.method.as_deref().unwrap_or("?"),
                self.host.as_deref().unwrap_or(""),
                self.uri.as_deref().unwrap_or("")
            ),
            HttpKind::Response => format!(
                "{} {}",
                self.status.map(|s| s.to_string()).unwrap_or_default(),
                self.content_type.as_deref().unwrap_or("")
            )
            .trim_end()
            .to_string(),
        }
    }
}

/// Decode HTTP/1.x headers from the start of a TCP payload, or `None` if the
/// payload does not begin with a start line.
pub fn parse(payload: &[u8]) -> Option<HttpMessage> {
    // Headers are ASCII by spec; bail early on binary payloads.
    let head_end = find_header_end(payload);
    let head = &payload[..head_end];
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
    let start = lines.next()?;

    let mut msg = if let Some(rest) = start.strip_prefix("HTTP/") {
        let mut parts = rest.splitn(3, ' ');
        let version = format!("HTTP/{}", parts.next()?);
        let status = parts.next()?.parse::<u16>().ok()?;
        if !(100..=599).contains(&status) {
            return None;
        }
        HttpMessage {
            kind: HttpKind::Response,
            version,
            method: None,
            uri: None,
            status: Some(status),
            reason: parts.next().map(|s| truncate(s, 120)),
            ..empty()
        }
    } else {
        let mut parts = start.split(' ');
        let method = parts.next()?;
        if !METHODS.contains(&method) {
            return None;
        }
        let uri = parts.next()?;
        let version = parts.next()?;
        if !version.starts_with("HTTP/1.") {
            return None;
        }
        HttpMessage {
            kind: HttpKind::Request,
            version: version.to_string(),
            method: Some(method.to_string()),
            uri: Some(truncate(uri, 512)),
            status: None,
            reason: None,
            ..empty()
        }
    };

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        msg.header_count += 1;

        match name.as_str() {
            "authorization" | "proxy-authorization" => msg.has_authorization = true,
            "cookie" | "set-cookie" => msg.has_cookie = true,
            _ => {}
        }
        if !KEPT_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let value = truncate(value, 256);
        match name.as_str() {
            "host" => msg.host = Some(value),
            "user-agent" => msg.user_agent = Some(value),
            "server" => msg.server = Some(value),
            "content-type" => msg.content_type = Some(value),
            "content-length" => msg.content_length = value.parse().ok(),
            "location" => msg.location = Some(value),
            "referer" => msg.referer = Some(value),
            _ => {}
        }
    }

    Some(msg)
}

fn empty() -> HttpMessage {
    HttpMessage {
        kind: HttpKind::Request,
        version: String::new(),
        method: None,
        uri: None,
        status: None,
        reason: None,
        host: None,
        user_agent: None,
        server: None,
        content_type: None,
        content_length: None,
        location: None,
        referer: None,
        has_authorization: false,
        has_cookie: false,
        header_count: 0,
    }
}

/// End of the header block, or the whole payload when the segment cuts it off.
fn find_header_end(payload: &[u8]) -> usize {
    const LIMIT: usize = 16 * 1024;
    let hay = &payload[..payload.len().min(LIMIT)];
    hay.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2)
        .unwrap_or(hay.len())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request() {
        let raw = b"GET /admin/index.php?id=1 HTTP/1.1\r\n\
                    Host: intranet.corp.local\r\n\
                    User-Agent: curl/8.4.0\r\n\
                    Authorization: Basic dXNlcjpwYXNz\r\n\
                    Accept: */*\r\n\r\nbody";
        let m = parse(raw).unwrap();
        assert_eq!(m.kind, HttpKind::Request);
        assert_eq!(m.method.as_deref(), Some("GET"));
        assert_eq!(m.host.as_deref(), Some("intranet.corp.local"));
        assert_eq!(m.user_agent.as_deref(), Some("curl/8.4.0"));
        assert!(m.has_authorization);
        assert_eq!(m.header_count, 4);
        assert_eq!(m.summary(), "GET intranet.corp.local/admin/index.php?id=1");
    }

    #[test]
    fn parses_response() {
        let raw = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 153\r\n\r\n";
        let m = parse(raw).unwrap();
        assert_eq!(m.kind, HttpKind::Response);
        assert_eq!(m.status, Some(404));
        assert_eq!(m.reason.as_deref(), Some("Not Found"));
        assert_eq!(m.server.as_deref(), Some("nginx"));
        assert_eq!(m.content_length, Some(153));
    }

    #[test]
    fn handles_headers_cut_by_snaplen() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nUser-Ag";
        let m = parse(raw).unwrap();
        assert_eq!(m.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse(b"\x16\x03\x01\x00\x50").is_none());
        assert!(parse(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
        assert!(parse(b"GETS /x HTTP/1.1\r\n\r\n").is_none());
    }
}
