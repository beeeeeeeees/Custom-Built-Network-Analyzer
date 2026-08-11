//! Application-layer decoders.
//!
//! These run opportunistically on transport payloads. Each returns `None`
//! rather than an error when the payload is simply not that protocol, so the
//! dispatcher can try candidates cheaply.

pub mod dns;
pub mod http;
pub mod tls;

pub use dns::{DnsMessage, DnsQuestion, DnsRecord};
pub use http::{HttpKind, HttpMessage};
pub use tls::{TlsHello, TlsHelloKind};

/// Shannon entropy of a byte string, in bits per character.
///
/// Used to score DNS labels: encoded tunnel data and DGA names sit well above
/// the ~3.0-3.5 bits typical of English-like hostnames.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Lowercase hex encoding, used for digests and fingerprints.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_separates_words_from_noise() {
        let word = shannon_entropy("mail.google.com");
        let noise = shannon_entropy("k3n8vq2xzp7wl9rt4bj6");
        assert!(word < noise, "{word} should be below {noise}");
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn hex_encodes() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
