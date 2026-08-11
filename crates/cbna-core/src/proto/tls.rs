//! TLS handshake decoding: ClientHello / ServerHello, SNI, ALPN, and JA3.
//!
//! JA3 is computed exactly as specified by Salesforce's original definition:
//! `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`, with GREASE
//! values removed, MD5 of that string. JA3S (the server side) uses
//! `SSLVersion,Cipher,Extensions`.

use crate::bytes::Reader;
use crate::error::Result;
use crate::proto::hex;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsHelloKind {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsHello {
    pub kind: TlsHelloKind,
    /// Record-layer version (legacy; often 0x0301 even for TLS 1.3).
    pub record_version: u16,
    /// Highest version offered/selected, resolved through supported_versions.
    pub negotiated_version: u16,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    /// The raw JA3/JA3S string, kept so an analyst can see what was hashed.
    pub ja3: String,
    pub ja3_md5: String,
    pub session_id_len: usize,
    /// The record's declared length was fully present in the payload.
    ///
    /// A ClientHello that spills into the next segment still yields whatever
    /// extensions fit, so SNI and JA3 can be silently wrong — JA3 hashes the
    /// extension list, and a truncated list hashes to a different client. The
    /// reassembler uses this to decide whether to rebuild the record.
    pub complete: bool,
}

/// Wire version to its human name. Free-standing because findings render a
/// version recorded on a flow, long after the hello itself is gone.
pub fn version_name(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

impl TlsHello {
    pub fn version_name(&self) -> &'static str {
        version_name(self.negotiated_version)
    }

    /// Versions that should not be seen on a modern network.
    pub fn is_obsolete_version(&self) -> bool {
        matches!(self.negotiated_version, 0x0300..=0x0302)
    }
}

/// GREASE values (RFC 8701) are randomly injected and must not affect the
/// fingerprint, or every connection from a Chrome-family client hashes
/// differently.
fn is_grease(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0x00FF)
}

/// Decode a TLS handshake from the start of a TCP payload.
pub fn parse(payload: &[u8]) -> Option<TlsHello> {
    parse_strict(payload).ok().flatten()
}

fn parse_strict(payload: &[u8]) -> Result<Option<TlsHello>> {
    let mut r = Reader::new(payload, "tls record");
    if r.peek_u8()? != CONTENT_TYPE_HANDSHAKE {
        return Ok(None);
    }
    r.skip(1)?;
    let record_version = r.be_u16()?;
    let record_len = r.be_u16()? as usize;
    // The handshake may span records; decode as much as this one carries.
    let available = record_len.min(r.remaining());
    let complete = record_len <= r.remaining();
    let mut rec = r.sub(available, "tls handshake")?;

    let msg_type = rec.u8()?;
    let kind = match msg_type {
        HANDSHAKE_CLIENT_HELLO => TlsHelloKind::Client,
        HANDSHAKE_SERVER_HELLO => TlsHelloKind::Server,
        _ => return Ok(None),
    };
    let _len = rec.be_u24()?;

    let legacy_version = rec.be_u16()?;
    rec.skip(32)?; // random
    let session_id_len = rec.u8()? as usize;
    rec.skip(session_id_len)?;

    let mut cipher_suites = Vec::new();
    match kind {
        TlsHelloKind::Client => {
            let cs_len = rec.be_u16()? as usize;
            let mut cs = rec.sub(cs_len, "tls ciphers")?;
            while cs.remaining() >= 2 {
                let v = cs.be_u16()?;
                if !is_grease(v) {
                    cipher_suites.push(v);
                }
            }
            let comp_len = rec.u8()? as usize;
            rec.skip(comp_len)?;
        }
        TlsHelloKind::Server => {
            cipher_suites.push(rec.be_u16()?);
            rec.skip(1)?; // compression method
        }
    }

    let mut sni = None;
    let mut alpn = Vec::new();
    let mut extensions = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut point_formats: Vec<u8> = Vec::new();
    let mut negotiated_version = legacy_version;

    // Extensions are optional in the wire format (SSLv3-era hellos omit them).
    if rec.remaining() >= 2 {
        let ext_total = rec.be_u16()? as usize;
        let mut exts = rec.sub(ext_total.min(rec.remaining()), "tls extensions")?;
        while exts.remaining() >= 4 {
            let ext_type = exts.be_u16()?;
            let ext_len = exts.be_u16()? as usize;
            let Ok(mut data) = exts.sub(ext_len, "tls extension") else {
                break;
            };
            if is_grease(ext_type) {
                continue;
            }
            extensions.push(ext_type);

            match ext_type {
                EXT_SERVER_NAME => {
                    if let Ok(name) = read_sni(&mut data) {
                        sni = name;
                    }
                }
                EXT_ALPN => {
                    if let Ok(list) = read_alpn(&mut data) {
                        alpn = list;
                    }
                }
                EXT_SUPPORTED_GROUPS => {
                    // Skip the list length, then take every remaining pair.
                    if data.be_u16().is_ok() {
                        while let Ok(v) = data.be_u16() {
                            if !is_grease(v) {
                                groups.push(v);
                            }
                        }
                    }
                }
                EXT_EC_POINT_FORMATS => {
                    if let Ok(len) = data.u8() {
                        for _ in 0..len {
                            match data.u8() {
                                Ok(v) => point_formats.push(v),
                                Err(_) => break,
                            }
                        }
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    negotiated_version = read_supported_versions(&mut data, kind)
                        .unwrap_or(negotiated_version)
                        .max(negotiated_version);
                }
                _ => {}
            }
        }
    }

    let ja3 = match kind {
        TlsHelloKind::Client => format!(
            "{},{},{},{},{}",
            legacy_version,
            join_u16(&cipher_suites),
            join_u16(&extensions),
            join_u16(&groups),
            point_formats
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        ),
        TlsHelloKind::Server => format!(
            "{},{},{}",
            legacy_version,
            join_u16(&cipher_suites),
            join_u16(&extensions),
        ),
    };

    let mut hasher = Md5::new();
    hasher.update(ja3.as_bytes());
    let ja3_md5 = hex(&hasher.finalize());

    Ok(Some(TlsHello {
        kind,
        record_version,
        negotiated_version,
        sni,
        alpn,
        cipher_suites,
        extensions,
        ja3,
        ja3_md5,
        session_id_len,
        complete,
    }))
}

fn join_u16(v: &[u16]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn read_sni(r: &mut Reader<'_>) -> Result<Option<String>> {
    let list_len = r.be_u16()? as usize;
    let mut list = r.sub(list_len.min(r.remaining()), "sni list")?;
    while list.remaining() >= 3 {
        let name_type = list.u8()?;
        let len = list.be_u16()? as usize;
        let bytes = list.take(len)?;
        if name_type == 0 {
            return Ok(Some(String::from_utf8_lossy(bytes).into_owned()));
        }
    }
    Ok(None)
}

fn read_alpn(r: &mut Reader<'_>) -> Result<Vec<String>> {
    let list_len = r.be_u16()? as usize;
    let mut list = r.sub(list_len.min(r.remaining()), "alpn list")?;
    let mut out = Vec::new();
    while list.remaining() >= 1 {
        let len = list.u8()? as usize;
        let bytes = list.take(len)?;
        out.push(String::from_utf8_lossy(bytes).into_owned());
    }
    Ok(out)
}

/// ClientHello sends a list; ServerHello sends the single selected version.
fn read_supported_versions(r: &mut Reader<'_>, kind: TlsHelloKind) -> Result<u16> {
    match kind {
        TlsHelloKind::Server => r.be_u16(),
        TlsHelloKind::Client => {
            let len = r.u8()? as usize;
            let mut list = r.sub(len.min(r.remaining()), "supported versions")?;
            let mut best = 0;
            while list.remaining() >= 2 {
                let v = list.be_u16()?;
                if !is_grease(v) && v > best {
                    best = v;
                }
            }
            Ok(best)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello() -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
        hs.extend_from_slice(&[0x00; 32]); // random
        hs.push(0x00); // no session id
                       // cipher suites: GREASE, 0x1301, 0x1302
        hs.extend_from_slice(&[0x00, 0x06]);
        hs.extend_from_slice(&[0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02]);
        hs.extend_from_slice(&[0x01, 0x00]); // compression: null

        let mut exts = Vec::new();
        // server_name: example.org
        let host = b"example.org";
        let mut sni = Vec::new();
        sni.push(0x00);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni);
        exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        // alpn: h2, http/1.1
        let mut alpn = Vec::new();
        alpn.push(2);
        alpn.extend_from_slice(b"h2");
        alpn.push(8);
        alpn.extend_from_slice(b"http/1.1");
        let mut alpn_ext = (alpn.len() as u16).to_be_bytes().to_vec();
        alpn_ext.extend_from_slice(&alpn);
        exts.extend_from_slice(&EXT_ALPN.to_be_bytes());
        exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn_ext);
        // supported_groups: 0x001d
        exts.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        // ec_point_formats: uncompressed
        exts.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x02, 0x01, 0x00]);
        // supported_versions: TLS 1.3
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x04]);

        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let len = hs.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_alpn_and_version() {
        let hello = parse(&client_hello()).unwrap();
        assert_eq!(hello.kind, TlsHelloKind::Client);
        assert_eq!(hello.sni.as_deref(), Some("example.org"));
        assert_eq!(hello.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(hello.negotiated_version, 0x0304);
        assert_eq!(hello.version_name(), "TLS 1.3");
        assert!(!hello.is_obsolete_version());
    }

    #[test]
    fn ja3_excludes_grease_and_is_stable() {
        let hello = parse(&client_hello()).unwrap();
        // 771 = 0x0303; GREASE cipher 0x0a0a dropped; extensions in wire order.
        assert_eq!(hello.ja3, "771,4865-4866,0-16-10-11-43,29,0");
        assert_eq!(hello.ja3_md5.len(), 32);

        // The digest must be reproducible across runs.
        let again = parse(&client_hello()).unwrap();
        assert_eq!(hello.ja3_md5, again.ja3_md5);
    }

    #[test]
    fn ignores_non_handshake_records() {
        assert!(parse(&[0x17, 0x03, 0x03, 0x00, 0x10]).is_none()); // application data
        assert!(parse(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xdada));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a0b));
    }
}
