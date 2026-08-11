//! Layer 4: TCP (including the options we care about) and UDP.

use crate::bytes::Reader;
use crate::error::{DecodeError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;

    pub fn has(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }
    pub fn syn(&self) -> bool {
        self.has(Self::SYN)
    }
    pub fn ack(&self) -> bool {
        self.has(Self::ACK)
    }
    pub fn fin(&self) -> bool {
        self.has(Self::FIN)
    }
    pub fn rst(&self) -> bool {
        self.has(Self::RST)
    }
    /// Connection opener: SYN without ACK.
    pub fn is_syn_only(&self) -> bool {
        self.syn() && !self.ack()
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ordered so combinations render as the shorthand analysts actually
        // write and search for: SA, PA, FA, RA — not header bit order.
        const NAMES: [(u8, &str); 8] = [
            (TcpFlags::SYN, "S"),
            (TcpFlags::FIN, "F"),
            (TcpFlags::RST, "R"),
            (TcpFlags::PSH, "P"),
            (TcpFlags::ACK, "A"),
            (TcpFlags::URG, "U"),
            (TcpFlags::ECE, "E"),
            (TcpFlags::CWR, "C"),
        ];
        let mut any = false;
        for (bit, name) in NAMES {
            if self.0 & bit != 0 {
                f.write_str(name)?;
                any = true;
            }
        }
        if !any {
            f.write_str("-")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub data_offset: u8,
    pub options: TcpOptions,
}

pub fn parse_tcp(buf: &[u8]) -> Result<(Tcp, &[u8])> {
    let mut r = Reader::new(buf, "tcp");
    let src_port = r.be_u16()?;
    let dst_port = r.be_u16()?;
    let seq = r.be_u32()?;
    let ack = r.be_u32()?;
    let offset_flags = r.be_u16()?;
    let data_offset = (offset_flags >> 12) as u8;
    if data_offset < 5 {
        return Err(DecodeError::malformed(
            "tcp",
            "data offset below the 20-byte minimum",
        ));
    }
    let flags = TcpFlags((offset_flags & 0x00FF) as u8);
    let window = r.be_u16()?;
    let checksum = r.be_u16()?;
    let urgent = r.be_u16()?;

    let options_len = data_offset as usize * 4 - 20;
    let options = if options_len > 0 {
        let mut opt_reader = r.sub(options_len, "tcp options")?;
        parse_tcp_options(&mut opt_reader)
    } else {
        TcpOptions::default()
    };

    Ok((
        Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            checksum,
            urgent,
            data_offset,
            options,
        },
        r.rest(),
    ))
}

/// Best-effort option walk. A malformed option stops the walk rather than
/// failing the packet — the header itself already parsed cleanly.
fn parse_tcp_options(r: &mut Reader<'_>) -> TcpOptions {
    let mut out = TcpOptions::default();
    while let Ok(kind) = r.u8() {
        match kind {
            0 => break,    // end of option list
            1 => continue, // nop padding
            _ => {}
        }
        let len = match r.u8() {
            Ok(l) if l >= 2 => l as usize - 2,
            _ => break,
        };
        let Ok(mut data) = r.sub(len, "tcp option") else {
            break;
        };
        match kind {
            2 => out.mss = data.be_u16().ok(),
            3 => out.window_scale = data.u8().ok(),
            4 => out.sack_permitted = true,
            8 => out.timestamps = true,
            _ => {}
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Udp {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse_udp(buf: &[u8]) -> Result<(Udp, &[u8])> {
    let mut r = Reader::new(buf, "udp");
    let src_port = r.be_u16()?;
    let dst_port = r.be_u16()?;
    let length = r.be_u16()?;
    let checksum = r.be_u16()?;

    // The length field covers the 8-byte header too; trust it only when it is
    // sane, since offload captures sometimes leave it at zero.
    if length >= 8 {
        r.limit(length as usize - 8);
    }

    Ok((
        Udp {
            src_port,
            dst_port,
            length,
            checksum,
        },
        r.rest(),
    ))
}

/// Well-known service label for a port, used for the service breakdown.
pub fn service_name(port: u16, tcp: bool) -> Option<&'static str> {
    Some(match (port, tcp) {
        (20, true) | (21, true) => "ftp",
        (22, true) => "ssh",
        (23, true) => "telnet",
        (25, true) | (587, true) => "smtp",
        (53, _) => "dns",
        (67, false) | (68, false) => "dhcp",
        (69, false) => "tftp",
        (80, true) | (8080, true) | (8000, true) => "http",
        (88, _) => "kerberos",
        (110, true) => "pop3",
        (123, false) => "ntp",
        (135, true) => "msrpc",
        (137, false) | (138, false) => "netbios",
        (139, true) | (445, true) => "smb",
        (143, true) => "imap",
        (161, false) | (162, false) => "snmp",
        (389, _) => "ldap",
        (443, true) | (8443, true) => "https",
        (443, false) => "quic",
        (514, false) => "syslog",
        (636, true) => "ldaps",
        (1433, true) => "mssql",
        (1521, true) => "oracle",
        (3306, true) => "mysql",
        (3389, true) => "rdp",
        (5060, _) | (5061, _) => "sip",
        (5432, true) => "postgres",
        (5353, false) => "mdns",
        (5985, true) | (5986, true) => "winrm",
        (6379, true) => "redis",
        (9200, true) => "elasticsearch",
        (27017, true) => "mongodb",
        _ => return None,
    })
}

/// Cleartext protocols worth flagging when observed carrying real traffic.
pub fn is_cleartext_service(port: u16, tcp: bool) -> Option<&'static str> {
    match service_name(port, tcp)? {
        s @ ("ftp" | "telnet" | "http" | "pop3" | "imap" | "smtp" | "tftp" | "syslog" | "snmp") => {
            Some(s)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_syn_with_options() {
        let mut b = vec![
            0xc0, 0x00, // src 49152
            0x01, 0xbb, // dst 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x80, 0x02, // data offset 8, SYN
            0xfa, 0xf0, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent
        ];
        // options: MSS 1460, NOP, window scale 7, SACK permitted, EOL
        b.extend_from_slice(&[0x02, 0x04, 0x05, 0xb4]);
        b.extend_from_slice(&[0x01, 0x03, 0x03, 0x07]);
        b.extend_from_slice(&[0x04, 0x02, 0x00, 0x00]);
        b.extend_from_slice(&[0xde, 0xad]); // payload

        let (tcp, payload) = parse_tcp(&b).unwrap();
        assert_eq!(tcp.src_port, 49152);
        assert_eq!(tcp.dst_port, 443);
        assert!(tcp.flags.is_syn_only());
        assert_eq!(tcp.flags.to_string(), "S");
        assert_eq!(tcp.options.mss, Some(1460));
        assert_eq!(tcp.options.window_scale, Some(7));
        assert!(tcp.options.sack_permitted);
        assert_eq!(payload, &[0xde, 0xad]);
    }

    #[test]
    fn renders_flag_combinations() {
        assert_eq!(TcpFlags(TcpFlags::SYN | TcpFlags::ACK).to_string(), "SA");
        assert_eq!(TcpFlags(TcpFlags::RST | TcpFlags::ACK).to_string(), "RA");
        assert_eq!(TcpFlags(TcpFlags::PSH | TcpFlags::ACK).to_string(), "PA");
        assert_eq!(TcpFlags(TcpFlags::FIN | TcpFlags::ACK).to_string(), "FA");
        assert_eq!(TcpFlags(0).to_string(), "-");
    }

    #[test]
    fn rejects_short_data_offset() {
        let b = [0u8; 20];
        assert!(parse_tcp(&b).is_err());
    }

    #[test]
    fn udp_length_bounds_payload() {
        let mut b = vec![0x00, 0x35, 0xc0, 0x00, 0x00, 0x0c, 0x00, 0x00];
        b.extend_from_slice(&[1, 2, 3, 4, 0xff, 0xff]); // 2 bytes of trailer
        let (udp, payload) = parse_udp(&b).unwrap();
        assert_eq!(udp.src_port, 53);
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn service_lookup() {
        assert_eq!(service_name(443, true), Some("https"));
        assert_eq!(service_name(443, false), Some("quic"));
        assert_eq!(service_name(64123, true), None);
        assert_eq!(is_cleartext_service(23, true), Some("telnet"));
        assert_eq!(is_cleartext_service(22, true), None);
    }
}
