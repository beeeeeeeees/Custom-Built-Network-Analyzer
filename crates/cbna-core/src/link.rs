//! Layer 2: Ethernet II, 802.1Q/802.1ad VLAN stacking, and ARP.

use crate::bytes::Reader;
use crate::error::{DecodeError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_QINQ: u16 = 0x88A8;
pub const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;

/// A 48-bit MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0x00; 6]);

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    /// Group bit set: broadcast or multicast delivery.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Locally administered address — common for randomised/virtual NICs.
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// The OUI (first three bytes) as a `AA:BB:CC` string.
    pub fn oui(&self) -> String {
        format!("{:02X}:{:02X}:{:02X}", self.0[0], self.0[1], self.0[2])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// A single VLAN tag from the stack (outermost first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanTag {
    pub tpid: u16,
    pub priority: u8,
    pub dei: bool,
    pub vid: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ethernet {
    pub dst: MacAddr,
    pub src: MacAddr,
    /// EtherType after any VLAN tags have been stripped.
    pub ethertype: u16,
    pub vlans: Vec<VlanTag>,
}

impl Ethernet {
    /// Innermost VLAN id, if the frame was tagged.
    pub fn vlan_id(&self) -> Option<u16> {
        self.vlans.last().map(|v| v.vid)
    }
}

/// Parse an Ethernet II header, unwrapping up to three stacked VLAN tags.
pub fn parse_ethernet(buf: &[u8]) -> Result<(Ethernet, &[u8])> {
    let mut r = Reader::new(buf, "ethernet");
    let dst = MacAddr(r.array::<6>()?);
    let src = MacAddr(r.array::<6>()?);
    let mut ethertype = r.be_u16()?;

    let mut vlans = Vec::new();
    // Q-in-Q in the wild rarely exceeds two tags; cap the loop so a crafted
    // frame of repeating 0x8100 cannot spin here.
    for _ in 0..3 {
        if !matches!(
            ethertype,
            ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_LEGACY
        ) {
            break;
        }
        let tci = r.be_u16()?;
        vlans.push(VlanTag {
            tpid: ethertype,
            priority: (tci >> 13) as u8,
            dei: (tci >> 12) & 1 == 1,
            vid: tci & 0x0FFF,
        });
        ethertype = r.be_u16()?;
    }

    Ok((
        Ethernet {
            dst,
            src,
            ethertype,
            vlans,
        },
        r.rest(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpOp {
    Request,
    Reply,
    Other(u16),
}

impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOp::Request => f.write_str("request"),
            ArpOp::Reply => f.write_str("reply"),
            ArpOp::Other(v) => write!(f, "op:{v}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arp {
    pub op: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl Arp {
    /// Gratuitous ARP: sender and target protocol addresses match. Legitimate
    /// on interface-up, but also the shape of an ARP-poisoning announcement.
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }
}

/// Parse ARP, restricted to the Ethernet/IPv4 binding (htype 1, ptype 0x0800).
pub fn parse_arp(buf: &[u8]) -> Result<Arp> {
    let mut r = Reader::new(buf, "arp");
    let htype = r.be_u16()?;
    let ptype = r.be_u16()?;
    let hlen = r.u8()?;
    let plen = r.u8()?;
    let op = r.be_u16()?;

    if htype != 1 || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(DecodeError::malformed(
            "arp",
            "only ethernet/ipv4 hardware bindings are decoded",
        ));
    }

    let sender_mac = MacAddr(r.array::<6>()?);
    let sender_ip = Ipv4Addr::from(r.array::<4>()?);
    let target_mac = MacAddr(r.array::<6>()?);
    let target_ip = Ipv4Addr::from(r.array::<4>()?);

    Ok(Arp {
        op: match op {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            other => ArpOp::Other(other),
        },
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// Human label for an EtherType, for display only.
pub fn ethertype_name(et: u16) -> &'static str {
    match et {
        ETHERTYPE_IPV4 => "IPv4",
        ETHERTYPE_ARP => "ARP",
        ETHERTYPE_IPV6 => "IPv6",
        0x8847 | 0x8848 => "MPLS",
        0x88CC => "LLDP",
        0x8863 | 0x8864 => "PPPoE",
        0x8035 => "RARP",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH_IPV4: [u8; 16] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst broadcast
        0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c, // src
        0x08, 0x00, // ipv4
        0xde, 0xad, // payload
    ];

    #[test]
    fn parses_plain_ethernet() {
        let (eth, payload) = parse_ethernet(&ETH_IPV4).unwrap();
        assert!(eth.dst.is_broadcast());
        assert_eq!(eth.src.to_string(), "00:0c:29:1a:2b:3c");
        assert_eq!(eth.src.oui(), "00:0C:29");
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert!(eth.vlans.is_empty());
        assert_eq!(payload, &[0xde, 0xad]);
    }

    #[test]
    fn unwraps_stacked_vlans() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00; 12]);
        frame.extend_from_slice(&[0x88, 0xa8]); // outer QinQ
        frame.extend_from_slice(&[0x20, 0x64]); // pcp 1, vid 100
        frame.extend_from_slice(&[0x81, 0x00]); // inner 802.1Q
        frame.extend_from_slice(&[0x00, 0xc8]); // vid 200
        frame.extend_from_slice(&[0x08, 0x00]); // ipv4
        frame.push(0x42);

        let (eth, payload) = parse_ethernet(&frame).unwrap();
        assert_eq!(eth.vlans.len(), 2);
        assert_eq!(eth.vlans[0].vid, 100);
        assert_eq!(eth.vlans[0].priority, 1);
        assert_eq!(eth.vlan_id(), Some(200));
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert_eq!(payload, &[0x42]);
    }

    #[test]
    fn truncated_frame_errors() {
        assert!(parse_ethernet(&[0x00; 8]).is_err());
    }

    #[test]
    fn parses_gratuitous_arp() {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x01]); // htype ethernet
        b.extend_from_slice(&[0x08, 0x00]); // ptype ipv4
        b.extend_from_slice(&[0x06, 0x04]); // hlen, plen
        b.extend_from_slice(&[0x00, 0x02]); // reply
        b.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]);
        b.extend_from_slice(&[192, 168, 1, 1]);
        b.extend_from_slice(&[0x00; 6]);
        b.extend_from_slice(&[192, 168, 1, 1]);

        let arp = parse_arp(&b).unwrap();
        assert_eq!(arp.op, ArpOp::Reply);
        assert!(arp.is_gratuitous());
        assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn rejects_non_ipv4_arp() {
        let b = [0x00, 0x01, 0x86, 0xdd, 0x06, 0x10, 0x00, 0x01];
        assert!(parse_arp(&b).is_err());
    }
}
