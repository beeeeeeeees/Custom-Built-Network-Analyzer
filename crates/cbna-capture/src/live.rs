//! Live capture from a network interface, via libpcap (Npcap on Windows).
//!
//! Compiled only with `--features live`, because it needs the platform capture
//! library present at build time.

use crate::{CaptureError, RawPacket, Source};
use cbna_core::packet::LinkType;
use cbna_core::Timestamp;
use pcap::{Active, Capture, Device};

/// A capture-capable interface.
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub is_loopback: bool,
    pub is_up: bool,
}

/// Enumerate interfaces the current process can open.
pub fn list_interfaces() -> Result<Vec<Interface>, CaptureError> {
    let devices = Device::list()?;
    Ok(devices
        .into_iter()
        .map(|d| Interface {
            is_loopback: d.flags.is_loopback(),
            is_up: d.flags.is_up(),
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
            description: d.desc,
            name: d.name,
        })
        .collect())
}

/// How a live capture should be opened.
#[derive(Debug, Clone)]
pub struct LiveConfig {
    pub interface: String,
    pub promiscuous: bool,
    pub snaplen: i32,
    /// Read timeout in milliseconds; also bounds how long a quiet interface
    /// blocks before the loop can check for shutdown.
    pub timeout_ms: i32,
    /// BPF filter expression, e.g. `tcp port 443`.
    pub filter: Option<String>,
    /// Kernel buffer size in bytes. Larger absorbs bursts without drops.
    pub buffer_size: i32,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            promiscuous: true,
            snaplen: 65_535,
            timeout_ms: 250,
            filter: None,
            buffer_size: 16 * 1024 * 1024,
        }
    }
}

pub struct LiveSource {
    capture: Capture<Active>,
    link_type: LinkType,
    interface: String,
    index: u64,
    /// Packets libpcap reports as dropped, refreshed on each stats call.
    dropped: u64,
}

impl LiveSource {
    pub fn open(config: &LiveConfig) -> Result<Self, CaptureError> {
        let device = if config.interface.is_empty() {
            Device::lookup()?.ok_or_else(|| {
                CaptureError::Malformed("no default capture interface is available".into())
            })?
        } else {
            Device::list()?
                .into_iter()
                .find(|d| {
                    d.name == config.interface
                        || d.desc.as_deref() == Some(config.interface.as_str())
                })
                .ok_or_else(|| {
                    CaptureError::Malformed(format!(
                        "no interface named or described as '{}'",
                        config.interface
                    ))
                })?
        };
        let name = device.name.clone();

        let mut capture = Capture::from_device(device)?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .timeout(config.timeout_ms)
            .buffer_size(config.buffer_size)
            // Deliver packets as they arrive rather than batching, so the
            // dashboard is not several seconds behind the wire.
            .immediate_mode(true)
            .open()?;

        if let Some(filter) = &config.filter {
            capture.filter(filter, true)?;
        }

        let link_type = LinkType::from_u32(capture.get_datalink().0 as u32);

        Ok(Self {
            capture,
            link_type,
            interface: name,
            index: 0,
            dropped: 0,
        })
    }

    /// Packets dropped by the capture engine since the last check.
    pub fn dropped(&mut self) -> u64 {
        if let Ok(stats) = self.capture.stats() {
            self.dropped = stats.dropped as u64 + stats.if_dropped as u64;
        }
        self.dropped
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl Source for LiveSource {
    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn next_packet(&mut self) -> Option<Result<RawPacket, CaptureError>> {
        loop {
            match self.capture.next_packet() {
                Ok(packet) => {
                    self.index += 1;
                    let ts = Timestamp::from_micros(
                        packet.header.ts.tv_sec as i64,
                        packet.header.ts.tv_usec as u32,
                    );
                    return Some(Ok(RawPacket::new(
                        self.index,
                        ts,
                        packet.header.len,
                        packet.data.to_vec(),
                    )));
                }
                // A quiet interface hits the read timeout; that is not an error,
                // so keep waiting rather than ending the stream.
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return None,
                Err(e) => return Some(Err(e.into())),
            }
        }
    }

    fn description(&self) -> String {
        format!("live: {} ({})", self.interface, self.link_type.name())
    }
}
