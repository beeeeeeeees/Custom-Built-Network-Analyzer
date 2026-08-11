//! Minimal UTC timestamp handling.
//!
//! Deliberately dependency-free: we only need a monotonic-ish wall clock value
//! per packet plus an RFC3339 rendering for reports.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp { secs: 0, nanos: 0 };

    pub fn new(secs: i64, nanos: u32) -> Self {
        Self {
            secs: secs + (nanos / 1_000_000_000) as i64,
            nanos: nanos % 1_000_000_000,
        }
    }

    pub fn from_micros(secs: i64, micros: u32) -> Self {
        Self::new(secs, micros.saturating_mul(1_000))
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.secs as f64 + self.nanos as f64 / 1e9
    }

    /// Seconds between two timestamps (`self - earlier`).
    pub fn delta_secs(&self, earlier: Timestamp) -> f64 {
        self.as_secs_f64() - earlier.as_secs_f64()
    }

    pub fn is_zero(&self) -> bool {
        self.secs == 0 && self.nanos == 0
    }

    /// Render as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub fn to_rfc3339(&self) -> String {
        let (y, mo, d, h, mi, s) = civil_from_unix(self.secs);
        format!(
            "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z",
            self.nanos / 1_000_000
        )
    }

    /// Render as `HH:MM:SS.ffffff`, the usual per-packet console form.
    pub fn to_time_of_day(&self) -> String {
        let (_, _, _, h, mi, s) = civil_from_unix(self.secs);
        format!("{h:02}:{mi:02}:{s:02}.{:06}", self.nanos / 1_000)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Days-to-civil conversion (Howard Hinnant's algorithm), then time of day.
fn civil_from_unix(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let rem = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format a byte count with a binary unit suffix.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Format a 0.0-1.0 ratio as a percentage, with precision scaled to magnitude.
///
/// Beacon jitter spans orders of magnitude: a two-minute heartbeat drifting
/// 5ms is 0.004%, while bursty traffic is 40%. Any fixed decimal count either
/// collapses the tight ones into a meaningless "0%" — losing exactly the
/// distinction that separates a metronome from a merely regular flow — or pads
/// the loose ones with digits that imply precision the estimate does not have.
pub fn human_percent(ratio: f64) -> String {
    let pct = ratio * 100.0;
    if !pct.is_finite() || pct <= 0.0 {
        "0%".to_string()
    } else if pct >= 10.0 {
        format!("{pct:.0}%")
    } else if pct >= 1.0 {
        format!("{pct:.1}%")
    } else if pct >= 0.1 {
        format!("{pct:.2}%")
    } else if pct >= 0.001 {
        format!("{pct:.3}%")
    } else {
        "<0.001%".to_string()
    }
}

/// Format a duration in seconds compactly (`1h02m`, `4.2s`, `310ms`).
pub fn human_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.1}s")
    } else if secs < 3600.0 {
        format!("{}m{:02}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    } else {
        format!(
            "{}h{:02}m",
            (secs / 3600.0) as u64,
            ((secs % 3600.0) / 60.0) as u64
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_renders() {
        assert_eq!(
            Timestamp::new(0, 0).to_rfc3339(),
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn known_instant_renders() {
        // 2026-08-10T12:34:56Z
        assert_eq!(
            Timestamp::new(1_786_365_296, 250_000_000).to_rfc3339(),
            "2026-08-10T12:34:56.250Z"
        );
    }

    #[test]
    fn micros_roll_into_secs() {
        let t = Timestamp::from_micros(10, 1_500_000);
        assert_eq!(t.secs, 11);
        assert_eq!(t.nanos, 500_000_000);
    }

    #[test]
    fn byte_and_duration_formatting() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_duration(0.31), "310ms");
        assert_eq!(human_duration(90.0), "1m30s");
    }

    #[test]
    fn percent_keeps_small_jitter_distinguishable() {
        // The real values that motivated this: a 120s mDNS heartbeat and a 9s
        // keepalive both rendered as "0%" under a fixed format.
        assert_ne!(human_percent(0.000_044_8), human_percent(0.004_068));
        assert_eq!(human_percent(0.004_068), "0.41%");
        assert_eq!(human_percent(0.000_448), "0.045%");
        assert_eq!(human_percent(0.0), "0%");
        assert_eq!(human_percent(0.000_000_9), "<0.001%");
    }

    #[test]
    fn percent_scales_precision_with_magnitude() {
        assert_eq!(human_percent(0.4237), "42%");
        assert_eq!(human_percent(0.0521), "5.2%");
        assert_eq!(human_percent(0.0037), "0.37%");
        assert_eq!(human_percent(f64::NAN), "0%");
    }
}
