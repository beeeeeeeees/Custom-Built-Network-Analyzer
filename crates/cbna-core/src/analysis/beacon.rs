//! Periodicity scoring for C2-style beaconing.
//!
//! The signal is regularity of inter-arrival times. We use the median interval
//! and the median absolute deviation rather than mean/stddev: real beacons run
//! through packet loss, sleep-skew and retries, and a handful of large gaps
//! would wreck a mean-based score while barely moving the median.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconScore {
    pub flow: String,
    pub destination: String,
    pub sni: Option<String>,
    /// Median seconds between packets.
    pub interval: f64,
    /// Normalised MAD; 0.0 is a metronome, 1.0 is noise.
    pub jitter: f64,
    /// 0.0-1.0, combining regularity with how much evidence backs it.
    pub confidence: f64,
    /// Number of inter-arrival samples scored.
    pub samples: usize,
    /// Span covered by those samples.
    pub total_seconds: f64,
    pub samples_truncated: bool,
}

/// Score a series of packet timestamps (seconds, any epoch).
///
/// Returns `None` when there is too little to say anything: fewer than four
/// intervals, or a degenerate series where every packet shares a timestamp.
pub fn score_intervals(timestamps: &[f64]) -> Option<BeaconScore> {
    if timestamps.len() < 5 {
        return None;
    }

    let mut deltas: Vec<f64> = timestamps
        .windows(2)
        .map(|w| w[1] - w[0])
        .filter(|d| *d > 0.0)
        .collect();
    if deltas.len() < 4 {
        return None;
    }

    let total_seconds = timestamps[timestamps.len() - 1] - timestamps[0];
    deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let interval = median_sorted(&deltas);
    if interval <= 0.0 {
        return None;
    }

    // Median absolute deviation, scaled by the interval so the score is
    // dimensionless and comparable across a 1s beacon and a 1h beacon.
    let mut abs_dev: Vec<f64> = deltas.iter().map(|d| (d - interval).abs()).collect();
    abs_dev.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = median_sorted(&abs_dev);
    let jitter = (mad / interval).min(1.0);

    // Evidence weighting: 5 intervals is thin, 30+ is convincing.
    let evidence = ((deltas.len() as f64 - 4.0) / 26.0).clamp(0.0, 1.0);
    let regularity = 1.0 - jitter;
    let confidence = (regularity * (0.6 + 0.4 * evidence)).clamp(0.0, 1.0);

    Some(BeaconScore {
        flow: String::new(),
        destination: String::new(),
        sni: None,
        interval,
        jitter,
        confidence,
        samples: deltas.len(),
        total_seconds,
        samples_truncated: false,
    })
}

fn median_sorted(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(start: f64, interval: f64, n: usize, jitter: impl Fn(usize) -> f64) -> Vec<f64> {
        (0..n)
            .map(|i| start + interval * i as f64 + jitter(i))
            .collect()
    }

    #[test]
    fn metronome_scores_high() {
        let ts = series(1000.0, 60.0, 40, |_| 0.0);
        let s = score_intervals(&ts).unwrap();
        assert!((s.interval - 60.0).abs() < 1e-9);
        assert_eq!(s.jitter, 0.0);
        assert!(s.confidence > 0.95, "confidence was {}", s.confidence);
        assert_eq!(s.samples, 39);
    }

    #[test]
    fn small_jitter_still_scores_as_a_beacon() {
        // +/- 5% sleep skew, the shape most implants actually produce.
        let ts = series(0.0, 30.0, 30, |i| if i % 2 == 0 { 1.2 } else { -1.1 });
        let s = score_intervals(&ts).unwrap();
        assert!(s.jitter < 0.20, "jitter was {}", s.jitter);
        assert!((s.interval - 30.0).abs() < 3.0);
        assert!(s.confidence > 0.7);
    }

    #[test]
    fn bursty_traffic_scores_low() {
        let ts = vec![
            0.0, 0.01, 0.02, 0.4, 12.0, 12.1, 60.0, 61.5, 300.0, 300.2, 301.0, 900.0,
        ];
        let s = score_intervals(&ts).unwrap();
        assert!(s.jitter > 0.5, "jitter was {}", s.jitter);
        assert!(s.confidence < 0.5);
    }

    #[test]
    fn a_few_dropped_check_ins_do_not_break_the_score() {
        // 60s beacon that misses two check-ins partway through.
        let mut ts: Vec<f64> = (0..20).map(|i| i as f64 * 60.0).collect();
        ts.retain(|t| *t != 480.0 && *t != 540.0);
        let s = score_intervals(&ts).unwrap();
        assert!((s.interval - 60.0).abs() < 1e-9);
        assert!(s.jitter < 0.05, "median was robust: jitter {}", s.jitter);
    }

    #[test]
    fn refuses_thin_or_degenerate_input() {
        assert!(score_intervals(&[]).is_none());
        assert!(score_intervals(&[1.0, 2.0, 3.0]).is_none());
        assert!(score_intervals(&[5.0; 10]).is_none());
    }
}
