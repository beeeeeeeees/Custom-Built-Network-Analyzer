//! Shared fuzz entry point for the feed parsers.
//!
//! See `cbna_core::fuzz` for why these live in the library rather than in the
//! `fuzz/` targets. Feed bytes come from a third party over the network, so the
//! parser must return normally on anything; this runs every built-in feed's
//! format over the same input and reads the result back.

use crate::feed::BUILTIN;
use crate::parse::parse_into;
use cbna_core::ioc::IocSet;
use std::hint::black_box;

/// Parse arbitrary bytes as each built-in feed format. No panics, and no work
/// beyond the input's own line count.
pub fn parse_feed(data: &[u8]) {
    for feed in BUILTIN {
        let mut set = IocSet::default();
        black_box(parse_into(&mut set, feed, data));
        black_box(set.len());
    }
}
