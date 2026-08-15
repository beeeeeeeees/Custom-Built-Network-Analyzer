//! Thin wrapper. The body lives in `cbna_intel::fuzz` so this target and the
//! stable harness in `crates/cbna-intel/tests/fuzz_smoke.rs` cannot drift.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cbna_intel::fuzz::parse_feed(data));
