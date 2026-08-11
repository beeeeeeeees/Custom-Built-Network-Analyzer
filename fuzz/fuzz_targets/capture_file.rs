//! Thin wrapper. The body lives in `cbna_capture::fuzz` so this target and the
//! stable harness in `crates/cbna-capture/tests/fuzz_smoke.rs` cannot drift.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cbna_capture::fuzz::capture_file(data));
