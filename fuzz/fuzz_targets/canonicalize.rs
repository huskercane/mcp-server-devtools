//! libFuzzer target for `policy::canonical` (plan §3.5, WP A.6 / A.10).
//!
//! The invariants asserted here are the same ones
//! `tests/canonicalization_tests.rs` checks over a seeded corpus on stable;
//! this target lets libFuzzer search for inputs that break them. Any panic
//! here is a bug in the canonicalizer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcp_server_devtools::policy::canonical::invariants;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    invariants::check(input);
});
