//! Fuzz target that parses arbitrary bytes as PE headers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::PeHeaders;

fuzz_target!(|data: &[u8]| {
    let _ = PeHeaders::from_slice(data);
});
