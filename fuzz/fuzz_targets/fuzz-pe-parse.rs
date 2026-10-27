//! Fuzz target that parses arbitrary bytes as PE files and as PE images.

#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::{PeFile, PeImage};

fuzz_target!(|data: &[u8]| {
    let _ = PeImage::parse(data);
    let _ = PeImage::parse_mapped(data);
    let _ = PeFile::parse(data);
});
