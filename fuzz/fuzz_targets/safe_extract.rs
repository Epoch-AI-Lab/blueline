#![no_main]

use libfuzzer_sys::fuzz_target;
use blueline::extract::{safe_extract, ExtractionLimits};

fuzz_target!(|data: &[u8]| {
    let Ok(temp) = tempfile::tempdir() else { return };
    let limits = ExtractionLimits::default();
    let _ = safe_extract(data, temp.path(), &limits);
});
