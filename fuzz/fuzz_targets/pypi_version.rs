#![no_main]

use libfuzzer_sys::fuzz_target;
use blueline::version::{Pep440Version, VersionInfo};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = Pep440Version::parse(s) {
            let canonical = v.canonical();
            assert!(Pep440Version::parse(&canonical).is_ok());
            let _ = v.is_prerelease();
        }
    }
});
