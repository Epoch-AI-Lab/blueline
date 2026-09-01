#![no_main]

use blueline::version::{AurVersionInfo, VersionInfo};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = AurVersionInfo::parse(s) {
            let canonical = v.canonical();
            assert!(
                AurVersionInfo::parse(&canonical).is_ok(),
                "canonical form of {s:?} re-parses"
            );
            let _ = v.is_prerelease();
        }
    }
});
