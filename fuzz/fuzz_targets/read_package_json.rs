#![no_main]

use std::io::Write;
use libfuzzer_sys::fuzz_target;
use blueline::manifest::read_package_json;

fuzz_target!(|data: &[u8]| {
    let Ok(temp) = tempfile::tempdir() else { return };
    let json_path = temp.path().join("package.json");
    if let Ok(mut f) = std::fs::File::create(&json_path) {
        if f.write_all(data).is_ok() {
            let _ = read_package_json(&json_path);
        }
    }
});
