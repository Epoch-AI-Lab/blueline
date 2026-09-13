#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: String| {
    let refs = blueline::install_ref::scan_line(&data);
    // The scanner must never panic on hostile input, and any spec it
    // captures must round-trip through raw_ref without panicking either.
    for (manager, spec) in refs {
        let _ = blueline::install_ref::raw_ref(
            blueline::install_ref::RefOrigin::NpmLifecycle {
                script: "fuzz".to_string(),
            },
            manager,
            &spec,
        );
    }
});
