#![no_main]

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() > 64 * 1024 {
            return;
        }
        if let Ok(tokens) = blueline::pkgbuild::tokenize(s) {
            if let Ok(folded) = blueline::pkgbuild::resolve_vars(&tokens) {
                let _ = blueline::pkgbuild::check(&folded);
            }
        }
    }
});
