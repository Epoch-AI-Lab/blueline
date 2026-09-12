//! Dogfood: blueline reviews its own distribution artifacts. The AUR
//! scaffold PKGBUILD must pass our own PKGBUILD heuristics before it ever
//! lands on the AUR, and the npm shims must parse as valid manifests.

use std::path::PathBuf;

#[test]
fn our_aur_pkgbuild_passes_our_own_heuristics() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/aur/PKGBUILD");
    let content = std::fs::read_to_string(&path).unwrap();
    let findings = blueline::pkgbuild::review_text(&content).unwrap();
    let loud: Vec<_> = findings
        .iter()
        .filter(|f| f.severity > blueline::verdict::VerdictBand::Low)
        .collect();
    assert!(
        loud.is_empty(),
        "our own AUR scaffold must not trip our own heuristics above INFO: {loud:?}"
    );
}

#[test]
fn npm_shims_declare_the_published_platform_matrix() {
    let expected: [&str; 7] = [
        "@bluelinecli/binary-darwin-arm64",
        "@bluelinecli/binary-darwin-x64",
        "@bluelinecli/binary-linux-arm64-gnu",
        "@bluelinecli/binary-linux-x64-musl",
        "@bluelinecli/binary-linux-x64-gnu",
        "@bluelinecli/binary-win32-arm64",
        "@bluelinecli/binary-win32-x64",
    ];
    for shim in [
        "packages/blueline/package.json",
        "packages/npx/package.json",
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(shim);
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let deps = manifest["optionalDependencies"].as_object().unwrap();
        for platform in expected {
            assert!(
                deps.contains_key(platform),
                "{shim} must carry {platform} so that platform installs a working launcher"
            );
        }
        assert_eq!(deps.len(), expected.len(), "{shim} carries stray platforms");
    }
}
