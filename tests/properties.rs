//! Property-based invariants over the fail-closed surfaces.
//!
//! The scenario suite pins specific attacks; these properties pin the
//! *general* invariant behind them, over generated inputs:
//!
//! - version ordering is a total order in every ecosystem grammar;
//! - a policy that parses round-trips through TOML with identical semantics;
//! - extraction, on any archive the fixture writer can express, either fails
//!   closed or writes nothing outside the extraction root.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use blueline::extract::{ExtractionLimits, safe_extract};
use blueline::policy::Policy;
use blueline::version::{AurVersionInfo, Pep440Version, VersionInfo};

// ---------------------------------------------------------------------------
// Version ordering is a total order
// ---------------------------------------------------------------------------

fn pep440_strategy() -> impl Strategy<Value = String> {
    (
        prop::option::of(0u64..4u64),
        prop::collection::vec(0u64..1000u64, 1..5usize),
        prop::option::of((prop::sample::select(vec!["a", "b", "rc"]), 0u64..30u64)),
        prop::option::of(0u64..50u64),
        prop::option::of(0u64..50u64),
    )
        .prop_map(|(epoch, release, pre, post, dev)| {
            let mut s = String::new();
            if let Some(e) = epoch {
                s.push_str(&format!("{e}!"));
            }
            s.push_str(
                &release
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join("."),
            );
            if let Some((kind, n)) = pre {
                s.push_str(&format!("{kind}{n}"));
            }
            if let Some(p) = post {
                s.push_str(&format!(".post{p}"));
            }
            if let Some(d) = dev {
                s.push_str(&format!(".dev{d}"));
            }
            s
        })
}

fn semver_strategy() -> impl Strategy<Value = String> {
    (
        0u64..50u64,
        0u64..50u64,
        0u64..50u64,
        prop::option::of(prop::sample::select(vec![
            "alpha".to_string(),
            "alpha.1".to_string(),
            "beta.2".to_string(),
            "rc.0".to_string(),
            "0".to_string(),
            "1".to_string(),
        ])),
        prop::option::of(prop::sample::select(vec![
            "abc".to_string(),
            "007".to_string(),
            "x.1".to_string(),
        ])),
    )
        .prop_map(|(maj, min, patch, pre, local)| {
            let mut s = format!("{maj}.{min}.{patch}");
            if let Some(pre) = pre {
                s.push('-');
                s.push_str(&pre);
            }
            if let Some(local) = local {
                s.push('+');
                s.push_str(&local);
            }
            s
        })
}

fn aur_strategy() -> impl Strategy<Value = String> {
    (
        prop::option::of(0u64..10u64),
        prop::collection::vec(
            (
                prop::sample::select(vec!["1", "42", "20240101", "r", "abc", "7"]),
                0u64..100u64,
            ),
            1..4usize,
        ),
        prop::option::of(0u64..20u64),
    )
        .prop_map(|(epoch, segments, pkgrel)| {
            let mut s = String::new();
            if let Some(e) = epoch {
                s.push_str(&format!("{e}:"));
            }
            s.push_str(
                &segments
                    .iter()
                    .map(|(kind, n)| format!("{kind}{n}"))
                    .collect::<Vec<_>>()
                    .join("."),
            );
            if let Some(rel) = pkgrel {
                s.push_str(&format!("-{rel}"));
            }
            s
        })
}

/// The anchors: concrete strings the grammar must accept, so the strategies
/// above cannot silently drift into generating strings that all fail to
/// parse (a vacuous property).
#[test]
fn version_grammars_accept_the_anchor_forms() {
    for s in [
        "1.0",
        "1!2.0",
        "1.0a1",
        "1.0b2",
        "1.0rc3",
        "1.0.post1",
        "1.0.dev1",
    ] {
        assert!(Pep440Version::parse(s).is_ok(), "PEP 440 rejected `{s}`");
    }
    for s in ["1.2.3", "1.2.3-1", "2:1.0.0-1", "0.9.1-5"] {
        assert!(AurVersionInfo::parse(s).is_ok(), "AUR rejected `{s}`");
    }
}

/// A representative document in the generator's exact output shape must
/// parse, validate, and round-trip. If the TOML the generator emits ever
/// stops matching serde's expectations, this fails loudly instead of letting
/// `policy_toml_roundtrip` silently skip every case as unparseable.
#[test]
fn policy_generator_produces_parsable_documents() {
    let doc = "\n[thresholds]\nmax_low_score = 5\nmax_medium_score = 10\nblock_score = 20\n\
               [policy]\nrequire_provenance = false\nblock_unreviewed_scripts = true\n\
               require_sandbox = false\nallow_git_dependencies = false\n\
               check_advisories = true\nfail_closed_network = false\n\
               [advisories]\nblock_on_malware = true\nblock_on_critical_cve = true\n\
               cache_ttl_hours_clean = 12\ncache_ttl_hours_vulnerable = 1\n\
               [provenance]\nrequire_provenance = false\nrequire_signatures = false\nallowed_builders = []\n\
               [ci]\nfail_on = \"high\"\nmax_evaluations = 100\ninclude_dev = true\n\
               allow_requirements_options = false\n\
               [recursion]\nmax_depth = 3\nmax_child_reviews = 8\nchild_block_band = \"HIGH\"\n";
    let policy = Policy::from_toml_str(doc).expect("generator-shaped document must parse");
    policy
        .validate()
        .expect("generator-shaped document must validate");
    let reserialized = toml::to_string(&policy).expect("re-serialize");
    let reparsed = Policy::from_toml_str(&reserialized).expect("re-parse");
    assert_eq!(policy, reparsed);
}

macro_rules! total_order_properties {
    ($mod_name:ident, $ty:ty, $strategy:expr) => {
        mod $mod_name {
            use super::*;

            proptest! {
                #[test]
                fn antisymmetric(a in $strategy, b in $strategy) {
                    if let (Ok(va), Ok(vb)) = (<$ty>::parse(&a), <$ty>::parse(&b)) {
                        prop_assert_eq!(va.cmp(&vb), vb.cmp(&va).reverse());
                    }
                }

                #[test]
                fn transitive(v in proptest::collection::vec($strategy, 1..6)) {
                    let parsed: Vec<_> = v.iter().filter_map(|s| <$ty>::parse(s).ok()).collect();
                    for i in 0..parsed.len() {
                        for j in 0..parsed.len() {
                            for k in 0..parsed.len() {
                                if parsed[i] <= parsed[j] && parsed[j] <= parsed[k] {
                                    prop_assert!(parsed[i] <= parsed[k]);
                                }
                            }
                        }
                    }
                }

                #[test]
                fn reflexive_and_connected(a in $strategy, b in $strategy) {
                    if let (Ok(va), Ok(vb)) = (<$ty>::parse(&a), <$ty>::parse(&b)) {
                        prop_assert_eq!(va.cmp(&va), std::cmp::Ordering::Equal);
                        prop_assert!(va.cmp(&vb) != std::cmp::Ordering::Equal || va == vb);
                    }
                }
            }
        }
    };
}

total_order_properties!(pep440_order, Pep440Version, pep440_strategy());
total_order_properties!(semver_order, semver::Version, semver_strategy());
total_order_properties!(aur_order, AurVersionInfo, aur_strategy());

// ---------------------------------------------------------------------------
// Policy TOML round-trip
// ---------------------------------------------------------------------------

fn band_name_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "HIGH".to_string(),
        "MEDIUM".to_string(),
        "LOW".to_string(),
        "BLOCK".to_string(),
    ])
}

fn builder_name_strategy() -> impl Strategy<Value = String> {
    // `string_regex` cannot fail on a constant pattern; expect, not unwrap,
    // because this helper is outside a #[test] fn.
    prop::string::string_regex("[a-z]{3,12}").expect("valid regex")
}

fn policy_toml_strategy() -> impl Strategy<Value = String> {
    (
        (0u32..20u32, 0u32..30u32, 0u32..50u32),
        // Nine policy booleans, in the fixed order they appear below.
        prop::collection::vec(any::<bool>(), 9usize),
        (1u64..100u64, 1u64..100u64),
        0u32..10u32,
        prop::sample::select(vec![
            "low".to_string(),
            "medium".to_string(),
            "high".to_string(),
            "block".to_string(),
        ]),
        (1usize..500usize, any::<bool>(), any::<bool>()),
        band_name_strategy(),
        prop::option::of(builder_name_strategy()),
    )
        .prop_map(
            |(
                (low, med_off, block_off),
                bools,
                (ttl_clean, ttl_vulnerable),
                recursion_depth,
                fail_on,
                (max_evaluations, include_dev, allow_requirements_options),
                child_block_band,
                builder,
            )| {
                let (
                    require_provenance,
                    block_unreviewed_scripts,
                    require_sandbox,
                    allow_git_dependencies,
                    check_advisories,
                    fail_closed_network,
                    block_on_malware,
                    block_on_critical_cve,
                    _unused,
                ) = (
                    bools[0], bools[1], bools[2], bools[3], bools[4], bools[5], bools[6], bools[7],
                    bools[8],
                );
                // Thresholds stay ordered so the document is valid by
                // construction; ordering validation is a separate concern.
                let max_medium_score = low + 1 + med_off;
                let block_score = max_medium_score + 1 + block_off;
                let builders_line = match &builder {
                    Some(b) => format!("allowed_builders = [\"{b}\"]\n"),
                    None => "allowed_builders = []\n".to_string(),
                };
                format!(
                    "[thresholds]\nmax_low_score = {low}\nmax_medium_score = {max_medium_score}\nblock_score = {block_score}\n\
                     [policy]\nrequire_provenance = {require_provenance}\nblock_unreviewed_scripts = {block_unreviewed_scripts}\n\
                     require_sandbox = {require_sandbox}\nallow_git_dependencies = {allow_git_dependencies}\n\
                     check_advisories = {check_advisories}\nfail_closed_network = {fail_closed_network}\n\
                     [advisories]\nblock_on_malware = {block_on_malware}\nblock_on_critical_cve = {block_on_critical_cve}\n\
                     cache_ttl_hours_clean = {ttl_clean}\ncache_ttl_hours_vulnerable = {ttl_vulnerable}\n\
                     [provenance]\nrequire_provenance = {require_provenance}\nrequire_signatures = false\n{builders_line}\
                     [ci]\nfail_on = \"{fail_on}\"\nmax_evaluations = {max_evaluations}\ninclude_dev = {include_dev}\n\
                     allow_requirements_options = {allow_requirements_options}\n\
                     [recursion]\nmax_depth = {recursion_depth}\nmax_child_reviews = 8\nchild_block_band = \"{child_block_band}\"\n"
                )
            },
        )
}

proptest! {
    /// A policy that loads must round-trip through TOML with identical
    /// semantics: `deny_unknown_fields` plus `serde(default)` is exactly the
    /// combination where a renamed key silently drops a field, and the
    /// round-trip is what catches it.
    #[test]
    fn policy_toml_roundtrip(doc in policy_toml_strategy()) {
        let policy = match Policy::from_toml_str(&doc) {
            Ok(p) => p,
            // Fail-closed refusal of a document is allowed; the generators
            // produce valid documents by construction, so anything rejected
            // here shows up in local runs as a suspicious skip.
            Err(_) => return Ok(()),
        };
        let reserialized = toml::to_string(&policy).expect("parsed policy re-serializes");
        let reparsed = match Policy::from_toml_str(&reserialized) {
            Ok(p) => p,
            Err(e) => {
                prop_assert!(false, "re-serialized policy must re-parse: {e}");
                return Ok(());
            }
        };
        prop_assert_eq!(policy, reparsed);
    }
}

// ---------------------------------------------------------------------------
// Extraction containment
// ---------------------------------------------------------------------------

/// One generated archive entry. Benign entries may extract; hostile ones
/// (traversal, absolute, device names, symlinks) must be refused or skipped,
/// never written.
#[derive(Debug, Clone)]
enum Spec {
    File { path: String, contents: String },
    Dir { path: String },
    Symlink { path: String, target: String },
}

fn benign_rel_path() -> impl Strategy<Value = String> {
    "[a-z]{1,6}/[a-z]{1,6}(/[a-z]{1,6})?"
}

fn archive_spec_strategy() -> impl Strategy<Value = Vec<Spec>> {
    prop::collection::vec(
        prop_oneof![
            // Benign relative path.
            benign_rel_path().prop_map(|p| Spec::File {
                path: format!("package/{p}.js"),
                contents: "ok".to_string(),
            }),
            // Parent traversal.
            benign_rel_path().prop_map(|p| Spec::File {
                path: format!("package/../{p}.txt"),
                contents: "x".to_string(),
            }),
            // Deep traversal out of the root.
            benign_rel_path().prop_map(|p| Spec::File {
                path: format!("package/../../{p}.txt"),
                contents: "x".to_string(),
            }),
            // Absolute path.
            benign_rel_path().prop_map(|p| Spec::File {
                path: format!("/{p}.txt"),
                contents: "x".to_string(),
            }),
            // Windows reserved device name as the final component.
            benign_rel_path().prop_map(|p| Spec::File {
                path: format!("package/{p}/CONIN$"),
                contents: "x".to_string(),
            }),
            // Symlink naming an outside target.
            benign_rel_path().prop_map(|p| Spec::Symlink {
                path: format!("package/{p}"),
                target: "../../../outside".to_string(),
            }),
            // Plain directory.
            benign_rel_path().prop_map(|p| Spec::Dir {
                path: format!("package/{p}"),
            }),
        ],
        1..8usize,
    )
}

fn is_clean_rel(rel: &str) -> bool {
    let path = Path::new(rel);
    if path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return false;
    }
    match path.file_name().map(|n| n.to_string_lossy().to_uppercase()) {
        Some(n) => !matches!(
            n.as_str(),
            "CONIN$" | "CONOUT$" | "CLOCK$" | "NUL" | "CON" | "PRN" | "AUX"
        ),
        None => true,
    }
}

/// The relative paths a successful extraction is allowed to have produced:
/// the clean benign entries plus the ancestor directories the extractor
/// creates implicitly.
fn expected_clean_paths(specs: &[Spec]) -> Vec<String> {
    let mut clean: Vec<String> = Vec::new();
    for spec in specs {
        let rel = match spec {
            Spec::File { path, .. } | Spec::Dir { path } => path.clone(),
            // Symlinks are refused outright by the extractor, never created.
            Spec::Symlink { .. } => continue,
        };
        if !rel.starts_with("package/") || !is_clean_rel(&rel) {
            continue;
        }
        clean.push(rel.clone());
        let mut ancestor = Path::new(&rel).to_path_buf();
        while let Some(parent) = ancestor.parent() {
            if parent == Path::new("") {
                break;
            }
            clean.push(
                parent
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
            ancestor = parent.to_path_buf();
        }
    }
    clean.sort();
    clean.dedup();
    clean
}

fn rel_components_under(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(root) else {
        return;
    };
    for entry in read.filter_map(Result::ok) {
        let path = entry.path();
        out.push(path.clone());
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            rel_components_under(&path, out);
        }
    }
}

proptest! {
    /// Any archive the fixture writer can express either fails closed or
    /// extracts exactly the benign subset inside `dest`. Nothing may appear
    /// beside `dest`, and nothing inside it may carry a `..` component, a
    /// device name, or a canonical form that leaves the extraction root.
    #[test]
    fn extraction_either_fails_closed_or_stays_inside(specs in archive_spec_strategy()) {
        let entries: Vec<support::Entry> = specs
            .iter()
            .map(|spec| match spec {
                Spec::File { path, contents } => support::Entry::file(path, contents.as_bytes()),
                Spec::Dir { path } => support::Entry::dir(path),
                Spec::Symlink { path, target } => support::Entry::symlink(path, target),
            })
            .collect();
        let tarball = support::archive(&entries);

        let tmp = tempfile::tempdir().expect("create scratch dir");
        let dest = tmp.path().join("dest");
        fs::create_dir(&dest).expect("create dest dir");

        let result = safe_extract(&tarball, &dest, &ExtractionLimits::default());

        // Nothing may exist beside `dest` inside the scratch dir.
        let siblings: Vec<String> = fs::read_dir(tmp.path())
            .expect("read scratch dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        prop_assert!(
            siblings.iter().all(|n| n == "dest"),
            "archive wrote outside dest: {siblings:?}"
        );

        let Ok(_stats) = result else {
            // Fail-closed refusal is a valid outcome.
            return Ok(());
        };

        let dest_canon = dest.canonicalize().expect("canonicalize dest");
        let expected = expected_clean_paths(&specs);
        let mut found = Vec::new();
        rel_components_under(&dest, &mut found);
        for path in found {
            let rel = path
                .strip_prefix(&dest)
                .expect("path under dest")
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            prop_assert!(
                is_clean_rel(&rel),
                "extracted path `{rel}` carries a traversal component or device name"
            );
            prop_assert!(
                expected.iter().any(|e| e == &rel),
                "extracted path `{rel}` corresponds to no benign archive entry"
            );
            let canon = path.canonicalize().expect("canonicalize extracted path");
            prop_assert!(
                canon.starts_with(&dest_canon),
                "canonicalized path `{}` escaped dest",
                canon.display()
            );
        }
    }
}
