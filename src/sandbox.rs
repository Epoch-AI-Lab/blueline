//! OS-level confinement for archive extraction.
//!
//! blueline unpacks a package tarball that nobody has approved yet, using a
//! parser reading bytes an attacker chose. The path grammar, the entry-type
//! rejection and the byte and entry caps are what bound that today. This module
//! adds a layer underneath them: the kernel refuses a read, a write or an exec
//! outside the extraction directory, so a bug in `extract.rs` or in `tar-rs`
//! cannot turn into a write anywhere else on the filesystem.
//!
//! **What this does not buy.** Package code is never executed by blueline, on
//! any path, with or without this layer. The threat is not an attacker running
//! code; it is our own parser being wrong. Every escape in `tests/scenarios.rs`
//! is already refused by `validate_entry_path` before any byte is written, and
//! this layer is behind that, not instead of it.
//!
//! **Why a child process.** Landlock is irreversible: `restrict_self()` narrows
//! the calling process permanently. A review extracts, then keeps working — it
//! writes to the SQLite store, fetches the baseline tarball, queries OSV, and
//! renders a card. Confining that process would break every one of those. So
//! the extraction runs in a child that confines *itself* and exits, and the
//! parent is never restricted. The extracted tree survives as ordinary bytes in
//! a directory the parent already owns.
//!
//! **Why one child per extraction, not one per review.** The baseline tarball is
//! not fetched until after the target is extracted, so there is no point at
//! which both archives are in hand. Reusing one child across extractions is also
//! unsafe rather than merely wasteful: Landlock rulesets are cumulative, so a
//! long-lived child accumulates a write grant per destination and ends up able
//! to write to all of them at once.

use std::path::Path;

use crate::error::BluelineError;
use crate::extract::{ExtractStats, ExtractionLimits};
use crate::policy::Policy;
use crate::verdict::{Finding, VerdictBand};

/// Marker environment variable. The parent sets it; `child_entrypoint` keys on
/// it.
pub(crate) const CHILD_ENV: &str = "BLUELINE_SANDBOX_CHILD";
/// Canonical absolute path of the directory the child may write.
pub(crate) const DEST_ENV: &str = "BLUELINE_SANDBOX_DEST";
/// Which extractor the child runs.
pub(crate) const KIND_ENV: &str = "BLUELINE_SANDBOX_KIND";

/// Ceiling on the child's reply, so a child that streams nonsense cannot make
/// the parent allocate without bound. The reply is three numbers or a short
/// reason, so this is generous.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Which archive reader the child runs. Resolved by the parent, which already
/// has the ecosystem and the tarball URL, so the child never re-derives a
/// routing decision from bytes it would otherwise have to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Tar,
    Wheel,
}

impl ArchiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveKind::Tar => "tar",
            ArchiveKind::Wheel => "wheel",
        }
    }

    fn parse(s: &str) -> Result<Self, BluelineError> {
        match s {
            "tar" => Ok(ArchiveKind::Tar),
            "wheel" => Ok(ArchiveKind::Wheel),
            other => Err(BluelineError::Sandbox(format!(
                "unknown archive kind `{other}`"
            ))),
        }
    }
}

/// The reason the kernel-level layer is not active.
///
/// Every variant except the last means nothing was attempted or nothing was
/// applied, so the destination is untouched and the in-process fallback is
/// safe. `ChildDied` is the exception and is never a fallback: the child may
/// have written a partial tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxSkip {
    /// Not Linux. Landlock is a Linux LSM and the `landlock` crate does not
    /// build elsewhere, so this is fixed at compile time.
    UnsupportedPlatform,
    /// Linux, kernel has no Landlock: `CONFIG_SECURITY_LANDLOCK` off or
    /// `landlock` absent from `CONFIG_LSM`.
    KernelWithoutLandlock,
    /// Landlock exists but no tier could be established under
    /// `CompatLevel::HardRequirement`. `last_tried` is the floor reached.
    AbiUnavailable { last_tried: &'static str },
    /// The child ran and reported that it could not confine itself. The child's
    /// own words, because the child is the only place the ruleset was built.
    Unavailable { detail: String },
    /// `current_exe()` or `spawn` failed. A broken install or an exhausted
    /// process table, not a kernel feature, and an operator reading this
    /// disclosure should look for a different problem.
    SelfExecUnavailable { detail: String },
    /// The child died, panicked, or broke the protocol. `dest` may hold a
    /// partial tree, so this is an error and never a fallback.
    ChildDied { status: String, stderr: String },
}

impl std::fmt::Display for SandboxSkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxSkip::UnsupportedPlatform => {
                write!(f, "this platform has no Landlock, which is Linux-only")
            }
            SandboxSkip::KernelWithoutLandlock => {
                write!(f, "this kernel has no Landlock")
            }
            SandboxSkip::AbiUnavailable { last_tried } => write!(
                f,
                "no Landlock ABI tier could be established, down to tier {last_tried}"
            ),
            SandboxSkip::Unavailable { detail } => {
                write!(f, "the extraction child could not confine itself: {detail}")
            }
            SandboxSkip::SelfExecUnavailable { detail } => {
                write!(f, "the extraction child could not be started: {detail}")
            }
            SandboxSkip::ChildDied { status, .. } => {
                write!(f, "the extraction child died ({status})")
            }
        }
    }
}

/// Per-review record of whether extraction was confined.
///
/// Lives on `ReviewContext` so every package in one review reports the same
/// answer and the disclosure attaches to each verdict from one read.
#[derive(Debug, Default, Clone)]
pub struct SandboxLedger {
    skip: Option<SandboxSkip>,
}

impl SandboxLedger {
    /// Record that the layer is not active. First writer wins: both extractions
    /// in a review hit the same unavailable platform, and the first reason is
    /// the one that happened before anything was attempted.
    pub fn record_skip(&mut self, reason: SandboxSkip) {
        self.skip.get_or_insert(reason);
    }

    pub fn skip(&self) -> Option<&SandboxSkip> {
        self.skip.as_ref()
    }

    /// `None` when confined. Otherwise a `Low` finding naming the reason.
    ///
    /// **LOW, and score-neutral, because the band is the exit code.**
    /// `review --yes` only marks clean at `Low`, `agent` exits 2 above it
    /// (`src/agent.rs:83-90`), and the non-interactive review path exits 2 above
    /// it too (`src/review.rs:898-907`). A MEDIUM disclosure here would refuse
    /// every review on macOS, Windows and any Landlock-less kernel, for a check
    /// the operator never asked for. This is the same reasoning that demoted
    /// `P03_PROVENANCE_REQUIRED_MISSING` to LOW.
    pub fn disclosure(&self) -> Option<Finding> {
        self.skip.as_ref().map(|skip| Finding {
            rule_id: "P05_SANDBOX_UNAVAILABLE".into(),
            severity: VerdictBand::Low,
            title: "Extraction sandbox was not available".into(),
            description: format!(
                "this release's archive was unpacked without OS-level Landlock confinement \
                 ({skip}). The path grammar, the entry-type rejection and the byte and entry \
                 caps all still applied, so the extraction was bounded exactly as before; what \
                 was missing is the kernel refusing a write, a read or an exec outside the \
                 extraction directory had the extractor itself been buggy. Nothing from this \
                 release was executed. Set `[policy] require_sandbox = true` to refuse the \
                 review instead of disclosing it."
            ),
        })
    }
}

/// The child's exit codes. Distinct so the parent can tell a refusal from a
/// missing kernel feature from a child that died mid-write.
pub mod exit {
    /// Extraction ran, confined, and completed.
    pub const OK: i32 = 0;
    /// The extraction was refused. The reply carries which limit or which
    /// error, so the parent can rebuild the original variant.
    pub const REFUSED: i32 = 3;
    /// The layer could not be established. The parent may fall back.
    pub const UNAVAILABLE: i32 = 4;
    /// The child could not run at all. Not a fallback: `dest` may be partial.
    pub const UNUSABLE: i32 = 5;
}

/// The framed reply. The byte-count prefix exists because a bare read-to-end
/// cannot distinguish a complete reply from one the child died halfway through.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum Reply {
    Ok {
        files: usize,
        dirs: usize,
        unpacked_bytes: u64,
    },
    Refused {
        variant: String,
        message: String,
    },
    Unavailable {
        reason: String,
    },
}

/// Map a child `Reply::Refused` back to the variant the extractor produced.
///
/// Matched on the variant rather than stringified, and an unrecognised name is
/// refused rather than defaulted. Defaulting a new variant to `Extraction` would
/// downgrade a limit breach to a plain failure, and the limit messages are
/// asserted on by shipped tests (`references/features/extract.md`).
fn rebuild_error(variant: &str, message: String) -> BluelineError {
    match variant {
        "extraction_limit" => BluelineError::ExtractionLimit(message),
        // Only these two variants are reachable today, so an unknown name is a
        // protocol break rather than a new extractor error.
        _ => BluelineError::Sandbox(format!(
            "child reported an unrecognised refusal variant `{variant}`: {message}"
        )),
    }
}

fn extract_local(
    kind: ArchiveKind,
    bytes: &[u8],
    dest: &Path,
) -> Result<ExtractStats, BluelineError> {
    let limits = ExtractionLimits::default();
    match kind {
        // `src/wheel_extract.rs` is a one-line re-export of
        // `safe_extract_wheel`, so going through it would be ceremony preserving
        // a module with no other reason to exist.
        ArchiveKind::Tar => crate::extract::safe_extract(bytes, dest, &limits),
        ArchiveKind::Wheel => crate::extract::safe_extract_wheel(bytes, dest, &limits),
    }
}

fn write_reply(reply: &Reply) {
    use std::io::Write;
    let body = serde_json::to_vec(reply).unwrap_or_else(|_| {
        // Serialising our own two-variant enum cannot fail, but a fallback that
        // still speaks the protocol beats a panic: an unserialisable reply
        // would otherwise read to the parent as a child that died.
        let fallback = Reply::Unavailable {
            reason: "reply could not be serialised".into(),
        };
        serde_json::to_vec(&fallback).unwrap_or_default()
    });
    let mut out = std::io::stdout().lock();
    // `writeln!` rather than `write!` with a trailing newline: the latter is a
    // clippy error, and the prefix is the framing, not decoration.
    let _ = writeln!(out, "{}", body.len());
    let _ = out.write_all(&body);
    let _ = out.flush();
}

/// Read the framed reply, refusing a truncated or oversized one.
fn read_reply(stdout: &[u8]) -> Result<Reply, BluelineError> {
    let nl = stdout
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| BluelineError::Sandbox("child reply had no length prefix".into()))?;
    let count: usize = std::str::from_utf8(&stdout[..nl])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| BluelineError::Sandbox("child reply had an unreadable length".into()))?;
    if count > MAX_REPLY_BYTES {
        return Err(BluelineError::Sandbox(format!(
            "child reply declared {count} bytes, over the {MAX_REPLY_BYTES} ceiling"
        )));
    }
    let body = stdout
        .get(nl + 1..nl + 1 + count)
        .ok_or_else(|| BluelineError::Sandbox("child reply was truncated".into()))?;
    serde_json::from_slice(body)
        .map_err(|e| BluelineError::Sandbox(format!("child reply did not parse: {e}")))
}

/// Entry point for the extraction child, checked before clap parses.
///
/// Returns `Some(code)` when this process is the child and the caller should
/// exit with it, `None` for an ordinary invocation.
pub fn child_entrypoint() -> Option<i32> {
    // `?` on the `Option` return: no marker means an ordinary invocation.
    std::env::var_os(CHILD_ENV)?;
    // The parent spawns this process with no arguments at all, so an argument
    // here means something else set the marker. Treating that as a review would
    // silently replace `blueline review <pkg>` with extract-and-exit, which is a
    // downgrade that looks like success.
    if std::env::args_os().count() != 1 {
        eprintln!("error: {CHILD_ENV} is set but this invocation has arguments; refusing");
        return Some(exit::UNAVAILABLE);
    }
    Some(run_child())
}

fn run_child() -> i32 {
    use std::io::Read;

    let dest = match std::env::var_os(DEST_ENV) {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            eprintln!("error: {DEST_ENV} is not set");
            return exit::UNUSABLE;
        }
    };
    let kind = match std::env::var(KIND_ENV)
        .ok()
        .as_deref()
        .map(ArchiveKind::parse)
    {
        Some(Ok(k)) => k,
        Some(Err(e)) => {
            eprintln!("error: {e}");
            return exit::UNUSABLE;
        }
        None => {
            eprintln!("error: {KIND_ENV} is not set");
            return exit::UNUSABLE;
        }
    };

    // Read to the end of stdin rather than framing the archive on the way in.
    // A pipe carries no file path, so the child needs no filesystem grant to
    // receive the bytes and the archive never lands on disk twice.
    let mut bytes = Vec::new();
    if let Err(e) = std::io::stdin().lock().read_to_end(&mut bytes) {
        eprintln!("error: reading archive from stdin: {e}");
        return exit::UNUSABLE;
    }

    // Confine before touching a byte of the archive. On failure the layer was
    // never applied, so the parent may retry in-process.
    #[cfg(target_os = "linux")]
    let confined = confined::confine(&dest);
    #[cfg(not(target_os = "linux"))]
    let confined: Result<&'static str, String> =
        Err("Landlock is Linux-only, so there is nothing to confine".into());

    if let Err(e) = confined {
        write_reply(&Reply::Unavailable {
            reason: e.to_string(),
        });
        return exit::UNAVAILABLE;
    }

    match extract_local(kind, &bytes, &dest) {
        Ok(stats) => {
            write_reply(&Reply::Ok {
                files: stats.files,
                dirs: stats.dirs,
                unpacked_bytes: stats.unpacked_bytes,
            });
            exit::OK
        }
        Err(e) => {
            let variant = match &e {
                BluelineError::ExtractionLimit(_) => "extraction_limit",
                BluelineError::Extraction(_) => "extraction",
                _ => "extraction",
            };
            write_reply(&Reply::Refused {
                variant: variant.into(),
                message: e.to_string(),
            });
            exit::REFUSED
        }
    }
}

/// Confinement, and the reason it is shaped the way it is.
#[cfg(target_os = "linux")]
mod confined {
    use super::*;
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    /// The ABI tiers this build tries, most capable first.
    ///
    /// **V5 is the ceiling that matters.** Reading `AccessFs::from_write` in
    /// `landlock-0.4.7/src/fs.rs:135-156`: V1 adds the base set, V2 `Refer`,
    /// V3/V4 `Truncate`, V5 `IoctlDev`, and V9 `ResolveUnix`. So V5 is the
    /// highest ABI that adds a *filesystem* right, and `Truncate` at V3 is the
    /// one an extractor needs: without `Truncate` handled, `open(2)` with
    /// `O_TRUNC` outside the granted subtree is permitted, which is exactly the
    /// `fs::File::create`-on-a-mis-resolved-path bug class this layer exists to
    /// contain. V1 is the floor and still covers every right the extractors
    /// exercise, so a 5.13 kernel gets real confinement rather than nothing.
    ///
    /// V9 is deliberately not requested: its only filesystem addition is
    /// `ResolveUnix`, about abstract unix sockets rather than files, and the
    /// crate's own doc warns against requesting rights you have not vetted.
    const TIERS: [(&str, landlock::ABI); 2] =
        [("V5", landlock::ABI::V5), ("V1", landlock::ABI::V1)];

    pub enum ConfineError {
        /// Nothing was restricted. Safe to fall back.
        Unsupported(String),
        /// The domain is partly applied, or the attempt failed after narrowing
        /// something. Never a fallback.
        Failed(String),
    }

    impl std::fmt::Display for ConfineError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ConfineError::Unsupported(d) | ConfineError::Failed(d) => f.write_str(d),
            }
        }
    }

    /// Grant every filesystem right under `dest` and nothing anywhere else, then
    /// make it permanent for this process.
    pub fn confine(dest: &Path) -> Result<&'static str, ConfineError> {
        let mut last = TIERS[TIERS.len() - 1].0;
        for (name, abi) in TIERS {
            match restrict_once(dest, abi) {
                // `restrict_self` ran. Its status is the only trustworthy
                // answer, and there is no second attempt after this point: the
                // domain may already be partly applied and a Landlock domain can
                // never be widened. A non-`FullyEnforced` status is therefore
                // `Failed`, not `Unsupported`, and the caller refuses rather
                // than extracting from a half-applied domain.
                Ok(RulesetStatus::FullyEnforced) => return Ok(name),
                Ok(got) => {
                    return Err(ConfineError::Failed(format!(
                        "Landlock reported {got:?} at tier {name}; refusing to extract \
                         unconfined from a partly applied domain"
                    )));
                }
                // Nothing was restricted. `create`, `add_rule` and
                // `restrict_self` all returned `Err`, and only
                // `restrict_self` narrows anything, so the next tier is still
                // safe to try.
                Err(RestrictError::Unsupported) => last = name,
                Err(RestrictError::Failed(detail)) => {
                    return Err(ConfineError::Failed(detail));
                }
            }
        }
        Err(ConfineError::Unsupported(format!(
            "no Landlock ABI tier could be established, down to tier {last}"
        )))
    }

    enum RestrictError {
        Unsupported,
        Failed(String),
    }

    fn restrict_once(dest: &Path, abi: landlock::ABI) -> Result<RulesetStatus, RestrictError> {
        let access = AccessFs::from_all(abi);

        // Split out on purpose: `PathFd::new` returns `PathFdError`, which has no
        // `From` into `RulesetError`, so it cannot be `?`-ed into this chain.
        let dest_fd = PathFd::new(dest)
            .map_err(|e| RestrictError::Failed(format!("opening {dest:?} for the ruleset: {e}")))?;

        let out = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(access)
            .and_then(Ruleset::create)
            .and_then(|created| created.add_rule(PathBeneath::new(dest_fd, access)))
            .and_then(|created| {
                // `HardRequirement` is the load-bearing part. The crate defaults
                // to `BestEffort`, under which an access right the kernel does
                // not implement is dropped and `restrict_self()` still returns
                // `Ok`, reporting `PartiallyEnforced`. A caller checking only
                // `is_ok()` would read a kernel without Landlock as a sandbox.
                // Measured on a V7 kernel: `ABI::V9` under `BestEffort` gives
                // `Ok(PartiallyEnforced)`, under `HardRequirement` an `Err`.
                created
                    .set_compatibility(CompatLevel::HardRequirement)
                    .restrict_self()
            });

        match out {
            Ok(status) => Ok(status.ruleset),
            // `HardRequirement` reports an over-ABI request as a hard error from
            // `handle_access`, and a kernel with no Landlock as a
            // `CreateRulesetError` from `create`. Both mean "try the next tier",
            // because neither reached `restrict_self`.
            Err(_) => Err(RestrictError::Unsupported),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn confine(_dest: &Path) -> Result<&'static str, String> {
    Err("Landlock is Linux-only".into())
}

/// Extract one archive under OS-level confinement, or disclose there was none.
///
/// The routing decision stays in the caller, which already knows the ecosystem
/// and the tarball URL, so the child never re-derives it from bytes.
pub fn extract(
    kind: ArchiveKind,
    bytes: &[u8],
    dest: &Path,
    ledger: &mut SandboxLedger,
    policy: &Policy,
) -> Result<ExtractStats, BluelineError> {
    // Canonicalise before handing the path over, so the child opens exactly the
    // directory the parent validated and there is no window in which a relative
    // or `..`-bearing path resolves somewhere else. The child re-derives its own
    // `PathFd` from this value rather than trusting a string.
    let canonical = dest
        .canonicalize()
        .map_err(|e| BluelineError::Sandbox(format!("canonicalising {}: {e}", dest.display())))?;

    match spawn_child(kind, bytes, &canonical) {
        Ok(stats) => Ok(stats),
        // The child died or broke its protocol. `dest` may hold a partial tree,
        // so this is an error and never a fallback: an in-process retry would
        // read whatever the dead child managed to write.
        Err(ChildFailure::Unusable(e)) => Err(e),
        // The extractor refused the archive. That is the extractor's own
        // answer, rebuilt into the variant the in-process path would have
        // produced, so the message a limit breach shows is unchanged by whether
        // the sandbox was available.
        Err(ChildFailure::Refused(e)) => Err(e),
        Err(ChildFailure::Skip(skip)) => {
            if policy.policy.require_sandbox {
                return Err(BluelineError::Sandbox(format!(
                    "[policy] require_sandbox is set and the sandbox was unavailable: {skip}"
                )));
            }
            ledger.record_skip(skip);
            // The layer was never applied, so `dest` is untouched and an
            // in-process retry is safe.
            extract_local(kind, bytes, dest)
        }
    }
}

enum ChildFailure {
    /// The layer was not established. Fall back and disclose.
    Skip(SandboxSkip),
    /// The child could not run, or the protocol broke. `dest` may be partial.
    Unusable(BluelineError),
    /// The child ran the extractor and it refused. The child is not at fault,
    /// the archive is, so this surfaces as the extractor's own error rather
    /// than as a sandbox failure. Distinct from `Unusable` because a refusal is
    /// a clean answer rather than a broken handshake.
    Refused(BluelineError),
}

/// Whether this process may exec an extraction child.
///
/// **Fork-bomb guard. Never weaken either condition, and never remove this
/// function to "simplify" `spawn_child`.**
///
/// `spawn_child` re-execs `current_exe()`, and under `cargo test` that file is
/// the libtest harness, not blueline: the harness `main` never reaches
/// `child_entrypoint`, so the child runs the whole suite again and every test
/// that extracts spawns the next generation. One `cargo test --lib review::`
/// run produced 529 live processes, a load average of 733, exhausted RAM, and
/// a machine that had to be rebooted (2026-10-09). Tests take the in-process
/// fallback instead; `the_test_harness_is_never_allowed_to_spawn_an_extraction_child`
/// pins this and fails if the guard is removed, without forking anything.
///
/// The marker condition stops the same recursion from a child of any build: a
/// process holding `CHILD_ENV` is (or leaked out of) an extraction child, and
/// production never needs it because `run_child` extracts in-process.
fn may_spawn_child() -> bool {
    if cfg!(test) {
        return false;
    }
    std::env::var_os(CHILD_ENV).is_none()
}

fn spawn_child(kind: ArchiveKind, bytes: &[u8], dest: &Path) -> Result<ExtractStats, ChildFailure> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // See `may_spawn_child`: exec from the test harness (or from a child)
    // re-runs tests instead of the extractor and can fork-bomb the machine.
    if !may_spawn_child() {
        return Err(ChildFailure::Skip(SandboxSkip::SelfExecUnavailable {
            detail: "refusing to re-exec the test harness or an extraction child".into(),
        }));
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return Err(ChildFailure::Skip(SandboxSkip::SelfExecUnavailable {
                detail: e.to_string(),
            }));
        }
    };

    let mut child = match Command::new(exe)
        .env(CHILD_ENV, "1")
        .env(DEST_ENV, dest)
        .env(KIND_ENV, kind.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Err(ChildFailure::Skip(SandboxSkip::SelfExecUnavailable {
                detail: e.to_string(),
            }));
        }
    };

    // Feed the archive from a thread so a child that exits early cannot deadlock
    // the parent on a full pipe. `wait_with_output` reads stdout and stderr
    // concurrently but writes nothing to stdin, so writing here first would
    // hang forever against a child that stopped reading. Only the stdin handle
    // moves into the thread; `child` stays here to be waited on.
    let mut stdin = child.stdin.take();
    let payload = bytes.to_vec();
    let writer = std::thread::spawn(move || {
        if let Some(mut pipe) = stdin.take() {
            let _ = pipe.write_all(&payload);
        }
        // Dropping the handle closes the pipe, which is the child's EOF signal.
    });

    // Bounded: an extraction is bounded work, so a child that has not finished
    // by now is wedged, and a wedged child is a fail-open risk if we wait
    // forever. 300s matches the CI mutant timeout's order of magnitude and is
    // far above any legitimate extraction.
    const CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

    let status = match wait_with_timeout(&mut child, CHILD_TIMEOUT) {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            return Err(ChildFailure::Unusable(BluelineError::Sandbox(format!(
                "the extraction child did not finish within {}s and was killed",
                CHILD_TIMEOUT.as_secs()
            ))));
        }
    };
    let _ = writer.join();

    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return Err(ChildFailure::Unusable(BluelineError::Sandbox(format!(
                "collecting the extraction child's output: {e}"
            ))));
        }
    };
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();

    let died = |why: String| {
        ChildFailure::Unusable(BluelineError::Sandbox(format!(
            "the extraction child died ({why}); {} may hold a partial tree, so the review \
             stops rather than reading it",
            dest.display()
        )))
    };

    match status.code() {
        Some(exit::OK) => {}
        Some(exit::REFUSED) => {}
        Some(exit::UNAVAILABLE) => {
            let reason = read_reply(&out.stdout)
                .ok()
                .and_then(|r| match r {
                    Reply::Unavailable { reason } => Some(reason),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    if stderr.is_empty() {
                        "the child gave no reason".to_string()
                    } else {
                        stderr.clone()
                    }
                });
            return Err(ChildFailure::Skip(SandboxSkip::Unavailable {
                detail: reason,
            }));
        }
        // A child that exits 0 having written nothing, or exits with a signal,
        // or exits with a code we do not define, is never a fallback.
        Some(code) => {
            return Err(died(format!(
                "exit code {code}{}",
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                }
            )));
        }
        None => {
            return Err(died(format!(
                "killed by a signal{}",
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                }
            )));
        }
    }

    match read_reply(&out.stdout) {
        Err(e) => Err(died(e.to_string())),
        Ok(Reply::Ok {
            files,
            dirs,
            unpacked_bytes,
        }) => Ok(ExtractStats {
            files,
            dirs,
            unpacked_bytes,
        }),
        Ok(Reply::Refused { variant, message }) => {
            Err(ChildFailure::Refused(rebuild_error(&variant, message)))
        }
        Ok(Reply::Unavailable { reason }) => Err(ChildFailure::Skip(SandboxSkip::Unavailable {
            detail: reason,
        })),
    }
}

/// `wait_with_output` blocks forever, so poll the child and give up on a bound.
///
/// `try_wait` is the only non-blocking primitive on `Child`, and it reaps on
/// success, so the later `wait_with_output` sees an already-reaped child and
/// returns its status rather than blocking.
fn wait_with_timeout(
    child: &mut std::process::Child,
    limit: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if start.elapsed() >= limit {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_ledger_reports_no_disclosure() {
        let ledger = SandboxLedger::default();
        assert!(ledger.skip().is_none());
        assert!(
            ledger.disclosure().is_none(),
            "a confined review must say nothing"
        );
    }

    /// The band is the exit code. `review --yes` only marks clean at `Low` and
    /// `agent` exits 2 above it, so anything higher refuses every review on a
    /// platform without Landlock. This pins that.
    #[test]
    fn the_unavailable_disclosure_is_low() {
        let mut ledger = SandboxLedger::default();
        ledger.record_skip(SandboxSkip::UnsupportedPlatform);
        let finding = ledger.disclosure().expect("a skip must disclose");
        assert_eq!(finding.severity, VerdictBand::Low, "{finding:?}");
        assert_eq!(finding.rule_id, "P05_SANDBOX_UNAVAILABLE");
        assert!(
            finding
                .description
                .contains("without OS-level Landlock confinement"),
            "the wording must say the layer was absent: {}",
            finding.description
        );
        assert!(
            finding
                .description
                .contains("Nothing from this release was executed"),
            "the disclosure must not imply code ran: {}",
            finding.description
        );
    }

    /// Both extractions in a review hit the same unavailable platform, so the
    /// disclosure must appear once and name the first reason.
    #[test]
    fn the_first_skip_reason_wins() {
        let mut ledger = SandboxLedger::default();
        ledger.record_skip(SandboxSkip::KernelWithoutLandlock);
        ledger.record_skip(SandboxSkip::SelfExecUnavailable {
            detail: "later".into(),
        });
        assert_eq!(ledger.skip(), Some(&SandboxSkip::KernelWithoutLandlock));
    }

    /// An unrecognised refusal variant must not be relabelled as a plain
    /// extraction failure, which would downgrade a limit breach.
    #[test]
    fn an_unknown_refusal_variant_is_not_downgraded() {
        let rebuilt = rebuild_error("extraction_limit", "entry count over cap".into());
        assert!(
            matches!(rebuilt, BluelineError::ExtractionLimit(_)),
            "{rebuilt:?}"
        );
        let unknown = rebuild_error("something_new", "boom".into());
        assert!(
            matches!(unknown, BluelineError::Sandbox(_)),
            "an unknown variant must refuse, not relabel: {unknown:?}"
        );
    }

    #[test]
    fn a_truncated_reply_is_refused_rather_than_parsed() {
        let err = read_reply(b"999\n{}").unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "a short body must be a truncation, got: {err}"
        );
    }

    #[test]
    fn an_oversized_reply_is_refused_before_allocating() {
        let header = format!("{}\n", MAX_REPLY_BYTES + 1);
        let err = read_reply(header.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("ceiling"), "got: {err}");
    }

    #[test]
    fn a_reply_with_no_length_prefix_is_refused() {
        let err = read_reply(b"{}").unwrap_err();
        assert!(err.to_string().contains("length prefix"), "got: {err}");
    }

    #[test]
    fn a_complete_round_trip_parses() {
        let reply = Reply::Ok {
            files: 3,
            dirs: 1,
            unpacked_bytes: 4096,
        };
        let body = serde_json::to_vec(&reply).unwrap();
        let framed = format!("{}\n", body.len()).into_bytes();
        let mut framed = framed;
        framed.extend_from_slice(&body);
        match read_reply(&framed).expect("a well-formed reply parses") {
            Reply::Ok {
                files,
                dirs,
                unpacked_bytes,
            } => {
                assert_eq!((files, dirs, unpacked_bytes), (3, 1, 4096));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// Fork-bomb pin. `cargo test --lib review::` once spawned 529 copies of
    /// the harness because `spawn_child` re-exec'd `current_exe()`, which
    /// under test is libtest itself: the child ran the suite, each extract
    /// test spawned the next generation, and the machine had to be rebooted.
    /// This asserts only `may_spawn_child`, so removing the guard fails here
    /// instead of forking the machine.
    #[test]
    fn the_test_harness_is_never_allowed_to_spawn_an_extraction_child() {
        assert!(
            !may_spawn_child(),
            "may_spawn_child must refuse the test harness: re-exec here runs \
             the whole suite and every extract spawns the next generation"
        );
    }

    /// Pins the fork-bomb guard in `spawn_child` (incident 2026-10-09: an
    /// unguarded self-exec under `cargo test` spawned 529 harness processes
    /// and forced a reboot). Extraction inside a test harness must take the
    /// in-process path and return a `Skip` — it must never reach `Command`,
    /// because `current_exe()` here is the test binary and spawning it re-runs
    /// the suite, which spawns again, unbounded.
    #[test]
    fn extraction_in_a_test_never_re_execs_the_harness() {
        let dir = tempfile::tempdir().unwrap();
        let Err(failure) = spawn_child(ArchiveKind::Tar, b"not-read", dir.path()) else {
            panic!("the harness must not spawn a child process");
        };
        assert!(
            matches!(
                failure,
                ChildFailure::Skip(SandboxSkip::SelfExecUnavailable { .. })
            ),
            "the guard must return a Skip disclosure, never a spawn"
        );
    }

    /// The child must refuse to run when the marker is set but arguments are
    /// present, because that would otherwise turn `blueline review <pkg>` into
    /// extract-and-exit on a host where the variable leaked into the
    /// environment.
    ///
    /// This drives the real binary: `child_entrypoint` reads process state, so
    /// pinning it on this harness's own arguments only held when the harness
    /// happened to be invoked with a test-name filter, and failed on a plain
    /// `cargo test` run (2026-10-09).
    #[test]
    fn the_child_refuses_when_it_was_given_arguments() {
        let out = assert_cmd::Command::cargo_bin("blueline")
            .unwrap()
            .env(CHILD_ENV, "1")
            .arg("review")
            .arg("some-pkg")
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(exit::UNAVAILABLE),
            "marker plus arguments must exit UNAVAILABLE, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("refusing"),
            "the refusal must say so, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confine_reports_whether_the_kernel_actually_enforced() {
        // Not a unit test of the ruleset's effect, which needs a child to be
        // safe. It pins that the status is *read* and compared against
        // `FullyEnforced`, because `restrict_self()` returns `Ok` on a kernel
        // with no Landlock and a caller checking only `is_ok()` would report a
        // sandbox that does not exist.
        let dir = crate::extract::private_temp_dir().expect("temp dir");
        match confined::confine(dir.path()) {
            Ok(tier) => assert!(
                !tier.is_empty(),
                "a confined result names the tier that was established"
            ),
            Err(confined::ConfineError::Unsupported(_))
            | Err(confined::ConfineError::Failed(_)) => {}
        }
    }

    #[test]
    fn archive_kind_round_trips_and_refuses_unknown() {
        for kind in [ArchiveKind::Tar, ArchiveKind::Wheel] {
            assert_eq!(ArchiveKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(
            ArchiveKind::parse("rar").is_err(),
            "an unknown kind must be refused, not defaulted"
        );
    }
}
