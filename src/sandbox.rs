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
///
/// `pub(crate)` now: the integration test that pinned the marker's effect
/// reaches the decision through `may_spawn_child_given` instead of writing the
/// real environment, so nothing outside the crate needs the name.
pub(crate) const CHILD_ENV: &str = "BLUELINE_SANDBOX_CHILD";
/// Canonical absolute path of the directory the child may write.
pub(crate) const DEST_ENV: &str = "BLUELINE_SANDBOX_DEST";
/// Which extractor the child runs.
pub(crate) const KIND_ENV: &str = "BLUELINE_SANDBOX_KIND";

/// Ceiling on the reply the parent will *read*.
///
/// Checked in one place, on the parent's side: a reply that declares more than
/// this is refused rather than parsed. It does not bound what the parent
/// allocates overall: `wait_with_output` collects the child's whole stdout
/// before `read_reply` runs, so a hostile stdout past the framing is already in
/// memory by the time the ceiling is checked. That is accepted because the
/// child is our own binary, not an attacker-controlled peer. The reply itself
/// is three numbers or a short reason, so this is generous.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Ceiling on the reply *body* the child writes, which is the smaller number.
///
/// `write_reply` prefixes the body with its decimal length and a newline, and
/// the parent does not read stdout until the child has exited, so a body at
/// `MAX_REPLY_BYTES` is still six bytes past a 64 KiB pipe: the child blocks in
/// `write_all` and the parent waits out the full `CHILD_TIMEOUT`. The reader's
/// job is refusing a hostile peer, the writer's is fitting a pipe, and sharing
/// one constant between them is how a six-byte window survived a fix for the
/// unbounded version of the same bug. The reserve is pinned by a test so it
/// cannot be quietly removed.
const MAX_REPLY_BODY_BYTES: usize = MAX_REPLY_BYTES - 32;

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
/// Every variant means nothing was attempted or nothing was applied, so the
/// destination is untouched and the in-process fallback is safe. A child that
/// died or failed its confinement never becomes a `SandboxSkip`: it is
/// `ChildFailure::Unusable`, an error the review stops on.
///
/// Three variants, and all three are reachable in production.
/// `KernelWithoutLandlock`, `AbiUnavailable` and `ChildDied` used to advertise
/// a taxonomy nothing built: the "no Landlock" and "no ABI tier" answers both
/// arrive as the child's own `Unavailable` reason text, and a dead child is
/// the `Unusable` error above. Both review rounds flagged the dead members,
/// because a caller who matches on a variant that can never fire has built a
/// decision on nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxSkip {
    /// Not Linux. Landlock is a Linux LSM and the `landlock` crate does not
    /// build elsewhere, so this is fixed at compile time.
    UnsupportedPlatform,
    /// The child ran and reported that it could not confine itself. The child's
    /// own words, because the child is the only place the ruleset was built.
    Unavailable { detail: String },
    /// `current_exe()` or `spawn` failed. A broken install or an exhausted
    /// process table, not a kernel feature, and an operator reading this
    /// disclosure should look for a different problem.
    SelfExecUnavailable { detail: String },
}

impl std::fmt::Display for SandboxSkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxSkip::UnsupportedPlatform => {
                write!(f, "this platform has no Landlock, which is Linux-only")
            }
            SandboxSkip::Unavailable { detail } => {
                write!(f, "the extraction child could not confine itself: {detail}")
            }
            SandboxSkip::SelfExecUnavailable { detail } => {
                write!(f, "the extraction child could not be started: {detail}")
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
                "an archive in this review was unpacked without OS-level Landlock confinement \
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
    /// Confinement was attempted and failed after narrowing something (or the
    /// destination could not even be opened for the ruleset). Never a fallback:
    /// `dest` may hold a partial tree. Distinct from `Unavailable`, which means
    /// nothing was applied and the parent may retry in-process.
    Unusable {
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
        // The common case. Without this arm every ordinary extractor refusal,
        // which is the thing an attacker triggers most easily, came back to the
        // operator as "the sandbox protocol broke" when the sandbox worked
        // exactly as intended.
        "extraction" => BluelineError::Extraction(message),
        // An unknown name is a protocol break rather than a new extractor error.
        _ => BluelineError::Sandbox(format!(
            "child reported an unrecognised refusal variant `{variant}`: {message}"
        )),
    }
}

/// The refusal name the child sends for an extractor error.
///
/// A separate function so the mapping is pinned by unit tests: the extractor
/// grows variants over time, and a new arm that falls through to the wrong
/// name either downgrades a limit breach or breaks the parent's rebuild.
fn refusal_variant(e: &BluelineError) -> &'static str {
    match e {
        BluelineError::ExtractionLimit(_) => "extraction_limit",
        _ => "extraction",
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

/// Serialise a reply, guaranteeing it fits a pipe buffer.
///
/// The parent calls `wait_with_timeout` before it reads stdout, so a reply
/// larger than the pipe blocks the child in `write_all` and the parent blocks
/// waiting for an exit that cannot come: the full `CHILD_TIMEOUT`, once per
/// extraction, twice when there is a baseline. Refusal messages embed archive
/// entry paths, so the size is attacker-controlled.
///
/// What gets cut to fit is the free text, never the outcome. An oversized reply
/// used to be replaced wholesale with `Unavailable`, which the parent reads as
/// "nothing was confined, retry in-process", and for a `Refused` that re-ran
/// the extraction unconfined over a `dest` the child had already partly
/// written: the outcome this module exists to prevent.
fn framed_reply_bytes(reply: &Reply) -> Vec<u8> {
    serialise(&fit_to_frame(reply.clone()))
}

/// Marker left behind when a message was cut to fit the frame.
const TRUNCATION_NOTE: &str = " [message truncated to fit the reply frame]";

/// Bytes a character-boundary walk-back can give back when the cut point
/// lands inside a multi-byte character. A 4-byte character loses at most 3.
const BOUNDARY_SLACK: usize = 3;

fn serialise(reply: &Reply) -> Vec<u8> {
    serde_json::to_vec(reply).unwrap_or_else(|_| {
        // Serialising our own four-variant enum cannot fail, but a fallback that
        // still speaks the protocol beats a panic: an unserialisable reply
        // would otherwise read to the parent as a child that died.
        let fallback = Reply::Unavailable {
            reason: "reply could not be serialised".into(),
        };
        serde_json::to_vec(&fallback).unwrap_or_default()
    })
}

/// Cut a reply's free text until its body fits `MAX_REPLY_BODY_BYTES`.
///
/// One round, not a loop. JSON escaping only ever expands, so cutting
/// `over + marker + slack` raw bytes removes at least `over + marker`
/// escaped bytes: cutting N raw bytes always removes at least N escaped
/// bytes, because escaping is per-character and additive. The body lands at
/// or under the ceiling on the first cut. The slack pays for the character
/// boundary `cut_to` walks back to when the cut point lands inside a
/// multi-byte character; that walk-back only shortens the kept text, which
/// only adds headroom. A loop would let an inverted overage subtraction spin
/// forever, so there is nothing here to spin.
fn fit_to_frame(reply: Reply) -> Reply {
    let mut reply = reply;
    let len = serialise(&reply).len();
    if len <= MAX_REPLY_BODY_BYTES {
        return reply;
    }
    let Some(text) = free_text_mut(&mut reply) else {
        // `Ok` carries three integers and is never the oversized reply.
        return reply;
    };
    let over = len - MAX_REPLY_BODY_BYTES;
    let keep = text
        .len()
        .saturating_sub(over + TRUNCATION_NOTE.len() + BOUNDARY_SLACK);
    if keep == 0 {
        // Shorter than the marker it would have to carry. The outcome
        // alone is the answer: an empty text serialises to a few dozen
        // bytes of punctuation against a 64 KiB ceiling.
        text.clear();
        return reply;
    }
    *text = format!("{}{TRUNCATION_NOTE}", cut_to(text, keep));
    reply
}

/// The free-text field of a reply, or `None` for `Ok`.
fn free_text_mut(reply: &mut Reply) -> Option<&mut String> {
    match reply {
        Reply::Refused { message, .. } => Some(message),
        Reply::Unavailable { reason } | Reply::Unusable { reason } => Some(reason),
        Reply::Ok { .. } => None,
    }
}

/// Cut `text` to at most `max` bytes, never mid-character.
///
/// A byte offset landing inside a multi-byte character makes `&text[..end]`
/// panic, and a panic in the child reads to the parent as a child that died:
/// a worse answer than a truncated message. The cut is the start of the first
/// character whose end passes `max`, so it is always a boundary, always a
/// prefix of `text`, and never longer than `max`. Past the end of the string
/// there is no such character, and the whole text is the answer.
fn cut_to(text: &str, max: usize) -> &str {
    let end = text
        .char_indices()
        .find_map(|(i, c)| (i + c.len_utf8() > max).then_some(i))
        .unwrap_or(text.len());
    &text[..end]
}

fn write_reply(reply: &Reply) {
    use std::io::Write;
    let body = framed_reply_bytes(reply);
    let mut out = std::io::stdout().lock();
    // `writeln!` rather than `write!` with a trailing newline: the latter is a
    // clippy error, and the prefix is the framing, not decoration.
    let _ = writeln!(out, "{}", body.len());
    let _ = out.write_all(&body);
    let _ = out.flush();
}

/// Read the framed reply, refusing a truncated or oversized one.
fn read_reply(stdout: &[u8]) -> Result<Reply, BluelineError> {
    // Bound the raw stdout before parsing anything out of it.
    // `wait_with_output` already collected all of it, so a child that streams
    // megabytes would otherwise have the parent parse megabytes. The only
    // thing a well-behaved child writes is one framed reply: a body at the
    // ceiling plus its short count header (see the margin test below).
    if stdout.len() > MAX_REPLY_BYTES + 32 {
        return Err(BluelineError::Sandbox(format!(
            "child stdout was {} bytes, over the {MAX_REPLY_BYTES} reply ceiling",
            stdout.len()
        )));
    }
    let nl = stdout
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| BluelineError::Sandbox("child reply had no length prefix".into()))?;
    // Split off the header rather than slicing from `nl`: every formulation
    // with `nl + 1` in it silently tolerates the header newline leaking into
    // the body (`serde_json` skips leading whitespace), so an off-by-one in
    // the framing would parse and no test could tell.
    let (header, rest) = stdout.split_at(nl);
    let count: usize = std::str::from_utf8(header)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| BluelineError::Sandbox("child reply had an unreadable length".into()))?;
    if count > MAX_REPLY_BYTES {
        return Err(BluelineError::Sandbox(format!(
            "child reply declared {count} bytes, over the {MAX_REPLY_BYTES} ceiling"
        )));
    }
    let body = rest
        .get(1..count + 1)
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

    // Confine before reading a byte of the archive. The archive arrives over a
    // pipe, which needs no filesystem grant, so restricting first costs
    // nothing on Linux and saves the whole round-trip where there is nothing
    // to confine with: without this order every extraction off Linux spawns a
    // process, copies the entire tarball through a pipe, then discards it.
    match confine(&dest) {
        Ok(tier) => {
            // Diagnostics only, and only on the success path. Nothing reads it
            // in production: `unavailable_reason` consults stderr only when the
            // reply is missing, and a confined child always writes one. It
            // exists so a test can drive the built binary and read which ABI
            // tier the kernel actually granted, which is the one confinement
            // fact that cannot be observed from inside the harness without
            // narrowing the harness.
            eprintln!("confined at tier {tier}");
        }
        // Nothing was applied, so the parent may retry in-process.
        Err(ConfineError::Unsupported(detail)) => {
            write_reply(&Reply::Unavailable { reason: detail });
            return exit::UNAVAILABLE;
        }
        // Something narrowed, or the destination could not even be opened for
        // the ruleset. The parent must not retry in-process: `dest` may hold
        // a partial tree, or the failure itself is the signal.
        Err(ConfineError::Failed(detail)) => {
            write_reply(&Reply::Unusable { reason: detail });
            return exit::UNUSABLE;
        }
    }

    // Read to the end of stdin rather than framing the archive on the way in.
    // A pipe carries no file path, so the child needs no filesystem grant to
    // receive the bytes and the archive never lands on disk twice.
    let mut bytes = Vec::new();
    if let Err(e) = std::io::stdin().lock().read_to_end(&mut bytes) {
        eprintln!("error: reading archive from stdin: {e}");
        return exit::UNUSABLE;
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
            let variant = refusal_variant(&e);
            write_reply(&Reply::Refused {
                variant: variant.into(),
                message: e.to_string(),
            });
            exit::REFUSED
        }
    }
}

/// Why confinement did not happen, split so the caller can tell "nothing was
/// applied, retry in-process" from "something narrowed, refuse".
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// The tier names `confine` can report on success. Pinned by
/// `confinement_reports_a_known_tier_or_an_honest_gap`, because a tier string
/// the ladder never named is a protocol break, not confinement.
pub const TIER_NAMES: [&str; 3] = ["V5", "V3", "V1"];

/// Dispatch to the Linux Landlock implementation, or report the platform gap.
///
/// **One `confine` for every platform, not a `#[cfg]` twin per platform.**
///
/// Two `#[cfg]`-gated functions mean the non-Linux one does not exist in a
/// Linux build, so `cargo mutants` offers a function-level mutation of it that
/// no test can ever kill: the mutant compiles, runs, and is unobservable
/// because nothing on Linux calls it. That is exactly what CI reported against
/// this file. Two blocks in one signature keep the symbol present on every
/// host, so the tier assertion in `confinement_reports_a_known_tier_or_an_honest_gap`
/// can see the mutation.
fn confine(dest: &Path) -> Result<&'static str, ConfineError> {
    #[cfg(target_os = "linux")]
    {
        confined::confine(dest)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dest;
        Err(ConfineError::Unsupported(
            "Landlock is Linux-only, so there is nothing to confine".into(),
        ))
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
    ///
    /// The ladder is V5, V3, V1 rather than just the ceiling and the floor. V3
    /// is the newest tier that adds a filesystem right (`Truncate`) without
    /// also demanding `IoctlDev`, so a kernel too old for V5 still keeps the
    /// `O_TRUNC` containment above instead of silently dropping to V1, which
    /// does not handle `Truncate` at all.
    const TIERS: [(&str, landlock::ABI); 3] = [
        ("V5", landlock::ABI::V5),
        ("V3", landlock::ABI::V3),
        ("V1", landlock::ABI::V1),
    ];

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
                Ok(status) if is_fully_enforced(&status) => return Ok(name),
                Ok(got) => {
                    return Err(ConfineError::Failed(format!(
                        "Landlock reported {got:?} at tier {name}; refusing to extract \
                         unconfined from a partly applied domain"
                    )));
                }
                // Nothing was restricted: only `restrict_self` narrows anything,
                // and it never ran, so the next tier is still safe to try.
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

    /// Whether a finished ruleset is the one status that means confined.
    ///
    /// A function of its own so the decision between "confined" and "refuse" is
    /// pinned without applying a ruleset to the process running the test.
    /// `restrict_self` is irreversible and thread-inheriting, so a test that
    /// called `confine` directly narrowed every thread libtest spawned for the
    /// rest of the run; the only safe way to observe real confinement is
    /// `run_child_binary` driving the built binary. The comparison is pure and
    /// carries the whole fail-closed argument, so it gets its own unit tests.
    ///
    /// `NotEnforced` and `PartiallyEnforced` are both "something was requested
    /// and the kernel did not deliver it", and both must read as a refusal. The
    /// distinction matters because `restrict_self` returns `Ok` under all three
    /// on a kernel that swallowed the request, so an `is_ok()` check would call
    /// a no-op sandbox a sandbox.
    fn is_fully_enforced(status: &RulesetStatus) -> bool {
        matches!(status, RulesetStatus::FullyEnforced)
    }

    fn restrict_once(dest: &Path, abi: landlock::ABI) -> Result<RulesetStatus, RestrictError> {
        let access = AccessFs::from_all(abi);

        // Split out on purpose: `PathFd::new` returns `PathFdError`, which has no
        // `From` into `RulesetError`, so it cannot be `?`-ed into this chain.
        let dest_fd = PathFd::new(dest)
            .map_err(|e| RestrictError::Failed(format!("opening {dest:?} for the ruleset: {e}")))?;

        // Staged, not chained: only the last stage narrows anything. An
        // over-ABI `handle_access`, a no-Landlock `create`, or a rejected
        // `add_rule` all happen before `restrict_self` runs, so nothing was
        // applied and the next tier is safe to try. A `restrict_self` failure
        // is different: it runs after `no_new_privs` handling inside the
        // crate, so a hardened container that blocks `prctl` fails here, and
        // diagnosing that as "the kernel has no Landlock" would silently
        // downgrade a real restriction failure into an unconfined extraction.
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(access)
            .map_err(|_| RestrictError::Unsupported)?;
        let created = ruleset.create().map_err(|_| RestrictError::Unsupported)?;
        let with_rule = created
            .add_rule(PathBeneath::new(dest_fd, access))
            .map_err(|_| RestrictError::Unsupported)?;
        let status = with_rule
            // `HardRequirement` is the load-bearing part. The crate defaults
            // to `BestEffort`, under which an access right the kernel does
            // not implement is dropped and `restrict_self()` still returns
            // `Ok`, reporting `PartiallyEnforced`. A caller checking only
            // `is_ok()` would read a kernel without Landlock as a sandbox.
            // Measured on a V7 kernel: `ABI::V9` under `BestEffort` gives
            // `Ok(PartiallyEnforced)`, under `HardRequirement` an `Err`.
            .set_compatibility(CompatLevel::HardRequirement)
            .restrict_self()
            .map_err(|e| {
                RestrictError::Failed(format!("restricting to {dest:?} at this tier: {e}"))
            })?;

        Ok(status.ruleset)
    }

    /// The status comparison, without applying anything.
    ///
    /// `Ok` under every status is what `restrict_self` returns on a kernel that
    /// swallowed the request, so this is the line between "the kernel enforced
    /// the ruleset" and "the child extracted unconfined while reporting a
    /// tier". It lives here rather than in the outer `tests` module because it
    /// names `RulesetStatus`, which the crate does not otherwise re-export.
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn only_fully_enforced_reads_as_confined() {
            assert!(is_fully_enforced(&RulesetStatus::FullyEnforced));
            assert!(
                !is_fully_enforced(&RulesetStatus::PartiallyEnforced),
                "a partly enforced ruleset confined something and left the rest open"
            );
            assert!(
                !is_fully_enforced(&RulesetStatus::NotEnforced),
                "a not-enforced ruleset is the kernel without Landlock"
            );
        }
    }
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

#[derive(Debug)]
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

/// The child's reason for reporting it could not confine itself.
///
/// A separate function so the preference is pinned: the child's own framed
/// reason first, stderr only when the reply is missing or says something else,
/// "no reason" last. Without the first arm every confinement failure would
/// read as a bare exit with no diagnosis.
fn unavailable_reason(stdout: &[u8], stderr: &str) -> String {
    read_reply(stdout)
        .ok()
        .and_then(|r| match r {
            Reply::Unavailable { reason } => Some(reason),
            _ => None,
        })
        .unwrap_or_else(|| {
            if stderr.is_empty() {
                "the child gave no reason".to_string()
            } else {
                stderr.to_string()
            }
        })
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
///
/// `pub` (and `#[doc(hidden)]`) so an integration test can pin the production
/// case: under `cfg(test)` this always returns `false`, so no unit test can
/// tell the guard from a hardcoded `false`. `tests/sandbox_spawns.rs` asserts
/// the `true` case from outside the harness, where the lib is built normally.
#[doc(hidden)]
pub fn may_spawn_child() -> bool {
    may_spawn_child_given(std::env::var_os(CHILD_ENV).is_some())
}

/// The guard's decision as a pure function of its two inputs.
///
/// Split out so both arms are reachable from a test. Under `cfg(test)` the
/// marker branch is dead, so `may_spawn_child` alone can only ever be observed
/// returning `false`, and the honest way to reach the other arm is to set the
/// marker: `set_var` is `unsafe` from edition 2024 because another test thread
/// may read the environment mid-write, so a test that did it was safe only for
/// as long as nothing else lived in its binary. Taking the inputs as arguments
/// removes both problems. `tests/sandbox_spawns.rs` pins the real answers.
#[doc(hidden)]
pub fn may_spawn_child_given(marker_set: bool) -> bool {
    !cfg!(test) && !marker_set
}

fn spawn_child(kind: ArchiveKind, bytes: &[u8], dest: &Path) -> Result<ExtractStats, ChildFailure> {
    // See `may_spawn_child`: exec from the test harness (or from a child)
    // re-runs tests instead of the extractor and can fork-bomb the machine.
    if !may_spawn_child() {
        return Err(ChildFailure::Skip(SandboxSkip::SelfExecUnavailable {
            detail: "refusing to re-exec the test harness or an extraction child".into(),
        }));
    }

    // Off Linux there is nothing to confine with, and the child would say so
    // only after a full spawn plus a copy of the archive through a pipe. Skip
    // before either cost, with the same disclosure the child would report.
    #[cfg(target_os = "linux")]
    return spawn_child_on_linux(kind, bytes, dest);

    #[cfg(not(target_os = "linux"))]
    Err(ChildFailure::Skip(SandboxSkip::UnsupportedPlatform))
}

/// The Linux half of `spawn_child`: everything from resolving `current_exe`
/// onwards. Split out so the non-Linux arm above is a plain expression rather
/// than an early `return`, which would leave the rest of the function as
/// unreachable code that `-D warnings` rejects on macOS and Windows.
#[cfg(target_os = "linux")]
fn spawn_child_on_linux(
    kind: ArchiveKind,
    bytes: &[u8],
    dest: &Path,
) -> Result<ExtractStats, ChildFailure> {
    use std::io::Write;
    use std::process::{Command, Stdio};

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

    map_child_result(status.code(), &out.stdout, &stderr, dest)
}

/// The child's reason for a failed confinement.
///
/// Same shape as `unavailable_reason`, kept separate so each exit code pins
/// which replies it trusts: a confessed failure is believed from either
/// failure reply, anything else falls back to stderr.
fn unusable_reason(stdout: &[u8], stderr: &str) -> String {
    read_reply(stdout)
        .ok()
        .and_then(|r| match r {
            Reply::Unusable { reason } | Reply::Unavailable { reason } => Some(reason),
            _ => None,
        })
        .unwrap_or_else(|| {
            if stderr.is_empty() {
                "the child gave no reason".to_string()
            } else {
                stderr.to_string()
            }
        })
}

/// Map a finished child's exit code and output to a result, without spawning.
///
/// Pure so the exit-code mapping is pinned by unit tests: no test can spawn a
/// real child from the harness (`may_spawn_child` forbids it), and the
/// distinction between "retry in-process" (`Skip`) and "refuse" (`Unusable`)
/// is the fail-closed core of this module. Every arm below has a test.
fn map_child_result(
    code: Option<i32>,
    stdout: &[u8],
    stderr: &str,
    dest: &Path,
) -> Result<ExtractStats, ChildFailure> {
    let died = |why: String| {
        ChildFailure::Unusable(BluelineError::Sandbox(format!(
            "the extraction child died ({why}); {} may hold a partial tree, so the review \
             stops rather than reading it",
            dest.display()
        )))
    };

    match code {
        Some(exit::OK) | Some(exit::REFUSED) => {}
        Some(exit::UNAVAILABLE) => {
            return Err(ChildFailure::Skip(SandboxSkip::Unavailable {
                detail: unavailable_reason(stdout, stderr),
            }));
        }
        // Confinement was attempted and failed. `dest` may hold a partial
        // tree, so this is an error and never a fallback. The reply carries
        // the child's own diagnosis when it survived; stderr otherwise.
        Some(exit::UNUSABLE) => {
            return Err(died(unusable_reason(stdout, stderr)));
        }
        // A child that exits with a code we do not define, or dies on a
        // signal, is never a fallback either.
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

    match read_reply(stdout) {
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
        // The child confessed it failed confinement but exited as if the
        // extraction ran. Trust the confession: `dest` may be partial.
        Ok(Reply::Unusable { reason }) => Err(died(reason)),
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
        ledger.record_skip(SandboxSkip::Unavailable {
            detail: "no Landlock ABI tier could be established".into(),
        });
        ledger.record_skip(SandboxSkip::SelfExecUnavailable {
            detail: "later".into(),
        });
        assert_eq!(
            ledger.skip(),
            Some(&SandboxSkip::Unavailable {
                detail: "no Landlock ABI tier could be established".into(),
            })
        );
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

    /// `"extraction"` is what the child emits for every ordinary extractor
    /// refusal, which is the variant an attacker triggers most easily. It used
    /// to fall through to the unknown-variant arm, so a correct refusal reached
    /// the operator as "the sandbox protocol broke".
    #[test]
    fn an_ordinary_extraction_refusal_is_not_reported_as_a_protocol_break() {
        let rebuilt = rebuild_error(
            "extraction",
            "parent traversal in entry path rejected".into(),
        );
        assert!(
            matches!(rebuilt, BluelineError::Extraction(_)),
            "an ordinary refusal must not be relabelled as a sandbox failure: {rebuilt:?}"
        );
    }

    /// Every extractor error maps to a refusal name the parent can rebuild.
    /// Deleting the limit arm downgrades a limit breach to a plain failure.
    ///
    /// `Extraction` is pinned here rather than by naming its own match arm: an
    /// explicit `BluelineError::Extraction(_) => "extraction"` sits directly
    /// above the `_` arm that produces the same string, so no test can tell the
    /// two apart and `cargo mutants` correctly reports deleting it as a
    /// survivor. One arm, one behaviour.
    #[test]
    fn refusal_variant_names_every_extractor_error() {
        assert_eq!(
            refusal_variant(&BluelineError::ExtractionLimit("cap".into())),
            "extraction_limit"
        );
        assert_eq!(
            refusal_variant(&BluelineError::Extraction("traversal".into())),
            "extraction"
        );
        assert_eq!(
            refusal_variant(&BluelineError::Sandbox("other".into())),
            "extraction"
        );
    }

    fn framed(reason: &str) -> Vec<u8> {
        let body = serde_json::to_vec(&Reply::Unavailable {
            reason: reason.into(),
        })
        .unwrap();
        let mut out = format!("{}\n", body.len()).into_bytes();
        out.extend_from_slice(&body);
        out
    }

    /// The child's own framed reason wins over stderr. Without this arm every
    /// confinement failure would read as a bare exit with no diagnosis.
    #[test]
    fn unavailable_reason_prefers_the_childs_own_words() {
        assert_eq!(
            unavailable_reason(&framed("no Landlock ABI tier"), "some stderr"),
            "no Landlock ABI tier"
        );
    }

    #[test]
    fn unavailable_reason_falls_back_to_stderr_then_to_no_reason() {
        assert_eq!(
            unavailable_reason(b"garbage", "child stderr words"),
            "child stderr words"
        );
        assert_eq!(
            unavailable_reason(b"garbage", ""),
            "the child gave no reason"
        );
        // A reply of the wrong variant is a protocol mismatch, not a reason.
        let ok = serde_json::to_vec(&Reply::Ok {
            files: 1,
            dirs: 0,
            unpacked_bytes: 1,
        })
        .unwrap();
        let mut out = format!("{}\n", ok.len()).into_bytes();
        out.extend_from_slice(&ok);
        assert_eq!(unavailable_reason(&out, "stderr wins"), "stderr wins");
    }

    fn framed_unusable(reason: &str) -> Vec<u8> {
        let body = serde_json::to_vec(&Reply::Unusable {
            reason: reason.into(),
        })
        .unwrap();
        let mut out = format!("{}\n", body.len()).into_bytes();
        out.extend_from_slice(&body);
        out
    }

    /// A confessed failure is believed from either failure reply; anything
    /// else falls back to stderr. Without the reply arms the child's own
    /// diagnosis would be discarded exactly when it matters.
    #[test]
    fn unusable_reason_believes_a_confessed_failure() {
        assert_eq!(
            unusable_reason(&framed_unusable("prctl blocked"), "stderr"),
            "prctl blocked"
        );
        assert_eq!(unusable_reason(&framed("abi gone"), "stderr"), "abi gone");
        assert_eq!(unusable_reason(b"garbage", "stderr words"), "stderr words");
        assert_eq!(unusable_reason(b"garbage", ""), "the child gave no reason");
    }

    fn framed_ok() -> Vec<u8> {
        let body = serde_json::to_vec(&Reply::Ok {
            files: 2,
            dirs: 1,
            unpacked_bytes: 20,
        })
        .unwrap();
        let mut out = format!("{}\n", body.len()).into_bytes();
        out.extend_from_slice(&body);
        out
    }

    fn framed_refused() -> Vec<u8> {
        let body = serde_json::to_vec(&Reply::Refused {
            variant: "extraction".into(),
            message: "traversal".into(),
        })
        .unwrap();
        let mut out = format!("{}\n", body.len()).into_bytes();
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn a_clean_child_maps_to_its_stats() {
        let dir = tempfile::tempdir().unwrap();
        for code in [exit::OK, exit::REFUSED] {
            let stats = map_child_result(code.into(), &framed_ok(), "", dir.path())
                .expect("a clean reply maps to stats");
            assert_eq!((stats.files, stats.dirs, stats.unpacked_bytes), (2, 1, 20));
        }
    }

    #[test]
    fn a_refusing_child_maps_to_the_extractor_error() {
        let dir = tempfile::tempdir().unwrap();
        let Err(ChildFailure::Refused(e)) =
            map_child_result(Some(exit::REFUSED), &framed_refused(), "", dir.path())
        else {
            panic!("a refusal must surface as the extractor's error");
        };
        assert!(matches!(e, BluelineError::Extraction(_)), "{e:?}");
    }

    #[test]
    fn an_unavailable_child_is_a_skip_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let Err(ChildFailure::Skip(skip)) = map_child_result(
            Some(exit::UNAVAILABLE),
            &framed("no tier"),
            "stderr",
            dir.path(),
        ) else {
            panic!("an unavailable child must fall back with a disclosure");
        };
        assert_eq!(
            skip,
            SandboxSkip::Unavailable {
                detail: "no tier".into()
            }
        );
    }

    /// Exit 5 with a confessed failure must refuse with the child's diagnosis,
    /// not fall back and not relabel. Deleting the UNUSABLE arm would answer
    /// "exit code 5" here instead.
    #[test]
    fn an_unusable_child_is_never_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        for stdout in [framed_unusable("prctl blocked"), framed("abi gone")] {
            let Err(failure) =
                map_child_result(Some(exit::UNUSABLE), &stdout, "stderr", dir.path())
            else {
                panic!("a failed confinement must refuse, never fall back");
            };
            let ChildFailure::Unusable(e) = failure else {
                panic!("exit 5 must be unusable, got: {failure:?}");
            };
            assert!(
                e.to_string().contains("partial tree"),
                "the refusal must warn dest may be partial, got: {e}"
            );
        }
        // The child's own words survive in the refusal.
        let Err(ChildFailure::Unusable(e)) = map_child_result(
            Some(exit::UNUSABLE),
            &framed_unusable("prctl blocked"),
            "",
            dir.path(),
        ) else {
            panic!("unreachable");
        };
        assert!(e.to_string().contains("prctl blocked"), "got: {e}");
    }

    #[test]
    fn an_unknown_code_or_signal_is_never_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        for code in [Some(99), None] {
            let Err(failure) = map_child_result(code, &framed_ok(), "boom", dir.path()) else {
                panic!("code {code:?} must refuse, never fall back");
            };
            assert!(
                matches!(failure, ChildFailure::Unusable(_)),
                "code {code:?} must be unusable, got: {failure:?}"
            );
        }
    }

    /// A clean exit carrying a failure reply is a protocol mismatch, handled
    /// by what the reply confesses, not by the exit code.
    #[test]
    fn a_mismatched_reply_is_handled_by_what_it_confesses() {
        let dir = tempfile::tempdir().unwrap();
        let Err(ChildFailure::Skip(skip)) =
            map_child_result(Some(exit::OK), &framed("late gap"), "", dir.path())
        else {
            panic!("an Unavailable reply must disclose even on exit 0");
        };
        assert!(matches!(skip, SandboxSkip::Unavailable { .. }));
        let Err(failure) = map_child_result(
            Some(exit::OK),
            &framed_unusable("late failure"),
            "",
            dir.path(),
        ) else {
            panic!("an Unusable reply must refuse even on exit 0");
        };
        assert!(matches!(failure, ChildFailure::Unusable(_)));
        let Err(failure) = map_child_result(Some(exit::OK), b"garbage", "", dir.path()) else {
            panic!("garbage on a clean exit must refuse, never fall back");
        };
        assert!(matches!(failure, ChildFailure::Unusable(_)));
    }

    /// `require_sandbox` refuses the review instead of falling back. Runs
    /// entirely in-harness: spawning is forbidden here, so the guard returns a
    /// skip and the policy turns it into a refusal before any extraction.
    #[test]
    fn require_sandbox_refuses_instead_of_falling_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = SandboxLedger::default();
        let mut policy = Policy::default();
        policy.policy.require_sandbox = true;
        let err = extract(
            ArchiveKind::Tar,
            b"never-read",
            dir.path(),
            &mut ledger,
            &policy,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("require_sandbox"),
            "the refusal must name the key, got: {err}"
        );
        assert!(
            err.to_string().contains("re-exec the test harness"),
            "the refusal must carry the skip detail, got: {err}"
        );
        assert!(
            ledger.skip().is_none(),
            "a refused review records no disclosure"
        );
    }

    /// The child writes its whole reply to a pipe the parent does not read until
    /// after `wait_with_timeout` returns. A reply larger than the pipe buffer
    /// therefore blocks the child in `write_all` and the parent waits out the
    /// full timeout. Refusal messages embed archive entry paths, so the size is
    /// attacker-controlled: this was a 300s hang per extraction, reachable from
    /// one malicious tarball.
    #[test]
    fn an_oversized_reply_is_never_written() {
        let huge = Reply::Refused {
            variant: "extraction".into(),
            message: "x".repeat(MAX_REPLY_BYTES * 4),
        };
        assert!(
            serde_json::to_vec(&huge).unwrap().len() > MAX_REPLY_BYTES,
            "the fixture must actually be oversized, or this test proves nothing"
        );
        // Same bound `write_reply` applies before touching stdout.
        let written = framed_reply_bytes(&huge);
        assert!(
            written.len() <= MAX_REPLY_BYTES,
            "what is written must fit a pipe buffer, got {}",
            written.len()
        );
        let parsed: Reply = serde_json::from_slice(&written).expect("still valid JSON");
        assert!(
            matches!(parsed, Reply::Refused { .. }),
            "an oversized reply keeps its outcome: rewriting it to `Unavailable` would \
             hand the parent a fallback over a dest the child already partly wrote, \
             got {parsed:?}"
        );
        let Reply::Refused { message, .. } = parsed else {
            unreachable!("just asserted")
        };
        assert!(
            message.ends_with(TRUNCATION_NOTE),
            "the operator is told the message was cut, got a message ending in {:?}",
            message.chars().rev().take(8).collect::<String>()
        );
    }

    /// The ordinary case must survive the bound untouched, or this fix has
    /// silently cost every normal refusal its message.
    #[test]
    fn a_normal_reply_passes_the_bound_unchanged() {
        let reply = Reply::Refused {
            variant: "extraction_limit".into(),
            message: "entry count over cap".into(),
        };
        let written = framed_reply_bytes(&reply);
        assert_eq!(
            serde_json::from_slice::<Reply>(&written).expect("round-trips"),
            reply
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

    /// The ceiling is 64 KiB, not 64 + 1024 and not anything else. A wrong
    /// constant here silently moves every bound in both directions.
    #[test]
    fn the_reply_ceiling_is_64_kib() {
        assert_eq!(MAX_REPLY_BYTES, 64 * 1024);
    }

    /// The body ceiling has to leave room for the length prefix and its
    /// newline, or the child deadlocks the parent again. The prefix is the
    /// decimal body length plus `\n`: 6 bytes at this size, so 32 is the reserve
    /// and it must not be spent.
    #[test]
    fn the_body_ceiling_leaves_room_for_the_length_prefix() {
        assert_eq!(MAX_REPLY_BODY_BYTES, MAX_REPLY_BYTES - 32);
        let prefix = format!("{}\n", MAX_REPLY_BODY_BYTES).len();
        assert!(
            MAX_REPLY_BYTES - MAX_REPLY_BODY_BYTES > prefix,
            "the reserve must exceed the longest length prefix, or a body at \
             the ceiling overruns the pipe it has to fit"
        );
    }

    /// Pad a refusal until its serialised body is exactly the *body* ceiling,
    /// so the boundary tests below prove something about `>` rather than `>=`.
    fn reply_at_exactly_the_ceiling() -> (Reply, Vec<u8>) {
        let base = serde_json::to_vec(&Reply::Refused {
            variant: "extraction".into(),
            message: String::new(),
        })
        .unwrap()
        .len();
        let reply = Reply::Refused {
            variant: "extraction".into(),
            message: "x".repeat(MAX_REPLY_BODY_BYTES - base),
        };
        let body = serde_json::to_vec(&reply).unwrap();
        assert_eq!(
            body.len(),
            MAX_REPLY_BODY_BYTES,
            "the fixture must sit exactly on the boundary, or these tests prove nothing"
        );
        (reply, body)
    }

    /// The whole point of the split: a body at the writer's ceiling still has to
    /// fit the pipe once the prefix is added. `write_reply` emits the decimal
    /// body length, a newline, then the body, so that sum is the length the
    /// parent actually has to drain from a 64 KiB pipe it does not read until
    /// the child has exited.
    #[test]
    fn a_framed_body_at_the_ceiling_still_fits_the_pipe() {
        let (_, body) = reply_at_exactly_the_ceiling();
        let on_wire = format!("{}\n", body.len()).len() + body.len();
        assert!(
            on_wire <= MAX_REPLY_BYTES,
            "a ceiling-sized reply wrote {on_wire} bytes, past the {MAX_REPLY_BYTES} pipe"
        );
    }

    /// `body.len() > MAX` passes an exactly-MAX body through. With `>=` this
    /// fails, and every normal-sized refusal near the ceiling would lose its
    /// message to the deadlock guard.
    #[test]
    fn a_reply_at_exactly_the_ceiling_passes_through() {
        let (reply, body) = reply_at_exactly_the_ceiling();
        assert_eq!(framed_reply_bytes(&reply), body);
    }

    /// `count > MAX` parses a declared count of exactly MAX. With `>=` the
    /// largest legal reply would be refused.
    #[test]
    fn a_declared_count_at_exactly_the_ceiling_parses() {
        let (reply, body) = reply_at_exactly_the_ceiling();
        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        assert_eq!(
            read_reply(&framed).expect("ceiling-sized reply parses"),
            reply
        );
    }

    /// The framing slices exactly `count` bytes, so trailing garbage after a
    /// complete reply must not move the parse. A framing off-by-one in either
    /// direction reads the wrong bytes and fails here.
    #[test]
    fn trailing_bytes_after_a_reply_do_not_move_the_parse() {
        let reply = Reply::Ok {
            files: 1,
            dirs: 0,
            unpacked_bytes: 7,
        };
        let body = serde_json::to_vec(&reply).unwrap();
        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        framed.extend_from_slice(b"TRAILING");
        assert_eq!(
            read_reply(&framed).expect("trailing bytes are ignored"),
            reply
        );
    }

    /// The raw stdout guard fires far past the framing, and names the ceiling.
    /// Without the message assertion a mutant that never fires would still
    /// refuse (via "no length prefix") and read as covered.
    #[test]
    fn an_oversized_stdout_is_refused_without_parsing() {
        let stdout = vec![b'9'; MAX_REPLY_BYTES + 33];
        let err = read_reply(&stdout).unwrap_err();
        assert!(
            err.to_string().contains("reply ceiling"),
            "a megabyte stdout must hit the ceiling guard, got: {err}"
        );
    }

    /// The guard allows the framing overhead: the largest legal body plus its
    /// short count header is a legal stdout, not an attack. The padding is
    /// computed rather than assumed, because the body sits on the *body*
    /// ceiling now, so the header is slack rather than the whole 32 bytes.
    #[test]
    fn a_stdout_at_exactly_the_margin_parses() {
        let (reply, body) = reply_at_exactly_the_ceiling();
        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        let slack = MAX_REPLY_BYTES + 32 - framed.len();
        framed.extend(std::iter::repeat_n(b't', slack));
        assert_eq!(framed.len(), MAX_REPLY_BYTES + 32);
        assert_eq!(read_reply(&framed).expect("marginal stdout parses"), reply);
    }

    #[test]
    fn an_oversized_reply_is_refused_before_allocating() {
        let header = format!("{}\n", MAX_REPLY_BYTES + 1);
        let err = read_reply(header.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("ceiling"), "got: {err}");
    }

    /// The bug the reviewer found: an oversized refusal used to be replaced by
    /// `Unavailable`, which the parent reads as "nothing was confined, retry
    /// in-process". That re-ran the extraction unconfined over a `dest` the
    /// child had already partly written. This drives the whole path, not just
    /// the serialiser, because the damage was in the mapping.
    #[test]
    fn an_oversized_refusal_stays_a_refusal_and_never_becomes_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let reply = Reply::Refused {
            variant: "extraction".into(),
            message: "entry ../../etc/passwd escapes the destination ".repeat(4_000),
        };
        let body = framed_reply_bytes(&reply);
        assert!(
            body.len() <= MAX_REPLY_BODY_BYTES,
            "the framed reply must fit the pipe, got {}",
            body.len()
        );

        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        let Err(ChildFailure::Refused(e)) =
            map_child_result(Some(exit::REFUSED), &framed, "", dir.path())
        else {
            panic!(
                "an oversized refusal must stay a Refused; a Skip here is the \
                 unconfined in-process retry over a partial tree"
            );
        };
        assert!(
            matches!(e, BluelineError::Extraction(_)),
            "the extractor's own variant must survive, got {e:?}"
        );
        assert!(
            e.to_string().contains(TRUNCATION_NOTE),
            "the operator must be told the message was cut, got: {e}"
        );
    }

    /// Same leak on the other branch that carries free text. `Unusable` means
    /// confinement failed and `dest` may be partial, so downgrading it to
    /// `Unavailable` invites the same retry.
    #[test]
    fn an_oversized_unusable_stays_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let reply = Reply::Unusable {
            reason: "no Landlock ABI tier could be established: ".repeat(4_000),
        };
        let body = framed_reply_bytes(&reply);
        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        let Err(ChildFailure::Unusable(_)) =
            map_child_result(Some(exit::UNUSABLE), &framed, "", dir.path())
        else {
            panic!("an oversized Unusable must not become a Skip");
        };
    }

    /// The cut lands wherever the byte budget runs out, which for a multi-byte
    /// character is inside it. `cut_to` walks back to a boundary; without that
    /// the child panics and the parent reads a live refusal as a dead child.
    /// The maximality assertion is what pins the walk-back arithmetic: a cut
    /// that stops one character early is still a safe prefix, so "never
    /// mid-character" alone cannot tell a tight cut from a timid one.
    #[test]
    fn a_cut_never_splits_a_multi_byte_character() {
        let text = "é".repeat(64); // 128 bytes, 64 two-byte characters
        for max in 0..=text.len() + 8 {
            let cut = cut_to(&text, max);
            assert!(
                cut.len() <= max,
                "cut of {max} bytes was {} bytes",
                cut.len()
            );
            assert!(
                text.starts_with(cut),
                "the cut must be a prefix, so the message keeps its head"
            );
            let next = text[cut.len()..].chars().next();
            assert!(
                next.is_none_or(|c| cut.len() + c.len_utf8() > max),
                "the cut must be maximal: a whole character still fits under {max}"
            );
            // The invariant that actually matters: this must not panic.
            let _ = serde_json::to_vec(&cut);
        }
    }

    /// A reply one byte over the body ceiling is still written, still framed,
    /// and still parses. The truncation path is not a refusal path.
    #[test]
    fn a_reply_one_byte_over_the_body_ceiling_is_truncated_not_dropped() {
        let base = serde_json::to_vec(&Reply::Refused {
            variant: "extraction".into(),
            message: String::new(),
        })
        .unwrap()
        .len();
        let reply = Reply::Refused {
            variant: "extraction".into(),
            message: "x".repeat(MAX_REPLY_BODY_BYTES - base + 1),
        };
        let body = framed_reply_bytes(&reply);
        assert!(body.len() <= MAX_REPLY_BODY_BYTES);
        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        let parsed = read_reply(&framed).expect("a truncated refusal still parses");
        let Reply::Refused { message, .. } = parsed else {
            panic!("the variant must survive truncation, got {parsed:?}");
        };
        assert!(message.ends_with(TRUNCATION_NOTE), "got: {message:?}");
        assert!(message.contains("entry") || message.starts_with('x'));
    }

    /// The cut is the overage, not a rough guess. For a plain-ASCII message
    /// (escaping is 1:1) the net removal is the overage plus the boundary
    /// slack and nothing more: the cut spares `over + marker + slack` raw
    /// bytes, then the marker is re-appended, so the marker nets to zero and
    /// only the slack is left. That is what makes the one-round argument
    /// checkable. A cut that keeps too little silently amputates the
    /// operator's diagnosis; a cut that keeps too much pushes the body back
    /// over the ceiling it exists to fit.
    #[test]
    fn an_oversized_reply_is_cut_by_almost_exactly_the_overage() {
        let original_len = MAX_REPLY_BODY_BYTES;
        let reply = Reply::Refused {
            variant: "extraction".into(),
            message: "x".repeat(original_len),
        };
        let before = serialise(&reply).len();
        let over = before - MAX_REPLY_BODY_BYTES;
        let body = framed_reply_bytes(&reply);
        assert!(body.len() <= MAX_REPLY_BODY_BYTES, "got {}", body.len());
        let parsed: Reply = serde_json::from_slice(&body).expect("truncated reply parses");
        let Reply::Refused { message: kept, .. } = parsed else {
            panic!("the variant survives truncation, got {parsed:?}");
        };
        let removed = original_len - kept.len();
        assert_eq!(
            removed,
            over + BOUNDARY_SLACK,
            "for an ASCII message the net removal is the overage plus the \
             boundary slack: the marker is cut out then re-appended, so it \
             nets to zero"
        );
        assert!(
            kept.ends_with(TRUNCATION_NOTE),
            "the marker must still be appended, got tail {:?}",
            &kept[kept.len().saturating_sub(60)..]
        );
    }

    /// The boundary walk-back is paid for, not swallowed: when the cut point
    /// lands inside a 4-byte character the reply keeps exactly the walk-back
    /// less and still fits. The real cut point is `MAX - wrapper - marker -
    /// slack`, measured rather than assumed, so the crab lands on it whatever
    /// the JSON wrapper costs. The crab starts `BOUNDARY_SLACK` bytes before
    /// the cut and ends one past it, so `cut_to` must walk back to the crab's
    /// start: never a mid-character slice, never the whole over-removed.
    #[test]
    fn a_cut_inside_a_four_byte_character_costs_exactly_the_walk_back() {
        // The real cut point, derived the same way `fit_to_frame` derives it.
        let probe = Reply::Refused {
            variant: "extraction".into(),
            message: String::new(),
        };
        let wrapper = serialise(&probe).len();
        let cut_point = MAX_REPLY_BODY_BYTES - wrapper - TRUNCATION_NOTE.len() - BOUNDARY_SLACK;
        // The crab straddles the cut: it starts `BOUNDARY_SLACK` bytes early
        // and runs one past, so its end is the first character end over it.
        let message = format!(
            "{}🦀{}",
            "x".repeat(cut_point - BOUNDARY_SLACK),
            "x".repeat(64)
        );
        let original_len = message.len();
        let reply = Reply::Refused {
            variant: "extraction".into(),
            message,
        };
        let before = serialise(&reply).len();
        let over = before - MAX_REPLY_BODY_BYTES;
        let body = framed_reply_bytes(&reply);
        assert!(body.len() <= MAX_REPLY_BODY_BYTES, "got {}", body.len());
        let parsed: Reply = serde_json::from_slice(&body).expect("truncated reply parses");
        let Reply::Refused { message: kept, .. } = parsed else {
            panic!("the variant survives truncation, got {parsed:?}");
        };
        // The cut landed on the crab's start byte: the crab and its tail are
        // gone, never split, and the marker is appended.
        let expected_keep = cut_point - BOUNDARY_SLACK;
        assert!(
            !kept.contains('🦀'),
            "the cut must walk back past the crab, never split it"
        );
        assert!(
            kept.ends_with(TRUNCATION_NOTE),
            "the marker must still be appended"
        );
        assert_eq!(
            kept.len(),
            expected_keep + TRUNCATION_NOTE.len(),
            "the reply keeps exactly the walk-back less, plus the marker"
        );
        // Net removal is the overage, the slack, and the full walk-back.
        assert_eq!(
            original_len - kept.len(),
            over + BOUNDARY_SLACK + BOUNDARY_SLACK,
            "the crab straddles the cut, so the full {BOUNDARY_SLACK}-byte \
             walk-back is paid on top of the overage and slack"
        );
    }

    /// `Ok` carries three integers and no free text, so there is nothing to
    /// cut. Pinned directly: a mutant that gave `Ok` a free-text arm, or
    /// dropped the `None` that makes `fit_to_frame` leave it alone, would
    /// otherwise be invisible because no oversized `Ok` exists to route
    /// through `fit_to_frame`.
    #[test]
    fn ok_has_no_free_text_to_cut() {
        let mut ok = Reply::Ok {
            files: 1,
            dirs: 0,
            unpacked_bytes: 0,
        };
        assert!(free_text_mut(&mut ok).is_none());
    }

    /// A message made of characters that escape to two bytes each drives the
    /// keep down to zero, and a zero keep clears the text rather than leaving
    /// a bare marker: the outcome alone is the reply. Escaping is the only
    /// way to reach it, because for an ASCII message `keep` is a constant
    /// `MAX - wrapper - marker - slack` no matter how long the text is.
    #[test]
    fn a_reply_whose_cut_would_keep_nothing_keeps_the_outcome() {
        let probe = Reply::Refused {
            variant: "extraction".into(),
            message: String::new(),
        };
        let wrapper = serialise(&probe).len();
        // Newlines escape to `\n` (two bytes), so escaped length is 2T.
        // keep = T - (over + marker + slack) and over = wrapper + 2T - MAX,
        // so keep = MAX - wrapper - marker - slack - T; T at that value is 0.
        let t = MAX_REPLY_BODY_BYTES - wrapper - TRUNCATION_NOTE.len() - BOUNDARY_SLACK;
        let reply = Reply::Refused {
            variant: "extraction".into(),
            message: "\n".repeat(t),
        };
        let before = serialise(&reply).len();
        assert!(
            before > MAX_REPLY_BODY_BYTES,
            "the fixture must be oversized, got {before}"
        );
        let body = framed_reply_bytes(&reply);
        assert!(body.len() <= MAX_REPLY_BODY_BYTES, "got {}", body.len());
        let parsed: Reply = serde_json::from_slice(&body).expect("truncated reply parses");
        let Reply::Refused { message: kept, .. } = parsed else {
            panic!("the variant survives truncation, got {parsed:?}");
        };
        assert!(
            kept.is_empty(),
            "a cut that would keep nothing clears the text, got {kept:?}"
        );
    }

    #[test]
    fn a_reply_with_no_length_prefix_is_refused() {
        let err = read_reply(b"{}").unwrap_err();
        assert!(err.to_string().contains("length prefix"), "got: {err}");
    }

    /// A reply that declares exactly the ceiling is legal; the guard refuses
    /// only past it. Without this the declared-count boundary is pinned from
    /// the refusing side alone, and `>` becoming `>=` would refuse the largest
    /// reply the protocol allows and nothing would notice.
    #[test]
    fn a_reply_declaring_exactly_the_ceiling_parses() {
        let base = serde_json::to_vec(&Reply::Unavailable {
            reason: String::new(),
        })
        .unwrap()
        .len();
        let body = serde_json::to_vec(&Reply::Unavailable {
            reason: "x".repeat(MAX_REPLY_BYTES - base),
        })
        .unwrap();
        assert_eq!(
            body.len(),
            MAX_REPLY_BYTES,
            "the fixture must declare exactly the ceiling, or this proves nothing"
        );
        let mut framed = format!("{}\n", body.len()).into_bytes();
        framed.extend_from_slice(&body);
        let reply = read_reply(&framed).expect("a reply declaring exactly the ceiling parses");
        assert!(matches!(reply, Reply::Unavailable { .. }), "{reply:?}");
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

    /// Build a gzipped tarball in memory. The `tar` builder writes honest
    /// archives; malicious ones need hand-rolled headers (see below).
    fn child_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// A tarball whose entry escapes the destination. Hand-rolled because the
    /// builder writes the path it is given and the extractor must refuse it.
    fn child_traversal_tarball() -> Vec<u8> {
        use std::io::Write;
        let mut header = [0u8; 512];
        header[..8].copy_from_slice(b"../evil\x00");
        header[100..108].copy_from_slice(b"0000644\x00");
        header[124..136].copy_from_slice(format!("{:011o}\x00", 2).as_bytes());
        header[156] = b'0';
        let mut sum: u32 = header.iter().map(|&b| b as u32).sum();
        sum += 8 * (b' ' as u32);
        header[148..156].copy_from_slice(format!("{sum:06o}\x00 ").as_bytes());
        let mut raw = Vec::new();
        raw.extend_from_slice(&header);
        raw.extend_from_slice(b"hi");
        raw.extend_from_slice(&vec![0u8; 510]);
        raw.extend_from_slice(&[0u8; 1024]);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw).unwrap();
        enc.finish().unwrap()
    }

    /// Drive the built binary as an extraction child. This is the one place
    /// that may exec: the target is the compiled binary, never this harness
    /// (`may_spawn_child` forbids re-exec here for exactly that reason).
    fn run_child_binary(kind: &str, dest: &Path, tarball: &[u8]) -> std::process::Output {
        assert_cmd::Command::cargo_bin("blueline")
            .unwrap()
            .env(CHILD_ENV, "1")
            .env(DEST_ENV, dest)
            .env(KIND_ENV, kind)
            .write_stdin(tarball.to_vec())
            .output()
            .unwrap()
    }

    fn stdout_reply(out: &std::process::Output) -> Reply {
        read_reply(&out.stdout).expect("a finished child leaves a parseable reply on stdout")
    }

    /// The confined happy path, end to end: a real child confines itself,
    /// extracts, and reports its stats in a framed reply.
    ///
    /// Gated on Linux because the assertion *is* the confinement: off Linux
    /// `run_child` never spawns and the child would exit `UNAVAILABLE`, and a
    /// Linux kernel without Landlock in `CONFIG_LSM` fails the same way. The
    /// protocol half is pinned everywhere by `map_child_result`'s unit tests;
    /// this one exists to prove the ruleset on a kernel that has it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_child_extracts_and_reports_its_stats() {
        let dir = tempfile::tempdir().unwrap();
        let tarball = child_tarball(&[
            ("package/package.json", b"{}"),
            ("package/lib/index.js", b"module.exports = 1;"),
        ]);
        let out = run_child_binary("tar", dir.path(), &tarball);
        assert_eq!(
            out.status.code(),
            Some(exit::OK),
            "a clean archive extracts confined, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        match stdout_reply(&out) {
            Reply::Ok {
                files,
                unpacked_bytes,
                ..
            } => {
                assert_eq!(files, 2);
                assert_eq!(unpacked_bytes, 21);
            }
            other => panic!("a clean archive reports Ok, got: {other:?}"),
        }
        assert!(dir.path().join("package/lib/index.js").exists());
    }

    /// A traversal archive is refused by the extractor in the child, and the
    /// refusal crosses the protocol as the extractor's own error, not as a
    /// sandbox failure.
    ///
    /// The message assertion is load-bearing. A broken hand-rolled checksum
    /// would make tar-rs fail to parse the header, and both that error and
    /// `validate_entry_path`'s rejection exit `REFUSED` with the `extraction`
    /// variant, so without naming the traversal itself this test would pass on
    /// an archive the extractor never even looked at.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_child_refuses_a_traversal_archive() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_child_binary("tar", dir.path(), &child_traversal_tarball());
        assert_eq!(
            out.status.code(),
            Some(exit::REFUSED),
            "a traversal archive is refused, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        match stdout_reply(&out) {
            Reply::Refused { variant, message } => {
                assert_eq!(variant, "extraction");
                assert!(
                    message.contains("parent traversal") && message.contains("../evil"),
                    "the refusal must be the path grammar naming the entry, not a parse \
                     error on the fixture's header, got: {message}"
                );
            }
            other => panic!("a refused archive reports Refused, got: {other:?}"),
        }
    }

    /// B1 regression: when confinement fails after narrowing started (here the
    /// destination cannot even be opened for the ruleset), the child exits
    /// UNUSABLE with a confessed failure, never UNAVAILABLE. An UNAVAILABLE
    /// here would read to the parent as "retry in-process", unconfined.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_that_cannot_confine_never_reports_unavailable() {
        let missing = std::env::temp_dir().join("blueline-sandbox-never-exists-9f3c");
        assert!(
            !missing.exists(),
            "the fixture needs a destination that is not there"
        );
        let out = run_child_binary("tar", &missing, b"never-read");
        assert_eq!(
            out.status.code(),
            Some(exit::UNUSABLE),
            "a failed confinement is unusable, never a fallback, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        match stdout_reply(&out) {
            Reply::Unusable { reason } => assert!(
                !reason.is_empty(),
                "the confession must diagnose the failure"
            ),
            other => panic!("a failed confinement confesses Unusable, got: {other:?}"),
        }
    }

    /// The child reports the tier the kernel granted, and it is one the ladder
    /// names.
    ///
    /// Drives the built binary, which is the only safe place to observe
    /// confinement: the harness must never call `restrict_self` itself. This is
    /// what pins `TIER_NAMES` against a tier string nothing produces, and what
    /// makes a `confine` that stopped confining observable at all, since a
    /// child that cannot confine exits `UNAVAILABLE` instead of `OK`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_confined_child_names_the_tier_it_established() {
        let dir = tempfile::tempdir().unwrap();
        let tarball = child_tarball(&[("package/package.json", b"{}")]);
        let out = run_child_binary("tar", dir.path(), &tarball);
        assert_eq!(
            out.status.code(),
            Some(exit::OK),
            "the child must extract confined, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        let named = TIER_NAMES.iter().any(|tier| stderr.contains(tier));
        assert!(
            named,
            "a confined child names one of {TIER_NAMES:?} on stderr, got: {stderr}"
        );
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
