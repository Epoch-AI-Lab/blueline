use crate::error::BluelineError;
use crate::manifest::parse_aur_srcinfo;
use crate::registry::http_util::RegistryLimits;
use crate::registry::{Checksum, ChecksumAlg, Ecosystem, Package, Registry, Release, hex_encode};
use crate::version::{AurVersionInfo, VersionInfo};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use ureq::Agent;

const USER_AGENT: &str = concat!("blueline/", env!("CARGO_PKG_VERSION"));
const RPC_VERSION: u8 = 5;

/// AUR RPC v5 metadata for one package (the `multiinfo` result shape).
/// Required fields fail closed on absence; optional fields are `None` when
/// the AUR omits or nulls them (e.g. `Maintainer` is null for orphans).
#[derive(Debug, Clone, Deserialize)]
pub struct AurInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Description")]
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "URL")]
    #[serde(default)]
    pub url: Option<String>,
    #[serde(rename = "NumVotes")]
    #[serde(default)]
    pub num_votes: Option<u64>,
    #[serde(rename = "Popularity")]
    #[serde(default)]
    pub popularity: Option<f64>,
    /// Unix timestamp when the package was flagged out-of-date, if it is.
    #[serde(rename = "OutOfDate")]
    #[serde(default)]
    pub out_of_date: Option<u64>,
    /// Null means the package is orphaned.
    #[serde(rename = "Maintainer")]
    #[serde(default)]
    pub maintainer: Option<String>,
    #[serde(rename = "FirstSubmitted")]
    #[serde(default)]
    pub first_submitted: Option<u64>,
    #[serde(rename = "LastModified")]
    #[serde(default)]
    pub last_modified: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AurRpcResponse {
    #[serde(rename = "version")]
    #[allow(dead_code)]
    version: u8,
    #[serde(rename = "type")]
    result_type: String,
    #[serde(rename = "resultcount")]
    result_count: u32,
    #[serde(rename = "results")]
    results: Vec<AurInfo>,
}

/// AUR names are lowercase alphanumerics plus `.@_+-`, bounded to 255 bytes,
/// and must start and end alphanumeric (the makepkg pkgname grammar,
/// restricted to what the AUR actually hosts).
pub fn validate_aur_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    name.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '+' | '-' | '@')
    })
}

/// Percent-encode a validated AUR name for use as a query value, so names
/// containing `+` or `@` cannot shift the query-string structure.
fn encode_query_value(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Client for the AUR RPC v5 metadata interface
/// (https://aur.archlinux.org/rpc/v5). Read-only; fetches package metadata
/// and the pkgname → pkgbase mapping used by the git-backed adapter below.
pub struct AurRpc {
    agent: Agent,
    base: String,
    limits: RegistryLimits,
}

impl AurRpc {
    pub fn new(base: &str) -> Self {
        Self::with_limits(base, RegistryLimits::default())
    }

    pub fn with_limits(base: &str, limits: RegistryLimits) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(90))
            .user_agent(USER_AGENT)
            .redirects(0)
            .build();
        Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            limits,
        }
    }

    /// Fetch RPC metadata for one package name. The returned `AurInfo::name`
    /// is compared verbatim against the request; a mismatch fails closed.
    pub fn info(&self, name: &str) -> Result<AurInfo, BluelineError> {
        if !validate_aur_name(name) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{name}` invalid AUR package name"
            )));
        }
        let url = format!(
            "{}/rpc/v5/info?arg%5B%5D={}",
            self.base,
            encode_query_value(name)
        );
        let resp = match self.agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                return Err(BluelineError::Manifest(
                    name.to_string(),
                    "not found".into(),
                ));
            }
            Err(e) => return Err(BluelineError::Network(format!("GET {url}: {e}"))),
        };
        if resp
            .header("content-type")
            .is_some_and(|ct| !ct.to_ascii_lowercase().contains("json"))
        {
            return Err(BluelineError::Manifest(
                name.to_string(),
                "bad content-type".into(),
            ));
        }
        let mut body = String::new();
        resp.into_reader()
            .take(self.limits.max_packument_bytes + 1)
            .read_to_string(&mut body)
            .map_err(|e| BluelineError::Network(format!("{e}")))?;
        if body.len() as u64 > self.limits.max_packument_bytes {
            return Err(BluelineError::ExtractionLimit(format!(
                "cap {}",
                self.limits.max_packument_bytes
            )));
        }
        let parsed: AurRpcResponse = serde_json::from_str(&body)
            .map_err(|e| BluelineError::Manifest(name.to_string(), format!("bad json: {e}")))?;
        if parsed.version != RPC_VERSION {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!("unsupported RPC version {}", parsed.version),
            ));
        }
        if parsed.result_type != "multiinfo" {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!("unexpected RPC result type `{}`", parsed.result_type),
            ));
        }
        if parsed.result_count as usize != parsed.results.len() {
            return Err(BluelineError::Manifest(
                name.to_string(),
                "resultcount does not match results".into(),
            ));
        }
        if parsed.results.len() > 1 {
            return Err(BluelineError::Manifest(
                name.to_string(),
                "expected exactly one result for an exact-name lookup".into(),
            ));
        }
        let info = parsed.results.into_iter().next().ok_or_else(|| {
            BluelineError::Manifest(name.to_string(), "not found in AUR".to_string())
        })?;
        if info.name != name {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!("registry returned name `{}` instead", info.name),
            ));
        }
        if !validate_aur_name(&info.package_base) {
            return Err(BluelineError::Manifest(
                name.to_string(),
                format!(
                    "registry returned invalid PackageBase `{}`",
                    info.package_base
                ),
            ));
        }
        Ok(info)
    }

    /// The git repository / package base that owns this package name. Split
    /// packages share a pkgbase; every repo-level operation must address it.
    pub fn pkgbase(&self, name: &str) -> Result<String, BluelineError> {
        Ok(self.info(name)?.package_base)
    }
}

/// How far back the git history walk may go, per the AUR night-run ruling.
/// Truncation is always surfaced in errors, never silent.
pub const MAX_HISTORY_COMMITS: usize = 200;

/// Cap on captured `git` stderr (error messages) and on tiny plumbing
/// outputs (rev-list counts, cat-file kinds, author emails).
const MAX_GIT_STDERR_BYTES: u64 = 4096;
const MAX_GIT_SMALL_OUTPUT_BYTES: u64 = 64 * 1024;

/// One commit from the history walk: 40-hex hash plus committer timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitMeta {
    hash: String,
    timestamp: i64,
}

fn validate_commit_hash(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `git+<clone-url>#<40-hex-commit>` is the only tarball URL grammar this
/// adapter produces or accepts.
fn parse_git_tarball_url(url: &str) -> Result<(String, String), BluelineError> {
    let fail = |msg: String| BluelineError::Verification(format!("AUR tarball url `{url}`: {msg}"));
    let rest = url
        .strip_prefix("git+")
        .ok_or_else(|| fail("must start with `git+`".to_string()))?;
    let (clone_url, commit) = rest
        .rsplit_once('#')
        .ok_or_else(|| fail("must pin a `#<commit>`".to_string()))?;
    if clone_url.is_empty() {
        return Err(fail("clone url is empty".to_string()));
    }
    if !validate_commit_hash(commit) {
        return Err(fail(
            "does not pin a 40-hex lowercase commit hash".to_string(),
        ));
    }
    Ok((clone_url.to_string(), commit.to_string()))
}

fn git_verb<'a>(args: &'a [&'a str]) -> &'a str {
    args.first().copied().unwrap_or("git")
}

fn git_spawn_error(e: &std::io::Error) -> BluelineError {
    if e.kind() == std::io::ErrorKind::NotFound {
        BluelineError::Network(
            "the `git` binary was not found; AUR reviews require the system git".to_string(),
        )
    } else {
        BluelineError::Network(format!("spawning `git`: {e}"))
    }
}

/// Run the system `git` with fixed argv (never a shell), capture stdout
/// capped at `max_stdout` bytes, and fail closed on any nonzero exit. Stderr
/// is drained on a thread so a chatty child cannot deadlock the pipes.
fn git_output(
    dir: Option<&Path>,
    args: &[&str],
    max_stdout: u64,
) -> Result<Vec<u8>, BluelineError> {
    let mut child = Command::new("git")
        .args(args)
        .current_dir(dir.unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| git_spawn_error(&e))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| BluelineError::Network("git stderr pipe unavailable".to_string()))?;
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe
            .take(MAX_GIT_STDERR_BYTES + 1)
            .read_to_end(&mut buf);
        buf
    });
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| BluelineError::Network("git stdout pipe unavailable".to_string()))?;
    let mut out = Vec::new();
    stdout_pipe
        .take(max_stdout + 1)
        .read_to_end(&mut out)
        .map_err(|e| BluelineError::Network(format!("reading git output: {e}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| BluelineError::Network("git stderr reader panicked".to_string()))?;
    let stdout_over_cap = out.len() as u64 > max_stdout;
    let stderr_over_cap = stderr.len() as u64 > MAX_GIT_STDERR_BYTES;
    if stdout_over_cap || stderr_over_cap {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| BluelineError::Network(format!("waiting for git: {e}")))?;
    if stdout_over_cap {
        return Err(BluelineError::ExtractionLimit(format!(
            "git {} output exceeds cap of {max_stdout} bytes",
            git_verb(args)
        )));
    }
    if stderr_over_cap {
        return Err(BluelineError::ExtractionLimit(format!(
            "git {} stderr exceeds cap of {MAX_GIT_STDERR_BYTES} bytes",
            git_verb(args)
        )));
    }
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(BluelineError::Network(format!(
            "git {} failed ({}): {}",
            git_verb(args),
            status,
            detail.trim()
        )));
    }
    Ok(out)
}

fn git_text(dir: Option<&Path>, args: &[&str], max_stdout: u64) -> Result<String, BluelineError> {
    let bytes = git_output(dir, args, max_stdout)?;
    String::from_utf8(bytes).map_err(|_| {
        BluelineError::Network(format!("git {} produced non-UTF-8 output", git_verb(args)))
    })
}

/// History walk over one cloned repo: the newest `cap` commits, ordered by
/// committer timestamp with the commit hash as deterministic tiebreak, plus
/// whether the walk truncated the repo's full history.
fn commit_history(repo: &Path, cap: usize) -> Result<(Vec<CommitMeta>, bool), BluelineError> {
    let count_text = git_text(
        Some(repo),
        &["rev-list", "--count", "HEAD"],
        MAX_GIT_SMALL_OUTPUT_BYTES,
    )?;
    let total: usize = count_text.trim().parse().map_err(|_| {
        BluelineError::Network(format!(
            "git rev-list --count produced unparseable output `{}`",
            count_text.trim()
        ))
    })?;
    let truncated = total > cap;
    let cap_str = cap.to_string();
    let log_text = git_text(
        Some(repo),
        &["log", "-n", &cap_str, "--format=%H %ct"],
        MAX_GIT_SMALL_OUTPUT_BYTES,
    )?;
    let mut commits = Vec::new();
    for line in log_text.lines() {
        let (hash, ts_str) = line.split_once(' ').ok_or_else(|| {
            BluelineError::Network(format!("git log produced unexpected line `{line}`"))
        })?;
        if !validate_commit_hash(hash) {
            return Err(BluelineError::Network(format!(
                "git log produced a commit reference `{hash}` that is not 40 lowercase hex"
            )));
        }
        let timestamp: i64 = ts_str.trim().parse().map_err(|_| {
            BluelineError::Network(format!("git log produced unparseable timestamp `{ts_str}`"))
        })?;
        commits.push(CommitMeta {
            hash: hash.to_string(),
            timestamp,
        });
    }
    commits.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.hash.cmp(&a.hash))
    });
    Ok((commits, truncated))
}

/// Static `.SRCINFO` version of one commit. A commit whose `.SRCINFO` is
/// missing, oversized, malformed, or carries an unparseable version yields
/// `None` (counted as a skip by the callers — VCS packages mutate pkgver
/// dynamically). Plumbing failures of `git rev-list`/`git log` never reach
/// this function; a `git show` failure here is per-commit, not repo-wide.
fn commit_version(repo: &Path, hash: &str) -> Option<AurVersionInfo> {
    let spec = format!("{hash}:.SRCINFO");
    let raw = git_text(
        Some(repo),
        &["show", &spec],
        crate::manifest::SRCINFO_MAX_BYTES,
    )
    .ok()?;
    parse_aur_srcinfo(&raw)
        .ok()
        .and_then(|s| AurVersionInfo::parse(&s.version).ok())
}

fn verify_commit_exists(repo: &Path, hash: &str) -> Result<(), BluelineError> {
    if !validate_commit_hash(hash) {
        return Err(BluelineError::Verification(format!(
            "`{hash}` is not a 40-hex lowercase commit hash"
        )));
    }
    let kind = git_text(Some(repo), &["cat-file", "-t", hash], 256)?;
    let kind = kind.trim();
    if kind != "commit" {
        return Err(BluelineError::Verification(format!(
            "`{hash}` exists in the clone but is a `{kind}`, not a commit"
        )));
    }
    Ok(())
}

fn with_aur_context(e: BluelineError, name: &str) -> BluelineError {
    match e {
        BluelineError::Manifest(_, msg) => {
            BluelineError::Manifest(format!("AUR package `{name}`"), msg)
        }
        BluelineError::Network(msg) => BluelineError::Network(format!("AUR: {msg}")),
        other => other,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

/// Registry adapter over AUR git history: resolves pkgname → pkgbase via
/// RPC, then addresses the package's git repo at
/// `{base}/{pkgbase}.git`. The commit hash is the trust anchor; review bytes
/// are `git archive` output verified against a resolve-time sha256 digest.
pub struct AurRegistry {
    rpc: AurRpc,
    git_base: String,
    limits: RegistryLimits,
}

impl AurRegistry {
    pub fn new(base: &str) -> Self {
        Self::with_bases(base, base, RegistryLimits::default())
    }

    /// Separate RPC and git bases: production derives both from the AUR base
    /// URL; tests point the RPC at a loopback fixture and git at a local
    /// path (plain `git clone` accepts local paths).
    pub fn with_bases(rpc_base: &str, git_base: &str, limits: RegistryLimits) -> Self {
        Self {
            rpc: AurRpc::with_limits(rpc_base, limits),
            git_base: git_base.trim_end_matches('/').to_string(),
            limits,
        }
    }

    fn clone_url(&self, pkgbase: &str) -> String {
        format!("{}/{}.git", self.git_base, pkgbase)
    }

    fn clone_repo(&self, url: &str, dest: &Path) -> Result<(), BluelineError> {
        let dest_str = dest.display().to_string();
        git_output(
            None,
            &["clone", "--quiet", url, &dest_str],
            MAX_GIT_SMALL_OUTPUT_BYTES,
        )?;
        Ok(())
    }

    fn archive_bytes(&self, repo: &Path, hash: &str) -> Result<Vec<u8>, BluelineError> {
        if !validate_commit_hash(hash) {
            return Err(BluelineError::Verification(format!(
                "`{hash}` is not a 40-hex lowercase commit hash"
            )));
        }
        git_output(
            Some(repo),
            &["archive", "--format=tar.gz", hash],
            self.limits.max_tarball_bytes,
        )
    }

    fn temp_repo(&self) -> Result<tempfile::TempDir, BluelineError> {
        tempfile::tempdir().map_err(|e| BluelineError::Network(format!("creating temp dir: {e}")))
    }

    fn resolve_package(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        if !validate_aur_name(name) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{name}` invalid AUR package name"
            )));
        }
        let target = AurVersionInfo::parse(version).map_err(|_| {
            BluelineError::InvalidPackageSpec(format!("`{name}@{version}` invalid AUR version"))
        })?;
        let pkgbase = self
            .rpc
            .pkgbase(name)
            .map_err(|e| with_aur_context(e, name))?;
        let clone_url = self.clone_url(&pkgbase);
        let repo = self.temp_repo()?;
        self.clone_repo(&clone_url, repo.path())?;
        let (commits, truncated) = commit_history(repo.path(), MAX_HISTORY_COMMITS)?;

        let mut skipped = 0usize;
        let mut matched: Option<&CommitMeta> = None;
        for c in &commits {
            match commit_version(repo.path(), &c.hash) {
                Some(v) if v == target => {
                    matched = Some(c);
                    break;
                }
                Some(_) => {}
                None => skipped += 1,
            }
        }
        let commit = matched.ok_or_else(|| {
            let mut msg = format!(
                "version `{version}` not found in the git history of `{pkgbase}` \
                 (checked {} commits, {skipped} without a parseable .SRCINFO)",
                commits.len()
            );
            if truncated {
                msg.push_str(&format!(
                    "; the walk stopped at the {MAX_HISTORY_COMMITS} newest commits, \
                     so an older matching commit would be missed and the review fails closed"
                ));
            }
            BluelineError::Manifest(pkgbase.clone(), msg)
        })?;

        let bytes = self.archive_bytes(repo.path(), &commit.hash)?;
        let checksum = Checksum {
            alg: ChecksumAlg::Sha256,
            value_hex: sha256_hex(&bytes),
        };
        Ok(Package {
            name: pkgbase,
            version: version.to_string(),
            tarball_url: format!("git+{clone_url}#{}", commit.hash),
            integrity: Some(checksum),
        })
    }

    fn fetch_verified(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        let (clone_url, commit) = parse_git_tarball_url(&pkg.tarball_url)?;
        let repo = self.temp_repo()?;
        self.clone_repo(&clone_url, repo.path())?;
        verify_commit_exists(repo.path(), &commit)?;
        let bytes = self.archive_bytes(repo.path(), &commit)?;
        let expected = pkg
            .integrity
            .as_ref()
            .ok_or_else(|| BluelineError::Verification("no checksum".to_string()))?;
        if expected.alg != ChecksumAlg::Sha256 {
            return Err(BluelineError::Verification("not sha256".to_string()));
        }
        let computed = sha256_hex(&bytes);
        if computed != expected.value_hex {
            return Err(BluelineError::Verification(format!(
                "sha256 mismatch {} vs {computed}",
                expected.to_display()
            )));
        }
        Ok(bytes)
    }

    fn releases_sorted(&self, name: &str) -> Result<Vec<Release>, BluelineError> {
        if !validate_aur_name(name) {
            return Err(BluelineError::InvalidPackageSpec(format!(
                "`{name}` invalid AUR package name"
            )));
        }
        let pkgbase = self
            .rpc
            .pkgbase(name)
            .map_err(|e| with_aur_context(e, name))?;
        let clone_url = self.clone_url(&pkgbase);
        let repo = self.temp_repo()?;
        self.clone_repo(&clone_url, repo.path())?;
        let (commits, truncated) = commit_history(repo.path(), MAX_HISTORY_COMMITS)?;
        if truncated {
            return Err(BluelineError::Manifest(
                pkgbase,
                format!(
                    "history walk stopped at the {MAX_HISTORY_COMMITS} newest commits, \
                     so older releases are outside the window and the review fails closed"
                ),
            ));
        }

        let mut seen: Vec<(AurVersionInfo, Release)> = Vec::new();
        let mut skipped = 0usize;
        for c in &commits {
            match commit_version(repo.path(), &c.hash) {
                Some(v) => {
                    // Commits are newest-first; keep the newest commit per
                    // distinct version for an accurate publish time.
                    if !seen.iter().any(|(bv, _)| *bv == v) {
                        let version = v.canonical();
                        seen.push((
                            v,
                            Release {
                                version,
                                yanked: false,
                                publish_time: Some(c.timestamp),
                            },
                        ));
                    }
                }
                None => skipped += 1,
            }
        }
        if seen.is_empty() {
            let msg = format!(
                "none of the last {} commits of `{pkgbase}` exposed a \
                 parseable .SRCINFO version ({skipped} commits skipped)",
                commits.len()
            );
            return Err(BluelineError::Manifest(pkgbase, msg));
        }
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(seen.into_iter().map(|(_, r)| r).collect())
    }
}

impl Registry for AurRegistry {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Aur
    }

    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
        self.resolve_package(name, version)
    }

    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError> {
        self.fetch_verified(pkg)
    }

    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError> {
        let mut v: Vec<semver::Version> = self
            .list_releases(name)?
            .into_iter()
            .filter_map(|r| {
                semver::Version::parse(&r.version).ok().or_else(|| {
                    AurVersionInfo::parse(&r.version)
                        .ok()
                        .and_then(|p| semver::Version::parse(&p.canonical()).ok())
                })
            })
            .collect();
        v.sort();
        Ok(v)
    }

    fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError> {
        self.releases_sorted(name)
    }

    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError> {
        Ok(self.list_releases(name)?.last().map(|r| r.version.clone()))
    }

    /// The commit author email of the pinned commit (self-declared AUR
    /// identity). Failures degrade to `None` = "unknown" by design.
    fn release_author(&self, pkg: &Package) -> Option<String> {
        let (clone_url, commit) = parse_git_tarball_url(&pkg.tarball_url).ok()?;
        let repo = self.temp_repo().ok()?;
        self.clone_repo(&clone_url, repo.path()).ok()?;
        let text = git_text(
            Some(repo.path()),
            &["log", "-1", "--format=%ae", &commit],
            MAX_GIT_SMALL_OUTPUT_BYTES,
        )
        .ok()?;
        let email = text.trim();
        if email.is_empty() || email.chars().any(char::is_control) {
            None
        } else {
            Some(email.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;

    fn rpc_body(info: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 5,
            "type": "multiinfo",
            "resultcount": 1,
            "results": [info]
        }))
        .unwrap()
    }

    fn sample_info() -> serde_json::Value {
        serde_json::json!({
            "ID": 100,
            "Name": "yay",
            "PackageBaseID": 101,
            "PackageBase": "yay",
            "Version": "12.4.2-1",
            "Description": "Yet another yogurt",
            "URL": "https://github.com/Jguer/yay",
            "NumVotes": 800,
            "Popularity": 42.5,
            "OutOfDate": null,
            "Maintainer": "Jguer",
            "FirstSubmitted": 1478763459,
            "LastModified": 1735689600,
            "URLPath": "/cgit/aur.git/snapshot/yay.tar.gz"
        })
    }

    struct MockAurServer {
        base: String,
        _handle: std::thread::JoinHandle<()>,
    }

    impl MockAurServer {
        fn spawn<F: Fn(&str) -> (u16, String, Vec<u8>) + Send + Sync + 'static>(
            handler: F,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let handler = Arc::new(handler);
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let h = handler.clone();
                    std::thread::spawn(move || {
                        let mut stream = stream;
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/")
                            .to_string();
                        let (status, ctype, body) = h(&path);
                        let head = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&body);
                    });
                }
            });
            Self {
                base,
                _handle: handle,
            }
        }
    }

    #[test]
    fn validate_aur_name_accepts_grammar_and_rejects_the_rest() {
        for ok in [
            "yay",
            "python-pydantic",
            "lib32-mesa",
            "2ping",
            "g_w-k.a+b@1x",
        ] {
            assert!(validate_aur_name(ok), "expected valid: {ok}");
        }
        for bad in [
            "",
            "-yay",
            "yay-",
            ".yay",
            "yay.",
            "+yay",
            "Yay",
            "y ay",
            "yay/",
            "yay?x",
            "yay&x",
            "é",
            "yay\t",
            &"a".repeat(256),
        ] {
            assert!(!validate_aur_name(bad), "expected invalid: {bad}");
        }
        assert!(validate_aur_name(&"a".repeat(255)));
    }

    #[test]
    fn encode_query_value_keeps_url_structure() {
        assert_eq!(encode_query_value("yay"), "yay");
        assert_eq!(encode_query_value("a+b"), "a%2Bb");
        assert_eq!(encode_query_value("a@b.c_d-e"), "a%40b.c_d-e");
    }

    #[test]
    fn info_resolves_metadata_and_pkgbase() {
        let server = MockAurServer::spawn(|path| {
            if path.starts_with("/rpc/v5/info?arg%5B%5D=yay") {
                (200, "application/json".into(), rpc_body(sample_info()))
            } else {
                (404, "text/plain".into(), b"nope".to_vec())
            }
        });
        let rpc = AurRpc::new(&server.base);
        let info = rpc.info("yay").unwrap();
        assert_eq!(info.name, "yay");
        assert_eq!(info.package_base, "yay");
        assert_eq!(info.version, "12.4.2-1");
        assert_eq!(info.num_votes, Some(800));
        assert_eq!(info.maintainer, Some("Jguer".to_string()));
        assert_eq!(info.out_of_date, None);
        assert_eq!(rpc.pkgbase("yay").unwrap(), "yay");
    }

    #[test]
    fn info_handles_split_packages_orphans_and_not_found() {
        let server = MockAurServer::spawn(|path| {
            if path.starts_with("/rpc/v5/info?arg%5B%5D=python-demo") {
                let mut info = sample_info();
                info["Name"] = serde_json::json!("python-demo");
                info["PackageBase"] = serde_json::json!("demo");
                info["Maintainer"] = serde_json::Value::Null;
                (200, "application/json".into(), rpc_body(info))
            } else if path.starts_with("/rpc/v5/info?arg%5B%5D=ghost") {
                (
                    200,
                    "application/json".into(),
                    serde_json::to_vec(&serde_json::json!({
                        "version": 5, "type": "multiinfo",
                        "resultcount": 0, "results": []
                    }))
                    .unwrap(),
                )
            } else {
                (404, "text/plain".into(), b"nope".to_vec())
            }
        });
        let rpc = AurRpc::new(&server.base);
        let info = rpc.info("python-demo").unwrap();
        assert_eq!(info.package_base, "demo");
        assert_eq!(info.maintainer, None);
        assert!(matches!(
            rpc.info("ghost"),
            Err(BluelineError::Manifest(_, _))
        ));
    }

    #[test]
    fn info_fails_closed_on_name_mismatch() {
        let server =
            MockAurServer::spawn(|_| (200, "application/json".into(), rpc_body(sample_info())));
        let rpc = AurRpc::new(&server.base);
        let err = rpc.info("not-yay").unwrap_err();
        assert!(err.to_string().contains("returned name `yay`"));
    }

    #[test]
    fn info_fails_closed_on_bad_rpc_shapes() {
        let cases: Vec<(String, &str)> = vec![
            (
                serde_json::json!({
                    "version": 6, "type": "multiinfo", "resultcount": 1,
                    "results": [sample_info()]
                })
                .to_string(),
                "unsupported RPC version",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "error", "resultcount": 0, "results": []
                })
                .to_string(),
                "unexpected RPC result type",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "multiinfo", "resultcount": 3,
                    "results": [sample_info(), sample_info()]
                })
                .to_string(),
                "resultcount does not match",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "multiinfo", "resultcount": 2,
                    "results": [sample_info(), sample_info()]
                })
                .to_string(),
                "expected exactly one result",
            ),
            (
                serde_json::json!({
                    "version": 5, "type": "multiinfo", "resultcount": 1,
                    "results": [{"Name": "yay", "Version": "1-1"}]
                })
                .to_string(),
                "bad json",
            ),
        ];
        for (body, needle) in cases {
            let server = MockAurServer::spawn(move |_| {
                (200, "application/json".into(), body.clone().into_bytes())
            });
            let rpc = AurRpc::new(&server.base);
            let err = rpc.info("yay").unwrap_err().to_string();
            assert!(err.contains(needle), "expected `{needle}` in `{err}`");
        }
    }

    #[test]
    fn info_fails_closed_on_bad_content_type_and_oversize() {
        let server = MockAurServer::spawn(|_| (200, "text/html".into(), b"<html/>".to_vec()));
        assert!(matches!(
            AurRpc::new(&server.base).info("yay"),
            Err(BluelineError::Manifest(_, _))
        ));

        let big = " ".repeat(4096);
        let server = MockAurServer::spawn(move |_| {
            (
                200,
                "application/json".into(),
                format!("{{\"pad\":\"{big}\"}}").into_bytes(),
            )
        });
        let rpc = AurRpc::with_limits(
            &server.base,
            RegistryLimits {
                max_packument_bytes: 1024,
                ..RegistryLimits::default()
            },
        );
        assert!(matches!(
            rpc.info("yay"),
            Err(BluelineError::ExtractionLimit(_))
        ));
    }

    #[test]
    fn info_rejects_invalid_names_before_any_network_use() {
        let server = MockAurServer::spawn(|_| (200, "application/json".into(), Vec::new()));
        let rpc = AurRpc::new(&server.base);
        assert!(matches!(
            rpc.info("../etc/passwd"),
            Err(BluelineError::InvalidPackageSpec(_))
        ));
    }

    // ===== AurRegistry: git-backed adapter fixtures =====

    const TS_BASE: i64 = 1_700_000_000;

    /// Serves the RPC pkgname → pkgbase mapping as the identity for every
    /// requested name; the git side lives in a real local repo at
    /// `{fixtures}/{name}.git`, reached by `git clone` over the plain path.
    struct AurGitFixture {
        _dir: tempfile::TempDir,
        server: MockAurServer,
        fixtures: std::path::PathBuf,
    }

    fn spawn_git_fixture() -> AurGitFixture {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = dir.path().join("fixtures");
        std::fs::create_dir_all(&fixtures).unwrap();
        let server = MockAurServer::spawn(|path| {
            if let Some(name) = path.strip_prefix("/rpc/v5/info?arg%5B%5D=") {
                let name = name.split('&').next().unwrap_or("");
                let info = serde_json::json!({
                    "ID": 1,
                    "Name": name,
                    "PackageBaseID": 1,
                    "PackageBase": name,
                    "Version": "1.0-1",
                    "Maintainer": "someone"
                });
                (200, "application/json".into(), rpc_body(info))
            } else {
                (404, "text/plain".into(), b"nope".to_vec())
            }
        });
        AurGitFixture {
            _dir: dir,
            server,
            fixtures,
        }
    }

    impl AurGitFixture {
        fn registry(&self) -> AurRegistry {
            AurRegistry::with_bases(
                &self.server.base,
                self.fixtures.to_str().unwrap(),
                RegistryLimits::default(),
            )
        }
    }

    fn git_run(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_fixture_repo(fixtures: &Path, pkgbase: &str) -> std::path::PathBuf {
        let repo = fixtures.join(format!("{pkgbase}.git"));
        std::fs::create_dir_all(&repo).unwrap();
        git_run(&repo, &["init", "--quiet", "-b", "master"]);
        git_run(&repo, &["config", "user.email", "default@example.com"]);
        git_run(&repo, &["config", "user.name", "Fixture"]);
        git_run(&repo, &["config", "commit.gpgsign", "false"]);
        repo
    }

    /// Writes PKGBUILD + .SRCINFO and commits them with a fixed committer
    /// timestamp and author email; returns the new HEAD hash.
    fn commit_pkg(
        repo: &Path,
        pkgbase: &str,
        pkgver: &str,
        pkgrel: &str,
        ts: i64,
        email: &str,
    ) -> String {
        std::fs::write(
            repo.join("PKGBUILD"),
            format!("pkgname={pkgbase}\npkgver={pkgver}\npkgrel={pkgrel}\n# fixture commit {ts}\n"),
        )
        .unwrap();
        std::fs::write(
            repo.join(".SRCINFO"),
            format!("pkgbase = {pkgbase}\n\tpkgver = {pkgver}\n\tpkgrel = {pkgrel}\n"),
        )
        .unwrap();
        git_run(repo, &["add", "-A"]);
        let date = format!("@{ts} +0000");
        let out = Command::new("git")
            .args([
                "commit",
                "--quiet",
                "-m",
                &format!("{pkgbase} {pkgver}-{pkgrel}"),
            ])
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date)
            .env("GIT_AUTHOR_EMAIL", email)
            .env("GIT_COMMITTER_EMAIL", email)
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git commit of {pkgbase} {pkgver}-{pkgrel} in {} failed: {} | stdout: {}",
            repo.display(),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo)
            .output()
            .unwrap();
        String::from_utf8(head.stdout).unwrap().trim().to_string()
    }

    /// Commits: 1.0.0-1 (alice) → 1.1.0-1 (bob) → 1.1.0-1 again (bob, newer
    /// commit, same version) → 1.2.0-1 (bob).
    fn spawn_versioned_fixture() -> (AurGitFixture, std::path::PathBuf) {
        let fx = spawn_git_fixture();
        let repo = init_fixture_repo(&fx.fixtures, "yay");
        commit_pkg(&repo, "yay", "1.0.0", "1", TS_BASE, "alice@example.com");
        commit_pkg(
            &repo,
            "yay",
            "1.1.0",
            "1",
            TS_BASE + 1000,
            "bob@example.com",
        );
        commit_pkg(
            &repo,
            "yay",
            "1.1.0",
            "1",
            TS_BASE + 2000,
            "bob@example.com",
        );
        commit_pkg(
            &repo,
            "yay",
            "1.2.0",
            "1",
            TS_BASE + 3000,
            "bob@example.com",
        );
        (fx, repo)
    }

    #[test]
    fn resolve_picks_newest_commit_for_a_version() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let pkg = reg.resolve("yay", "1.1.0-1").unwrap();
        assert_eq!(pkg.name, "yay");
        assert_eq!(pkg.version, "1.1.0-1");
        assert!(
            pkg.tarball_url.starts_with("git+"),
            "unexpected url {}",
            pkg.tarball_url
        );
        assert!(pkg.tarball_url.contains("/yay.git#"));
        assert_eq!(
            pkg.tarball_url.rsplit('#').next().unwrap().len(),
            40,
            "pinned commit must be a full hash: {}",
            pkg.tarball_url
        );
        assert!(pkg.integrity.is_some());
        assert_eq!(
            pkg.integrity.as_ref().unwrap().alg,
            crate::registry::ChecksumAlg::Sha256
        );
    }

    #[test]
    fn resolve_uses_the_newest_commit_when_versions_share_a_release() {
        let (fx, repo) = spawn_versioned_fixture();
        let newest_shared = Command::new("git")
            .args(["rev-parse", "HEAD~1"])
            .current_dir(&repo)
            .output()
            .unwrap();
        let newest_shared = String::from_utf8(newest_shared.stdout)
            .unwrap()
            .trim()
            .to_string();
        let reg = fx.registry();
        let pkg = reg.resolve("yay", "1.1.0-1").unwrap();
        assert_eq!(
            pkg.tarball_url.rsplit('#').next().unwrap(),
            newest_shared,
            "the newest commit carrying 1.1.0-1 must win"
        );
    }

    #[test]
    fn resolve_fails_closed_when_version_is_not_in_history() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let err = reg.resolve("yay", "9.9.9-1").unwrap_err().to_string();
        assert!(
            err.contains("not found in the git history"),
            "unexpected error: {err}"
        );
        assert!(err.contains("yay"), "error must name the pkgbase: {err}");
    }

    #[test]
    fn resolve_rejects_invalid_name_and_version_before_any_git_use() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        assert!(matches!(
            reg.resolve("Bad_Name!", "1.0.0-1"),
            Err(BluelineError::InvalidPackageSpec(_))
        ));
        assert!(matches!(
            reg.resolve("yay", "not//a/version"),
            Err(BluelineError::InvalidPackageSpec(_))
        ));
    }

    #[test]
    fn fetch_tarball_returns_verified_archive_content() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let pkg = reg.resolve("yay", "1.2.0-1").unwrap();
        let bytes = reg.fetch_tarball(&pkg).unwrap();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b], "archive must be gzip tar");

        let dest = tempfile::tempdir().unwrap();
        crate::extract::safe_extract(
            &bytes,
            dest.path(),
            &crate::extract::ExtractionLimits::default(),
        )
        .unwrap();
        assert!(
            dest.path().join("PKGBUILD").is_file(),
            "archive root must carry PKGBUILD"
        );
        assert!(dest.path().join(".SRCINFO").is_file());
        assert!(
            !dest.path().join("yay").exists(),
            "git archive emits files at the root, not under a pkgbase dir"
        );
    }

    #[test]
    fn fetch_tarball_fails_closed_on_tampered_integrity() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let pkg = reg.resolve("yay", "1.2.0-1").unwrap();

        let mut tampered = pkg.clone();
        tampered.integrity = Some(crate::registry::Checksum {
            alg: crate::registry::ChecksumAlg::Sha256,
            value_hex: "ab".repeat(32),
        });
        assert!(matches!(
            reg.fetch_tarball(&tampered),
            Err(BluelineError::Verification(_))
        ));

        let mut wrong_alg = pkg.clone();
        wrong_alg.integrity = Some(crate::registry::Checksum {
            alg: crate::registry::ChecksumAlg::Sha512,
            value_hex: "cd".repeat(64),
        });
        assert!(matches!(
            reg.fetch_tarball(&wrong_alg),
            Err(BluelineError::Verification(_))
        ));

        let mut missing = pkg.clone();
        missing.integrity = None;
        assert!(matches!(
            reg.fetch_tarball(&missing),
            Err(BluelineError::Verification(_))
        ));
    }

    #[test]
    fn fetch_tarball_enforces_the_git_url_grammar() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let mk_pkg = |url: &str| crate::registry::Package {
            name: "yay".to_string(),
            version: "1.0.0-1".to_string(),
            tarball_url: url.to_string(),
            integrity: Some(crate::registry::Checksum {
                alg: crate::registry::ChecksumAlg::Sha256,
                value_hex: "ab".repeat(32),
            }),
        };
        for bad in [
            "https://aur.archlinux.org/yay.git#0123456789abcdef0123456789abcdef01234567",
            "git+https://aur.archlinux.org/yay.git",
            "git+https://aur.archlinux.org/yay.git#abc123",
            "git+#0123456789abcdef0123456789abcdef01234567",
            "git+#0123456789ABCDEF0123456789abcdef01234567",
        ] {
            assert!(
                matches!(
                    reg.fetch_tarball(&mk_pkg(bad)),
                    Err(BluelineError::Verification(_))
                ),
                "expected grammar rejection for {bad}"
            );
        }
    }

    #[test]
    fn list_releases_orders_collapses_and_times_from_newest_commits() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let releases = reg.list_releases("yay").unwrap();
        let versions: Vec<&str> = releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, ["1.0.0-1", "1.1.0-1", "1.2.0-1"]);
        assert!(releases.iter().all(|r| !r.yanked));
        assert_eq!(releases[0].publish_time, Some(TS_BASE));
        // The shared-version release keeps the NEWEST commit's timestamp.
        assert_eq!(releases[1].publish_time, Some(TS_BASE + 2000));
        assert_eq!(releases[2].publish_time, Some(TS_BASE + 3000));

        assert_eq!(
            reg.default_version("yay").unwrap().as_deref(),
            Some("1.2.0-1")
        );
        let semvers = reg.list_versions("yay").unwrap();
        assert_eq!(semvers.len(), 3);
        assert_eq!(semvers[0].to_string(), "1.0.0-1");
    }

    #[test]
    fn list_releases_skips_unparseable_versions_and_fails_when_all_fail() {
        let fx = spawn_git_fixture();
        let repo = init_fixture_repo(&fx.fixtures, "skippy");
        commit_pkg(&repo, "skippy", "1.0.0", "1", TS_BASE, "a@example.com");
        // `+` is not a valid pkgver character, so this commit's version
        // cannot be derived and must be skipped, not fatal.
        commit_pkg(
            &repo,
            "skippy",
            "2.0+git",
            "1",
            TS_BASE + 1,
            "a@example.com",
        );
        commit_pkg(&repo, "skippy", "3.0.0", "1", TS_BASE + 2, "a@example.com");
        let reg = fx.registry();
        let releases = reg.list_releases("skippy").unwrap();
        let versions: Vec<&str> = releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, ["1.0.0-1", "3.0.0-1"]);

        let allbad = init_fixture_repo(&fx.fixtures, "allbad");
        commit_pkg(&allbad, "allbad", "1.0+git", "1", TS_BASE, "a@example.com");
        let err = reg.list_releases("allbad").unwrap_err().to_string();
        assert!(
            err.contains("parseable .SRCINFO"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn history_walk_caps_at_200_commits_and_states_truncation() {
        let fx = spawn_git_fixture();
        let repo = init_fixture_repo(&fx.fixtures, "long");
        for i in 0..201 {
            commit_pkg(
                &repo,
                "long",
                &format!("0.0.{i}"),
                "1",
                TS_BASE + i as i64,
                "a@example.com",
            );
        }
        let reg = fx.registry();

        // In-cap newest version resolves fine.
        if let Err(e) = reg.resolve("long", "0.0.200-1") {
            panic!("in-cap newest version must resolve: {e:#}");
        }

        // The oldest commit fell outside the 200-commit walk: fail closed
        // and state the truncation instead of pretending the version is gone.
        let err = reg.resolve("long", "0.0.0-1").unwrap_err().to_string();
        assert!(
            err.contains("200 newest commits"),
            "truncation must be stated: {err}"
        );

        // list_releases fails closed on truncation like resolve does.
        let err = reg.list_releases("long").unwrap_err().to_string();
        assert!(
            err.contains("200 newest commits"),
            "truncation must be stated: {err}"
        );
    }

    #[test]
    fn clone_failure_fails_closed_with_a_clear_error() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = AurRegistry::with_bases(
            &fx.server.base,
            "/nonexistent/blueline-fixture-path",
            RegistryLimits::default(),
        );
        let err = reg.resolve("yay", "1.0.0-1").unwrap_err().to_string();
        assert!(err.contains("git clone failed"), "unexpected error: {err}");
    }

    #[test]
    fn release_author_returns_the_pinned_commit_author_email() {
        let (fx, _repo) = spawn_versioned_fixture();
        let reg = fx.registry();
        let newer = reg.resolve("yay", "1.2.0-1").unwrap();
        assert_eq!(
            reg.release_author(&newer).as_deref(),
            Some("bob@example.com")
        );
        let older = reg.resolve("yay", "1.0.0-1").unwrap();
        assert_eq!(
            reg.release_author(&older).as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn tarball_url_grammar_helper_rejects_malformed_input() {
        assert!(
            parse_git_tarball_url("git+https://aur/x.git#0123456789abcdef0123456789abcdef01234567")
                .is_ok()
        );
        assert!(
            parse_git_tarball_url("git+/tmp/f/x.git#0123456789abcdef0123456789abcdef01234567")
                .is_ok()
        );
        assert!(
            parse_git_tarball_url("https://aur/x.git#0123456789abcdef0123456789abcdef01234567")
                .is_err()
        );
        assert!(parse_git_tarball_url("git+https://aur/x.git").is_err());
        assert!(parse_git_tarball_url("git+https://aur/x.git#nothex").is_err());
        assert!(parse_git_tarball_url("git+#0123456789abcdef0123456789abcdef01234567").is_err());
    }
}
