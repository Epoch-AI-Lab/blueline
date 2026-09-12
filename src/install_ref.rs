//! Static extraction of install references: package-manager invocations
//! inside a reviewed payload that resolve ANOTHER install on the victim
//! machine at install/build time (the TanStack `optionalDependencies →
//! github:orphan-commit → prepare` and Atomic Arch `npm install
//! atomic-lockfile` lane). Pure scanning of already-extracted bytes —
//! nothing here executes, fetches, or resolves anything.

use std::path::Path;

use crate::diff::Delta;
use crate::manifest::PackageJson;

const MAX_SCAN_LINE_BYTES: usize = 4096;

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
        }
    }
}

/// Where in the reviewed payload the reference was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefOrigin {
    NpmLifecycle { script: String },
    Pkgbuild { function: String },
    WheelDataScript { path: String },
}

/// One machine-resolved install reference. `pinned` means the spec carries
/// an exact version; `parseable` is false when the spec is dynamic
/// (shell expansion, wildcards, metacharacters) — the reference exists but
/// its target cannot be resolved statically, which downstream review treats
/// as its own finding, never as a guess.
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
    /// scoped npm names). Anything else — git/URL specs, ranges, dynamic
    /// payloads — is surfaced but not recursively resolvable.
    pub fn registry_spec(&self) -> Option<(&str, Option<&str>)> {
        if !self.parseable || self.spec.is_empty() {
            return None;
        }
        match self.manager {
            RefManager::Pip => {
                let (name, version) = match self.spec.split_once("==") {
                    Some((n, v)) => (n, Some(v)),
                    None => (self.spec.as_str(), None),
                };
                if valid_py_name(name) {
                    Some((name, version))
                } else {
                    None
                }
            }
            _ => {
                let (name, version) = match self.spec.rsplit_once('@') {
                    // A leading `@` with no second separator is a bare scoped
                    // name (`@scope/pkg`), not a version split.
                    Some((n, v)) if !n.is_empty() && !n.ends_with('@') => (n, Some(v)),
                    _ => (self.spec.as_str(), None),
                };
                if valid_npm_name(name) {
                    Some((name, version))
                } else {
                    None
                }
            }
        }
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

fn plain_npm_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '~')
        })
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
                | '|'
                | '&'
                | ';'
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

fn clean_token(token: &str) -> &str {
    token.trim_end_matches([',', ';'])
}

fn version_is_exact(manager: RefManager, version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    match manager {
        RefManager::Pip => version.chars().next().is_some_and(|c| c.is_ascii_digit()),
        _ => semver::Version::parse(version).is_ok(),
    }
}

/// Extract (manager, spec) pairs from one line of shell-like text. Words
/// are matched case-insensitively against package-manager invocation
/// shapes; the first positional argument after the verb is the spec. An
/// empty spec string means the invocation exists but its target is
/// dynamic/unparseable.
fn scan_words(words: &[&str]) -> Vec<(RefManager, String)> {
    let mut refs = Vec::new();
    for i in 0..words.len() {
        let w = clean_token(words[i]);
        let next = words.get(i + 1).map(|w| clean_token(w));
        let manager = match w {
            "npm" => RefManager::Npm,
            "npx" => RefManager::Npx,
            "pnpm" => RefManager::Pnpm,
            "yarn" => RefManager::Yarn,
            "bun" => RefManager::Bun,
            "bunx" => RefManager::Bunx,
            "pip" | "pip3" => RefManager::Pip,
            _ => continue,
        };
        let spec = match manager {
            RefManager::Npx | RefManager::Bunx => first_positional(&words[i + 1..]),
            RefManager::Pip => {
                if matches!(next, Some("install" | "i")) {
                    first_positional(&words[i + 2..])
                } else {
                    continue;
                }
            }
            RefManager::Pnpm | RefManager::Yarn if next == Some("dlx") => {
                first_positional(&words[i + 2..])
            }
            RefManager::Npm | RefManager::Pnpm | RefManager::Yarn | RefManager::Bun
                if matches!(next, Some("install" | "i" | "add")) =>
            {
                first_positional(&words[i + 2..])
            }
            _ => continue,
        };
        // `npm install` with no positional argument installs the manifest's
        // own declared dependencies — reviewed by R04, not an external ref.
        if let Some(spec) = spec {
            refs.push((manager, spec));
        }
    }
    refs
}

/// First positional (non-flag) token after a verb, or `Some("")` when the
/// next positional token exists but is dynamic/unparseable.
fn first_positional(words: &[&str]) -> Option<String> {
    for word in words {
        let token = clean_token(word);
        if token.is_empty() {
            continue;
        }
        if token.starts_with('-') {
            continue;
        }
        // A shell separator ends the command; nothing positional follows.
        if matches!(
            token,
            "&&" | "||" | "|" | ";" | "&" | "\n" | "echo" | "exit"
        ) {
            return None;
        }
        if has_dynamic_syntax(token) {
            // The invocation exists and names a target we cannot resolve
            // statically; the empty spec is disclosed, never guessed.
            return Some(String::new());
        }
        return Some(token.to_string());
    }
    None
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
    let version = match manager {
        RefManager::Pip => spec.split_once("==").map(|(_, v)| v),
        _ => match spec.rsplit_once('@') {
            Some((n, v)) if !n.is_empty() => Some(v),
            _ => None,
        },
    };
    let pinned = version
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

/// Install references inside an npm package's lifecycle scripts. Only the
/// scripts that run during a plain `npm install` are scanned — a reference
/// in `test` or `lint` never executes on the install line.
pub fn from_npm_lifecycle(manifest: &PackageJson) -> Vec<InstallRef> {
    let mut refs = Vec::new();
    for script_name in manifest.lifecycle_scripts() {
        let Some(body) = manifest.scripts.get(&script_name) else {
            continue;
        };
        for line in body.lines() {
            if line.len() > MAX_SCAN_LINE_BYTES {
                continue;
            }
            let lower = line.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            for (manager, spec) in scan_words(&words) {
                let origin = RefOrigin::NpmLifecycle {
                    script: script_name.clone(),
                };
                refs.push(raw_ref(origin, manager, &spec));
            }
        }
    }
    refs
}

/// Install references inside wheel `.data/scripts` payloads, which ship
/// onto PATH and run with the user's privileges. Scan is delta-driven and
/// bounded: only text files listed in the delta under a `.data/scripts/`
/// directory, each capped at `MAX_SCAN_LINE_BYTES` per line. A script file
/// that cannot be read as UTF-8 is disclosed as an unparseable reference
/// rather than silently skipped.
pub fn from_wheel_data_scripts(root: &Path, delta: &Delta) -> Vec<InstallRef> {
    let mut refs = Vec::new();
    let mut changed = delta
        .files_added
        .iter()
        .chain(delta.files_modified.iter())
        .filter(|f| f.relative_path.contains(".data/scripts/"));
    for change in changed.by_ref() {
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
            if line.len() > MAX_SCAN_LINE_BYTES {
                continue;
            }
            let lower = line.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            for (manager, spec) in scan_words(&words) {
                let origin = RefOrigin::WheelDataScript { path: path.clone() };
                refs.push(raw_ref(origin, manager, &spec));
            }
        }
    }
    refs
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
    fn lifecycle_npx_and_bunx() {
        let refs = npm_refs("prepare", "npx cypress@13.0.0 install && bunx esbuild");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].manager, RefManager::Npx);
        assert_eq!(refs[0].spec, "cypress@13.0.0");
        assert_eq!(refs[1].manager, RefManager::Bunx);
        assert_eq!(refs[1].spec, "esbuild");
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
    fn non_lifecycle_scripts_are_ignored() {
        assert!(npm_refs("test", "npm install something").is_empty());
        assert!(npm_refs("lint", "npx eslint .").is_empty());
    }

    #[test]
    fn unpinned_range_is_not_pinned() {
        let refs = npm_refs("postinstall", "npm install left-pad@^1.3.0");
        assert_eq!(refs.len(), 1);
        assert!(!refs[0].pinned);
        assert_eq!(refs[0].registry_spec(), Some(("left-pad", Some("^1.3.0"))));
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
    fn pnpm_dlx_and_pip3_shapes() {
        let words: Vec<&str> = "pnpm dlx malcontent && pip3 install evil-pkg"
            .split_whitespace()
            .collect();
        let refs = scan_words(&words);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].0, RefManager::Pnpm);
        assert_eq!(refs[0].1, "malcontent");
        assert_eq!(refs[1].0, RefManager::Pip);
        assert_eq!(refs[1].1, "evil-pkg");
    }
}
