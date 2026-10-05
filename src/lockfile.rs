use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::version::VersionInfo;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile JSON: {0}")]
    InvalidJson(serde_json::Error),

    #[error("failed to parse Cargo.lock TOML: {0}")]
    InvalidToml(String),

    #[error("lockfile is missing mandatory field: {0}")]
    MissingField(&'static str),

    #[error("invalid lockfile data: {0}")]
    InvalidData(String),
}

// Manual From instead of #[from]: the Display already embeds the serde_json
// detail, and thiserror's #[from] would also attach it as `source()`, which
// makes `{e:#}` in main print the detail twice.
impl From<serde_json::Error> for LockfileError {
    fn from(e: serde_json::Error) -> Self {
        LockfileError::InvalidJson(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub integrity: Option<String>,
    pub resolved: Option<String>,
    pub is_dev: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageUpgrade {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub old_integrity: Option<String>,
    pub new_integrity: Option<String>,
    pub resolved: Option<String>,
    pub is_dev: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileDelta {
    pub added: Vec<PackageEntry>,
    pub upgraded: Vec<PackageUpgrade>,
    pub removed: Vec<PackageEntry>,
    pub unchanged_count: usize,
}

impl LockfileDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.upgraded.is_empty() && self.removed.is_empty()
    }

    pub fn total_changed(&self) -> usize {
        self.added.len() + self.upgraded.len() + self.removed.len()
    }
}

#[derive(Deserialize)]
struct RawLockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u32>,
    packages: Option<BTreeMap<String, RawPackageV3>>,
    dependencies: Option<BTreeMap<String, RawDependencyV1>>,
}

#[derive(Deserialize)]
struct RawPackageV3 {
    name: Option<String>,
    version: Option<String>,
    integrity: Option<String>,
    resolved: Option<String>,
    dev: Option<bool>,
    /// npm writes a workspace entry as `{"resolved": "packages/x", "link": true}`
    /// with no `version` and no `integrity`: it points at a directory in the
    /// repo, not at an installed artifact.
    link: Option<bool>,
}

#[derive(Deserialize)]
struct RawDependencyV1 {
    version: Option<String>,
    integrity: Option<String>,
    resolved: Option<String>,
    dev: Option<bool>,
    dependencies: Option<BTreeMap<String, RawDependencyV1>>,
}

pub fn parse_lockfile_packages(
    json_content: &str,
) -> Result<BTreeMap<String, PackageEntry>, LockfileError> {
    let raw: RawLockfile = serde_json::from_str(json_content)?;
    let mut packages = BTreeMap::new();

    if let Some(raw_packages) = raw.packages {
        // v2 / v3 format
        for (path, pkg) in raw_packages {
            // Skip root package represented by empty string or "."
            if path.is_empty() || path == "." {
                continue;
            }

            // A workspace link (`link: true`) points at a directory in the repo
            // rather than an installed artifact, so npm writes it with no
            // `version` and no `integrity`, and it is skipped, as the
            // empty-string root entry above is.
            //
            // The skip is narrow on purpose. Keying it on `link` alone meant any
            // entry could add `"link": true` and leave the graph carrying
            // nothing at all: the delta put the entry in `removed`, which
            // `ci` never evaluates, so a version or an integrity swap became
            // silence while `passed` stayed true. npm does not write a link
            // entry that also declares a version or an integrity, so that shape
            // is a hand edit and there is no honest reading of it.
            if pkg.link.unwrap_or(false) {
                if pkg.version.is_some() || pkg.integrity.is_some() {
                    return Err(LockfileError::InvalidData(format!(
                        "`{path}` is a link but declares a version or an integrity; \
                         npm writes a link as `{{\"resolved\": ..., \"link\": true}}` \
                         with neither, refusing to review an entry that cannot be read"
                    )));
                }
                continue;
            }

            // Every other entry with no version is not a package that does not
            // exist. Skipping it dropped the entry from the graph, so a
            // lockfile whose entry was rewritten into a shape the parser cannot
            // read still compared as fully reviewed and the delta reported
            // nothing where the entry used to be. Refuse, naming the path,
            // which is the fail-closed reading and matches how the alias
            // mismatch below handles an entry whose identity is ambiguous.
            let Some(version) = pkg.version else {
                return Err(LockfileError::InvalidData(format!(
                    "`{path}` declares no version; refusing to review a lockfile \
                     with an entry that cannot be read"
                )));
            };

            let key_name = extract_package_name_from_path(&path);
            let name = match pkg.name {
                Some(n) if n.is_empty() => key_name.clone(),
                Some(n) => n,
                None => key_name.clone(),
            };

            // A path that yields no name is not a package with an empty name.
            // Skipping it dropped the entry from the graph, so a lockfile whose
            // entry was rewritten into a shape this parser cannot name still
            // compared as fully reviewed. Refuse, naming the path, for the same
            // reason the versionless entry above is refused.
            if name.is_empty() {
                return Err(LockfileError::InvalidData(format!(
                    "`{path}` yields no package name; refusing to review a lockfile \
                     with an entry that cannot be read"
                )));
            }

            // Under node_modules, a declared name that differs from the
            // directory is an npm alias, and npm records the real source in
            // `resolved`. Requiring those to agree rejects a hand-edited entry
            // pointing one package at another, while every honest alias
            // passes. A mismatch with no `resolved` has no honest explanation.
            if path.contains("node_modules/") && name != key_name {
                let resolved = pkg.resolved.as_deref().unwrap_or_default();
                if !resolved_names_package(resolved, &name) {
                    return Err(LockfileError::InvalidData(format!(
                        "`{path}` declares name `{name}` but its resolved URL is `{resolved}`; \
                         refusing to review an entry whose identity is ambiguous"
                    )));
                }
            }

            let entry = PackageEntry {
                name: name.clone(),
                version,
                integrity: pkg.integrity,
                resolved: pkg.resolved,
                is_dev: pkg.dev.unwrap_or(false),
            };

            // Key by normalized path in node_modules tree to handle nested deps
            let normalized_key = normalize_node_modules_path(&path);
            packages.insert(normalized_key, entry);
        }
    } else if let Some(raw_dependencies) = raw.dependencies {
        // v1 format
        walk_v1_dependencies("", &raw_dependencies, &mut packages, 0);
    } else {
        // Lockfile with neither packages nor dependencies (empty or invalid)
        if raw.lockfile_version.is_none() {
            return Err(LockfileError::MissingField("lockfileVersion"));
        }
    }

    Ok(packages)
}

const MAX_LOCKFILE_RECURSION_DEPTH: usize = 32;

fn walk_v1_dependencies(
    prefix: &str,
    deps: &BTreeMap<String, RawDependencyV1>,
    out: &mut BTreeMap<String, PackageEntry>,
    depth: usize,
) {
    if depth > MAX_LOCKFILE_RECURSION_DEPTH {
        return;
    }

    for (name, dep) in deps {
        let Some(version) = &dep.version else {
            continue;
        };

        let path_key = if prefix.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{prefix}/node_modules/{name}")
        };

        let entry = PackageEntry {
            name: name.clone(),
            version: version.clone(),
            integrity: dep.integrity.clone(),
            resolved: dep.resolved.clone(),
            is_dev: dep.dev.unwrap_or(false),
        };

        out.insert(path_key.clone(), entry);

        if let Some(nested) = &dep.dependencies {
            walk_v1_dependencies(&path_key, nested, out, depth + 1);
        }
    }
}

fn extract_package_name_from_path(path: &str) -> String {
    let name_part = path.rsplit("node_modules/").next().unwrap_or(path);
    name_part.trim_end_matches('/').to_string()
}

/// Does an npm `resolved` URL name the package it claims to? `resolved` plus
/// `integrity` is what npm actually fetches, so it, not the directory name,
/// is the install identity.
fn resolved_names_package(resolved: &str, name: &str) -> bool {
    if resolved.is_empty() {
        return false;
    }
    let Some(last) = resolved.rsplit('/').next() else {
        return false;
    };
    // `<name>-<version>.tgz`, where a scoped name keeps its slash.
    let stem = last.strip_suffix(".tgz").unwrap_or(last);
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    stem.strip_prefix(unscoped)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
}

fn normalize_node_modules_path(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_end_matches('/')
        .to_string()
}

const MAX_CARGO_LOCK_BYTES: usize = 10 * 1024 * 1024;

#[derive(Deserialize)]
struct CargoLockFile {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

pub fn parse_cargo_lock_packages(
    toml_content: &str,
) -> Result<BTreeMap<String, PackageEntry>, LockfileError> {
    if toml_content.len() > MAX_CARGO_LOCK_BYTES {
        return Err(LockfileError::InvalidData(format!(
            "Cargo.lock exceeds maximum size of {} bytes (got {})",
            MAX_CARGO_LOCK_BYTES,
            toml_content.len()
        )));
    }

    let parsed: CargoLockFile =
        toml::from_str(toml_content).map_err(|e| LockfileError::InvalidToml(e.to_string()))?;

    let packages = parsed.package.unwrap_or_default();
    let mut out = BTreeMap::new();

    for pkg in packages {
        let name = pkg.name.ok_or_else(|| {
            LockfileError::InvalidData("cargo package missing mandatory field: name".to_string())
        })?;
        let version = pkg.version.ok_or_else(|| {
            LockfileError::InvalidData("cargo package missing mandatory field: version".to_string())
        })?;

        if name.is_empty() || version.is_empty() {
            return Err(LockfileError::InvalidData(
                "cargo package has empty name or version".to_string(),
            ));
        }

        let integrity = match pkg.checksum {
            Some(c) => {
                let hex = c.to_lowercase();
                if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    return Err(LockfileError::InvalidData(format!(
                        "invalid cargo checksum for {name}@{version}: expected 64 hex chars, got `{c}`",
                    )));
                }
                Some(format!("sha256:{hex}"))
            }
            None => None,
        };
        let resolved = pkg.source.clone();

        let entry = PackageEntry {
            name: name.clone(),
            version: version.clone(),
            integrity,
            resolved,
            is_dev: false,
        };

        let key = format!("cargo/{}@{}", name, version);
        if let Some(prev) = out.get(&key)
            && prev != &entry
        {
            return Err(LockfileError::InvalidData(format!(
                "duplicate cargo package entry for {key} with differing data",
            )));
        }
        out.insert(key, entry);
    }

    Ok(out)
}

const MAX_REQUIREMENTS_TXT_BYTES: usize = 10 * 1024 * 1024;

/// The two spellings the token loop below consumes as a hash rather than as a
/// requirement spec. Every other token starting with `-` is an option.
fn is_hash_option(token: &str) -> bool {
    token == "--hash" || token.starts_with("--hash=")
}

/// Whether a token could be an option's *value* rather than a requirement.
///
/// Under the options opt-in, a line that mixes an option with a requirement
/// cannot be split reliably: whether `-r` consumes the token after it is pip's
/// business, not ours, and three separate rounds of review each found another
/// requirement shape that a splitting heuristic lost -- a pinned spec, an
/// unpinned range, then a bare name, an extras form and a direct URL. So the
/// line is only treated as option-only when every token is unmistakably part of
/// an option: a flag, a URL, a path, or the working directory.
///
/// A filename used to be on that list, on the reasoning that `base.txt` is what
/// `-r` consumes. It cannot come off by narrowing the rule, because a PyPI
/// project name may legally contain dots and end in a letter: `payload.txt` and
/// `payload.in` are valid names, and `payload.txt==1.0.0` is a valid pin. So the
/// shape does not distinguish the two cases, it only decides which one gets
/// silently dropped. `requests==2.31.0 --pre payload.txt` parsed as a truncated
/// line, the pin survived and `payload.txt` vanished -- and a package that pip
/// still installs then lands in the *removed* set, which CI never evaluates and
/// reports as if it had been uninstalled.
///
/// Whether `-r` consumes the next token is pip's business and this parser
/// deliberately does not model it, so the ambiguous class is refused. That does
/// mean the opt-in no longer tolerates `-r other.txt` or `-c constraints.txt`,
/// which is the correct direction: both name a second file whose contents this
/// parser never sees.
///
/// Erring towards "requirement" is the fail-closed direction: it refuses a line
/// rather than dropping a package from the reviewed graph.
fn is_option_or_value(token: &str) -> bool {
    token.starts_with('-')
        || token.contains("://")
        || token.contains('/')
        || token.contains('\\')
        // `-e .` is an editable install of the working directory, which is a
        // value rather than a requirement. `.` and `..` are not valid project
        // names, so unlike `payload.txt` they are unambiguously a path.
        || token == "."
        || token == ".."
}

/// Whether a set of tokens contains something that is not part of an option, and
/// so must be a requirement this parser would otherwise lose.
fn carries_requirement(tokens: &[&str]) -> bool {
    tokens.iter().any(|t| !is_option_or_value(t))
}

/// Parse a pinned requirements.txt file (PEP 508 / pip requirements format).
/// Fail-closed rules:
/// - Size cap 10 MiB.
/// - Unpinned specifications (e.g. `foo>=1.0`, `bar`, `baz~=2.0`, `qux!=1.1`) fail closed
///   with line-numbered errors listing every unpinned line.
/// - Valid lines must have exact pinned version `name == version` (or `name==version`).
/// - Optional `--hash=sha256:<hex>` is parsed and validated (64 hex characters).
/// - Comments (`#...`) and blank lines are skipped. Any other option
///   (`--index-url`, `--extra-index-url`, `-r`, ...) fails the file closed
///   unless `allow_options` opts in, on any token of the line, not only a
///   leading one.
pub fn parse_requirements_txt_packages(
    content: &str,
    allow_options: bool,
) -> Result<BTreeMap<String, PackageEntry>, LockfileError> {
    if content.len() > MAX_REQUIREMENTS_TXT_BYTES {
        return Err(LockfileError::InvalidData(format!(
            "requirements.txt exceeds maximum size of {} bytes (got {})",
            MAX_REQUIREMENTS_TXT_BYTES,
            content.len()
        )));
    }

    let mut packages = BTreeMap::new();
    let mut unpinned_errors = Vec::new();

    // Process line continuations (lines ending in `\`)
    let mut raw_lines = Vec::new();
    let mut current_line = String::new();
    let mut start_line_num = 1;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();
        if let Some(without_slash) = trimmed.strip_suffix('\\') {
            if current_line.is_empty() {
                start_line_num = line_num;
            }
            current_line.push_str(without_slash.trim_end());
            current_line.push(' ');
        } else if !current_line.is_empty() {
            current_line.push_str(trimmed);
            raw_lines.push((start_line_num, std::mem::take(&mut current_line)));
        } else if !trimmed.is_empty() {
            raw_lines.push((line_num, trimmed.to_string()));
        }
    }
    if !current_line.is_empty() {
        raw_lines.push((start_line_num, current_line));
    }

    for (line_num, raw_line) in raw_lines {
        let line = raw_line.trim();
        let code_part = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        if code_part.is_empty() {
            continue;
        }

        let mut code_part: String = code_part.to_string();
        // An option that redirects pip changes which packages get installed,
        // so reviewing the pinned lines alone certifies a graph nobody will
        // install. Refused rather than skipped, unless policy opts in, and
        // checked on every token so a flag trailing a spec is caught too: a
        // line-leading check folded `--index-url https://evil` into the
        // version string and refused it as a PEP 440 error quoting the flag,
        // which is not the refusal it is.
        if let Some(option) = code_part
            .split_whitespace()
            .find(|tok| tok.starts_with('-') && !is_hash_option(tok))
        {
            if !allow_options {
                return Err(LockfileError::InvalidData(format!(
                    "line {line_num}: unsupported requirements option `{option}`; blueline \
                     models only pinned `name==version [--hash sha256:...]` lines and cannot \
                     follow an alternative index, an extra requirements file, or a constraints \
                     file. Set [ci] allow_requirements_options = true to review the pins anyway."
                )));
            }
            // The opt-in path must still review the pin on this line. Skipping
            // the line outright meant `requests==2.31.0 --index-url ...` put
            // nothing in the graph, so the package the line pins was never
            // checked at all -- a fail-open dressed as a disclosure.
            //
            // Everything from the first non-hash option onward is dropped, and
            // the spec before it is parsed as normal. Truncating is simpler
            // and safer than picking option tokens out one at a time: whether
            // `-r` consumes the next token is pip's business, and guessing
            // wrong folds a path or a URL into a version. A `--hash` before
            // the first redirecting option is kept, because that one is part of
            // the pin. A `--hash` after it is lost, which makes the line fail
            // its hash check rather than pass unreviewed.
            let tokens: Vec<&str> = code_part.split_whitespace().collect();
            match tokens
                .iter()
                .position(|tok| tok.starts_with('-') && !is_hash_option(tok))
            {
                None => {}
                Some(cut) => {
                    // Everything from the first redirecting option onward is
                    // off-limits, because a requirement in that tail is
                    // unreachable and nothing downstream would ever say so.
                    // Refuse rather than review a partial line: silently
                    // dropping a pin files the package as *removed*, and
                    // silently dropping a range loses the unpinned error.
                    if tokens[cut..].iter().any(|t| is_hash_option(t)) {
                        return Err(LockfileError::InvalidData(format!(
                            "line {line_num}: a requirements option precedes `--hash`, so the \
                             declared hash would be discarded unreviewed: `{code_part}`"
                        )));
                    }
                    if carries_requirement(&tokens[cut..]) {
                        return Err(LockfileError::InvalidData(format!(
                            "line {line_num}: a requirements option is mixed with a requirement \
                             on the same line, so the requirement cannot be reviewed alongside \
                             it: `{code_part}`"
                        )));
                    }
                    // Option-only line: the ordinary pip layout, where the
                    // requirement it belongs to is on another line.
                    if cut == 0 {
                        continue;
                    }
                    code_part = tokens[..cut].join(" ");
                }
            }
        }

        let tokens: Vec<&str> = code_part.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let mut hashes = Vec::new();
        let mut spec_tokens = Vec::new();

        let mut tokens_iter = tokens.into_iter();
        while let Some(tok) = tokens_iter.next() {
            if let Some(h) = tok.strip_prefix("--hash=") {
                let h_clean = h.strip_prefix("sha256:").unwrap_or(h).trim();
                hashes.push(h_clean.to_string());
            } else if tok == "--hash" {
                if let Some(next) = tokens_iter.next() {
                    let h_clean = next.strip_prefix("sha256:").unwrap_or(next).trim();
                    hashes.push(h_clean.to_string());
                } else {
                    return Err(LockfileError::InvalidData(format!(
                        "line {line_num}: `--hash` option missing hash value"
                    )));
                }
            } else {
                spec_tokens.push(tok);
            }
        }

        let spec = spec_tokens.join("");
        if spec.is_empty() {
            continue;
        }

        // Separate environment marker `; ...` before range checking the requirement
        let (req_spec, _marker) = match spec.split_once(';') {
            Some((before, after)) => (before.trim(), Some(after.trim())),
            None => (spec.as_str(), None),
        };

        if req_spec.is_empty() {
            continue;
        }

        let has_range_op = [">=", "<=", ">", "<", "~=", "!=", "===", "@"]
            .into_iter()
            .any(|op| req_spec.contains(op));

        if has_range_op {
            unpinned_errors.push(format!("  line {line_num}: unpinned range `{req_spec}`"));
            continue;
        }

        if let Some((name_part, ver_part)) = req_spec.split_once("==") {
            let raw_name = name_part.trim();
            let ver = ver_part.trim();

            if raw_name.is_empty() || ver.is_empty() {
                unpinned_errors.push(format!(
                    "  line {line_num}: invalid requirement `{req_spec}`"
                ));
                continue;
            }

            // Extract base package name and extras if present: `foo[extra1,extra2]`
            let name = if let Some((base, extras_part)) = raw_name.split_once('[') {
                if !extras_part.ends_with(']') {
                    return Err(LockfileError::InvalidData(format!(
                        "line {line_num}: unclosed extras bracket in `{raw_name}`"
                    )));
                }
                base.trim()
            } else {
                raw_name
            };

            if !crate::version::validate_pypi_name(name) {
                return Err(LockfileError::InvalidData(format!(
                    "line {line_num}: invalid PyPI package name `{name}`"
                )));
            }

            if crate::version::Pep440Version::parse(ver).is_err() {
                return Err(LockfileError::InvalidData(format!(
                    "line {line_num}: invalid PEP 440 version `{ver}` in `{req_spec}`"
                )));
            }

            let mut formatted_hashes = Vec::new();
            for h in hashes {
                let hex = h.to_lowercase();
                if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(LockfileError::InvalidData(format!(
                        "line {line_num}: invalid sha256 hash length (expected 64 hex chars, got `{h}`)"
                    )));
                }
                formatted_hashes.push(format!("sha256:{hex}"));
            }
            let integrity = if formatted_hashes.is_empty() {
                None
            } else {
                Some(formatted_hashes.join(" "))
            };

            let canon_name = crate::version::canonicalize_name(name);
            packages.insert(
                canon_name,
                PackageEntry {
                    name: name.to_string(),
                    version: ver.to_string(),
                    integrity,
                    resolved: None,
                    is_dev: false,
                },
            );
        } else {
            unpinned_errors.push(format!(
                "  line {line_num}: unpinned package `{spec}` (must use `name==version`)"
            ));
        }
    }

    if !unpinned_errors.is_empty() {
        return Err(LockfileError::InvalidData(format!(
            "requirements.txt contains unpinned dependencies (all packages must be pinned with `==`):\n{}",
            unpinned_errors.join("\n")
        )));
    }

    Ok(packages)
}

pub fn compute_delta_from_maps(
    base_pkgs: &BTreeMap<String, PackageEntry>,
    head_pkgs: &BTreeMap<String, PackageEntry>,
) -> LockfileDelta {
    let mut added = Vec::new();
    let mut upgraded = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged_count = 0;

    let mut base_iter = base_pkgs.iter().peekable();
    let mut head_iter = head_pkgs.iter().peekable();

    loop {
        match (base_iter.peek(), head_iter.peek()) {
            (Some(&(b_key, b_val)), Some(&(h_key, h_val))) => match b_key.cmp(h_key) {
                std::cmp::Ordering::Less => {
                    removed.push((*b_val).clone());
                    base_iter.next();
                }
                std::cmp::Ordering::Greater => {
                    added.push((*h_val).clone());
                    head_iter.next();
                }
                std::cmp::Ordering::Equal => {
                    // A different package name at a stable key and version is a
                    // swap, not an unchanged entry. It was counted as
                    // unchanged, so the new name was never reviewed.
                    if b_val.version != h_val.version
                        || b_val.integrity != h_val.integrity
                        || b_val.name != h_val.name
                    {
                        upgraded.push(PackageUpgrade {
                            name: h_val.name.clone(),
                            old_version: b_val.version.clone(),
                            new_version: h_val.version.clone(),
                            old_integrity: b_val.integrity.clone(),
                            new_integrity: h_val.integrity.clone(),
                            resolved: h_val.resolved.clone(),
                            is_dev: h_val.is_dev,
                        });
                    } else {
                        unchanged_count += 1;
                    }
                    base_iter.next();
                    head_iter.next();
                }
            },
            (Some(&(_, b_val)), None) => {
                removed.push((*b_val).clone());
                base_iter.next();
            }
            (None, Some(&(_, h_val))) => {
                added.push((*h_val).clone());
                head_iter.next();
            }
            (None, None) => break,
        }
    }

    LockfileDelta {
        added,
        upgraded,
        removed,
        unchanged_count,
    }
}

pub fn compute_lockfile_delta(
    base_json: &str,
    head_json: &str,
) -> Result<LockfileDelta, LockfileError> {
    let base_pkgs = parse_lockfile_packages(base_json)?;
    let head_pkgs = parse_lockfile_packages(head_json)?;
    Ok(compute_delta_from_maps(&base_pkgs, &head_pkgs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_json_has_no_source_chain() {
        use std::error::Error;
        // The Display already embeds the serde detail; a `source()` would
        // make `{e:#}` in main print the detail twice.
        let err =
            LockfileError::from(serde_json::from_str::<serde_json::Value>("{{{{").unwrap_err());
        assert!(err.source().is_none(), "source must be None: {err:#}");
    }

    /// An entry that cannot be turned into a package is not a package that does
    /// not exist. A silent `continue` dropped it from the graph, so a lockfile
    /// whose head rewrote a pinned package into a shape the parser skips still
    /// compares as fully reviewed, and the delta reports nothing where the
    /// attacker's entry used to be. Refusing is the fail-closed reading and
    /// matches how the alias mismatch below already handles ambiguity.
    #[test]
    fn an_entry_without_a_version_is_refused_rather_than_dropped() {
        let json = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
                },
                "node_modules/evil": {
                    "resolved": "https://evil.example/evil.tgz",
                    "integrity": "sha512-evil"
                }
            }
        }"#;

        let err = parse_lockfile_packages(json).expect_err(
            "an entry with no version must be refused, not silently dropped: \
             dropping it makes the lockfile look fully reviewed",
        );
        assert!(
            matches!(err, LockfileError::InvalidData(_)),
            "refuse with InvalidData, got: {err:?}"
        );
        assert!(
            format!("{err}").contains("node_modules/evil"),
            "the refusal must name the entry it refused: {err}"
        );
    }

    /// A workspace link is `{"resolved": "packages/x", "link": true}` with no
    /// `version`, and npm writes it that way deliberately: it points at a
    /// directory in the repo rather than an installed artifact. Refusing it
    /// would fail every workspace monorepo's own lockfile, which is what the
    /// dogfood CI job does to this repository. It must be skipped, while an
    /// ordinary entry with no version is still refused.
    #[test]
    fn a_workspace_link_is_skipped_while_an_unreadable_entry_is_refused() {
        let json = r#"{
            "name": "blueline-monorepo",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "blueline-monorepo", "workspaces": ["packages/*"] },
                "node_modules/@kridaydave/blueline-cli": {
                    "resolved": "packages/blueline",
                    "link": true
                },
                "node_modules/blueline-cli": {
                    "resolved": "packages/npx",
                    "link": true
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
                }
            }
        }"#;

        let pkgs = parse_lockfile_packages(json)
            .expect("a workspace link is not an installed package and must be skipped");
        assert_eq!(
            pkgs.keys().cloned().collect::<Vec<_>>(),
            vec!["node_modules/lodash".to_string()],
            "only the real installed package belongs in the graph: {pkgs:?}"
        );
    }

    /// `a_workspace_link_is_skipped_while_an_unreadable_entry_is_refused` above
    /// only pins that a link entry leaves the graph. It never covers a link entry
    /// that *also* declares a version and an integrity, and the skip keyed on
    /// `link` alone accepted one. The entry then left the graph entirely, so the
    /// delta put the base entry in `removed`, and `ci` evaluates only `added`
    /// chained with `upgraded`: a version or an integrity swap became silence
    /// while `passed` stayed true. Adding `"link": true` to any entry was the
    /// whole attack.
    ///
    /// npm writes a link as `{"resolved": "packages/x", "link": true}` and never
    /// gives one a version or an integrity, so this shape is refused rather than
    /// guessed at.
    #[test]
    fn a_link_entry_carrying_a_version_or_an_integrity_is_refused() {
        let head = r#"{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/lodash": {
                    "resolved": "packages/x",
                    "link": true,
                    "version": "4.17.21",
                    "integrity": "sha512-bbbb"
                }
            }
        }"#;

        let err = parse_lockfile_packages(head).expect_err(
            "a link carrying a version and an integrity must be refused: skipping it \
             hides the change in the `removed` bucket, which ci never evaluates",
        );
        assert!(
            matches!(err, LockfileError::InvalidData(_)),
            "refuse with InvalidData, got: {err:?}"
        );
        assert!(
            format!("{err}").contains("node_modules/lodash"),
            "the refusal must name the entry it refused: {err}"
        );

        // A link carrying only a version is refused the same way, and so is one
        // carrying only an integrity. Keying the skip on the presence of either
        // field is what makes it narrow.
        for extra in [r#""version": "4.17.21""#, r#""integrity": "sha512-bbbb""#] {
            let json = format!(
                r#"{{
                    "name": "app",
                    "lockfileVersion": 3,
                    "packages": {{
                        "": {{ "name": "app", "version": "1.0.0" }},
                        "node_modules/lodash": {{ "resolved": "packages/x", "link": true, {extra} }}
                    }}
                }}"#
            );
            parse_lockfile_packages(&json).unwrap_err();
        }
    }

    /// The delta shape the fix exists for, stated as one test. A version and an
    /// integrity swap smuggled behind `"link": true` used to read as
    /// `added=0 upgraded=0 removed=1`, which `ci` evaluates as nothing at all.
    /// The refusal is what stops it, and this pins that it stops it at the delta
    /// rather than at one parser call.
    #[test]
    fn a_link_smuggled_version_swap_cannot_reach_the_delta_as_a_removal() {
        let base = r#"{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-aaaa"
                }
            }
        }"#;
        let head = r#"{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/lodash": {
                    "resolved": "packages/x",
                    "link": true,
                    "version": "4.17.21",
                    "integrity": "sha512-bbbb"
                }
            }
        }"#;

        let err = compute_lockfile_delta(base, head).expect_err(
            "the delta must not compute at all: a swap hidden as a link reaches ci as \
             an unevaluated `removed` entry",
        );
        assert!(
            format!("{err}").contains("node_modules/lodash"),
            "the refusal must name the entry it refused: {err}"
        );
    }

    /// The same shape as the link skip, one branch further down: `node_modules/`
    /// yields no package name, and `if name.is_empty() { continue; }` dropped the
    /// entry from the graph, so the delta reported nothing where the entry used
    /// to be. Skipping it made the lockfile read as fully reviewed.
    #[test]
    fn an_entry_with_no_readable_name_is_refused() {
        let base = r#"{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-aaaa"
                }
            }
        }"#;
        let head = r#"{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/": { "version": "1.0.0" }
            }
        }"#;

        let err = compute_lockfile_delta(base, head).expect_err(
            "an entry whose path names no package must be refused, not dropped: dropping \
             it is what made the delta report nothing",
        );
        assert!(
            format!("{err}").contains("node_modules/"),
            "the refusal must name the entry it refused: {err}"
        );
    }

    #[test]
    fn parses_v3_lockfile() {
        let json = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-app",
                    "version": "1.0.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
                    "dev": false
                },
                "node_modules/@scope/pkg": {
                    "version": "2.0.0",
                    "integrity": "sha512-test",
                    "dev": true
                }
            }
        }"#;

        let pkgs = parse_lockfile_packages(json).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs.get("node_modules/lodash").unwrap().name, "lodash");
        assert_eq!(pkgs.get("node_modules/lodash").unwrap().version, "4.17.21");
        assert!(!pkgs.get("node_modules/lodash").unwrap().is_dev);

        assert_eq!(
            pkgs.get("node_modules/@scope/pkg").unwrap().name,
            "@scope/pkg"
        );
        assert_eq!(
            pkgs.get("node_modules/@scope/pkg").unwrap().version,
            "2.0.0"
        );
        assert!(pkgs.get("node_modules/@scope/pkg").unwrap().is_dev);
    }

    #[test]
    fn parses_v1_lockfile() {
        let json = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "integrity": "sha512-expresshash",
                    "dev": false,
                    "dependencies": {
                        "accepts": {
                            "version": "1.3.8",
                            "integrity": "sha512-acceptshash"
                        }
                    }
                }
            }
        }"#;

        let pkgs = parse_lockfile_packages(json).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs.get("node_modules/express").unwrap().version, "4.18.2");
        assert_eq!(
            pkgs.get("node_modules/express/node_modules/accepts")
                .unwrap()
                .version,
            "1.3.8"
        );
    }

    #[test]
    fn computes_delta_across_lockfiles() {
        let base_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/unchanged": { "version": "1.0.0", "integrity": "sha512-same" },
                "node_modules/upgraded": { "version": "1.0.0", "integrity": "sha512-old" },
                "node_modules/removed": { "version": "0.9.0", "integrity": "sha512-del" }
            }
        }"#;

        let head_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/unchanged": { "version": "1.0.0", "integrity": "sha512-same" },
                "node_modules/upgraded": { "version": "1.1.0", "integrity": "sha512-new" },
                "node_modules/added": { "version": "2.0.0", "integrity": "sha512-add", "dev": true }
            }
        }"#;

        let delta = compute_lockfile_delta(base_json, head_json).unwrap();
        assert_eq!(delta.unchanged_count, 1);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].name, "added");
        assert_eq!(delta.added[0].version, "2.0.0");
        assert!(delta.added[0].is_dev);

        assert_eq!(delta.upgraded.len(), 1);
        assert_eq!(delta.upgraded[0].name, "upgraded");
        assert_eq!(delta.upgraded[0].old_version, "1.0.0");
        assert_eq!(delta.upgraded[0].new_version, "1.1.0");

        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.removed[0].name, "removed");
        assert_eq!(delta.total_changed(), 3);
    }

    #[test]
    fn v1_recursion_depth_limit_enforced() {
        // Build a deeply nested structure exceeding MAX_LOCKFILE_RECURSION_DEPTH (32)
        let mut curr = serde_json::json!({
            "version": "1.0.0"
        });

        for i in 0..35 {
            curr = serde_json::json!({
                "version": "1.0.0",
                "dependencies": {
                    format!("dep-{}", i): curr
                }
            });
        }

        let root = serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {
                "dep-root": curr
            }
        });

        let json = serde_json::to_string(&root).unwrap();
        let pkgs = parse_lockfile_packages(&json).unwrap();
        // Should parse up to the limit (33 levels including root: depth 0 to 32)
        assert_eq!(pkgs.len(), MAX_LOCKFILE_RECURSION_DEPTH + 1);
    }

    #[test]
    fn delta_is_empty_and_integrity_only_upgrade() {
        let empty_delta = LockfileDelta {
            added: Vec::new(),
            upgraded: Vec::new(),
            removed: Vec::new(),
            unchanged_count: 5,
        };
        assert!(empty_delta.is_empty());

        let mut delta_with_add = empty_delta.clone();
        delta_with_add.added.push(PackageEntry {
            name: "pkg".into(),
            version: "1.0.0".into(),
            integrity: None,
            resolved: None,
            is_dev: false,
        });
        assert!(!delta_with_add.is_empty());

        let mut delta_with_up = empty_delta.clone();
        delta_with_up.upgraded.push(PackageUpgrade {
            name: "pkg".into(),
            old_version: "1.0.0".into(),
            new_version: "1.0.0".into(),
            old_integrity: Some("sha512-old".into()),
            new_integrity: Some("sha512-new".into()),
            resolved: None,
            is_dev: false,
        });
        assert!(!delta_with_up.is_empty());

        let mut delta_with_rem = empty_delta.clone();
        delta_with_rem.removed.push(PackageEntry {
            name: "pkg".into(),
            version: "1.0.0".into(),
            integrity: None,
            resolved: None,
            is_dev: false,
        });
        assert!(!delta_with_rem.is_empty());

        let base_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/tampered": { "version": "1.0.0", "integrity": "sha512-old" }
            }
        }"#;
        let head_json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/tampered": { "version": "1.0.0", "integrity": "sha512-new" }
            }
        }"#;
        let delta = compute_lockfile_delta(base_json, head_json).unwrap();
        assert_eq!(delta.upgraded.len(), 1);
        assert_eq!(delta.upgraded[0].name, "tampered");
        assert_eq!(
            delta.upgraded[0].old_integrity.as_deref(),
            Some("sha512-old")
        );
        assert_eq!(
            delta.upgraded[0].new_integrity.as_deref(),
            Some("sha512-new")
        );
    }

    #[test]
    fn parses_cargo_lock_registry_dep() {
        let toml = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
"#;
        let pkgs = parse_cargo_lock_packages(toml).unwrap();
        assert_eq!(pkgs.len(), 1);
        let entry = pkgs.get("cargo/serde@1.0.210").unwrap();
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.version, "1.0.210");
        assert_eq!(
            entry.integrity.as_deref(),
            Some("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        assert_eq!(
            entry.resolved.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert!(!entry.is_dev);
    }

    #[test]
    fn parses_cargo_lock_git_and_path_deps() {
        let toml = r#"
version = 4

[[package]]
name = "my-git-dep"
version = "0.1.0"
source = "git+https://github.com/example/repo#abc123"

[[package]]
name = "my-path-dep"
version = "0.2.0"

[[package]]
name = "regular"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"#;
        let pkgs = parse_cargo_lock_packages(toml).unwrap();
        assert_eq!(pkgs.len(), 3);

        let git = pkgs.get("cargo/my-git-dep@0.1.0").unwrap();
        assert_eq!(git.integrity, None);
        assert_eq!(
            git.resolved.as_deref(),
            Some("git+https://github.com/example/repo#abc123")
        );

        let path = pkgs.get("cargo/my-path-dep@0.2.0").unwrap();
        assert_eq!(path.integrity, None);
        assert_eq!(path.resolved, None);

        let reg = pkgs.get("cargo/regular@1.0.0").unwrap();
        assert_eq!(
            reg.integrity.as_deref(),
            Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        );
        assert!(reg.resolved.is_some());
    }

    #[test]
    fn cargo_lock_delta_via_parse_pair() {
        let base_toml = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

[[package]]
name = "unchanged"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

[[package]]
name = "removed"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
"#;

        let head_toml = r#"
version = 4

[[package]]
name = "serde"
version = "1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

[[package]]
name = "unchanged"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

[[package]]
name = "added"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
"#;

        let base = parse_cargo_lock_packages(base_toml).unwrap();
        let head = parse_cargo_lock_packages(head_toml).unwrap();
        let delta = compute_delta_from_maps(&base, &head);

        // With `cargo/name@version` keys, a version bump is not an `upgraded` but
        // a `removed` old key + `added` new key. Both are still evaluated in CI.
        assert_eq!(delta.added.len(), 2, "serde 1.1.0 + added");
        assert_eq!(delta.removed.len(), 2, "serde 1.0.0 + removed");
        assert_eq!(delta.upgraded.len(), 0);
        assert_eq!(delta.unchanged_count, 1);
        assert!(
            delta
                .added
                .iter()
                .any(|e| e.name == "serde" && e.version == "1.1.0")
        );
        assert!(delta.added.iter().any(|e| e.name == "added"));

        // Integrity-only change on same key is an `upgraded`.
        let base2 = parse_cargo_lock_packages(
            r#"
version = 4
[[package]]
name = "tampered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#,
        )
        .unwrap();
        let head2 = parse_cargo_lock_packages(
            r#"
version = 4
[[package]]
name = "tampered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        )
        .unwrap();
        let delta2 = compute_delta_from_maps(&base2, &head2);
        assert_eq!(delta2.upgraded.len(), 1);
        assert_eq!(delta2.upgraded[0].name, "tampered");
        assert_eq!(delta2.unchanged_count, 0);
    }

    #[test]
    fn cargo_lock_invalid_toml_fails_closed() {
        let bad = "[[package\nname = \"oops\"";
        let err = parse_cargo_lock_packages(bad).unwrap_err();
        assert!(
            matches!(err, LockfileError::InvalidToml(_)),
            "malformed TOML must be InvalidToml, got {err:?}"
        );

        let empty_pkg = r#"
version = 4

[[package]]
name = "no-version"
"#;
        let err2 = parse_cargo_lock_packages(empty_pkg).unwrap_err();
        match err2 {
            LockfileError::InvalidData(_) => {}
            other => panic!("expected InvalidData for missing version, got {other:?}"),
        }

        // Empty name or empty version must fail closed (|| vs && mutant).
        let empty_name = r#"
version = 4
[[package]]
name = ""
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(empty_name).unwrap_err(),
            LockfileError::InvalidData(_)
        ));
        let empty_version = r#"
version = 4
[[package]]
name = "x"
version = ""
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(empty_version).unwrap_err(),
            LockfileError::InvalidData(_)
        ));

        // Size cap: > MAX fails, == MAX passes. Kills *→+ and >→>= mutants.
        assert_eq!(
            MAX_CARGO_LOCK_BYTES, 10_485_760,
            "MAX must be 10 MiB; hard literal kills *→+ mutants"
        );
        let header = "version = 4\n";
        let mut at_limit_toml = String::with_capacity(MAX_CARGO_LOCK_BYTES);
        at_limit_toml.push_str(header);
        let remaining = MAX_CARGO_LOCK_BYTES - at_limit_toml.len() - 2;
        at_limit_toml.push('#');
        at_limit_toml.push_str(&"a".repeat(remaining));
        at_limit_toml.push('\n');
        assert_eq!(at_limit_toml.len(), MAX_CARGO_LOCK_BYTES);
        let at_limit_res = parse_cargo_lock_packages(&at_limit_toml);
        assert!(
            at_limit_res.is_ok(),
            "exactly MAX bytes must not be rejected by size cap (> vs >= mutant), got {at_limit_res:?}"
        );
        let oversized = format!("{at_limit_toml}a");
        assert_eq!(oversized.len(), MAX_CARGO_LOCK_BYTES + 1);
        let err3 = parse_cargo_lock_packages(&oversized).unwrap_err();
        match err3 {
            LockfileError::InvalidData(msg) => assert!(msg.contains("exceeds maximum size")),
            other => panic!("expected InvalidData for oversized, got {other:?}"),
        }

        // Checksum validation: wrong length vs bad hex must each fail (|| vs &&).
        let bad_len = r#"
version = 4
[[package]]
name = "bad"
version = "1.0.0"
checksum = "AAA"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(bad_len).unwrap_err(),
            LockfileError::InvalidData(_)
        ));
        let bad_hex = "g".repeat(64);
        let bad_hex_toml = format!(
            "version = 4\n[[package]]\nname = \"bad\"\nversion = \"1.0.0\"\nchecksum = \"{bad_hex}\"\n"
        );
        assert!(matches!(
            parse_cargo_lock_packages(&bad_hex_toml).unwrap_err(),
            LockfileError::InvalidData(_)
        ));

        // Duplicate with differing data must fail ( != vs == mutant).
        let dup_diff = r#"
version = 4
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#;
        assert!(matches!(
            parse_cargo_lock_packages(dup_diff).unwrap_err(),
            LockfileError::InvalidData(_)
        ));
        // Same duplicate with identical data is ok (last wins).
        let dup_same = r#"
version = 4
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        assert!(parse_cargo_lock_packages(dup_same).is_ok());
    }

    #[test]
    fn parses_pinned_requirements_txt_with_hashes() {
        let content = r#"
# Core dependencies
requests==2.31.0 \
    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

Flask==3.0.0 --hash sha256:1111111111111111111111111111111111111111111111111111111111111111
urllib3==2.1.0 # trailing comment
"#;
        let pkgs = parse_requirements_txt_packages(content, false).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs["requests"].version, "2.31.0");
        assert_eq!(
            pkgs["requests"].integrity.as_deref(),
            Some("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        assert_eq!(pkgs["flask"].name, "Flask");
        assert_eq!(pkgs["flask"].version, "3.0.0");
        assert_eq!(pkgs["urllib3"].integrity, None);
    }

    #[test]
    fn rejects_unpinned_requirements_with_line_numbers() {
        let content = "requests>=2.0.0\nflask==3.0.0\npytest~=7.0\nblack\n";
        let err = parse_requirements_txt_packages(content, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 1: unpinned range `requests>=2.0.0`"));
        assert!(err.contains("line 3: unpinned range `pytest~=7.0`"));
        assert!(err.contains("line 4: unpinned package `black`"));
    }

    #[test]
    fn a_name_swap_at_the_same_key_and_version_is_an_upgrade() {
        let mut b = BTreeMap::new();
        let mut h = BTreeMap::new();
        let entry = |name: &str| PackageEntry {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            integrity: Some("sha512-aa".to_string()),
            resolved: None,
            is_dev: false,
        };
        b.insert("node_modules/pinned".to_string(), entry("good"));
        h.insert("node_modules/pinned".to_string(), entry("evil"));
        let delta = compute_delta_from_maps(&b, &h);
        assert_eq!(
            delta.upgraded.len(),
            1,
            "a different package at a reviewed address must be evaluated"
        );
        assert_eq!(delta.upgraded[0].name, "evil");
    }

    #[test]
    fn an_entry_whose_name_disagrees_with_its_resolved_url_is_refused() {
        let json = r#"{"lockfileVersion":3,"packages":{
            "node_modules/foo":{"name":"bar","version":"1.0.0",
                "resolved":"https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"}}}"#;
        let err = parse_lockfile_packages(json).unwrap_err().to_string();
        assert!(
            err.contains("identity is ambiguous"),
            "a name pointing at a different tarball must be refused: {err}"
        );
    }

    #[test]
    fn a_real_npm_alias_still_parses() {
        // `"foo": "npm:bar@1.0.0"` makes npm record name `bar` under the
        // directory `foo`, so a strict name==directory check would reject
        // every aliased dependency in the wild.
        let json = r#"{"lockfileVersion":3,"packages":{
            "node_modules/foo":{"name":"bar","version":"1.0.0",
                "resolved":"https://registry.npmjs.org/bar/-/bar-1.0.0.tgz"}}}"#;
        let pkgs = parse_lockfile_packages(json).unwrap();
        assert_eq!(pkgs["node_modules/foo"].name, "bar");
    }

    #[test]
    fn a_name_mismatch_with_no_resolved_url_is_refused() {
        let json = r#"{"lockfileVersion":3,"packages":{
            "node_modules/foo":{"name":"bar","version":"1.0.0"}}}"#;
        assert!(parse_lockfile_packages(json).is_err());
    }

    /// A redirect flag trailing a spec has to be refused as the option it is.
    /// The check was line-leading only, so the flag was folded into the
    /// version string and surfaced as a PEP 440 error quoting the flag — a
    /// message about a version, for a line whose problem is that pip would
    /// install from somewhere else entirely.
    #[test]
    fn refuses_a_requirements_option_trailing_a_spec() {
        for opt in [
            "--index-url https://evil.example/simple",
            "--extra-index-url=https://evil.example/simple",
            "-r other-requirements.txt",
            "--constraint constraints.txt",
            "--trusted-host evil.example",
            "--pre",
        ] {
            let file = format!("requests==2.31.0 {opt}\nurllib3==2.1.0\n");
            let err = parse_requirements_txt_packages(&file, false)
                .unwrap_err()
                .to_string();
            let flag = opt.split_whitespace().next().unwrap();
            assert!(
                err.contains("unsupported requirements option"),
                "option `{opt}` must be refused as an option, not as a version: {err}"
            );
            assert!(err.contains(flag), "the refusal must name `{flag}`: {err}");
            // The opt-in lets the option through, but not a requirement mixed
            // with it: that line cannot be split reliably, so it is refused
            // rather than reviewed in part. Dropping the pin outright, as an
            // earlier version did, returned Ok with an empty result, so the
            // package the line pins was never checked at all.
            // Either the line is refused as unsplittable, or it is truncated
            // and the pin is kept. What must never happen is the pin being
            // dropped: that put a reviewed package into the *removed* set.
            match parse_requirements_txt_packages(&file, true) {
                Err(e) => assert!(
                    e.to_string().contains("mixed with a requirement"),
                    "an option mixed with a pin must be refused as unsplittable: {e}"
                ),
                Ok(opted_in) => assert!(
                    opted_in.values().any(|e| e.version == "2.31.0"),
                    "a truncated line must keep its pin, never drop it: {opted_in:?}"
                ),
            }
        }
    }

    /// A requirement whose *name* looks like a filename. `payload.txt` is a legal
    /// PyPI project name -- dots are permitted and a name may end in a letter --
    /// and the parser used to classify any token ending in `.txt` or `.in` as an
    /// option value, on the reasoning that `base.txt` is what `-r` consumes.
    ///
    /// The two cases are the same string, so that classification did not
    /// distinguish them; it only picked which one got dropped. Measured against
    /// the real parser and the real delta computation, a base of
    /// `payload.txt==1.0.0` and `requests==2.28.0` with a head of
    /// `requests==2.31.0 --pre payload.txt` produced `Ok(requests==2.31.0)`: the
    /// pin survived, `payload.txt` vanished, and the delta then reported
    /// `removed: [payload.txt@1.0.0]`. CI evaluates only `added` and `upgraded`,
    /// so a package pip still installs was never reviewed, and the report listed
    /// it under "Removed" as though it had been uninstalled.
    ///
    /// The refusal is the whole point: a package that is still installed cannot
    /// be reported as removed, and the line cannot be split without knowing
    /// whether the option consumes the next token, which is pip's business.
    #[test]
    fn a_requirement_named_like_a_filename_is_not_an_option_value() {
        for name in ["payload.txt", "payload.in", "zope.interface"] {
            // The name is a legal requirement and the parser must accept it as
            // one when it stands alone -- otherwise this test would pass for the
            // wrong reason, on a parser that refuses every dotted name.
            let alone = format!("{name}==1.0.0\n");
            let parsed = parse_requirements_txt_packages(&alone, false)
                .unwrap_or_else(|e| panic!("`{name}==1.0.0` is a valid pin: {e}"));
            assert_eq!(parsed.len(), 1, "`{name}` must parse as one requirement");

            // Mixed with an option on one line, it must be refused rather than
            // silently truncated.
            let mixed = format!("requests==2.31.0 --pre {name}\n");
            let err = parse_requirements_txt_packages(&mixed, true)
                .expect_err("a requirement riding along with an option must be refused")
                .to_string();
            assert!(
                err.contains("mixed with a requirement"),
                "`{name}` is a requirement, not an option value: {err}"
            );

            // And the consequence that made this worth fixing: the dropped name
            // must not be reportable as removed while pip still installs it.
            let base = format!("{name}==1.0.0\nrequests==2.28.0\n");
            let head = format!("requests==2.31.0 --pre {name}\n");
            let base_map = parse_requirements_txt_packages(&base, false).unwrap();
            assert!(
                parse_requirements_txt_packages(&head, true).is_err(),
                "the head must be refused, so no delta can be computed from it"
            );
            assert_eq!(base_map.len(), 2, "the base holds both packages");
        }
    }

    /// An option *before* the pin on the same line. Truncating at the option
    /// leaves nothing, and skipping the line loses the pin -- so
    /// `--index-url https://evil requests==2.31.0` against a base of
    /// `requests==2.28.0` put no entry for `requests` in the head graph. CI
    /// only walks `added` and `upgraded`, so the upgrade was never evaluated
    /// and the redirect never disclosed. An option alone on its line is the
    /// ordinary pip layout and stays allowed.
    #[test]
    fn an_option_before_the_pin_on_one_line_is_refused_not_skipped() {
        for file in [
            "--index-url https://evil.example/simple requests==2.31.0\n",
            "-r other-requirements.txt requests==2.31.0\n",
            "--pre requests==2.31.0\n",
        ] {
            let err = parse_requirements_txt_packages(file, true)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("mixed with a requirement"),
                "an option-led line carrying a pin must be refused, got: {err}"
            );
        }

        // Every requirement shape has to be refused, not just the pinned one.
        // Three rounds of review each found another shape that a splitting
        // heuristic lost: a pinned spec, then an unpinned range, then a bare
        // name, an extras form and a direct URL. Each of these is a package the
        // reviewed graph would otherwise not contain, while `ci` reports it as
        // *removed* and passes.
        for file in [
            // pinned, unpinned range, direct reference
            "--index-url https://evil.example/simple requests==2.31.0\n",
            "--index-url https://evil.example/simple requests>=2.0\n",
            "--index-url https://evil.example/simple foo @ https://evil/x.whl\n",
            // bare name and extras carry no operator at all
            "--index-url https://evil.example/simple requests\n",
            "--pre foo[bar]\n",
            // a line continuation joins the requirement onto the option's line
            "--index-url https://e/s \\\nrequests==2.31.0\n",
            // and the option *after* a spec, where truncation would drop the tail
            "requests==2.31.0 --index-url https://e/s urllib3==2.0.0\n",
            "requests==2.31.0 --index-url https://e/s bar>=2.0\n",
        ] {
            match parse_requirements_txt_packages(file, true) {
                Err(e) => assert!(
                    e.to_string().contains("mixed with a requirement"),
                    "`{file:?}` must be refused as mixed, gave: {e}"
                ),
                Ok(m) => panic!("`{file:?}` was ACCEPTED with {m:?} and its requirement lost"),
            }
        }

        // A `--hash` past the first redirecting option is what truncation
        // discards. Dropping it left the line with no integrity, so `R10_` never
        // compared the declared hash and it was neither verified nor disclosed.
        // With the hash *before* the option it survives and the line is reviewed
        // normally, so the refusal is about the order rather than the opt-in.
        let lost = "requests==2.31.0 --index-url https://e/s --hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        assert!(
            parse_requirements_txt_packages(lost, true)
                .unwrap_err()
                .to_string()
                .contains("precedes `--hash`"),
            "a hash after the redirecting option must be refused"
        );
        let kept = "requests==2.31.0 --hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --index-url https://e/s\n";
        assert!(
            parse_requirements_txt_packages(kept, true).is_ok(),
            "a hash before the redirecting option must still be reviewed"
        );

        // The ordinary layout still works: the option is on its own line.
        let ok = parse_requirements_txt_packages(
            "--index-url https://mirror.example/simple\nrequests==2.31.0\n",
            true,
        )
        .unwrap();
        assert!(
            ok.values().any(|e| e.version == "2.31.0"),
            "an option on its own line must not cost the pin: {ok:?}"
        );
    }

    /// The option scan looks at every token, so a flag that follows a spec
    /// through a line continuation is caught on the joined line too.
    #[test]
    fn refuses_a_requirements_option_trailing_a_continued_spec() {
        let file = "requests==2.31.0 \\\n  --index-url https://evil.example/simple\n";
        let err = parse_requirements_txt_packages(file, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unsupported requirements option"),
            "a continued line must still be scanned per token: {err}"
        );
    }

    #[test]
    fn requirements_txt_flags_and_edge_cases() {
        // Each of these redirects pip away from the graph blueline reviewed.
        // Skipping them meant the gate certified pins that were never the ones
        // installed, so they are refused instead. This assertion used to pin
        // the permissive behaviour.
        //
        // Only options whose value is unambiguously a URL, a path or a bare flag
        // survive the opt-in. An option whose value could equally be a project
        // name is in the second list below, not this one.
        for opt in [
            "-i https://pypi.org/simple",
            "--index-url https://example.com/pypi",
            "--extra-index-url https://example.com/pypi",
            "-f /path/to/wheels",
            "--find-links /path/to/wheels",
            "-e .",
            "--pre",
        ] {
            let file = format!("{opt}\nrequests==2.31.0\n");
            let err = parse_requirements_txt_packages(&file, false)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(opt.split_whitespace().next().unwrap()),
                "option `{opt}` must be refused by name: {err}"
            );
            // Opting in reviews the pins and discloses nothing.
            match parse_requirements_txt_packages(&file, true) {
                Ok(_) => {}
                Err(e) => panic!("the policy escape must let `{opt}` through, got: {e}"),
            }
        }

        // `--trusted-host` takes a bare hostname, which is shape-identical to a
        // bare requirement: `zope.interface` is a real PyPI name, so a dot
        // cannot tell them apart. Refused under the opt-in rather than guessed
        // at, since guessing wrong drops a package from the reviewed graph.
        // The option is deprecated in pip, and pinning a host is better done
        // with `PIP_INDEX_URL` in the environment, which blueline does not
        // read either way.
        //
        // `-r`/`-c`/`--requirement`/`--constraint` belong here for the same
        // reason, and this is the change: their value is a *filename*, which was
        // previously on the "unmistakably an option" list. A project name may
        // contain dots and end in a letter, so `base.txt` is indistinguishable
        // from a package called `base.txt` -- and choosing wrong drops a package
        // pip still installs into the *removed* set, which CI reports as an
        // uninstall and never evaluates. All four also name a second file whose
        // contents this parser never reads, so the opt-in cannot honestly claim
        // to have reviewed the graph.
        for opt in [
            "--trusted-host example.com",
            "-r base.txt",
            "--requirement other.txt",
            "-c constraints.txt",
            "--constraint constraints.txt",
        ] {
            let file = format!("{opt}\nrequests==2.31.0\n");
            let err = parse_requirements_txt_packages(&file, true)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("mixed with a requirement"),
                "a value shape-identical to a project name must not be guessed \
                 at: `{opt}`: {err}"
            );
        }

        let content = r#"
# Empty lines and comments with whitespace
   # leading space comment
   
requests==2.31.0 \
    --hash sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 \
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
"#;
        let pkgs = parse_requirements_txt_packages(content, false).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs["requests"].version, "2.31.0");

        // Trailing line continuation with no trailing newline
        let no_nl = "urllib3==2.1.0 \\\n  --hash sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let pkgs2 = parse_requirements_txt_packages(no_nl, false).unwrap();
        assert_eq!(pkgs2["urllib3"].version, "2.1.0");

        // Missing hash value after `--hash`
        let missing_hash = "requests==2.31.0 --hash";
        let err = parse_requirements_txt_packages(missing_hash, false).unwrap_err();
        assert!(
            matches!(err, LockfileError::InvalidData(msg) if msg.contains("missing hash value"))
        );

        // Exact MAX_REQUIREMENTS_TXT_BYTES size boundary test
        let header = "requests==2.31.0\n";
        let mut at_limit = String::with_capacity(MAX_REQUIREMENTS_TXT_BYTES);
        at_limit.push_str(header);
        let remaining = MAX_REQUIREMENTS_TXT_BYTES - at_limit.len() - 2;
        at_limit.push('#');
        at_limit.push_str(&"a".repeat(remaining));
        at_limit.push('\n');
        assert_eq!(at_limit.len(), MAX_REQUIREMENTS_TXT_BYTES);
        assert!(parse_requirements_txt_packages(&at_limit, false).is_ok());

        let over_limit = format!("{at_limit}a");
        assert_eq!(over_limit.len(), MAX_REQUIREMENTS_TXT_BYTES + 1);
        let err_over = parse_requirements_txt_packages(&over_limit, false).unwrap_err();
        assert!(
            matches!(err_over, LockfileError::InvalidData(msg) if msg.contains("exceeds maximum size"))
        );

        assert_eq!(MAX_REQUIREMENTS_TXT_BYTES, 10 * 1024 * 1024);

        let blanks_and_comments =
            "\n\n# comment 1\n   # comment 2\n\nflask==3.0.0\n\n# trailing comment\n";
        let parsed = parse_requirements_txt_packages(blanks_and_comments, false).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed["flask"].version, "3.0.0");

        // Test each unpinned range operator
        for op in [">=", "<=", ">", "<", "~=", "!=", "===", "@"] {
            let spec = if op == "@" {
                "pkg @ https://example.com/pkg.whl".to_string()
            } else {
                format!("pkg{op}1.0.0")
            };
            let err = parse_requirements_txt_packages(&spec, false).unwrap_err();
            assert!(
                matches!(err, LockfileError::InvalidData(msg) if msg.contains("unpinned range")),
                "expected unpinned error for operator {op}"
            );
        }

        // Empty name or version
        let err_noname = parse_requirements_txt_packages("==1.0.0", false).unwrap_err();
        assert!(
            matches!(err_noname, LockfileError::InvalidData(msg) if msg.contains("invalid requirement `==1.0.0`"))
        );

        let err_nover = parse_requirements_txt_packages("pkg==", false).unwrap_err();
        assert!(
            matches!(err_nover, LockfileError::InvalidData(msg) if msg.contains("invalid requirement `pkg==`"))
        );

        // Unclosed extras bracket
        let err_bracket = parse_requirements_txt_packages("pkg[extra==1.0.0", false).unwrap_err();
        assert!(
            matches!(err_bracket, LockfileError::InvalidData(msg) if msg.contains("unclosed extras bracket"))
        );

        // Invalid hash hex character (64 chars but contains 'z')
        let bad_hex = format!("pkg==1.0.0 --hash=sha256:{}z", "a".repeat(63));
        let err_hex = parse_requirements_txt_packages(&bad_hex, false).unwrap_err();
        assert!(
            matches!(err_hex, LockfileError::InvalidData(msg) if msg.contains("invalid sha256 hash length"))
        );

        // Trailing continuation line without subsequent non-slash line
        let trailing_cont = "pkg==1.0.0 \\\n";
        let parsed_trailing = parse_requirements_txt_packages(trailing_cont, false).unwrap();
        assert_eq!(parsed_trailing["pkg"].version, "1.0.0");
    }

    /// An entry whose `name` is the empty string takes its name from the key.
    ///
    /// A lockfile is attacker-shaped in the sense that matters here: a registry
    /// chooses the keys, and one that emitted `"name": ""` would otherwise put a
    /// nameless entry in the graph. The guard substitutes the key name in that
    /// case, and nothing tested it — with the guard disabled the entry falls to
    /// the `Some(n) => n` arm, arrives with an empty name, and is refused a few
    /// lines later as a nameless package. Loud rather than silently wrong, which
    /// is part of why it survived: no existing fixture has an empty `name`.
    ///
    /// The key is a real `node_modules/...` path, not `""` — that one is the
    /// root entry and is skipped before this code is reached, so a fixture using
    /// it would exercise nothing and pass for the wrong reason.
    #[test]
    fn an_entry_with_an_empty_name_falls_back_to_its_key() {
        let content = r#"{
          "name": "root",
          "version": "1.0.0",
          "lockfileVersion": 3,
          "requires": true,
          "packages": {
            "": {
              "name": "root",
              "version": "1.0.0"
            },
            "node_modules/left-pad": {
              "name": "",
              "version": "9.9.9",
              "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
              "integrity": "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }
          }
        }"#;
        let parsed =
            parse_lockfile_packages(content).expect("an empty name must not fail the parse");
        // The map is keyed by install path; the *name* is the field under test.
        let entry = parsed
            .get("node_modules/left-pad")
            .unwrap_or_else(|| panic!("the entry must be present, got {:?}", parsed.keys()));
        assert_eq!(
            entry.name, "left-pad",
            "an empty `name` must be replaced by the name in the key"
        );
        assert_eq!(entry.version, "9.9.9", "the entry's own version is kept");

        // A populated name still wins over the key. npm's alias shape is the
        // honest fixture for this: the key is what the importer asked for, the
        // declared name and the resolved URL are what the registry served, and
        // they legitimately differ. If the guard were reading the key instead,
        // this entry would be reviewed under the alias.
        let aliased = content
            .replace("\"node_modules/left-pad\"", "\"node_modules/pad-alias\"")
            .replace("\"name\": \"\",", "\"name\": \"left-pad\",");
        let parsed = parse_lockfile_packages(&aliased).expect("an aliased entry parses");
        assert_eq!(
            parsed
                .get("node_modules/pad-alias")
                .map(|e| e.name.as_str()),
            Some("left-pad"),
            "a populated name must be used as-is, not replaced by the key's"
        );
    }
}
