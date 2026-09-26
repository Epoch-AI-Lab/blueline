use std::any::Any;
use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::BluelineError;

pub mod aur;
pub mod cratesio;
pub mod http_util;
pub mod npm;
pub mod pypi;

/// The package ecosystems blueline knows about. npm is fully wired; cargo,
/// PyPI, and AUR adapters build on these seams in later PRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    PyPi,
    Aur,
}

impl Ecosystem {
    /// Lowercase key used in the local store and policy files.
    pub fn key(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Aur => "aur",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlg {
    Sha256,
    Sha512,
}

impl ChecksumAlg {
    pub fn name(self) -> &'static str {
        match self {
            ChecksumAlg::Sha256 => "sha256",
            ChecksumAlg::Sha512 => "sha512",
        }
    }

    /// Expected lowercase hex digest length for this algorithm.
    fn hex_len(self) -> usize {
        match self {
            ChecksumAlg::Sha256 => 64,
            ChecksumAlg::Sha512 => 128,
        }
    }
}

/// Typed content checksum. Construction normalizes every accepted spelling
/// (npm SRI `sha512-<base64>`, display forms `sha256:<hex>` / `sha512:<hex>`,
/// or bare hex) into a lowercase hex digest, so comparisons are exact and
/// algorithm-aware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    pub alg: ChecksumAlg,
    pub value_hex: String,
}

impl Checksum {
    /// Parse any accepted integrity spelling. Fail closed: unknown
    /// algorithms, odd hex, or undecodable base64 are errors.
    ///
    /// Accepts whitespace-separated token lists (npm `dist.integrity` may
    /// carry several algorithms); the first recognized token wins.
    pub fn parse(raw: &str) -> Result<Self, BluelineError> {
        let mut last_err: Option<BluelineError> = None;
        for token in raw.split_whitespace() {
            match Self::parse_token(token) {
                Ok(c) => return Ok(c),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            BluelineError::Verification(format!("empty integrity string `{raw}`"))
        }))
    }

    fn parse_token(token: &str) -> Result<Self, BluelineError> {
        const SRI_PREFIX: &str = "sha512-";

        if let Some(b64) = token.strip_prefix(SRI_PREFIX) {
            return base64_to_hex(ChecksumAlg::Sha512, b64);
        }

        if let Some((alg_name, hex)) = token.split_once(':') {
            let alg = match alg_name.to_ascii_lowercase().as_str() {
                "sha256" => ChecksumAlg::Sha256,
                "sha512" => ChecksumAlg::Sha512,
                other => {
                    return Err(BluelineError::Verification(format!(
                        "unsupported checksum algorithm `{other}` in `{token}`, expected sha256 or sha512"
                    )));
                }
            };
            return hex_to_checksum(alg, hex);
        }

        // Bare hex: infer the algorithm from the digest length.
        match token.len() {
            n if n == ChecksumAlg::Sha256.hex_len() => hex_to_checksum(ChecksumAlg::Sha256, token),
            n if n == ChecksumAlg::Sha512.hex_len() => hex_to_checksum(ChecksumAlg::Sha512, token),
            n => Err(BluelineError::Verification(format!(
                "integrity `{token}` is neither `{SRI_PREFIX}<base64>` nor a sha256/sha512 hex digest (got {n} chars)"
            ))),
        }
    }

    /// npm SRI form (`sha512-<base64>`), used when talking to npm-shaped
    /// registries and preserved for backwards-compatible display.
    pub fn to_sri(&self) -> String {
        match self.alg {
            ChecksumAlg::Sha512 => format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(hex_to_bytes(&self.value_hex))
            ),
            ChecksumAlg::Sha256 => self.to_display(),
        }
    }

    /// Canonical display/storage form: `<alg>:<lowercase hex>`.
    pub fn to_display(&self) -> String {
        format!("{}:{}", self.alg.name(), self.value_hex)
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0))
        .collect()
}

fn hex_to_checksum(alg: ChecksumAlg, hex: &str) -> Result<Checksum, BluelineError> {
    let hex_lower = hex.to_ascii_lowercase();
    if hex_lower.len() != alg.hex_len()
        || !hex_lower
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(BluelineError::Verification(format!(
            "invalid {} hex digest `{hex}`: expected {} lowercase hexadecimal characters",
            alg.name(),
            alg.hex_len()
        )));
    }
    Ok(Checksum {
        alg,
        value_hex: hex_lower,
    })
}

fn base64_to_hex(alg: ChecksumAlg, b64: &str) -> Result<Checksum, BluelineError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| {
            BluelineError::Verification(format!(
                "integrity `{}-{b64}` is not valid base64: {e}",
                alg.name()
            ))
        })?;
    let hex = hex_encode(&bytes);
    hex_to_checksum(alg, &hex)
}

/// A resolved package release point from the registry (metadata only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub tarball_url: String,
    /// Registry-provided content checksum, if published. Absence is fatal
    /// downstream: bytes are never trusted without one.
    pub integrity: Option<Checksum>,
}

/// One published release of a package, with the lifecycle metadata newer
/// registries expose. npm reports `yanked=false` and no publish time for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub yanked: bool,
    /// Unix epoch seconds, when the registry publishes it.
    pub publish_time: Option<i64>,
}

/// The withdrawal reasons a registry publishes, keyed by version.
///
/// `Release` carries the boolean; the cause is the fact that tells a reviewer
/// what to do next, and it is remote text that ends up on a card, so it is
/// carried verbatim here and sanitized where it is rendered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct YankedReasons {
    by_version: BTreeMap<String, String>,
}

impl YankedReasons {
    /// Record the reason one registry gave for withdrawing a version. A blank
    /// reason is the absence of a cause, not a cause, so it is dropped.
    pub fn record(&mut self, version: &str, reason: &str) {
        let reason = reason.trim();
        if !reason.is_empty() {
            self.by_version
                .insert(version.to_string(), reason.to_string());
        }
    }

    /// The stated reason for `version`, when the registry published one.
    pub fn get(&self, version: &str) -> Option<&str> {
        self.by_version.get(version).map(String::as_str)
    }
}

/// PEP 592 lets a registry withdraw a release with the bare boolean `true`,
/// which states no cause. The PyPI adapter carries that form as the word
/// `yanked`, so that its reason is `Some` exactly when the release is
/// withdrawn; that stand-in is not a cause, and rendering it as one would tell
/// a reviewer the registry said something it never said.
const YANKED_WITHOUT_A_CAUSE: &str = "yanked";

/// The release list for `name` plus the withdrawal reason each release
/// carries, in one read.
///
/// `Registry::list_releases` is implemented per adapter and its record has
/// nowhere to put a reason, so the adapter whose registry publishes one is
/// recognized here and read through its own accessor. Everything else takes
/// the same plain list it always did, with no reasons to report.
pub fn releases_with_reasons(
    registry: &dyn Registry,
    name: &str,
) -> Result<(Vec<Release>, YankedReasons), BluelineError> {
    let Some(pypi) = (registry as &dyn Any).downcast_ref::<pypi::PyPIRegistry>() else {
        return Ok((registry.list_releases(name)?, YankedReasons::default()));
    };
    let published = pypi.list_releases_with_reasons(name)?;
    let mut reasons = YankedReasons::default();
    let mut releases = Vec::with_capacity(published.len());
    for release in published {
        if let Some(reason) = &release.yanked_reason
            && reason != YANKED_WITHOUT_A_CAUSE
        {
            reasons.record(&release.version, reason);
        }
        releases.push(Release::from(release));
    }
    Ok((releases, reasons))
}

/// Seam for future registries (PyPI, cargo). npm is the only full impl for now.
///
/// `Any` is a supertrait so a caller holding a `&dyn Registry` can recover the
/// concrete adapter when one of them publishes something the seam cannot
/// carry (see `releases_with_reasons`).
pub trait Registry: Any {
    /// Which ecosystem this registry serves.
    fn ecosystem(&self) -> Ecosystem;

    /// Resolve `<name>@<version>` to a concrete release. Read-only.
    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError>;

    /// Download the release tarball. Bytes returned are integrity-verified
    /// against the manifest before returning (fail closed on mismatch).
    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError>;

    /// List all published versions for a package, sorted ascending.
    fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, BluelineError>;

    /// List published releases with lifecycle metadata, sorted ascending.
    fn list_releases(&self, name: &str) -> Result<Vec<Release>, BluelineError>;

    /// The registry's default version for a package (npm: `dist-tags.latest`,
    /// falling back to the highest stable release), if any exist.
    fn default_version(&self, name: &str) -> Result<Option<String>, BluelineError>;

    /// The publishing identity of one resolved release, when the registry
    /// exposes it per release (AUR: the commit author email). Registries
    /// without per-release authorship return `None`, which the trust engine
    /// treats as "unknown" rather than as a signal.
    fn release_author(&self, _pkg: &Package) -> Option<String> {
        None
    }

    /// The registry's own signature block for this exact release, as
    /// published next to the artifact (npm `dist.signatures`).
    ///
    /// Presence, never validity: nothing here verifies a signature, and a
    /// registry that publishes none — or whose metadata could not be read —
    /// returns `None` rather than a guess, so a policy that requires
    /// signatures keeps refusing.
    fn release_signatures(&self, _pkg: &Package) -> Option<serde_json::Value> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// sha512 SRI of the bytes "tarball-content".
    const TEST_SRI: &str = "sha512-dWJ6JIJkmHG8N3fH1b/hbpmBQ7wKIpEw3zsVl2873OtFXh9QhR1KUU3uojohuIJ/xd+hb1R0q/57C8sMt4tstQ==";
    const TEST_HEX: &str = "75627a2482649871bc3777c7d5bfe16e998143bc0a229130df3b15976f3bdceb455e1f50851d4a514deea23a21b8827fc5dfa16f5474abfe7b0bcb0cb78b6cb5";

    #[test]
    fn parses_npm_sri_form_to_hex() {
        let c = Checksum::parse(TEST_SRI).unwrap();
        assert_eq!(c.alg, ChecksumAlg::Sha512);
        assert_eq!(c.value_hex, TEST_HEX);
    }

    #[test]
    fn sri_round_trips_through_display() {
        let c = Checksum::parse(TEST_SRI).unwrap();
        assert_eq!(c.to_sri(), TEST_SRI);
        let again = Checksum::parse(&c.to_display()).unwrap();
        assert_eq!(again, c);
    }

    #[test]
    fn picks_sha512_from_multi_algorithm_list() {
        let c = Checksum::parse(&format!("sha1-YWJjZA== {TEST_SRI}")).unwrap();
        assert_eq!(c.alg, ChecksumAlg::Sha512);
    }

    #[test]
    fn parses_display_and_bare_hex_forms() {
        let sha256_hex = "ab".repeat(32);
        let c = Checksum::parse(&format!("sha256:{sha256_hex}")).unwrap();
        assert_eq!(c.alg, ChecksumAlg::Sha256);
        assert_eq!(c.value_hex, sha256_hex);

        let bare = Checksum::parse(&sha256_hex).unwrap();
        assert_eq!(bare, c);

        let sha512_bare = "cd".repeat(64);
        let c512 = Checksum::parse(&sha512_bare).unwrap();
        assert_eq!(c512.alg, ChecksumAlg::Sha512);

        // Uppercase hex normalizes to lowercase
        let upper = Checksum::parse(&sha256_hex.to_uppercase()).unwrap();
        assert_eq!(upper, c);
    }

    #[test]
    fn fails_closed_on_bad_checksum_input() {
        assert!(Checksum::parse("").is_err());
        assert!(Checksum::parse("sha1-YWJjZA==").is_err());
        assert!(Checksum::parse("md5:abcd").is_err());
        assert!(Checksum::parse("sha512-not-base64!!").is_err());
        // A sha512-labeled digest that decodes to the wrong byte length is rejected
        assert!(Checksum::parse("sha512-YWJjZA==").is_err());
        assert!(Checksum::parse(&"g".repeat(64)).is_err());
        assert!(Checksum::parse(&"ab".repeat(31)).is_err());
        assert!(Checksum::parse("deadbeef").is_err());
        // Whitespace-only token lists have nothing usable
        assert!(Checksum::parse("   ").is_err());
    }

    #[test]
    fn ecosystem_keys_are_stable() {
        assert_eq!(Ecosystem::Npm.key(), "npm");
        assert_eq!(Ecosystem::Cargo.key(), "cargo");
        assert_eq!(Ecosystem::PyPi.key(), "pypi");
        assert_eq!(Ecosystem::Aur.key(), "aur");
    }

    /// A blank reason is the absence of a cause. Recording it as `Some("")`
    /// would render an empty quote on the card and read like a cause.
    #[test]
    fn blank_reasons_are_not_recorded_as_causes() {
        let mut reasons = YankedReasons::default();
        reasons.record("1.0.0", "   ");
        assert_eq!(reasons.get("1.0.0"), None);
        reasons.record("2.0.0", "  broken wheel  ");
        assert_eq!(reasons.get("2.0.0"), Some("broken wheel"));
        assert_eq!(reasons.get("3.0.0"), None);
    }

    /// The reason is registry text with no bound on it, so it is kept as the
    /// registry spelled it and bounded where it is rendered, not here.
    #[test]
    fn a_registry_can_publish_an_oversized_reason() {
        let mut reasons = YankedReasons::default();
        reasons.record("1.0.0", &"x".repeat(100_000));
        assert_eq!(reasons.get("1.0.0").map(str::len), Some(100_000));
    }

    struct NoReasonRegistry;

    impl Registry for NoReasonRegistry {
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Npm
        }
        fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError> {
            Ok(Package {
                name: name.to_string(),
                version: version.to_string(),
                tarball_url: "https://example.com/x.tgz".to_string(),
                integrity: Some(Checksum::parse(TEST_SRI)?),
            })
        }
        fn fetch_tarball(&self, _pkg: &Package) -> Result<Vec<u8>, BluelineError> {
            Ok(vec![])
        }
        fn list_versions(&self, _name: &str) -> Result<Vec<semver::Version>, BluelineError> {
            Ok(vec![semver::Version::parse("1.0.0").map_err(|e| {
                BluelineError::Manifest("x".into(), e.to_string())
            })?])
        }
        fn list_releases(&self, _name: &str) -> Result<Vec<Release>, BluelineError> {
            Ok(vec![Release {
                version: "1.0.0".into(),
                yanked: true,
                publish_time: None,
            }])
        }
        fn default_version(&self, _name: &str) -> Result<Option<String>, BluelineError> {
            Ok(Some("1.0.0".into()))
        }
    }

    /// A registry that publishes no reason takes the same read it always took,
    /// with nothing to report. This lane is not PyPI, so the release list comes
    /// from the plain seam.
    #[test]
    fn a_registry_without_reasons_reports_none() {
        let (releases, reasons) = releases_with_reasons(&NoReasonRegistry, "pkg").unwrap();
        assert_eq!(releases.len(), 1);
        assert!(releases[0].yanked);
        assert_eq!(reasons.get("1.0.0"), None);
    }

    /// The point of the seam: PyPI's PEP 592 reason was read off the index and
    /// dropped at `From<PyPiRelease> for Release`, so the one field that says
    /// *why* a release was withdrawn never reached a caller.
    #[test]
    fn pypi_releases_carry_the_registry_stated_reason() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let _server = std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let path = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let body = if path == "/simple/demo/" {
                        serde_json::json!({
                            "name": "demo",
                            "versions": ["1.0.0", "2.0.0", "3.0.0"],
                            "files": [
                                {
                                    "filename": "demo-1.0.0-py3-none-any.whl",
                                    "url": "https://example.com/demo-1.0.0.whl",
                                    "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                                    "yanked": false
                                },
                                {
                                    "filename": "demo-2.0.0-py3-none-any.whl",
                                    "url": "https://example.com/demo-2.0.0.whl",
                                    "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                                    "yanked": "critical vulnerability, no upgrade path"
                                },
                                {
                                    "filename": "demo-3.0.0-py3-none-any.whl",
                                    "url": "https://example.com/demo-3.0.0.whl",
                                    "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                                    "yanked": true
                                }
                            ]
                        })
                        .to_string()
                    } else {
                        "not found".to_string()
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.pypi.simple.v1+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                });
            }
        });

        let registry = pypi::PyPIRegistry::new(&base);
        let (releases, reasons) = releases_with_reasons(&registry, "demo").unwrap();
        assert_eq!(releases.len(), 3);
        let live = releases.iter().find(|r| r.version == "1.0.0").unwrap();
        assert!(!live.yanked);
        let withdrawn = releases.iter().find(|r| r.version == "2.0.0").unwrap();
        assert!(withdrawn.yanked);
        assert_eq!(
            reasons.get("2.0.0"),
            Some("critical vulnerability, no upgrade path"),
            "the registry's own words for the withdrawal must reach the caller"
        );
        assert_eq!(reasons.get("1.0.0"), None);
        // PEP 592's bare `true` withdraws without stating a cause, and the
        // adapter spells that form `yanked`. Standing in a tautology for a
        // cause would put "the registry said `yanked`" on the card.
        let boolean_form = releases.iter().find(|r| r.version == "3.0.0").unwrap();
        assert!(boolean_form.yanked);
        assert_eq!(reasons.get("3.0.0"), None);
    }
}
