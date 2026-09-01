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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Seam for future registries (PyPI, cargo). npm is the only full impl for now.
pub trait Registry {
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
}
