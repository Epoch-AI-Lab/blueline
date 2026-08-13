use crate::error::BluelineError;

/// A resolved package release point from the registry (metadata only).
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub tarball_url: String,
    /// sha512 SRI from `dist.integrity` (e.g. `sha512-<base64>`), if provided.
    pub integrity: Option<String>,
}

/// Seam for future registries (PyPI, cargo). npm is the only impl for now.
pub trait Registry {
    /// Resolve `<name>@<version>` to a concrete release. Read-only.
    fn resolve(&self, name: &str, version: &str) -> Result<Package, BluelineError>;

    /// Download the release tarball. Bytes returned are integrity-verified
    /// against the manifest before returning (fail closed on mismatch).
    fn fetch_tarball(&self, pkg: &Package) -> Result<Vec<u8>, BluelineError>;
}

pub mod npm;
