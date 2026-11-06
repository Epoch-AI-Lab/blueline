//! Shared fixtures for the unit-test modules. One copy so test setups
//! cannot drift apart.

use crate::registry::{Checksum, ChecksumAlg};
use sha2::{Digest, Sha512};

/// Deterministic valid sha512 checksum derived from `tag`.
pub(crate) fn checksum(tag: &str) -> Checksum {
    let mut hasher = Sha512::new();
    hasher.update(tag.as_bytes());
    Checksum {
        alg: ChecksumAlg::Sha512,
        value_hex: format!("{:x}", hasher.finalize()),
    }
}
