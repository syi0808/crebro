use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{CrebroError, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollingFingerprint(pub u64);

impl std::fmt::Debug for RollingFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RollingFingerprint(..)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyedDigest(pub [u8; 32]);

impl std::fmt::Debug for KeyedDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyedDigest(..)")
    }
}

pub fn keyed_digest(key: &[u8; 32], bytes: &[u8]) -> Result<KeyedDigest> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|err| CrebroError::Secret(format!("invalid HMAC key: {err}")))?;
    mac.update(bytes);
    let out = mac.finalize().into_bytes();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    Ok(KeyedDigest(digest))
}

pub fn keyed_fingerprint(key: &[u8; 32], bytes: &[u8]) -> Result<RollingFingerprint> {
    let digest = keyed_digest(key, bytes)?;
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.0[..8]);
    Ok(RollingFingerprint(u64::from_le_bytes(head)))
}

pub fn cache_key(key: &[u8; 32], registry_version: u64, bytes: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|err| CrebroError::Secret(format!("invalid cache HMAC key: {err}")))?;
    mac.update(&registry_version.to_le_bytes());
    mac.update(bytes);
    let out = mac.finalize().into_bytes();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    Ok(digest)
}
