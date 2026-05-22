use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{CrebroError, Result};

use super::SecretLabel;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Placeholder(String);

impl Placeholder {
    pub fn new(label: &SecretLabel, secret_digest: &[u8; 32], key: &[u8; 32]) -> Result<Self> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|err| CrebroError::Secret(format!("invalid placeholder HMAC key: {err}")))?;
        mac.update(label.as_str().as_bytes());
        mac.update(secret_digest);
        let out = mac.finalize().into_bytes();
        let suffix = hex::encode(&out[..6]);
        Ok(Self(format!(
            "{{{{CREBRO_SECRET:v1:{}:s_{}}}}}",
            label.as_str(),
            suffix
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Placeholder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Placeholder").field(&self.0).finish()
    }
}
