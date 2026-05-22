use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CrebroError, Result};

use super::SecureBuf;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    master: [u8; 32],
    match_key: [u8; 32],
    cache_key: [u8; 32],
    placeholder_key: [u8; 32],
    prefilter_key: [u8; 32],
}

impl SessionKeys {
    pub fn generate() -> Self {
        let mut keys = Self {
            master: [0; 32],
            match_key: [0; 32],
            cache_key: [0; 32],
            placeholder_key: [0; 32],
            prefilter_key: [0; 32],
        };
        OsRng.fill_bytes(&mut keys.master);
        OsRng.fill_bytes(&mut keys.match_key);
        OsRng.fill_bytes(&mut keys.cache_key);
        OsRng.fill_bytes(&mut keys.placeholder_key);
        OsRng.fill_bytes(&mut keys.prefilter_key);
        keys
    }

    pub fn master(&self) -> &[u8; 32] {
        &self.master
    }

    pub fn match_key(&self) -> &[u8; 32] {
        &self.match_key
    }

    pub fn cache_key(&self) -> &[u8; 32] {
        &self.cache_key
    }

    pub fn placeholder_key(&self) -> &[u8; 32] {
        &self.placeholder_key
    }

    pub fn prefilter_key(&self) -> &[u8; 32] {
        &self.prefilter_key
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct SecretCapsule {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl SecretCapsule {
    pub fn encrypt(secret: &SecureBuf, key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), secret.expose())
            .map_err(|err| CrebroError::Secret(format!("secret encryption failed: {err}")))?;
        Ok(Self { nonce, ciphertext })
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<SecureBuf> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|err| CrebroError::Secret(format!("secret decryption failed: {err}")))?;
        Ok(SecureBuf::new(plaintext))
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn restore_to_vec(&self, key: &[u8; 32], output: &mut Vec<u8>) -> Result<()> {
        let mut scratch = self.decrypt(key)?;
        output.extend_from_slice(scratch.expose());
        scratch.zeroize_now();
        Ok(())
    }
}

impl std::fmt::Debug for SecretCapsule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCapsule")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl Drop for SecretCapsule {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}
