use std::collections::HashMap;

use crate::{CrebroError, Result};

use super::{
    Placeholder, SecretCapsule, SecureBuf, SessionKeys,
    fingerprint::{KeyedDigest, RollingFingerprint, keyed_digest, keyed_fingerprint},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretId(u64);

impl SecretId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretLabel(String);

impl SecretLabel {
    pub fn new(label: impl AsRef<str>) -> Self {
        let cleaned: String = label
            .as_ref()
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let cleaned = if cleaned.is_empty() {
            "SECRET".to_string()
        } else {
            cleaned
        };
        Self(cleaned)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretLabel").field(&self.0).finish()
    }
}

#[derive(Clone)]
pub struct SecretEntry {
    pub id: SecretId,
    pub label: SecretLabel,
    pub len: usize,
    pub keyed_digest: KeyedDigest,
    pub prefilter: RollingFingerprint,
    pub placeholder: Placeholder,
    pub capsule: SecretCapsule,
}

impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEntry")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("len", &self.len)
            .field("keyed_digest", &self.keyed_digest)
            .field("prefilter", &self.prefilter)
            .field("placeholder", &self.placeholder)
            .field("capsule", &self.capsule)
            .finish()
    }
}

pub struct SecretRegistry {
    keys: SessionKeys,
    entries: Vec<SecretEntry>,
    by_len_and_prefilter: HashMap<(usize, RollingFingerprint), Vec<SecretId>>,
    by_placeholder: HashMap<String, SecretId>,
    version: u64,
}

impl std::fmt::Debug for SecretRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRegistry")
            .field("keys", &self.keys)
            .field("entries", &self.entries)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl SecretRegistry {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            entries: Vec::new(),
            by_len_and_prefilter: HashMap::new(),
            by_placeholder: HashMap::new(),
            version: 0,
        }
    }

    pub fn with_generated_keys() -> Self {
        Self::new(SessionKeys::generate())
    }

    pub fn ingest(&mut self, label: SecretLabel, mut secret: SecureBuf) -> Result<SecretId> {
        if secret.is_empty() {
            return Err(CrebroError::Secret(
                "empty secret cannot be registered".into(),
            ));
        }

        let keyed_digest = keyed_digest(self.keys.match_key(), secret.expose())?;
        if let Some(existing) = self
            .entries
            .iter()
            .find(|entry| entry.keyed_digest == keyed_digest && entry.len == secret.len())
        {
            secret.zeroize_now();
            return Ok(existing.id);
        }

        let prefilter = keyed_fingerprint(self.keys.prefilter_key(), secret.expose())?;
        let placeholder = Placeholder::new(&label, &keyed_digest.0, self.keys.placeholder_key())?;
        let capsule = SecretCapsule::encrypt(&secret, self.keys.master())?;
        let id = SecretId((self.entries.len() + 1) as u64);
        let entry = SecretEntry {
            id,
            label,
            len: secret.len(),
            keyed_digest,
            prefilter,
            placeholder: placeholder.clone(),
            capsule,
        };

        self.by_len_and_prefilter
            .entry((entry.len, entry.prefilter))
            .or_default()
            .push(id);
        self.by_placeholder
            .insert(entry.placeholder.as_str().to_string(), id);
        self.entries.push(entry);
        self.version = self.version.saturating_add(1);
        secret.zeroize_now();
        Ok(id)
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn min_secret_len(&self) -> Option<usize> {
        self.entries.iter().map(|entry| entry.len).min()
    }

    pub fn max_secret_len(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.len)
            .max()
            .unwrap_or(0)
    }

    pub fn max_placeholder_len(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.placeholder.len())
            .max()
            .unwrap_or(0)
    }

    pub fn lengths(&self) -> Vec<usize> {
        let mut lengths = self
            .entries
            .iter()
            .map(|entry| entry.len)
            .collect::<Vec<_>>();
        lengths.sort_unstable();
        lengths.dedup();
        lengths
    }

    pub fn candidates(&self, len: usize, prefilter: RollingFingerprint) -> Vec<&SecretEntry> {
        self.by_len_and_prefilter
            .get(&(len, prefilter))
            .into_iter()
            .flatten()
            .filter_map(|id| self.entry(*id))
            .collect()
    }

    pub fn entry(&self, id: SecretId) -> Option<&SecretEntry> {
        let index = id.0.checked_sub(1)? as usize;
        self.entries.get(index)
    }

    pub fn placeholders(&self) -> Vec<(String, SecretId)> {
        self.by_placeholder
            .iter()
            .map(|(placeholder, id)| (placeholder.clone(), *id))
            .collect()
    }

    pub fn placeholder_for(&self, id: SecretId) -> Option<&Placeholder> {
        self.entry(id).map(|entry| &entry.placeholder)
    }

    pub fn verify_window(&self, entry: &SecretEntry, window: &[u8]) -> Result<bool> {
        Ok(keyed_digest(self.keys.match_key(), window)? == entry.keyed_digest)
    }

    pub fn prefilter_window(&self, window: &[u8]) -> Result<RollingFingerprint> {
        keyed_fingerprint(self.keys.prefilter_key(), window)
    }

    pub fn cache_key(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        super::fingerprint::cache_key(self.keys.cache_key(), self.version, bytes)
    }

    pub fn restore_to_vec(&self, id: SecretId, output: &mut Vec<u8>) -> Result<()> {
        let entry = self
            .entry(id)
            .ok_or_else(|| CrebroError::Restore(format!("unknown secret id {}", id.get())))?;
        entry.capsule.restore_to_vec(self.keys.master(), output)
    }
}
