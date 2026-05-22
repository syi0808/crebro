use crate::{Result, secrets::SecretRegistry};

use super::span::{RedactionSpan, select_longest_non_overlapping};

pub fn scan_string_token(bytes: &[u8], registry: &SecretRegistry) -> Result<Vec<RedactionSpan>> {
    if registry.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(min_len) = registry.min_secret_len()
        && bytes.len() < min_len
    {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::new();
    for len in registry.lengths() {
        if len > bytes.len() {
            continue;
        }
        for start in 0..=bytes.len() - len {
            let window = &bytes[start..start + len];
            let prefilter = registry.prefilter_window(window)?;
            for entry in registry.candidates(len, prefilter) {
                if registry.verify_window(entry, window)? {
                    candidates.push(RedactionSpan {
                        start,
                        len,
                        secret_id: entry.id,
                        placeholder: entry.placeholder.clone(),
                    });
                }
            }
        }
    }

    Ok(select_longest_non_overlapping(candidates))
}
