use std::{env, path::Path};

use zeroize::Zeroize;

use crate::{Result, patterns::CredentialPatternSet};

use super::{SecretLabel, SecureBuf};

#[derive(Debug)]
pub struct SecretCandidate {
    pub label: SecretLabel,
    pub value: SecureBuf,
}

pub fn discover_env_candidates(max: usize) -> Vec<SecretCandidate> {
    let patterns = CredentialPatternSet::builtin();
    discover_env_candidates_with_patterns(max, &patterns)
}

pub fn discover_env_candidates_with_patterns(
    max: usize,
    patterns: &CredentialPatternSet,
) -> Vec<SecretCandidate> {
    let mut candidates = Vec::new();
    for (key, value) in env::vars_os() {
        if candidates.len() >= max {
            break;
        }
        let Some(key) = key.to_str() else {
            continue;
        };
        let mut value_bytes = value.to_string_lossy().as_bytes().to_vec();
        if is_secret_candidate_with_patterns(key, &value_bytes, patterns) {
            candidates.push(SecretCandidate {
                label: SecretLabel::new(key),
                value: SecureBuf::new(std::mem::take(&mut value_bytes)),
            });
        }
        value_bytes.zeroize();
    }
    candidates
}

pub fn discover_dotenv_candidates(
    path: impl AsRef<Path>,
    max: usize,
) -> Result<Vec<SecretCandidate>> {
    let patterns = CredentialPatternSet::builtin();
    discover_dotenv_candidates_with_patterns(path, max, &patterns)
}

pub fn discover_dotenv_candidates_with_patterns(
    path: impl AsRef<Path>,
    max: usize,
    patterns: &CredentialPatternSet,
) -> Result<Vec<SecretCandidate>> {
    let path = path.as_ref();
    let mut bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    let candidates = parse_dotenv_candidates_from_bytes(&mut bytes, max, patterns);
    bytes.zeroize();
    Ok(candidates)
}

fn parse_dotenv_candidates_from_bytes(
    bytes: &mut [u8],
    max: usize,
    patterns: &CredentialPatternSet,
) -> Vec<SecretCandidate> {
    let mut candidates = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if candidates.len() >= max {
            break;
        }
        let line = strip_export_prefix(trim_ascii(line));
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some(eq_index) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let key = trim_ascii(&line[..eq_index]);
        let value = trim_ascii(strip_export_prefix(&line[eq_index + 1..]));
        let value = strip_matching_quotes(value);
        let Ok(key) = std::str::from_utf8(key) else {
            continue;
        };
        if is_secret_candidate_with_patterns(key, value, patterns) {
            candidates.push(SecretCandidate {
                label: SecretLabel::new(key),
                value: SecureBuf::from_slice(value),
            });
        }
    }
    bytes.zeroize();
    candidates
}

pub fn is_secret_candidate(key: &str, value: &[u8]) -> bool {
    let patterns = CredentialPatternSet::builtin();
    is_secret_candidate_with_patterns(key, value, &patterns)
}

pub fn is_secret_candidate_with_patterns(
    key: &str,
    value: &[u8],
    patterns: &CredentialPatternSet,
) -> bool {
    patterns.is_secret_candidate(key, value)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

fn strip_export_prefix(bytes: &[u8]) -> &[u8] {
    let bytes = trim_ascii(bytes);
    if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"export ") {
        trim_ascii(&bytes[7..])
    } else {
        bytes
    }
}

fn strip_matching_quotes(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &bytes[1..bytes.len() - 1];
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use crate::patterns::CredentialPatternSet;

    use super::parse_dotenv_candidates_from_bytes;

    #[test]
    fn dotenv_source_bytes_are_zeroized_after_candidate_extraction() {
        let mut bytes =
            b"NODE_ENV=development\nOPENAI_API_KEY=sk-dotenv-zeroize-1234567890\n".to_vec();
        let patterns = CredentialPatternSet::builtin();
        let candidates = parse_dotenv_candidates_from_bytes(&mut bytes, 10, &patterns);

        assert_eq!(candidates.len(), 1);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
