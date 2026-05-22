use std::{env, path::Path};

use zeroize::Zeroize;

use crate::Result;

use super::{SecretLabel, SecureBuf};

const SECRET_KEY_MARKERS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASS",
    "AUTH",
    "CREDENTIAL",
    "PRIVATE",
    "CERT",
    "DATABASE_URL",
    "CONNECTION_STRING",
];

const COMMON_VALUES: &[&str] = &[
    "true",
    "false",
    "debug",
    "development",
    "production",
    "test",
    "localhost",
    "127.0.0.1",
];

#[derive(Debug)]
pub struct SecretCandidate {
    pub label: SecretLabel,
    pub value: SecureBuf,
}

pub fn discover_env_candidates(max: usize) -> Vec<SecretCandidate> {
    let mut candidates = Vec::new();
    for (key, value) in env::vars_os() {
        if candidates.len() >= max {
            break;
        }
        let Some(key) = key.to_str() else {
            continue;
        };
        let mut value_bytes = value.to_string_lossy().as_bytes().to_vec();
        if is_secret_candidate(key, &value_bytes) {
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
    let path = path.as_ref();
    let mut bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    let candidates = parse_dotenv_candidates_from_bytes(&mut bytes, max);
    bytes.zeroize();
    Ok(candidates)
}

fn parse_dotenv_candidates_from_bytes(bytes: &mut [u8], max: usize) -> Vec<SecretCandidate> {
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
        if is_secret_candidate(key, value) {
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
    let key_upper = key.to_ascii_uppercase();
    if !SECRET_KEY_MARKERS
        .iter()
        .any(|marker| key_upper.contains(marker))
    {
        return false;
    }

    if value.len() < 12 {
        return false;
    }

    let lower = String::from_utf8_lossy(value).to_ascii_lowercase();
    if COMMON_VALUES.iter().any(|common| lower == *common) {
        return false;
    }
    if lower.chars().all(|ch| ch.is_ascii_digit()) && lower.len() <= 16 {
        return false;
    }

    rough_entropy(value) >= 3.0
}

fn rough_entropy(value: &[u8]) -> f64 {
    let mut seen = [false; 256];
    let mut unique = 0usize;
    for byte in value {
        if !seen[*byte as usize] {
            seen[*byte as usize] = true;
            unique += 1;
        }
    }
    (unique as f64).log2()
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
    use super::parse_dotenv_candidates_from_bytes;

    #[test]
    fn dotenv_source_bytes_are_zeroized_after_candidate_extraction() {
        let mut bytes =
            b"NODE_ENV=development\nOPENAI_API_KEY=sk-dotenv-zeroize-1234567890\n".to_vec();
        let candidates = parse_dotenv_candidates_from_bytes(&mut bytes, 10);

        assert_eq!(candidates.len(), 1);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
