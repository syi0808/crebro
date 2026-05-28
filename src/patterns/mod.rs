use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, OnceLock},
};

use regex::Regex;
use serde::Deserialize;

use crate::{CrebroError, Result};

const BUILTIN_CREDENTIALS_TOML: &str = include_str!("../../patterns/credentials.toml");

static BUILTIN_PATTERNS: OnceLock<Arc<CredentialPatternSet>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct CredentialPatternSet {
    env: EnvPatternRules,
    credential_patterns: Vec<CompiledCredentialPattern>,
}

#[derive(Debug, Clone)]
pub struct EnvPatternRules {
    exact_keys: Vec<String>,
    key_markers: Vec<String>,
    common_values: Vec<String>,
    min_value_len: usize,
    min_entropy: f64,
}

#[derive(Debug, Clone)]
pub struct CompiledCredentialPattern {
    id: String,
    description: Option<String>,
    regex: Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnUnregisteredMatch {
    RequireExplicitSecret,
    AutoRedact,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPatternMatch {
    pub id: String,
    pub on_unregistered_match: OnUnregisteredMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAutoRedactMatch {
    pub pattern_id: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Deserialize)]
struct RawPatternFile {
    env: RawEnvRules,
    #[serde(default)]
    credential_patterns: Vec<RawCredentialPattern>,
}

#[derive(Debug, Deserialize)]
struct RawEnvRules {
    #[serde(default)]
    exact_keys: Vec<String>,
    key_markers: Vec<String>,
    common_values: Vec<String>,
    min_value_len: usize,
    min_entropy: f64,
}

#[derive(Debug, Deserialize)]
struct RawCredentialPattern {
    id: String,
    description: Option<String>,
    regex: String,
}

impl CredentialPatternSet {
    pub fn builtin() -> Arc<Self> {
        Arc::clone(BUILTIN_PATTERNS.get_or_init(|| {
            Arc::new(
                Self::from_toml(BUILTIN_CREDENTIALS_TOML)
                    .expect("built-in credential pattern TOML must be valid"),
            )
        }))
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let raw: RawPatternFile = toml::from_str(text).map_err(|err| {
            CrebroError::Config(format!("invalid credential patterns TOML: {err}"))
        })?;
        raw.into_pattern_set()
    }

    pub fn is_secret_candidate(&self, key: &str, value: &[u8]) -> bool {
        self.env.is_secret_candidate(key, value)
    }

    pub fn inspect_unregistered_text(&self, text: &str) -> Vec<CredentialPatternMatch> {
        let _ = text;
        Vec::new()
    }

    pub fn auto_redact_matches(&self, text: &str) -> Vec<CredentialAutoRedactMatch> {
        let mut matches = Vec::new();
        for pattern in &self.credential_patterns {
            for matched in pattern.regex.find_iter(text) {
                matches.push(CredentialAutoRedactMatch {
                    pattern_id: pattern.id.clone(),
                    start: matched.start(),
                    end: matched.end(),
                });
            }
        }
        select_longest_non_overlapping_matches(matches)
    }

    pub fn has_credential_patterns(&self) -> bool {
        !self.credential_patterns.is_empty()
    }
}

fn select_longest_non_overlapping_matches(
    mut matches: Vec<CredentialAutoRedactMatch>,
) -> Vec<CredentialAutoRedactMatch> {
    matches.sort_by(|left, right| {
        let left_len = left.end.saturating_sub(left.start);
        let right_len = right.end.saturating_sub(right.start);
        right_len
            .cmp(&left_len)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
    });
    let mut selected: Vec<CredentialAutoRedactMatch> = Vec::new();
    'candidate: for candidate in matches {
        for existing in &selected {
            if candidate.start < existing.end && existing.start < candidate.end {
                continue 'candidate;
            }
        }
        selected.push(candidate);
    }
    selected.sort_by_key(|matched| matched.start);
    selected
}

impl RawPatternFile {
    fn into_pattern_set(self) -> Result<CredentialPatternSet> {
        let env = self.env.into_rules()?;
        let mut ids = HashSet::new();
        let mut credential_patterns = Vec::with_capacity(self.credential_patterns.len());
        for raw in self.credential_patterns {
            if raw.id.trim().is_empty() {
                return Err(CrebroError::Config(
                    "credential pattern id cannot be empty".into(),
                ));
            }
            if !ids.insert(raw.id.clone()) {
                return Err(CrebroError::Config(format!(
                    "duplicate credential pattern id `{}`",
                    raw.id
                )));
            }
            let regex = Regex::new(&raw.regex).map_err(|err| {
                CrebroError::Config(format!(
                    "invalid regex for credential pattern `{}`: {err}",
                    raw.id
                ))
            })?;
            credential_patterns.push(CompiledCredentialPattern {
                id: raw.id,
                description: raw.description,
                regex,
            });
        }
        Ok(CredentialPatternSet {
            env,
            credential_patterns,
        })
    }
}

impl RawEnvRules {
    fn into_rules(self) -> Result<EnvPatternRules> {
        if self.key_markers.is_empty() {
            return Err(CrebroError::Config(
                "env key_markers cannot be empty".into(),
            ));
        }
        Ok(EnvPatternRules {
            exact_keys: self
                .exact_keys
                .into_iter()
                .map(|key| key.to_ascii_uppercase())
                .collect(),
            key_markers: self
                .key_markers
                .into_iter()
                .map(|marker| marker.to_ascii_uppercase())
                .collect(),
            common_values: self
                .common_values
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            min_value_len: self.min_value_len,
            min_entropy: self.min_entropy,
        })
    }
}

impl EnvPatternRules {
    fn is_secret_candidate(&self, key: &str, value: &[u8]) -> bool {
        let key_upper = key.to_ascii_uppercase();
        if !self
            .exact_keys
            .iter()
            .any(|exact| key_upper.as_str() == exact)
            && !self
                .key_markers
                .iter()
                .any(|marker| key_upper.contains(marker))
        {
            return false;
        }

        if value.len() < self.min_value_len {
            return false;
        }

        let lower = String::from_utf8_lossy(value).to_ascii_lowercase();
        if self.common_values.contains(&lower) {
            return false;
        }
        if lower.chars().all(|ch| ch.is_ascii_digit()) && lower.len() <= 16 {
            return false;
        }

        rough_entropy(value) >= self.min_entropy
    }
}

impl CompiledCredentialPattern {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
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
