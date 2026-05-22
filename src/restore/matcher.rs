use aho_corasick::AhoCorasick;

use crate::{
    CrebroError, Result,
    secrets::{SecretId, SecretRegistry},
};

#[derive(Debug)]
pub struct PlaceholderMatcher {
    automaton: Option<AhoCorasick>,
    ids: Vec<SecretId>,
    patterns: Vec<String>,
}

impl PlaceholderMatcher {
    pub fn new(registry: &SecretRegistry) -> Result<Self> {
        let pairs = registry.placeholders();
        if pairs.is_empty() {
            return Ok(Self {
                automaton: None,
                ids: Vec::new(),
                patterns: Vec::new(),
            });
        }
        let patterns = pairs
            .iter()
            .map(|(placeholder, _)| placeholder.clone())
            .collect::<Vec<_>>();
        let ids = pairs.iter().map(|(_, id)| *id).collect::<Vec<_>>();
        let automaton = AhoCorasick::new(&patterns)
            .map_err(|err| CrebroError::Restore(format!("placeholder matcher failed: {err}")))?;
        Ok(Self {
            automaton: Some(automaton),
            ids,
            patterns,
        })
    }

    pub fn find_in<'a>(&'a self, bytes: &'a [u8]) -> Vec<PlaceholderMatch> {
        let Some(automaton) = &self.automaton else {
            return Vec::new();
        };
        automaton
            .find_iter(bytes)
            .map(|mat| PlaceholderMatch {
                start: mat.start(),
                end: mat.end(),
                secret_id: self.ids[mat.pattern().as_usize()],
            })
            .collect()
    }

    pub fn max_pattern_len(&self) -> usize {
        self.patterns.iter().map(String::len).max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderMatch {
    pub start: usize,
    pub end: usize,
    pub secret_id: SecretId,
}
