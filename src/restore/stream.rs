use crate::{Result, secrets::SecretRegistry};

use super::PlaceholderMatcher;

pub struct ResponseRestorer {
    matcher: PlaceholderMatcher,
    buffer: Vec<u8>,
    carry_len: usize,
}

impl ResponseRestorer {
    pub fn new(registry: &SecretRegistry) -> Result<Self> {
        let matcher = PlaceholderMatcher::new(registry)?;
        let carry_len = matcher.max_pattern_len().saturating_sub(1);
        Ok(Self {
            matcher,
            buffer: Vec::new(),
            carry_len,
        })
    }

    pub fn push_chunk(&mut self, chunk: &[u8], registry: &SecretRegistry) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        let safe_end = self.buffer.len().saturating_sub(self.carry_len);
        self.process_until(safe_end, registry)
    }

    pub fn finish(mut self, registry: &SecretRegistry) -> Result<Vec<u8>> {
        let safe_end = self.buffer.len();
        self.process_until(safe_end, registry)
    }

    fn process_until(&mut self, safe_end: usize, registry: &SecretRegistry) -> Result<Vec<u8>> {
        if safe_end == 0 {
            return Ok(Vec::new());
        }

        let matches = self.matcher.find_in(&self.buffer);
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut commit_until = safe_end;

        for mat in matches {
            if mat.start >= safe_end {
                break;
            }
            if mat.start < cursor {
                continue;
            }
            out.extend_from_slice(&self.buffer[cursor..mat.start]);
            registry.restore_to_vec(mat.secret_id, &mut out)?;
            cursor = mat.end;
            if cursor > commit_until {
                commit_until = cursor;
            }
        }

        if cursor < safe_end {
            out.extend_from_slice(&self.buffer[cursor..safe_end]);
        }

        self.buffer.drain(0..commit_until);
        Ok(out)
    }
}
