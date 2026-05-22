use crate::secrets::{Placeholder, SecretId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionSpan {
    pub start: usize,
    pub len: usize,
    pub secret_id: SecretId,
    pub placeholder: Placeholder,
}

impl RedactionSpan {
    pub fn end(&self) -> usize {
        self.start + self.len
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

pub fn select_longest_non_overlapping(mut spans: Vec<RedactionSpan>) -> Vec<RedactionSpan> {
    spans.sort_by(|a, b| {
        b.len
            .cmp(&a.len)
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| a.secret_id.cmp(&b.secret_id))
    });

    let mut selected: Vec<RedactionSpan> = Vec::new();
    for span in spans {
        if selected.iter().any(|selected| selected.overlaps(&span)) {
            continue;
        }
        selected.push(span);
    }
    selected.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len.cmp(&a.len))
            .then_with(|| a.secret_id.cmp(&b.secret_id))
    });
    selected
}

pub fn apply_spans(bytes: &[u8], spans: &[RedactionSpan]) -> Vec<u8> {
    if spans.is_empty() {
        return bytes.to_vec();
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    for span in spans {
        if span.start > cursor {
            out.extend_from_slice(&bytes[cursor..span.start]);
        }
        out.extend_from_slice(span.placeholder.as_str().as_bytes());
        cursor = span.end();
    }
    if cursor < bytes.len() {
        out.extend_from_slice(&bytes[cursor..]);
    }
    out
}
