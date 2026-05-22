use std::collections::{HashMap, VecDeque};

use crate::{Result, secrets::SecretRegistry};

use super::{
    scanner::scan_string_token,
    span::{RedactionSpan, apply_spans, select_longest_non_overlapping},
};

#[derive(Clone)]
pub enum CacheEntry {
    NoSecret,
    Spans(Vec<RedactionSpan>),
    Sanitized(Vec<u8>),
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSecret => f.write_str("NoSecret"),
            Self::Spans(spans) => f
                .debug_struct("Spans")
                .field("count", &spans.len())
                .finish_non_exhaustive(),
            Self::Sanitized(bytes) => f
                .debug_struct("Sanitized")
                .field("bytes_len", &bytes.len())
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub scanner_runs: u64,
    pub flushes: u64,
    pub evictions: u64,
}

pub struct RedactionCache {
    max_entries: usize,
    chunk_size: usize,
    registry_version: u64,
    entries: HashMap<[u8; 32], CacheEntry>,
    order: VecDeque<[u8; 32]>,
    stats: RedactionCacheStats,
}

impl std::fmt::Debug for RedactionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionCache")
            .field("max_entries", &self.max_entries)
            .field("chunk_size", &self.chunk_size)
            .field("registry_version", &self.registry_version)
            .field("entries_len", &self.entries.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl RedactionCache {
    pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

    pub fn new(max_entries: usize) -> Self {
        Self::new_with_chunk_size(max_entries, Self::DEFAULT_CHUNK_SIZE)
    }

    pub fn new_with_chunk_size(max_entries: usize, chunk_size: usize) -> Self {
        Self {
            max_entries,
            chunk_size: chunk_size.max(1024),
            registry_version: 0,
            entries: HashMap::new(),
            order: VecDeque::new(),
            stats: RedactionCacheStats::default(),
        }
    }

    pub fn stats(&self) -> RedactionCacheStats {
        self.stats.clone()
    }

    pub fn flush(&mut self, registry_version: u64) {
        self.registry_version = registry_version;
        self.entries.clear();
        self.order.clear();
        self.stats.flushes += 1;
    }

    fn sync_registry_version(&mut self, registry: &SecretRegistry) {
        if self.registry_version != registry.version() {
            self.flush(registry.version());
        }
    }

    pub fn sanitize_string(&mut self, bytes: &[u8], registry: &SecretRegistry) -> Result<Vec<u8>> {
        if registry.is_empty() {
            return Ok(bytes.to_vec());
        }
        if registry
            .min_secret_len()
            .is_some_and(|min_len| bytes.len() < min_len)
        {
            return Ok(bytes.to_vec());
        }

        if bytes.len() > self.chunk_size {
            return self.sanitize_large_string(bytes, registry);
        }

        self.sync_registry_version(registry);
        let key = registry.cache_key(bytes)?;
        if let Some(entry) = self.cached_entry(&key) {
            self.stats.hits += 1;
            return match entry {
                CacheEntry::NoSecret => Ok(bytes.to_vec()),
                CacheEntry::Spans(spans) => Ok(apply_spans(bytes, &spans)),
                CacheEntry::Sanitized(sanitized) => Ok(sanitized.clone()),
            };
        }

        self.stats.misses += 1;
        self.stats.scanner_runs += 1;
        let spans = scan_string_token(bytes, registry)?;
        let out = apply_spans(bytes, &spans);
        let entry = if spans.is_empty() {
            CacheEntry::NoSecret
        } else {
            CacheEntry::Spans(spans)
        };
        self.insert(key, entry);
        Ok(out)
    }

    fn sanitize_large_string(
        &mut self,
        bytes: &[u8],
        registry: &SecretRegistry,
    ) -> Result<Vec<u8>> {
        self.sync_registry_version(registry);
        let overlap = registry.max_secret_len().saturating_sub(1);
        let mut global_spans = Vec::new();
        let mut start = 0usize;
        while start < bytes.len() {
            let base_end = (start + self.chunk_size).min(bytes.len());
            let scan_start = start.saturating_sub(overlap);
            let scan_end = (base_end + overlap).min(bytes.len());
            let window = &bytes[scan_start..scan_end];
            let window_spans = self.spans_for_window(window, registry)?;
            for mut span in window_spans {
                span.start += scan_start;
                if span.start >= start && span.start < base_end {
                    global_spans.push(span);
                }
            }
            start = base_end;
        }
        let global_spans = select_longest_non_overlapping(global_spans);
        Ok(apply_spans(bytes, &global_spans))
    }

    fn spans_for_window(
        &mut self,
        window: &[u8],
        registry: &SecretRegistry,
    ) -> Result<Vec<RedactionSpan>> {
        let key = registry.cache_key(window)?;
        if let Some(entry) = self.cached_entry(&key) {
            match entry {
                CacheEntry::NoSecret => {
                    self.stats.hits += 1;
                    return Ok(Vec::new());
                }
                CacheEntry::Spans(spans) => {
                    self.stats.hits += 1;
                    return Ok(spans.clone());
                }
                CacheEntry::Sanitized(_) => {}
            }
        }

        self.stats.misses += 1;
        self.stats.scanner_runs += 1;
        let spans = scan_string_token(window, registry)?;
        let entry = if spans.is_empty() {
            CacheEntry::NoSecret
        } else {
            CacheEntry::Spans(spans.clone())
        };
        self.insert(key, entry);
        Ok(spans)
    }

    pub fn sanitize_object_bytes(
        &mut self,
        canonical_bytes: &[u8],
        registry: &mut SecretRegistry,
        sanitized_bytes: impl FnOnce(&mut Self, &mut SecretRegistry) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.sync_registry_version(registry);
        let version_before = registry.version();
        let key = registry.cache_key(canonical_bytes)?;
        if let Some(CacheEntry::Sanitized(sanitized)) = self.cached_entry(&key) {
            self.stats.hits += 1;
            return Ok(sanitized.clone());
        }
        self.stats.misses += 1;
        let sanitized = sanitized_bytes(self, registry)?;
        if registry.version() != version_before {
            self.flush(registry.version());
            return Ok(sanitized);
        }
        self.insert(key, CacheEntry::Sanitized(sanitized.clone()));
        Ok(sanitized)
    }

    fn insert(&mut self, key: [u8; 32], entry: CacheEntry) {
        if self.max_entries == 0 {
            return;
        }
        self.touch(&key);
        self.order.push_back(key);
        self.entries.insert(key, entry);
        while self.entries.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                if self.entries.remove(&old).is_some() {
                    self.stats.evictions += 1;
                }
            } else {
                break;
            }
        }
    }

    fn cached_entry(&mut self, key: &[u8; 32]) -> Option<CacheEntry> {
        let entry = self.entries.get(key).cloned()?;
        self.touch(key);
        self.order.push_back(*key);
        Some(entry)
    }

    fn touch(&mut self, key: &[u8; 32]) {
        self.order.retain(|entry| entry != key);
    }
}
