use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;

use crate::{
    CrebroError, Result,
    patterns::{CredentialPatternSet, OnUnregisteredMatch},
    secrets::{SecretId, SecretLabel, SecretRegistry, SecureBuf},
};

use super::{
    cache::{RedactionCache, RedactionCacheStats, SanitizedObject},
    directive::{DirectivePart, might_contain_directive_bytes, parse_user_secret_directives},
    field_policy::{FieldAction, FieldPolicy},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SanitizerReport {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub cache_stats: RedactionCacheStats,
    pub redacted_secret_ids: Vec<SecretId>,
    pub unregistered_pattern_ids: Vec<String>,
}

#[derive(Debug)]
pub struct JsonSanitizer {
    cache: RedactionCache,
    field_policy: FieldPolicy,
    patterns: Arc<CredentialPatternSet>,
}

#[derive(Default)]
pub struct StreamingJsonState {
    in_string: bool,
    escape_next: bool,
    raw_string: Vec<u8>,
    input_bytes: usize,
    output_bytes: usize,
    redacted_secret_ids: Vec<SecretId>,
    unregistered_pattern_ids: Vec<String>,
    path: Vec<String>,
    stack: Vec<StreamingFrame>,
}

impl std::fmt::Debug for StreamingJsonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingJsonState")
            .field("in_string", &self.in_string)
            .field("escape_next", &self.escape_next)
            .field("raw_string_len", &self.raw_string.len())
            .field("input_bytes", &self.input_bytes)
            .field("output_bytes", &self.output_bytes)
            .field("redaction_count", &self.redacted_secret_ids.len())
            .field(
                "unregistered_pattern_count",
                &self.unregistered_pattern_ids.len(),
            )
            .field("path_depth", &self.path.len())
            .field("stack_depth", &self.stack.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct StreamingFrame {
    container: StreamingContainer,
    path_len_on_exit: usize,
}

#[derive(Debug)]
enum StreamingContainer {
    Object {
        expecting_key: bool,
        pending_key: Option<String>,
    },
    Array,
}

#[derive(Debug)]
enum StreamingStringContext {
    ObjectKey,
    Value { path: Vec<String> },
}

impl JsonSanitizer {
    pub fn new(max_cache_entries: usize) -> Self {
        Self::with_patterns(max_cache_entries, CredentialPatternSet::builtin())
    }

    pub fn with_patterns(max_cache_entries: usize, patterns: Arc<CredentialPatternSet>) -> Self {
        Self {
            cache: RedactionCache::new(max_cache_entries),
            field_policy: FieldPolicy,
            patterns,
        }
    }

    pub fn cache_stats(&self) -> RedactionCacheStats {
        self.cache.stats()
    }

    pub fn sanitize_json(
        &mut self,
        body: &[u8],
        registry: &mut SecretRegistry,
    ) -> Result<(Vec<u8>, SanitizerReport)> {
        if registry.is_empty()
            && !self.patterns.has_credential_patterns()
            && !might_contain_directive_bytes(body)
        {
            return Ok((
                body.to_vec(),
                SanitizerReport {
                    input_bytes: body.len(),
                    output_bytes: body.len(),
                    cache_stats: self.cache.stats(),
                    redacted_secret_ids: Vec::new(),
                    unregistered_pattern_ids: Vec::new(),
                },
            ));
        }

        let mut value: Value = serde_json::from_slice(body)?;
        let mut report = SanitizerReport {
            input_bytes: body.len(),
            output_bytes: 0,
            cache_stats: self.cache.stats(),
            redacted_secret_ids: Vec::new(),
            unregistered_pattern_ids: Vec::new(),
        };
        self.sanitize_value(&mut value, registry, &mut Vec::new(), &mut report)?;
        let out = serde_json::to_vec(&value)?;
        report.output_bytes = out.len();
        report.cache_stats = self.cache.stats();
        Ok((out.clone(), report))
    }

    pub fn streaming_state(&self) -> StreamingJsonState {
        StreamingJsonState::default()
    }

    pub fn push_stream_chunk(
        &mut self,
        state: &mut StreamingJsonState,
        chunk: &Bytes,
        registry: &mut SecretRegistry,
    ) -> Result<Vec<u8>> {
        state.input_bytes += chunk.len();
        let mut out = Vec::with_capacity(chunk.len());
        for byte in chunk {
            if state.in_string {
                if state.escape_next {
                    state.raw_string.push(*byte);
                    state.escape_next = false;
                } else if *byte == b'\\' {
                    state.raw_string.push(*byte);
                    state.escape_next = true;
                } else if *byte == b'"' {
                    let raw_string = std::mem::take(&mut state.raw_string);
                    let context = state.complete_string_context(&raw_string)?;
                    let sanitized = match context {
                        StreamingStringContext::ObjectKey => quote_raw_json_string(&raw_string),
                        StreamingStringContext::Value { path } => self
                            .sanitize_streaming_raw_json_string(
                                &raw_string,
                                &path,
                                registry,
                                &mut state.redacted_secret_ids,
                                &mut state.unregistered_pattern_ids,
                            )?,
                    };
                    out.extend_from_slice(&sanitized);
                    state.in_string = false;
                } else {
                    state.raw_string.push(*byte);
                }
            } else if *byte == b'"' {
                state.in_string = true;
                state.escape_next = false;
                state.raw_string.clear();
            } else {
                state.observe_structural_byte(*byte);
                out.push(*byte);
            }
        }
        state.output_bytes += out.len();
        Ok(out)
    }

    pub fn finish_stream(
        &mut self,
        state: StreamingJsonState,
        _registry: &mut SecretRegistry,
    ) -> Result<(Vec<u8>, SanitizerReport)> {
        if state.in_string {
            return Err(CrebroError::Redaction(
                "unterminated JSON string in streaming sanitizer".into(),
            ));
        }
        Ok((
            Vec::new(),
            SanitizerReport {
                input_bytes: state.input_bytes,
                output_bytes: state.output_bytes,
                cache_stats: self.cache.stats(),
                redacted_secret_ids: state.redacted_secret_ids,
                unregistered_pattern_ids: state.unregistered_pattern_ids,
            },
        ))
    }

    pub fn sanitize_text_payload(
        &mut self,
        text: &str,
        registry: &mut SecretRegistry,
    ) -> Result<(String, SanitizerReport)> {
        let mut report = SanitizerReport {
            input_bytes: text.len(),
            output_bytes: 0,
            cache_stats: self.cache.stats(),
            redacted_secret_ids: Vec::new(),
            unregistered_pattern_ids: Vec::new(),
        };
        let sanitized = self.sanitize_decoded_string(
            text,
            registry,
            &mut report.redacted_secret_ids,
            &mut report.unregistered_pattern_ids,
        )?;
        report.output_bytes = sanitized.len();
        report.cache_stats = self.cache.stats();
        Ok((sanitized, report))
    }

    fn sanitize_raw_json_string(
        &mut self,
        raw_string: &[u8],
        registry: &mut SecretRegistry,
        redacted_secret_ids: &mut Vec<SecretId>,
        unregistered_pattern_ids: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let decoded = decode_raw_json_string(raw_string)?;
        self.sanitize_decoded_json_string(
            decoded,
            registry,
            redacted_secret_ids,
            unregistered_pattern_ids,
        )
    }

    fn sanitize_streaming_raw_json_string(
        &mut self,
        raw_string: &[u8],
        path: &[String],
        registry: &mut SecretRegistry,
        redacted_secret_ids: &mut Vec<SecretId>,
        unregistered_pattern_ids: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        if self.field_policy.action_for_path(path) == FieldAction::SkipKnownBinary {
            if !might_contain_directive_bytes(raw_string) {
                return Ok(quote_raw_json_string(raw_string));
            }
            let decoded = decode_raw_json_string(raw_string)?;
            return match replace_user_secret_directives(&decoded, registry, redacted_secret_ids)? {
                Some(sanitized) => serde_json::to_vec(&sanitized.text).map_err(Into::into),
                None => Ok(quote_raw_json_string(raw_string)),
            };
        }
        if registry.is_empty()
            && !self.patterns.has_credential_patterns()
            && !might_contain_directive_bytes(raw_string)
        {
            return Ok(quote_raw_json_string(raw_string));
        }
        self.sanitize_raw_json_string(
            raw_string,
            registry,
            redacted_secret_ids,
            unregistered_pattern_ids,
        )
    }

    fn sanitize_decoded_json_string(
        &mut self,
        decoded: String,
        registry: &mut SecretRegistry,
        redacted_secret_ids: &mut Vec<SecretId>,
        unregistered_pattern_ids: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let sanitized = self.sanitize_decoded_string(
            &decoded,
            registry,
            redacted_secret_ids,
            unregistered_pattern_ids,
        )?;
        serde_json::to_vec(&sanitized).map_err(Into::into)
    }

    fn sanitize_decoded_string(
        &mut self,
        decoded: &str,
        registry: &mut SecretRegistry,
        redacted_secret_ids: &mut Vec<SecretId>,
        unregistered_pattern_ids: &mut Vec<String>,
    ) -> Result<String> {
        if let Some(sanitized) =
            replace_user_secret_directives_with(decoded, registry, |text, registry| {
                let sanitized = self
                    .cache
                    .sanitize_string_detailed(text.as_bytes(), registry)?;
                redacted_secret_ids.extend(sanitized.redacted_secret_ids.iter().copied());
                Ok(sanitized.bytes)
            })?
        {
            redacted_secret_ids.extend(sanitized.secret_ids.iter().copied());
            let auto_redacted = self.auto_register_pattern_matches(&sanitized.text, registry)?;
            let sanitized_text = if auto_redacted {
                let sanitized_again = self
                    .cache
                    .sanitize_string_detailed(sanitized.text.as_bytes(), registry)?;
                redacted_secret_ids.extend(sanitized_again.redacted_secret_ids.iter().copied());
                String::from_utf8(sanitized_again.bytes).map_err(|_| {
                    CrebroError::Redaction("sanitized JSON string is not valid UTF-8".into())
                })?
            } else {
                sanitized.text
            };
            let pattern_ids = self.inspect_unregistered_patterns(&sanitized_text)?;
            unregistered_pattern_ids.extend(pattern_ids);
            return Ok(sanitized_text);
        }

        self.auto_register_pattern_matches(decoded, registry)?;
        if registry.is_empty() {
            let pattern_ids = self.inspect_unregistered_patterns(decoded)?;
            unregistered_pattern_ids.extend(pattern_ids);
            return Ok(decoded.to_string());
        }

        let sanitized = self
            .cache
            .sanitize_string_detailed(decoded.as_bytes(), registry)?;
        redacted_secret_ids.extend(sanitized.redacted_secret_ids.iter().copied());
        let text = String::from_utf8(sanitized.bytes).map_err(|_| {
            CrebroError::Redaction("sanitized JSON string is not valid UTF-8".into())
        })?;
        let pattern_ids = self.inspect_unregistered_patterns(&text)?;
        unregistered_pattern_ids.extend(pattern_ids);
        Ok(text)
    }

    fn auto_register_pattern_matches(
        &self,
        text: &str,
        registry: &mut SecretRegistry,
    ) -> Result<bool> {
        auto_register_pattern_matches(&self.patterns, text, registry)
    }

    fn sanitize_value(
        &mut self,
        value: &mut Value,
        registry: &mut SecretRegistry,
        path: &mut Vec<String>,
        report: &mut SanitizerReport,
    ) -> Result<()> {
        match value {
            Value::String(s) => {
                if self.field_policy.action_for_path(path) == FieldAction::SkipKnownBinary {
                    if let Some(sanitized) = replace_user_secret_directives(
                        s,
                        registry,
                        &mut report.redacted_secret_ids,
                    )? {
                        *s = sanitized.text;
                    }
                    return Ok(());
                }
                let sanitized = self.sanitize_decoded_string(
                    s,
                    registry,
                    &mut report.redacted_secret_ids,
                    &mut report.unregistered_pattern_ids,
                )?;
                if sanitized != *s {
                    *s = sanitized;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.sanitize_value(item, registry, path, report)?;
                }
            }
            Value::Object(map) => {
                let mut check_path = path.clone();
                if is_cacheable_object_path(path)
                    && !object_contains_skip_known_binary_field(
                        map,
                        &mut check_path,
                        &self.field_policy,
                    )
                {
                    let canonical = serde_json::to_vec(&Value::Object(map.clone()))?;
                    let sanitized = self.cache.sanitize_object_bytes(
                        &canonical,
                        registry,
                        |cache, registry| {
                            let mut object_value = Value::Object(map.clone());
                            let mut object_report = SanitizerReport::default();
                            sanitize_value_with_cache(
                                &mut object_value,
                                registry,
                                path,
                                cache,
                                &self.field_policy,
                                &self.patterns,
                                &mut object_report,
                            )?;
                            Ok(SanitizedObject {
                                bytes: serde_json::to_vec(&object_value)?,
                                redacted_secret_ids: object_report.redacted_secret_ids,
                                unregistered_pattern_ids: object_report.unregistered_pattern_ids,
                            })
                        },
                    )?;
                    report
                        .redacted_secret_ids
                        .extend(sanitized.redacted_secret_ids.iter().copied());
                    report
                        .unregistered_pattern_ids
                        .extend(sanitized.unregistered_pattern_ids.iter().cloned());
                    *value = serde_json::from_slice(&sanitized.bytes)?;
                    return Ok(());
                }

                for (key, child) in map.iter_mut() {
                    path.push(key.clone());
                    self.sanitize_value(child, registry, path, report)?;
                    path.pop();
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }

    fn inspect_unregistered_patterns(&self, text: &str) -> Result<Vec<String>> {
        let matches = self.patterns.inspect_unregistered_text(text);
        let mut allowed = Vec::new();
        for pattern_match in matches {
            match pattern_match.on_unregistered_match {
                OnUnregisteredMatch::RequireExplicitSecret => {
                    return Err(CrebroError::UnregisteredCredential {
                        pattern_id: pattern_match.id,
                    });
                }
                OnUnregisteredMatch::AutoRedact => {}
                OnUnregisteredMatch::Allow => allowed.push(pattern_match.id),
            }
        }
        Ok(allowed)
    }
}

fn sanitize_value_with_cache(
    value: &mut Value,
    registry: &mut SecretRegistry,
    path: &mut Vec<String>,
    cache: &mut RedactionCache,
    field_policy: &FieldPolicy,
    patterns: &CredentialPatternSet,
    report: &mut SanitizerReport,
) -> Result<()> {
    match value {
        Value::String(s) => {
            if field_policy.action_for_path(path) == FieldAction::SkipKnownBinary {
                if let Some(sanitized) =
                    replace_user_secret_directives(s, registry, &mut report.redacted_secret_ids)?
                {
                    *s = sanitized.text;
                }
                return Ok(());
            }
            let sanitized =
                sanitize_decoded_string_with_cache(s, registry, cache, patterns, report)?;
            if sanitized != *s {
                *s = sanitized;
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_value_with_cache(
                    item,
                    registry,
                    path,
                    cache,
                    field_policy,
                    patterns,
                    report,
                )?;
            }
        }
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                sanitize_value_with_cache(
                    child,
                    registry,
                    path,
                    cache,
                    field_policy,
                    patterns,
                    report,
                )?;
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn sanitize_decoded_string_with_cache(
    decoded: &str,
    registry: &mut SecretRegistry,
    cache: &mut RedactionCache,
    patterns: &CredentialPatternSet,
    report: &mut SanitizerReport,
) -> Result<String> {
    if let Some(sanitized) =
        replace_user_secret_directives_with(decoded, registry, |text, registry| {
            let sanitized = cache.sanitize_string_detailed(text.as_bytes(), registry)?;
            report
                .redacted_secret_ids
                .extend(sanitized.redacted_secret_ids.iter().copied());
            Ok(sanitized.bytes)
        })?
    {
        report.redacted_secret_ids.extend(sanitized.secret_ids);
        let auto_redacted = auto_register_pattern_matches(patterns, &sanitized.text, registry)?;
        let sanitized_text = if auto_redacted {
            let sanitized_again =
                cache.sanitize_string_detailed(sanitized.text.as_bytes(), registry)?;
            report
                .redacted_secret_ids
                .extend(sanitized_again.redacted_secret_ids.iter().copied());
            String::from_utf8(sanitized_again.bytes).map_err(|_| {
                CrebroError::Redaction("sanitized JSON string is not valid UTF-8".into())
            })?
        } else {
            sanitized.text
        };
        inspect_patterns(patterns, &sanitized_text, report)?;
        return Ok(sanitized_text);
    }

    auto_register_pattern_matches(patterns, decoded, registry)?;
    if registry.is_empty() {
        inspect_patterns(patterns, decoded, report)?;
        return Ok(decoded.to_string());
    }

    let sanitized = cache.sanitize_string_detailed(decoded.as_bytes(), registry)?;
    report
        .redacted_secret_ids
        .extend(sanitized.redacted_secret_ids.iter().copied());
    let text = String::from_utf8(sanitized.bytes)
        .map_err(|_| CrebroError::Redaction("sanitized JSON string is not valid UTF-8".into()))?;
    inspect_patterns(patterns, &text, report)?;
    Ok(text)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectiveText {
    text: String,
    secret_ids: Vec<SecretId>,
}

fn replace_user_secret_directives(
    decoded: &str,
    registry: &mut SecretRegistry,
    redacted_secret_ids: &mut Vec<SecretId>,
) -> Result<Option<DirectiveText>> {
    let replacement = replace_user_secret_directives_with(decoded, registry, |text, _registry| {
        Ok(text.as_bytes().to_vec())
    })?;
    if let Some(directive_text) = &replacement {
        redacted_secret_ids.extend(directive_text.secret_ids.iter().copied());
    }
    Ok(replacement)
}

fn replace_user_secret_directives_with(
    decoded: &str,
    registry: &mut SecretRegistry,
    mut sanitize_plain: impl FnMut(&str, &mut SecretRegistry) -> Result<Vec<u8>>,
) -> Result<Option<DirectiveText>> {
    let Some(replacement) = parse_user_secret_directives(decoded, registry)? else {
        return Ok(None);
    };

    let mut out = Vec::with_capacity(decoded.len());
    let mut secret_ids = Vec::new();
    for part in replacement.parts {
        match part {
            DirectivePart::Plain(text) => {
                out.extend(sanitize_plain(text, registry)?);
            }
            DirectivePart::Secret {
                placeholder,
                secret_id,
            } => {
                out.extend_from_slice(placeholder.as_bytes());
                secret_ids.push(secret_id);
            }
        }
    }

    let text = String::from_utf8(out).map_err(|_| {
        CrebroError::Redaction("sanitized directive string is not valid UTF-8".into())
    })?;
    Ok(Some(DirectiveText { text, secret_ids }))
}

fn inspect_patterns(
    patterns: &CredentialPatternSet,
    text: &str,
    report: &mut SanitizerReport,
) -> Result<()> {
    for pattern_match in patterns.inspect_unregistered_text(text) {
        match pattern_match.on_unregistered_match {
            OnUnregisteredMatch::RequireExplicitSecret => {
                return Err(CrebroError::UnregisteredCredential {
                    pattern_id: pattern_match.id,
                });
            }
            OnUnregisteredMatch::AutoRedact => {}
            OnUnregisteredMatch::Allow => report.unregistered_pattern_ids.push(pattern_match.id),
        }
    }
    Ok(())
}

fn auto_register_pattern_matches(
    patterns: &CredentialPatternSet,
    text: &str,
    registry: &mut SecretRegistry,
) -> Result<bool> {
    let matches = patterns.auto_redact_matches(text);
    let mut registered = false;
    for matched in matches {
        let Some(secret) = text.get(matched.start..matched.end) else {
            continue;
        };
        registry.ingest(
            SecretLabel::new(format!("AUTO_{}", matched.pattern_id.to_ascii_uppercase())),
            SecureBuf::from_slice(secret.as_bytes()),
        )?;
        registered = true;
    }
    Ok(registered)
}

fn is_cacheable_object_path(path: &[String]) -> bool {
    matches!(
        path.last().map(String::as_str),
        Some("tools" | "messages" | "input" | "contents" | "system_instruction")
    )
}

fn object_contains_skip_known_binary_field(
    map: &serde_json::Map<String, Value>,
    path: &mut Vec<String>,
    field_policy: &FieldPolicy,
) -> bool {
    for (key, child) in map {
        path.push(key.clone());
        let contains = value_contains_skip_known_binary_field(child, path, field_policy);
        path.pop();
        if contains {
            return true;
        }
    }
    false
}

fn value_contains_skip_known_binary_field(
    value: &Value,
    path: &mut Vec<String>,
    field_policy: &FieldPolicy,
) -> bool {
    match value {
        Value::String(_) => field_policy.action_for_path(path) == FieldAction::SkipKnownBinary,
        Value::Array(items) => items
            .iter()
            .any(|item| value_contains_skip_known_binary_field(item, path, field_policy)),
        Value::Object(map) => object_contains_skip_known_binary_field(map, path, field_policy),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

impl StreamingJsonState {
    fn observe_structural_byte(&mut self, byte: u8) {
        match byte {
            b'{' => self.begin_container(StreamingContainer::Object {
                expecting_key: true,
                pending_key: None,
            }),
            b'[' => self.begin_container(StreamingContainer::Array),
            b'}' | b']' => self.end_container(),
            b',' => {
                if let Some(StreamingFrame {
                    container:
                        StreamingContainer::Object {
                            expecting_key,
                            pending_key,
                        },
                    ..
                }) = self.stack.last_mut()
                {
                    *expecting_key = true;
                    *pending_key = None;
                }
            }
            _ => {}
        }
    }

    fn begin_container(&mut self, container: StreamingContainer) {
        let path_len_on_exit = self.path.len();
        if let Some(key) = self.take_pending_object_key() {
            self.path.push(key);
        }
        self.stack.push(StreamingFrame {
            container,
            path_len_on_exit,
        });
    }

    fn end_container(&mut self) {
        if let Some(frame) = self.stack.pop() {
            self.path.truncate(frame.path_len_on_exit);
        }
    }

    fn complete_string_context(&mut self, raw_string: &[u8]) -> Result<StreamingStringContext> {
        if self.top_object_expects_key() {
            let key = decode_raw_json_string(raw_string)?;
            if let Some(StreamingFrame {
                container:
                    StreamingContainer::Object {
                        expecting_key,
                        pending_key,
                    },
                ..
            }) = self.stack.last_mut()
            {
                *expecting_key = false;
                *pending_key = Some(key);
            }
            return Ok(StreamingStringContext::ObjectKey);
        }

        let mut path = self.path.clone();
        if let Some(key) = self.take_pending_object_key() {
            path.push(key);
        }
        Ok(StreamingStringContext::Value { path })
    }

    fn top_object_expects_key(&self) -> bool {
        matches!(
            self.stack.last(),
            Some(StreamingFrame {
                container: StreamingContainer::Object {
                    expecting_key: true,
                    ..
                },
                ..
            })
        )
    }

    fn take_pending_object_key(&mut self) -> Option<String> {
        match self.stack.last_mut() {
            Some(StreamingFrame {
                container: StreamingContainer::Object { pending_key, .. },
                ..
            }) => pending_key.take(),
            _ => None,
        }
    }
}

fn quote_raw_json_string(raw_string: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw_string.len() + 2);
    out.push(b'"');
    out.extend_from_slice(raw_string);
    out.push(b'"');
    out
}

fn decode_raw_json_string(raw_string: &[u8]) -> Result<String> {
    let quoted = quote_raw_json_string(raw_string);
    serde_json::from_slice(&quoted).map_err(Into::into)
}
