use bytes::Bytes;
use serde_json::Value;

use crate::{CrebroError, Result, secrets::SecretRegistry};

use super::{
    cache::{RedactionCache, RedactionCacheStats},
    directive::{DirectivePart, might_contain_directive_bytes, parse_user_secret_directives},
    field_policy::{FieldAction, FieldPolicy},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SanitizerReport {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub cache_stats: RedactionCacheStats,
}

#[derive(Debug)]
pub struct JsonSanitizer {
    cache: RedactionCache,
    field_policy: FieldPolicy,
}

#[derive(Default)]
pub struct StreamingJsonState {
    in_string: bool,
    escape_next: bool,
    raw_string: Vec<u8>,
    input_bytes: usize,
    output_bytes: usize,
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
        Self {
            cache: RedactionCache::new(max_cache_entries),
            field_policy: FieldPolicy,
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
        if registry.is_empty() && !might_contain_directive_bytes(body) {
            return Ok((
                body.to_vec(),
                SanitizerReport {
                    input_bytes: body.len(),
                    output_bytes: body.len(),
                    cache_stats: self.cache.stats(),
                },
            ));
        }

        let mut value: Value = serde_json::from_slice(body)?;
        self.sanitize_value(&mut value, registry, &mut Vec::new())?;
        let out = serde_json::to_vec(&value)?;
        Ok((
            out.clone(),
            SanitizerReport {
                input_bytes: body.len(),
                output_bytes: out.len(),
                cache_stats: self.cache.stats(),
            },
        ))
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
                        StreamingStringContext::Value { path } => {
                            self.sanitize_streaming_raw_json_string(&raw_string, &path, registry)?
                        }
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
            },
        ))
    }

    fn sanitize_raw_json_string(
        &mut self,
        raw_string: &[u8],
        registry: &mut SecretRegistry,
    ) -> Result<Vec<u8>> {
        let decoded = decode_raw_json_string(raw_string)?;
        self.sanitize_decoded_json_string(decoded, registry)
    }

    fn sanitize_streaming_raw_json_string(
        &mut self,
        raw_string: &[u8],
        path: &[String],
        registry: &mut SecretRegistry,
    ) -> Result<Vec<u8>> {
        if self.field_policy.action_for_path(path) == FieldAction::SkipKnownBinary {
            if !might_contain_directive_bytes(raw_string) {
                return Ok(quote_raw_json_string(raw_string));
            }
            let decoded = decode_raw_json_string(raw_string)?;
            return match replace_user_secret_directives(&decoded, registry)? {
                Some(sanitized) => serde_json::to_vec(&sanitized).map_err(Into::into),
                None => Ok(quote_raw_json_string(raw_string)),
            };
        }
        if registry.is_empty() && !might_contain_directive_bytes(raw_string) {
            return Ok(quote_raw_json_string(raw_string));
        }
        self.sanitize_raw_json_string(raw_string, registry)
    }

    fn sanitize_decoded_json_string(
        &mut self,
        decoded: String,
        registry: &mut SecretRegistry,
    ) -> Result<Vec<u8>> {
        let sanitized = self.sanitize_decoded_string(&decoded, registry)?;
        serde_json::to_vec(&sanitized).map_err(Into::into)
    }

    fn sanitize_decoded_string(
        &mut self,
        decoded: &str,
        registry: &mut SecretRegistry,
    ) -> Result<String> {
        if let Some(sanitized) =
            replace_user_secret_directives_with(decoded, registry, |text, registry| {
                self.cache.sanitize_string(text.as_bytes(), registry)
            })?
        {
            return Ok(sanitized);
        }

        if registry.is_empty() {
            return Ok(decoded.to_string());
        }

        let sanitized = self.cache.sanitize_string(decoded.as_bytes(), registry)?;
        String::from_utf8(sanitized)
            .map_err(|_| CrebroError::Redaction("sanitized JSON string is not valid UTF-8".into()))
    }

    fn sanitize_value(
        &mut self,
        value: &mut Value,
        registry: &mut SecretRegistry,
        path: &mut Vec<String>,
    ) -> Result<()> {
        match value {
            Value::String(s) => {
                if self.field_policy.action_for_path(path) == FieldAction::SkipKnownBinary {
                    if let Some(sanitized) = replace_user_secret_directives(s, registry)? {
                        *s = sanitized;
                    }
                    return Ok(());
                }
                let sanitized = self.sanitize_decoded_string(s, registry)?;
                if sanitized != *s {
                    *s = sanitized;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.sanitize_value(item, registry, path)?;
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
                            sanitize_value_with_cache(
                                &mut object_value,
                                registry,
                                path,
                                cache,
                                &self.field_policy,
                            )?;
                            serde_json::to_vec(&object_value).map_err(Into::into)
                        },
                    )?;
                    *value = serde_json::from_slice(&sanitized)?;
                    return Ok(());
                }

                for (key, child) in map.iter_mut() {
                    path.push(key.clone());
                    self.sanitize_value(child, registry, path)?;
                    path.pop();
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }
}

fn sanitize_value_with_cache(
    value: &mut Value,
    registry: &mut SecretRegistry,
    path: &mut Vec<String>,
    cache: &mut RedactionCache,
    field_policy: &FieldPolicy,
) -> Result<()> {
    match value {
        Value::String(s) => {
            if field_policy.action_for_path(path) == FieldAction::SkipKnownBinary {
                if let Some(sanitized) = replace_user_secret_directives(s, registry)? {
                    *s = sanitized;
                }
                return Ok(());
            }
            let sanitized = sanitize_decoded_string_with_cache(s, registry, cache)?;
            if sanitized != *s {
                *s = sanitized;
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_value_with_cache(item, registry, path, cache, field_policy)?;
            }
        }
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                sanitize_value_with_cache(child, registry, path, cache, field_policy)?;
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
) -> Result<String> {
    if let Some(sanitized) =
        replace_user_secret_directives_with(decoded, registry, |text, registry| {
            cache.sanitize_string(text.as_bytes(), registry)
        })?
    {
        return Ok(sanitized);
    }

    if registry.is_empty() {
        return Ok(decoded.to_string());
    }

    let sanitized = cache.sanitize_string(decoded.as_bytes(), registry)?;
    String::from_utf8(sanitized)
        .map_err(|_| CrebroError::Redaction("sanitized JSON string is not valid UTF-8".into()))
}

fn replace_user_secret_directives(
    decoded: &str,
    registry: &mut SecretRegistry,
) -> Result<Option<String>> {
    replace_user_secret_directives_with(decoded, registry, |text, _registry| {
        Ok(text.as_bytes().to_vec())
    })
}

fn replace_user_secret_directives_with(
    decoded: &str,
    registry: &mut SecretRegistry,
    mut sanitize_plain: impl FnMut(&str, &mut SecretRegistry) -> Result<Vec<u8>>,
) -> Result<Option<String>> {
    let Some(replacement) = parse_user_secret_directives(decoded, registry)? else {
        return Ok(None);
    };

    let mut out = Vec::with_capacity(decoded.len());
    for part in replacement.parts {
        match part {
            DirectivePart::Plain(text) => {
                out.extend(sanitize_plain(text, registry)?);
            }
            DirectivePart::Placeholder(placeholder) => {
                out.extend_from_slice(placeholder.as_bytes());
            }
        }
    }

    String::from_utf8(out)
        .map(Some)
        .map_err(|_| CrebroError::Redaction("sanitized directive string is not valid UTF-8".into()))
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
