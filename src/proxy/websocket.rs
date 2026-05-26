use std::{str, sync::Arc};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};

use crate::{
    CrebroError, Result, redact::JsonSanitizer, restore::PlaceholderMatcher,
    secrets::SecretRegistry,
};

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;
const MAX_TEXT_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

pub async fn relay_with_rewrite<C, U>(
    client: &mut C,
    upstream: &mut U,
    sanitizer: Arc<Mutex<JsonSanitizer>>,
    registry: Arc<RwLock<SecretRegistry>>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_text = MessageBuffer::default();
    let mut upstream_text = MessageBuffer::default();
    let mut upstream_restorer: Option<WebSocketTextRestorer> = None;

    loop {
        tokio::select! {
            frame = read_frame(client, true) => {
                let frame = match frame? {
                    Some(frame) => frame,
                    None => return Ok(()),
                };
                if handle_client_frame(
                    frame,
                    upstream,
                    Arc::clone(&sanitizer),
                    Arc::clone(&registry),
                    &mut client_text,
                ).await? {
                    return Ok(());
                }
            }
            frame = read_frame(upstream, false) => {
                let frame = match frame? {
                    Some(frame) => frame,
                    None => return Ok(()),
                };
                if handle_upstream_frame(
                    frame,
                    client,
                    Arc::clone(&registry),
                    &mut upstream_text,
                    &mut upstream_restorer,
                ).await? {
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Default)]
struct MessageBuffer {
    active_opcode: Option<u8>,
    payload: Vec<u8>,
}

async fn handle_client_frame<W>(
    frame: Frame,
    upstream: &mut W,
    sanitizer: Arc<Mutex<JsonSanitizer>>,
    registry: Arc<RwLock<SecretRegistry>>,
    buffer: &mut MessageBuffer,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame.opcode {
        OPCODE_TEXT => {
            if frame.fin {
                let payload =
                    sanitize_client_text(payload_ref(&frame), &sanitizer, &registry).await?;
                write_frame(upstream, true, OPCODE_TEXT, &payload, true).await?;
            } else {
                buffer.active_opcode = Some(OPCODE_TEXT);
                append_fragment(buffer, &frame.payload)?;
            }
        }
        OPCODE_CONTINUATION if buffer.active_opcode == Some(OPCODE_TEXT) => {
            append_fragment(buffer, &frame.payload)?;
            if frame.fin {
                let payload = std::mem::take(&mut buffer.payload);
                buffer.active_opcode = None;
                let payload = sanitize_client_text(&payload, &sanitizer, &registry).await?;
                write_frame(upstream, true, OPCODE_TEXT, &payload, true).await?;
            }
        }
        other => {
            return handle_passthrough_frame(
                Frame {
                    fin: frame.fin,
                    opcode: other,
                    payload: frame.payload,
                },
                upstream,
                true,
            )
            .await;
        }
    }
    Ok(false)
}

async fn handle_upstream_frame<W>(
    frame: Frame,
    client: &mut W,
    registry: Arc<RwLock<SecretRegistry>>,
    buffer: &mut MessageBuffer,
    restorer: &mut Option<WebSocketTextRestorer>,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame.opcode {
        OPCODE_TEXT => {
            if frame.fin {
                let payload =
                    restore_upstream_text(payload_ref(&frame), &registry, restorer).await?;
                write_frame(client, true, OPCODE_TEXT, &payload, false).await?;
            } else {
                buffer.active_opcode = Some(OPCODE_TEXT);
                append_fragment(buffer, &frame.payload)?;
            }
        }
        OPCODE_CONTINUATION if buffer.active_opcode == Some(OPCODE_TEXT) => {
            append_fragment(buffer, &frame.payload)?;
            if frame.fin {
                let payload = std::mem::take(&mut buffer.payload);
                buffer.active_opcode = None;
                let payload = restore_upstream_text(&payload, &registry, restorer).await?;
                write_frame(client, true, OPCODE_TEXT, &payload, false).await?;
            }
        }
        other => {
            return handle_passthrough_frame(
                Frame {
                    fin: frame.fin,
                    opcode: other,
                    payload: frame.payload,
                },
                client,
                false,
            )
            .await;
        }
    }
    Ok(false)
}

fn payload_ref(frame: &Frame) -> &[u8] {
    &frame.payload
}

async fn handle_passthrough_frame<W>(
    frame: Frame,
    output: &mut W,
    mask_output: bool,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame.opcode {
        OPCODE_BINARY | OPCODE_CONTINUATION => {
            write_frame(output, frame.fin, frame.opcode, &frame.payload, mask_output).await?;
        }
        OPCODE_CLOSE => {
            write_frame(output, true, OPCODE_CLOSE, &frame.payload, mask_output).await?;
            return Ok(true);
        }
        OPCODE_PING | OPCODE_PONG => {
            write_frame(output, true, frame.opcode, &frame.payload, mask_output).await?;
        }
        OPCODE_TEXT => {
            return Err(CrebroError::Gateway(
                "unexpected websocket text passthrough".into(),
            ));
        }
        _ => {
            return Err(CrebroError::Gateway(format!(
                "unsupported websocket opcode {}",
                frame.opcode
            )));
        }
    }
    Ok(false)
}

fn append_fragment(buffer: &mut MessageBuffer, payload: &[u8]) -> Result<()> {
    let new_len = buffer.payload.len().saturating_add(payload.len());
    if new_len > MAX_TEXT_MESSAGE_BYTES {
        return Err(CrebroError::Gateway(
            "websocket text message exceeded redaction buffer limit".into(),
        ));
    }
    buffer.payload.extend_from_slice(payload);
    Ok(())
}

async fn sanitize_client_text(
    payload: &[u8],
    sanitizer: &Arc<Mutex<JsonSanitizer>>,
    registry: &Arc<RwLock<SecretRegistry>>,
) -> Result<Vec<u8>> {
    let mut sanitizer = sanitizer.lock().await;
    let mut registry = registry.write().await;
    if serde_json::from_slice::<serde_json::Value>(payload).is_ok() {
        let (sanitized, _report) = sanitizer.sanitize_json(payload, &mut registry)?;
        return Ok(sanitized);
    }
    let text = str::from_utf8(payload)
        .map_err(|_| CrebroError::Gateway("websocket text frame was not UTF-8".into()))?;
    let (sanitized, _report) = sanitizer.sanitize_text_payload(text, &mut registry)?;
    Ok(sanitized.into_bytes())
}

async fn restore_upstream_text(
    payload: &[u8],
    registry: &Arc<RwLock<SecretRegistry>>,
    restorer: &mut Option<WebSocketTextRestorer>,
) -> Result<Vec<u8>> {
    let registry = registry.read().await;
    let version = registry.version();
    if restorer
        .as_ref()
        .is_none_or(|restorer| restorer.registry_version != version)
    {
        *restorer = Some(WebSocketTextRestorer::new(&registry)?);
    }
    let restorer = restorer
        .as_mut()
        .ok_or_else(|| CrebroError::Restore("missing websocket response restorer".into()))?;
    restorer.restore_payload(payload, &registry)
}

struct WebSocketTextRestorer {
    registry_version: u64,
    text_restorer: PlaceholderFragmentRestorer,
}

impl WebSocketTextRestorer {
    fn new(registry: &SecretRegistry) -> Result<Self> {
        Ok(Self {
            registry_version: registry.version(),
            text_restorer: PlaceholderFragmentRestorer::new(registry)?,
        })
    }

    fn restore_payload(&mut self, payload: &[u8], registry: &SecretRegistry) -> Result<Vec<u8>> {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(payload) {
            restore_json_text_fields(&mut value, &mut self.text_restorer, registry)?;
            return serde_json::to_vec(&value).map_err(Into::into);
        }

        let text = str::from_utf8(payload)
            .map_err(|_| CrebroError::Gateway("websocket text frame was not UTF-8".into()))?;
        Ok(self.text_restorer.push_text(text, registry)?.into_bytes())
    }
}

struct PlaceholderFragmentRestorer {
    matcher: PlaceholderMatcher,
    placeholders: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl PlaceholderFragmentRestorer {
    fn new(registry: &SecretRegistry) -> Result<Self> {
        Ok(Self {
            matcher: PlaceholderMatcher::new(registry)?,
            placeholders: registry
                .placeholders()
                .into_iter()
                .map(|(placeholder, _)| placeholder.into_bytes())
                .collect(),
            pending: Vec::new(),
        })
    }

    fn push_text(&mut self, text: &str, registry: &SecretRegistry) -> Result<String> {
        if self.placeholders.is_empty() {
            return Ok(text.to_string());
        }

        let mut combined = std::mem::take(&mut self.pending);
        combined.extend_from_slice(text.as_bytes());
        let hold_len = placeholder_prefix_suffix_len(&combined, &self.placeholders);
        let safe_len = combined.len().saturating_sub(hold_len);
        let restored = self.restore_complete_placeholders(&combined[..safe_len], registry)?;
        self.pending.extend_from_slice(&combined[safe_len..]);
        String::from_utf8(restored)
            .map_err(|_| CrebroError::Restore("restored websocket text is not UTF-8".into()))
    }

    fn restore_string_without_pending(
        &self,
        text: &str,
        registry: &SecretRegistry,
    ) -> Result<String> {
        let restored = self.restore_complete_placeholders(text.as_bytes(), registry)?;
        String::from_utf8(restored)
            .map_err(|_| CrebroError::Restore("restored websocket text is not UTF-8".into()))
    }

    fn restore_complete_placeholders(
        &self,
        bytes: &[u8],
        registry: &SecretRegistry,
    ) -> Result<Vec<u8>> {
        let matches = self.matcher.find_in(bytes);
        if matches.is_empty() {
            return Ok(bytes.to_vec());
        }

        let mut out = Vec::with_capacity(bytes.len());
        let mut cursor = 0usize;
        for mat in matches {
            if mat.start < cursor {
                continue;
            }
            out.extend_from_slice(&bytes[cursor..mat.start]);
            registry.restore_to_vec(mat.secret_id, &mut out)?;
            cursor = mat.end;
        }
        out.extend_from_slice(&bytes[cursor..]);
        Ok(out)
    }
}

fn restore_json_text_fields(
    value: &mut serde_json::Value,
    restorer: &mut PlaceholderFragmentRestorer,
    registry: &SecretRegistry,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if is_stream_text_field(key) {
                    restore_stream_text_value(child, restorer, registry)?;
                } else {
                    restore_non_stream_value(child, restorer, registry)?;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                restore_json_text_fields(item, restorer, registry)?;
            }
        }
        serde_json::Value::String(text) => {
            *text = restorer.restore_string_without_pending(text, registry)?;
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn restore_non_stream_value(
    value: &mut serde_json::Value,
    restorer: &mut PlaceholderFragmentRestorer,
    registry: &SecretRegistry,
) -> Result<()> {
    match value {
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            restore_json_text_fields(value, restorer, registry)
        }
        serde_json::Value::String(text) => {
            *text = restorer.restore_string_without_pending(text, registry)?;
            Ok(())
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Ok(())
        }
    }
}

fn restore_stream_text_value(
    value: &mut serde_json::Value,
    restorer: &mut PlaceholderFragmentRestorer,
    registry: &SecretRegistry,
) -> Result<()> {
    match value {
        serde_json::Value::String(text) => {
            *text = restorer.push_text(text, registry)?;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                restore_stream_text_value(item, restorer, registry)?;
            }
        }
        serde_json::Value::Object(map) => {
            for child in map.values_mut() {
                restore_stream_text_value(child, restorer, registry)?;
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn is_stream_text_field(key: &str) -> bool {
    matches!(
        key,
        "content" | "delta" | "text" | "output_text" | "message"
    )
}

fn placeholder_prefix_suffix_len(bytes: &[u8], placeholders: &[Vec<u8>]) -> usize {
    let mut best = 0usize;
    for placeholder in placeholders {
        let max_len = bytes.len().min(placeholder.len().saturating_sub(1));
        for len in (2..=max_len).rev() {
            if bytes[bytes.len() - len..] == placeholder[..len] {
                best = best.max(len);
                break;
            }
        }
    }
    best
}

async fn read_frame<R>(reader: &mut R, expect_masked: bool) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => {
            return Err(CrebroError::Gateway(format!(
                "failed to read websocket frame header: {err}"
            )));
        }
    }

    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if masked != expect_masked {
        return Err(CrebroError::Gateway(
            "websocket frame masking did not match direction".into(),
        ));
    }

    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await.map_err(|err| {
            CrebroError::Gateway(format!("failed to read websocket extended length: {err}"))
        })?;
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await.map_err(|err| {
            CrebroError::Gateway(format!("failed to read websocket extended length: {err}"))
        })?;
        len = u64::from_be_bytes(ext);
    }
    if len > MAX_TEXT_MESSAGE_BYTES as u64 {
        return Err(CrebroError::Gateway(
            "websocket frame exceeded maximum supported length".into(),
        ));
    }

    let mut mask = [0u8; 4];
    if masked {
        reader
            .read_exact(&mut mask)
            .await
            .map_err(|err| CrebroError::Gateway(format!("failed to read websocket mask: {err}")))?;
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await.map_err(|err| {
        CrebroError::Gateway(format!("failed to read websocket frame payload: {err}"))
    })?;
    if masked {
        apply_mask(&mut payload, mask);
    }

    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}

async fn write_frame<W>(
    writer: &mut W,
    fin: bool,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(payload.len().saturating_add(14));
    out.push(if fin { 0x80 | opcode } else { opcode });
    let mask_bit = if masked { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    if masked {
        let mut mask = [0u8; 4];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut mask)
            .map_err(|err| {
                CrebroError::Gateway(format!("failed to generate websocket mask: {err:?}"))
            })?;
        out.extend_from_slice(&mask);
        let mut masked_payload = payload.to_vec();
        apply_mask(&mut masked_payload, mask);
        out.extend_from_slice(&masked_payload);
    } else {
        out.extend_from_slice(payload);
    }

    writer
        .write_all(&out)
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to write websocket frame: {err}")))
}

fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::apply_mask;

    #[test]
    fn websocket_mask_round_trips() {
        let mask = [1, 2, 3, 4];
        let mut payload = b"hello".to_vec();
        apply_mask(&mut payload, mask);
        assert_ne!(&payload, b"hello");
        apply_mask(&mut payload, mask);
        assert_eq!(&payload, b"hello");
    }
}
