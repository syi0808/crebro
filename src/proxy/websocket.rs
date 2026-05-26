use std::{str, sync::Arc};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};

use crate::{
    CrebroError, Result, redact::JsonSanitizer, restore::ResponseRestorer, secrets::SecretRegistry,
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
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame.opcode {
        OPCODE_TEXT => {
            if frame.fin {
                let payload = restore_upstream_text(payload_ref(&frame), &registry).await?;
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
                let payload = restore_upstream_text(&payload, &registry).await?;
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
) -> Result<Vec<u8>> {
    let registry = registry.read().await;
    let mut restorer = ResponseRestorer::new(&registry)?;
    let mut out = restorer.push_chunk(payload, &registry)?;
    out.extend(restorer.finish(&registry)?);
    Ok(out)
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
