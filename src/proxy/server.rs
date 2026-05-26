use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    CrebroError, Result, gateway::tls::open_file_key_log, patterns::CredentialPatternSet,
    redact::JsonSanitizer, secrets::SecretRegistry,
};

use super::{ca::LocalCa, websocket::relay_with_rewrite};

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedStream = Box<dyn AsyncStream>;

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub allowlisted_connect_targets: Vec<String>,
    pub registry: Arc<RwLock<SecretRegistry>>,
    pub patterns: Arc<CredentialPatternSet>,
    pub cache_entries: usize,
    pub mitm: bool,
    pub upstream_tls: bool,
    pub tls_keylog_file: Option<PathBuf>,
    pub placeholder_guidance: bool,
    pub ca: Option<Arc<LocalCa>>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("listen_addr", &self.listen_addr)
            .field(
                "allowlisted_connect_targets",
                &self.allowlisted_connect_targets,
            )
            .field("cache_entries", &self.cache_entries)
            .field("mitm", &self.mitm)
            .field("upstream_tls", &self.upstream_tls)
            .field("tls_keylog_file", &self.tls_keylog_file)
            .field("placeholder_guidance", &self.placeholder_guidance)
            .field("ca_configured", &self.ca.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".to_string(),
            allowlisted_connect_targets: vec!["chatgpt.com:443".to_string()],
            registry: Arc::new(RwLock::new(SecretRegistry::with_generated_keys())),
            patterns: CredentialPatternSet::builtin(),
            cache_entries: 4096,
            mitm: true,
            upstream_tls: true,
            tls_keylog_file: None,
            placeholder_guidance: true,
            ca: None,
        }
    }
}

#[derive(Clone)]
struct ProxyState {
    allowlisted_connect_targets: Arc<HashSet<String>>,
    registry: Arc<RwLock<SecretRegistry>>,
    sanitizer: Arc<Mutex<JsonSanitizer>>,
    mitm: bool,
    upstream_tls: bool,
    upstream_key_log: Option<Arc<dyn rustls::KeyLog>>,
    ca: Option<Arc<LocalCa>>,
}

pub struct ProxyHandle {
    addr: SocketAddr,
    task: JoinHandle<()>,
    ca_bundle_path: Option<PathBuf>,
}

impl ProxyHandle {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn ca_bundle_path(&self) -> Option<&Path> {
        self.ca_bundle_path.as_deref()
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_proxy(config: ProxyConfig) -> Result<ProxyHandle> {
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to bind proxy: {err}")))?;
    let addr = listener
        .local_addr()
        .map_err(|err| CrebroError::Gateway(format!("failed to read proxy address: {err}")))?;
    let allowlisted_connect_targets = config
        .allowlisted_connect_targets
        .into_iter()
        .map(|target| target.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let ca = if config.mitm {
        Some(match config.ca {
            Some(ca) => ca,
            None => Arc::new(LocalCa::generate_session()?),
        })
    } else {
        None
    };
    let ca_bundle_path = ca.as_ref().map(|ca| ca.pem_path().clone());
    let upstream_key_log = if let Some(path) = config.tls_keylog_file.as_deref() {
        tracing::warn!("TLS key logging is enabled for Crebro proxy upstream traffic");
        Some(open_file_key_log(path)?)
    } else {
        None
    };

    tracing::warn!(
        mitm = config.mitm,
        "proxy mode is enabled for child process traffic"
    );

    let state = ProxyState {
        allowlisted_connect_targets: Arc::new(allowlisted_connect_targets),
        registry: config.registry,
        sanitizer: Arc::new(Mutex::new(
            JsonSanitizer::with_patterns_and_placeholder_guidance(
                config.cache_entries,
                config.patterns,
                config.placeholder_guidance,
            ),
        )),
        mitm: config.mitm,
        upstream_tls: config.upstream_tls,
        upstream_key_log,
        ca,
    };

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_proxy_connection(stream, state).await {
                    tracing::debug!(error = %err, "proxy connection failed");
                }
            });
        }
    });

    Ok(ProxyHandle {
        addr,
        task,
        ca_bundle_path,
    })
}

async fn handle_proxy_connection(mut client: TcpStream, state: ProxyState) -> Result<()> {
    let request = read_http_head(&mut client).await?;
    let header = std::str::from_utf8(request.head_without_delimiter())
        .map_err(|_| CrebroError::Gateway("proxy request header is not UTF-8".into()))?;
    let request_line = header
        .split("\r\n")
        .next()
        .ok_or_else(|| CrebroError::Gateway("missing proxy request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if !version.starts_with("HTTP/") {
        write_proxy_response(&mut client, 400, "Bad Request").await?;
        return Ok(());
    }

    if method != "CONNECT" {
        write_proxy_response(&mut client, 405, "Method Not Allowed").await?;
        return Ok(());
    }

    let normalized_target = target.to_ascii_lowercase();
    if !state
        .allowlisted_connect_targets
        .contains(&normalized_target)
    {
        tracing::warn!(target = %target, "proxy CONNECT target is not allowlisted");
        write_proxy_response(&mut client, 403, "Forbidden").await?;
        return Ok(());
    }

    if state.mitm {
        handle_mitm_connect(client, target, &request, state).await
    } else {
        handle_tunnel_connect(client, target, &request).await
    }
}

async fn handle_tunnel_connect(
    mut client: TcpStream,
    target: &str,
    request: &HttpHead,
) -> Result<()> {
    let mut upstream = TcpStream::connect(target)
        .await
        .map_err(|err| CrebroError::Upstream(format!("failed to connect proxy target: {err}")))?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to write CONNECT response: {err}")))?;

    if !request.extra_bytes().is_empty() {
        upstream
            .write_all(request.extra_bytes())
            .await
            .map_err(|err| {
                CrebroError::Upstream(format!("failed to forward buffered CONNECT bytes: {err}"))
            })?;
    }

    copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|err| CrebroError::Gateway(format!("proxy tunnel failed: {err}")))?;
    Ok(())
}

async fn handle_mitm_connect(
    mut client: TcpStream,
    target: &str,
    request: &HttpHead,
    state: ProxyState,
) -> Result<()> {
    if !request.extra_bytes().is_empty() {
        return Err(CrebroError::Gateway(
            "buffered bytes after CONNECT are not supported in proxy MITM mode".into(),
        ));
    }
    let host = target_host(target);
    let ca = state
        .ca
        .as_ref()
        .ok_or_else(|| CrebroError::Gateway("missing local CA for MITM proxy mode".into()))?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to write CONNECT response: {err}")))?;

    let server_config = ca.server_config_for_host(host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let mut client_tls = acceptor
        .accept(client)
        .await
        .map_err(|err| CrebroError::Gateway(format!("downstream TLS handshake failed: {err}")))?;

    let inner_request = read_http_head(&mut client_tls).await?;
    if is_websocket_upgrade(inner_request.head_without_delimiter()) {
        forward_websocket(client_tls, target, host, inner_request, state).await
    } else {
        forward_http(client_tls, target, host, inner_request, state).await
    }
}

async fn forward_websocket<C>(
    mut client: C,
    target: &str,
    host: &str,
    request: HttpHead,
    state: ProxyState,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = connect_upstream(
        target,
        host,
        state.upstream_tls,
        state.upstream_key_log.as_ref(),
    )
    .await?;
    let request_head = strip_header(request.head_without_delimiter(), "sec-websocket-extensions")?;
    upstream.write_all(&request_head).await.map_err(|err| {
        CrebroError::Upstream(format!("failed to write upstream websocket request: {err}"))
    })?;
    upstream.write_all(b"\r\n").await.map_err(|err| {
        CrebroError::Upstream(format!(
            "failed to finish upstream websocket request: {err}"
        ))
    })?;

    let response = read_http_head(&mut upstream).await?;
    let response_head = strip_header(
        response.head_without_delimiter(),
        "sec-websocket-extensions",
    )?;
    client.write_all(&response_head).await.map_err(|err| {
        CrebroError::Gateway(format!("failed to write websocket response head: {err}"))
    })?;
    client
        .write_all(b"\r\n")
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to finish response head: {err}")))?;

    if !response_is_switching_protocols(response.head_without_delimiter()) {
        if !response.extra_bytes().is_empty() {
            client
                .write_all(response.extra_bytes())
                .await
                .map_err(|err| {
                    CrebroError::Gateway(format!("failed to write upstream response bytes: {err}"))
                })?;
        }
        tokio::io::copy(&mut upstream, &mut client)
            .await
            .map_err(|err| {
                CrebroError::Gateway(format!("failed to copy upstream response: {err}"))
            })?;
        return Ok(());
    }

    if !request.extra_bytes().is_empty() || !response.extra_bytes().is_empty() {
        return Err(CrebroError::Gateway(
            "buffered websocket bytes after handshake are not supported yet".into(),
        ));
    }

    relay_with_rewrite(
        &mut client,
        &mut upstream,
        Arc::clone(&state.sanitizer),
        Arc::clone(&state.registry),
    )
    .await
}

async fn forward_http<C>(
    mut client: C,
    target: &str,
    host: &str,
    mut request: HttpHead,
    state: ProxyState,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = connect_upstream(
        target,
        host,
        state.upstream_tls,
        state.upstream_key_log.as_ref(),
    )
    .await?;
    let request_is_head = request_method_is(request.head_without_delimiter(), "HEAD");
    read_remaining_body(&mut client, &mut request).await?;
    let request = sanitize_http_request(request, &state).await?;
    upstream.write_all(&request).await.map_err(|err| {
        CrebroError::Upstream(format!("failed to forward HTTP request bytes: {err}"))
    })?;

    let mut response = read_http_head(&mut upstream).await?;
    if !response_can_have_body(request_is_head, response.head_without_delimiter()) {
        let response = http_head_only(&response);
        client.write_all(&response).await.map_err(|err| {
            CrebroError::Gateway(format!("failed to write downstream HTTP response: {err}"))
        })?;
        return Ok(());
    }
    if is_chunked_transfer(response.head_without_delimiter()) {
        if is_sse_http_body(response.head_without_delimiter())
            && !has_header(response.head_without_delimiter(), "content-encoding")
        {
            forward_sse_chunked_http_response(&mut client, &mut upstream, response, &state).await?;
        } else if is_redactable_http_body(response.head_without_delimiter())
            && !has_header(response.head_without_delimiter(), "content-encoding")
        {
            forward_chunked_http_response(&mut client, &mut upstream, response, &state).await?;
        } else {
            forward_passthrough_http_response(&mut client, &mut upstream, response).await?;
        }
        return Ok(());
    }
    read_remaining_body(&mut upstream, &mut response).await?;
    let response = restore_http_response(response, &state).await?;
    client.write_all(&response).await.map_err(|err| {
        CrebroError::Gateway(format!("failed to write downstream HTTP response: {err}"))
    })?;
    Ok(())
}

async fn read_remaining_body<R>(reader: &mut R, head: &mut HttpHead) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let content_length = content_length(head.head_without_delimiter()).unwrap_or(0);
    let buffered_body = head.extra_bytes().len();
    if content_length > buffered_body {
        let remaining = content_length - buffered_body;
        let mut body = vec![0u8; remaining];
        reader.read_exact(&mut body).await.map_err(|err| {
            CrebroError::Gateway(format!("failed to read HTTP message body: {err}"))
        })?;
        head.bytes.extend_from_slice(&body);
    }
    Ok(())
}

async fn sanitize_http_request(mut request: HttpHead, state: &ProxyState) -> Result<Vec<u8>> {
    let head = request.head_without_delimiter();
    let Some(content_length) = content_length(head) else {
        return strip_http_message_header(request, "accept-encoding");
    };
    if content_length == 0 || !is_redactable_http_body(head) {
        return strip_http_message_header(request, "accept-encoding");
    }

    let body_start = request.delimiter_start + 4;
    let body = request.bytes[body_start..].to_vec();
    let sanitized = {
        let mut sanitizer = state.sanitizer.lock().await;
        let mut registry = state.registry.write().await;
        sanitize_http_body(head, &body, &mut sanitizer, &mut registry)?
    };
    if sanitized == body && !has_header(head, "accept-encoding") {
        return Ok(request.bytes);
    }

    let head = rewrite_http_head_for_body(head, sanitized.len(), true)?;
    let mut out = head;
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&sanitized);
    request.bytes.clear();
    Ok(out)
}

fn strip_http_message_header(message: HttpHead, header_name: &str) -> Result<Vec<u8>> {
    if !has_header(message.head_without_delimiter(), header_name) {
        return Ok(message.bytes);
    }
    let mut out = strip_header(message.head_without_delimiter(), header_name)?;
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(message.extra_bytes());
    Ok(out)
}

async fn restore_http_response(mut response: HttpHead, state: &ProxyState) -> Result<Vec<u8>> {
    let head = response.head_without_delimiter();
    let Some(content_length) = content_length(head) else {
        return Ok(response.bytes);
    };
    if content_length == 0 || !is_redactable_http_body(head) {
        return Ok(response.bytes);
    }

    let body_start = response.delimiter_start + 4;
    let body = response.bytes[body_start..].to_vec();
    let restored = {
        let registry = state.registry.read().await;
        let mut restorer = crate::restore::ResponseRestorer::new(&registry)?;
        let mut out = restorer.push_chunk(&body, &registry)?;
        out.extend(restorer.finish(&registry)?);
        out
    };
    if restored == body {
        return Ok(response.bytes);
    }

    let head = rewrite_http_head_for_body(head, restored.len(), false)?;
    let mut out = head;
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&restored);
    response.bytes.clear();
    Ok(out)
}

fn sanitize_http_body(
    head: &[u8],
    body: &[u8],
    sanitizer: &mut JsonSanitizer,
    registry: &mut SecretRegistry,
) -> Result<Vec<u8>> {
    if is_json_http_body(head) {
        let (sanitized, _report) = sanitizer.sanitize_json(body, registry)?;
        return Ok(sanitized);
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| CrebroError::Gateway("HTTP text body was not UTF-8".into()))?;
    let (sanitized, _report) = sanitizer.sanitize_text_payload(text, registry)?;
    Ok(sanitized.into_bytes())
}

async fn forward_chunked_http_response<C, R>(
    client: &mut C,
    upstream: &mut R,
    response: HttpHead,
    state: &ProxyState,
) -> Result<()>
where
    C: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let head = rewrite_http_head_for_chunked(response.head_without_delimiter())?;
    client.write_all(&head).await.map_err(|err| {
        CrebroError::Gateway(format!(
            "failed to write downstream HTTP response head: {err}"
        ))
    })?;
    client.write_all(b"\r\n").await.map_err(|err| {
        CrebroError::Gateway(format!(
            "failed to finish downstream HTTP response head: {err}"
        ))
    })?;

    let registry = state.registry.read().await;
    let mut restorer = crate::restore::ResponseRestorer::new(&registry)?;
    let mut pending = response.extra_bytes().to_vec();

    loop {
        let line = read_chunk_line(upstream, &mut pending).await?;
        let chunk_len = parse_chunk_len(&line)?;
        if chunk_len == 0 {
            read_chunk_trailers(upstream, &mut pending).await?;
            let tail = restorer.finish(&registry)?;
            write_http_chunk(client, &tail).await?;
            client.write_all(b"0\r\n\r\n").await.map_err(|err| {
                CrebroError::Gateway(format!("failed to write final HTTP chunk: {err}"))
            })?;
            return Ok(());
        }

        let chunk = read_exact_pending(upstream, &mut pending, chunk_len).await?;
        let delimiter = read_exact_pending(upstream, &mut pending, 2).await?;
        if delimiter.as_slice() != b"\r\n" {
            return Err(CrebroError::Gateway(
                "invalid chunked HTTP response delimiter".into(),
            ));
        }
        let restored = restorer.push_chunk(&chunk, &registry)?;
        write_http_chunk(client, &restored).await?;
    }
}

async fn forward_sse_chunked_http_response<C, R>(
    client: &mut C,
    upstream: &mut R,
    response: HttpHead,
    state: &ProxyState,
) -> Result<()>
where
    C: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let head = rewrite_http_head_for_chunked(response.head_without_delimiter())?;
    client.write_all(&head).await.map_err(|err| {
        CrebroError::Gateway(format!(
            "failed to write downstream HTTP response head: {err}"
        ))
    })?;
    client.write_all(b"\r\n").await.map_err(|err| {
        CrebroError::Gateway(format!(
            "failed to finish downstream HTTP response head: {err}"
        ))
    })?;

    let registry = state.registry.read().await;
    let mut restorer = SseStreamRestorer::new(&registry)?;
    let mut pending = response.extra_bytes().to_vec();

    loop {
        let line = read_chunk_line(upstream, &mut pending).await?;
        let chunk_len = parse_chunk_len(&line)?;
        if chunk_len == 0 {
            read_chunk_trailers(upstream, &mut pending).await?;
            let tail = restorer.finish(&registry)?;
            write_http_chunk(client, &tail).await?;
            client.write_all(b"0\r\n\r\n").await.map_err(|err| {
                CrebroError::Gateway(format!("failed to write final HTTP chunk: {err}"))
            })?;
            return Ok(());
        }

        let chunk = read_exact_pending(upstream, &mut pending, chunk_len).await?;
        let delimiter = read_exact_pending(upstream, &mut pending, 2).await?;
        if delimiter.as_slice() != b"\r\n" {
            return Err(CrebroError::Gateway(
                "invalid chunked HTTP response delimiter".into(),
            ));
        }
        let restored = restorer.push_chunk(&chunk, &registry)?;
        write_http_chunk(client, &restored).await?;
    }
}

async fn forward_passthrough_http_response<C, R>(
    client: &mut C,
    upstream: &mut R,
    response: HttpHead,
) -> Result<()>
where
    C: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    client.write_all(&response.bytes).await.map_err(|err| {
        CrebroError::Gateway(format!("failed to write downstream HTTP response: {err}"))
    })?;
    tokio::io::copy(upstream, client)
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to copy HTTP response: {err}")))?;
    Ok(())
}

struct SseStreamRestorer {
    event_buffer: Vec<u8>,
    text_restorer: PlaceholderFragmentRestorer,
}

impl SseStreamRestorer {
    fn new(registry: &SecretRegistry) -> Result<Self> {
        Ok(Self {
            event_buffer: Vec::new(),
            text_restorer: PlaceholderFragmentRestorer::new(registry)?,
        })
    }

    fn push_chunk(&mut self, chunk: &[u8], registry: &SecretRegistry) -> Result<Vec<u8>> {
        self.event_buffer.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((event_end, separator_len)) = find_sse_event_end(&self.event_buffer) {
            let event = self.event_buffer[..event_end].to_vec();
            self.event_buffer.drain(..event_end + separator_len);
            out.extend(self.restore_event(&event, registry)?);
            out.push(b'\n');
            out.push(b'\n');
        }
        Ok(out)
    }

    fn finish(mut self, registry: &SecretRegistry) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        if !self.event_buffer.is_empty() {
            let event = std::mem::take(&mut self.event_buffer);
            out.extend(self.restore_event(&event, registry)?);
        }
        let tail = self.text_restorer.finish(registry)?;
        if !tail.is_empty() {
            out.extend_from_slice(b"\ndata: ");
            out.extend_from_slice(&serde_json::to_vec(&serde_json::json!({ "delta": tail }))?);
            out.push(b'\n');
            out.push(b'\n');
        }
        Ok(out)
    }

    fn restore_event(&mut self, event: &[u8], registry: &SecretRegistry) -> Result<Vec<u8>> {
        let text = std::str::from_utf8(event)
            .map_err(|_| CrebroError::Restore("SSE event is not UTF-8".into()))?;
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data:") {
                let had_space = data.starts_with(' ');
                let data = data.strip_prefix(' ').unwrap_or(data);
                out.push_str("data:");
                if had_space {
                    out.push(' ');
                }
                out.push_str(&self.restore_sse_data(data, registry)?);
                out.push('\n');
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if out.ends_with('\n') {
            out.pop();
        }
        Ok(out.into_bytes())
    }

    fn restore_sse_data(&mut self, data: &str, registry: &SecretRegistry) -> Result<String> {
        if data == "[DONE]" || data.trim().is_empty() {
            return Ok(data.to_string());
        }
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) else {
            return self.text_restorer.push_text(data, registry);
        };
        restore_text_fields_in_value(&mut value, &mut self.text_restorer, registry)?;
        serde_json::to_string(&value).map_err(Into::into)
    }
}

struct PlaceholderFragmentRestorer {
    matcher: crate::restore::PlaceholderMatcher,
    placeholders: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl PlaceholderFragmentRestorer {
    fn new(registry: &SecretRegistry) -> Result<Self> {
        Ok(Self {
            matcher: crate::restore::PlaceholderMatcher::new(registry)?,
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
            .map_err(|_| CrebroError::Restore("restored SSE text is not UTF-8".into()))
    }

    fn finish(mut self, registry: &SecretRegistry) -> Result<String> {
        let pending = std::mem::take(&mut self.pending);
        let restored = self.restore_complete_placeholders(&pending, registry)?;
        String::from_utf8(restored)
            .map_err(|_| CrebroError::Restore("restored SSE text is not UTF-8".into()))
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

fn restore_text_fields_in_value(
    value: &mut serde_json::Value,
    restorer: &mut PlaceholderFragmentRestorer,
    registry: &SecretRegistry,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if is_stream_text_field(key) {
                    restore_stream_field_value(child, restorer, registry)?;
                } else {
                    restore_text_fields_in_value(child, restorer, registry)?;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                restore_text_fields_in_value(item, restorer, registry)?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

fn restore_stream_field_value(
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
                match item {
                    serde_json::Value::String(text) => {
                        *text = restorer.push_text(text, registry)?;
                    }
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        restore_text_fields_in_value(item, restorer, registry)?;
                    }
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_) => {}
                }
            }
        }
        serde_json::Value::Object(_) => {
            restore_text_fields_in_value(value, restorer, registry)?;
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn is_stream_text_field(key: &str) -> bool {
    matches!(
        key,
        "content" | "delta" | "text" | "output_text" | "message" | "partial_json" | "thinking"
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

fn find_sse_event_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|window| window == b"\n\n");
    let crlf = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(lf), Some(crlf)) if crlf <= lf => Some((crlf, 4)),
        (Some(lf), _) => Some((lf, 2)),
        (None, Some(crlf)) => Some((crlf, 4)),
        (None, None) => None,
    }
}

async fn read_chunk_line<R>(reader: &mut R, pending: &mut Vec<u8>) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(pos) = pending.windows(2).position(|window| window == b"\r\n") {
            let line = pending[..pos].to_vec();
            pending.drain(..pos + 2);
            return Ok(line);
        }
        let mut buf = [0u8; 8192];
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|err| CrebroError::Gateway(format!("failed to read HTTP chunk: {err}")))?;
        if n == 0 {
            return Err(CrebroError::Gateway(
                "connection closed before chunked response completed".into(),
            ));
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

async fn read_exact_pending<R>(reader: &mut R, pending: &mut Vec<u8>, len: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    while pending.len() < len {
        let mut buf = [0u8; 8192];
        let n = reader.read(&mut buf).await.map_err(|err| {
            CrebroError::Gateway(format!("failed to read HTTP chunk body: {err}"))
        })?;
        if n == 0 {
            return Err(CrebroError::Gateway(
                "connection closed before chunked response body completed".into(),
            ));
        }
        pending.extend_from_slice(&buf[..n]);
    }
    Ok(pending.drain(..len).collect())
}

async fn read_chunk_trailers<R>(reader: &mut R, pending: &mut Vec<u8>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        if read_chunk_line(reader, pending).await?.is_empty() {
            return Ok(());
        }
    }
}

fn parse_chunk_len(line: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(line)
        .map_err(|_| CrebroError::Gateway("chunk size line is not UTF-8".into()))?;
    let size = text.split(';').next().unwrap_or_default().trim();
    usize::from_str_radix(size, 16)
        .map_err(|err| CrebroError::Gateway(format!("invalid HTTP chunk size: {err}")))
}

async fn write_http_chunk<W>(writer: &mut W, bytes: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if bytes.is_empty() {
        return Ok(());
    }
    writer
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to write HTTP chunk size: {err}")))?;
    writer
        .write_all(bytes)
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to write HTTP chunk body: {err}")))?;
    writer
        .write_all(b"\r\n")
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to finish HTTP chunk: {err}")))?;
    Ok(())
}

async fn connect_upstream(
    target: &str,
    host: &str,
    use_tls: bool,
    key_log: Option<&Arc<dyn rustls::KeyLog>>,
) -> Result<BoxedStream> {
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|err| CrebroError::Upstream(format!("failed to connect upstream: {err}")))?;
    if !use_tls {
        return Ok(Box::new(tcp));
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| CrebroError::Config(format!("invalid rustls protocol versions: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    if let Some(key_log) = key_log {
        client_config.key_log = Arc::clone(key_log);
    }
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| CrebroError::Gateway(format!("invalid upstream TLS server name: {host}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|err| CrebroError::Upstream(format!("upstream TLS handshake failed: {err}")))?;
    Ok(Box::new(tls))
}

struct HttpHead {
    bytes: Vec<u8>,
    delimiter_start: usize,
}

impl HttpHead {
    fn head_without_delimiter(&self) -> &[u8] {
        &self.bytes[..self.delimiter_start]
    }

    fn extra_bytes(&self) -> &[u8] {
        &self.bytes[self.delimiter_start + 4..]
    }
}

async fn read_http_head<R>(reader: &mut R) -> Result<HttpHead>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(4096);
    loop {
        let mut buf = [0u8; 1024];
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|err| CrebroError::Gateway(format!("failed to read HTTP head: {err}")))?;
        if n == 0 {
            return Err(CrebroError::Gateway(
                "connection closed before HTTP head completed".into(),
            ));
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > 32 * 1024 {
            return Err(CrebroError::Gateway(
                "HTTP request head exceeded proxy limit".into(),
            ));
        }
        if let Some(delimiter_start) = find_header_end(&bytes) {
            return Ok(HttpHead {
                bytes,
                delimiter_start,
            });
        }
    }
}

fn is_websocket_upgrade(head: &[u8]) -> bool {
    let Ok(head) = std::str::from_utf8(head) else {
        return false;
    };
    let mut has_upgrade = false;
    let mut has_connection_upgrade = false;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case("websocket") {
            has_upgrade = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection_upgrade = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        }
    }
    has_upgrade && has_connection_upgrade
}

fn response_is_switching_protocols(head: &[u8]) -> bool {
    std::str::from_utf8(head)
        .ok()
        .and_then(|text| text.split("\r\n").next())
        .is_some_and(|status| status.contains(" 101 "))
}

fn content_length(head: &[u8]) -> Option<usize> {
    header_value(head, "content-length").and_then(|value| value.trim().parse().ok())
}

fn is_chunked_transfer(head: &[u8]) -> bool {
    header_value(head, "transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn request_method_is(head: &[u8], expected: &str) -> bool {
    let Ok(head) = std::str::from_utf8(head) else {
        return false;
    };
    head.split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().next())
        .is_some_and(|method| method.eq_ignore_ascii_case(expected))
}

fn response_can_have_body(request_is_head: bool, head: &[u8]) -> bool {
    if request_is_head {
        return false;
    }
    let Some(status) = response_status_code(head) else {
        return true;
    };
    !(matches!(status, 100..=199) || status == 204 || status == 304)
}

fn response_status_code(head: &[u8]) -> Option<u16> {
    let head = std::str::from_utf8(head).ok()?;
    head.split("\r\n")
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn http_head_only(message: &HttpHead) -> Vec<u8> {
    let mut out = message.head_without_delimiter().to_vec();
    out.extend_from_slice(b"\r\n\r\n");
    out
}

fn is_redactable_http_body(head: &[u8]) -> bool {
    is_json_http_body(head) || is_text_http_body(head)
}

fn is_json_http_body(head: &[u8]) -> bool {
    content_type(head).is_some_and(|content_type| {
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media_type == "application/json"
            || media_type.ends_with("+json")
            || media_type == "text/json"
    })
}

fn is_text_http_body(head: &[u8]) -> bool {
    content_type(head).is_some_and(|content_type| {
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media_type.starts_with("text/") || media_type == "application/x-ndjson"
    })
}

fn is_sse_http_body(head: &[u8]) -> bool {
    content_type(head).is_some_and(|content_type| {
        content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("text/event-stream")
    })
}

fn content_type(head: &[u8]) -> Option<&str> {
    header_value(head, "content-type")
}

fn header_value<'a>(head: &'a [u8], header_name: &str) -> Option<&'a str> {
    let head = std::str::from_utf8(head).ok()?;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(header_name) {
            return Some(value.trim());
        }
    }
    None
}

fn has_header(head: &[u8], header_name: &str) -> bool {
    header_value(head, header_name).is_some()
}

fn rewrite_http_head_for_body(
    head: &[u8],
    content_length: usize,
    strip_accept_encoding: bool,
) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(head)
        .map_err(|_| CrebroError::Gateway("HTTP head is not UTF-8".into()))?;
    let mut out = String::with_capacity(text.len().saturating_add(32));
    let mut saw_content_length = false;
    for (index, line) in text.split("\r\n").enumerate() {
        if index == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        let Some((name, _value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            saw_content_length = true;
            out.push_str("content-length: ");
            out.push_str(&content_length.to_string());
            out.push_str("\r\n");
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        if strip_accept_encoding && name.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        if !strip_accept_encoding && name.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !saw_content_length {
        out.push_str("content-length: ");
        out.push_str(&content_length.to_string());
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

fn rewrite_http_head_for_chunked(head: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(head)
        .map_err(|_| CrebroError::Gateway("HTTP head is not UTF-8".into()))?;
    let mut out = String::with_capacity(text.len().saturating_add(32));
    let mut saw_transfer_encoding = false;
    for (index, line) in text.split("\r\n").enumerate() {
        if index == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        let Some((name, _value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("content-encoding")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            saw_transfer_encoding = true;
            out.push_str("transfer-encoding: chunked\r\n");
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !saw_transfer_encoding {
        out.push_str("transfer-encoding: chunked\r\n");
    }
    Ok(out.into_bytes())
}

fn strip_header(head: &[u8], strip_name: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(head)
        .map_err(|_| CrebroError::Gateway("HTTP head is not UTF-8".into()))?;
    let mut out = String::with_capacity(text.len());
    for (index, line) in text.split("\r\n").enumerate() {
        if index == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        let Some((name, _value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(strip_name) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

fn target_host(target: &str) -> &str {
    target
        .rsplit_once(':')
        .map(|(host, _port)| host.trim_matches(['[', ']']))
        .unwrap_or(target)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_proxy_response(client: &mut TcpStream, status: u16, reason: &str) -> Result<()> {
    let response = format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\n\r\n");
    client
        .write_all(response.as_bytes())
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to write proxy response: {err}")))
}

#[cfg(test)]
mod tests {
    use super::{
        content_length, find_header_end, is_websocket_upgrade, response_can_have_body,
        strip_header, target_host,
    };

    #[test]
    fn finds_proxy_header_end_at_crlfcrlf_start() {
        assert_eq!(find_header_end(b"CONNECT a:443 HTTP/1.1\r\n\r\n"), Some(22));
    }

    #[test]
    fn detects_websocket_upgrade_case_insensitively() {
        assert!(is_websocket_upgrade(
            b"GET / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket"
        ));
    }

    #[test]
    fn strips_websocket_extensions_header() {
        let stripped = strip_header(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate\r\n",
            "sec-websocket-extensions",
        )
        .unwrap();
        let stripped = String::from_utf8(stripped).unwrap();
        assert!(stripped.contains("Upgrade: websocket"));
        assert!(!stripped.contains("Sec-WebSocket-Extensions"));
    }

    #[test]
    fn extracts_connect_target_host() {
        assert_eq!(target_host("chatgpt.com:443"), "chatgpt.com");
        assert_eq!(target_host("[::1]:443"), "::1");
    }

    #[test]
    fn parses_content_length_case_insensitively() {
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\ncontent-length: 42"),
            Some(42)
        );
    }

    #[test]
    fn response_body_expectation_honors_head_and_empty_status_codes() {
        assert!(!response_can_have_body(
            true,
            b"HTTP/1.1 200 OK\r\ncontent-length: 42"
        ));
        assert!(!response_can_have_body(
            false,
            b"HTTP/1.1 204 No Content\r\ncontent-length: 42"
        ));
        assert!(!response_can_have_body(
            false,
            b"HTTP/1.1 304 Not Modified\r\ncontent-length: 42"
        ));
        assert!(response_can_have_body(
            false,
            b"HTTP/1.1 200 OK\r\ncontent-length: 42"
        ));
    }
}
