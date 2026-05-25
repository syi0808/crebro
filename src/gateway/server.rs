use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::Body as ReqwestBody;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use zeroize::Zeroize;

use crate::{
    CrebroError, Result,
    patterns::CredentialPatternSet,
    redact::JsonSanitizer,
    restore::ResponseRestorer,
    secrets::{
        SecretId, SecretLabel, SecretRegistry, SecureBuf, is_secret_candidate_with_patterns,
    },
    stats::StatsRecorder,
};

use super::{
    provider::{ProviderFamily, infer_provider_from_path},
    tls::build_upstream_client,
    upstream::join_upstream_url,
};

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub upstream_base: String,
    pub provider_auth_secret: Option<SecretId>,
    pub cache_entries: usize,
    pub streaming_json_threshold_bytes: usize,
    pub patterns: Arc<CredentialPatternSet>,
    pub stats_path: Option<PathBuf>,
    pub tls_keylog_file: Option<PathBuf>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: String::new(),
            provider_auth_secret: None,
            cache_entries: 4096,
            streaming_json_threshold_bytes: 256 * 1024,
            patterns: CredentialPatternSet::builtin(),
            stats_path: None,
            tls_keylog_file: None,
        }
    }
}

#[derive(Clone)]
struct AppState {
    registry: Arc<RwLock<SecretRegistry>>,
    sanitizer: Arc<Mutex<JsonSanitizer>>,
    upstream_base: String,
    provider_auth_secret: Option<SecretId>,
    streaming_json_threshold_bytes: usize,
    patterns: Arc<CredentialPatternSet>,
    stats: StatsRecorder,
    client: reqwest::Client,
}

pub struct GatewayHandle {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl GatewayHandle {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for GatewayHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_gateway(
    config: GatewayConfig,
    registry: Arc<RwLock<SecretRegistry>>,
) -> Result<GatewayHandle> {
    if config.upstream_base.is_empty() {
        return Err(CrebroError::Config("missing upstream base URL".into()));
    }

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|err| CrebroError::Gateway(format!("failed to bind gateway: {err}")))?;
    let addr = listener
        .local_addr()
        .map_err(|err| CrebroError::Gateway(format!("failed to read gateway address: {err}")))?;
    if config.tls_keylog_file.is_some() {
        tracing::warn!(
            "TLS key logging is enabled for Crebro upstream traffic; use only for QA and delete the key log after capture"
        );
    }
    let client = build_upstream_client(config.tls_keylog_file.as_deref())?;
    let state = AppState {
        registry,
        sanitizer: Arc::new(Mutex::new(JsonSanitizer::with_patterns(
            config.cache_entries,
            Arc::clone(&config.patterns),
        ))),
        upstream_base: config.upstream_base,
        provider_auth_secret: config.provider_auth_secret,
        streaming_json_threshold_bytes: config.streaming_json_threshold_bytes,
        patterns: config.patterns,
        stats: StatsRecorder::new(config.stats_path),
        client,
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let task = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(error = %err, "gateway server stopped with error");
        }
    });
    Ok(GatewayHandle { addr, task })
}

async fn proxy(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> std::result::Result<Response, GatewayHttpError> {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let provider = infer_provider_from_path(uri.path());
    tracing::debug!(provider = ?provider, path = uri.path(), "proxying provider request");

    let observed_auth = register_observed_auth_header(&headers, &state.registry, &state.patterns)
        .await
        .map_err(GatewayHttpError::from)?;

    let is_json_request = is_json_request(&headers);
    let sanitized = sanitize_request_body(&state, &headers, body, is_json_request)
        .await
        .map_err(|err| {
            state.stats.record_error(&err);
            GatewayHttpError::from(err)
        })?;

    let upstream_url = join_upstream_url(&state.upstream_base, path_and_query);
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|err| GatewayHttpError::bad_gateway(format!("invalid method: {err}")))?;
    let mut request = state.client.request(reqwest_method, upstream_url);
    for (key, value) in &headers {
        if should_skip_request_header(key, is_json_request) {
            continue;
        }
        request = request.header(key, value);
    }
    if let Some(secret_id) = state.provider_auth_secret {
        let mut auth = Vec::new();
        let registry = state.registry.read().await;
        registry
            .restore_to_vec(secret_id, &mut auth)
            .map_err(GatewayHttpError::from)?;
        request = apply_configured_provider_auth(provider, request, &auth)
            .map_err(GatewayHttpError::from)?;
        auth.zeroize();
    } else if let Some(observed_auth) = observed_auth {
        let mut auth = Vec::new();
        let registry = state.registry.read().await;
        registry
            .restore_to_vec(observed_auth.secret_id, &mut auth)
            .map_err(GatewayHttpError::from)?;
        request = observed_auth
            .apply(request, &auth)
            .map_err(GatewayHttpError::from)?;
        auth.zeroize();
    }
    let upstream_response = request
        .body(sanitized)
        .send()
        .await
        .map_err(GatewayHttpError::from)?;

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();
    let restored_body = restore_upstream_response_body(&state, upstream_response)
        .await
        .map_err(GatewayHttpError::from)?;

    let mut response = Response::builder().status(status);
    for (key, value) in &response_headers {
        if *key == header::CONTENT_LENGTH
            || *key == header::TRANSFER_ENCODING
            || *key == header::CONTENT_ENCODING
        {
            continue;
        }
        response = response.header(key, value);
    }
    response
        .body(restored_body)
        .map_err(|err| GatewayHttpError::bad_gateway(format!("failed to build response: {err}")))
}

fn is_json_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("application/json")
            })
        })
}

async fn sanitize_request_body(
    state: &AppState,
    headers: &HeaderMap,
    body: Body,
    is_json_request: bool,
) -> Result<ReqwestBody> {
    if is_json_request {
        sanitize_json_body(state, headers, body).await
    } else {
        Ok(stream_request_body(body))
    }
}

async fn sanitize_json_body(
    state: &AppState,
    headers: &HeaderMap,
    body: Body,
) -> Result<ReqwestBody> {
    if should_stream_json(headers, state.streaming_json_threshold_bytes) {
        sanitize_json_body_stream(state, body).await
    } else {
        let body = to_bytes(body, state.streaming_json_threshold_bytes)
            .await
            .map_err(|err| CrebroError::Gateway(format!("failed to read request body: {err}")))?;
        let mut sanitizer = state.sanitizer.lock().await;
        let mut registry = state.registry.write().await;
        let (sanitized, report) = sanitizer.sanitize_json(&body, &mut registry)?;
        state.stats.record_sanitizer_report(&registry, &report);
        Ok(ReqwestBody::from(sanitized))
    }
}

async fn restore_upstream_response_body(
    state: &AppState,
    upstream_response: reqwest::Response,
) -> Result<Body> {
    let registry = Arc::clone(&state.registry).read_owned().await;
    let restorer = ResponseRestorer::new(&registry)?;
    let upstream_stream = upstream_response.bytes_stream();
    let restored_stream = futures_util::stream::unfold(
        (upstream_stream, Some(restorer), registry, false),
        |(mut upstream_stream, mut restorer, registry, finished)| async move {
            if finished {
                return None;
            }

            loop {
                match upstream_stream.next().await {
                    Some(Ok(chunk)) => {
                        let out = {
                            let restorer = restorer.as_mut()?;
                            restorer.push_chunk(&chunk, &registry)
                        };
                        match out {
                            Ok(out) if out.is_empty() => continue,
                            Ok(out) => {
                                return Some((
                                    Ok::<Bytes, CrebroError>(Bytes::from(out)),
                                    (upstream_stream, restorer, registry, false),
                                ));
                            }
                            Err(err) => {
                                return Some((
                                    Err(err),
                                    (upstream_stream, restorer, registry, true),
                                ));
                            }
                        }
                    }
                    Some(Err(err)) => {
                        return Some((
                            Err(CrebroError::Http(err)),
                            (upstream_stream, restorer, registry, true),
                        ));
                    }
                    None => {
                        let finished_restorer = restorer.take()?;
                        match finished_restorer.finish(&registry) {
                            Ok(out) if out.is_empty() => return None,
                            Ok(out) => {
                                return Some((
                                    Ok(Bytes::from(out)),
                                    (upstream_stream, restorer, registry, true),
                                ));
                            }
                            Err(err) => {
                                return Some((
                                    Err(err),
                                    (upstream_stream, restorer, registry, true),
                                ));
                            }
                        }
                    }
                }
            }
        },
    );
    Ok(Body::from_stream(restored_stream))
}

async fn sanitize_json_body_stream(state: &AppState, body: Body) -> Result<ReqwestBody> {
    let stream = body.into_data_stream();
    let stream_state = {
        let sanitizer = state.sanitizer.lock().await;
        sanitizer.streaming_state()
    };
    let sanitizer = Arc::clone(&state.sanitizer);
    let registry = Arc::clone(&state.registry).write_owned().await;
    let stats = state.stats.clone();

    let sanitized_stream = futures_util::stream::unfold(
        (
            stream,
            sanitizer,
            registry,
            stats,
            Some(stream_state),
            false,
        ),
        |(mut stream, sanitizer, mut registry, stats, mut stream_state, finished)| async move {
            if finished {
                return None;
            }

            loop {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let state = stream_state.as_mut()?;
                        let sanitized = {
                            let mut sanitizer = sanitizer.lock().await;
                            sanitizer.push_stream_chunk(state, &chunk, &mut registry)
                        };
                        match sanitized {
                            Ok(out) if out.is_empty() => continue,
                            Ok(out) => {
                                return Some((
                                    Ok::<Bytes, CrebroError>(Bytes::from(out)),
                                    (stream, sanitizer, registry, stats, stream_state, false),
                                ));
                            }
                            Err(err) => {
                                stats.record_error(&err);
                                return Some((
                                    Err(err),
                                    (stream, sanitizer, registry, stats, stream_state, true),
                                ));
                            }
                        }
                    }
                    Some(Err(err)) => {
                        return Some((
                            Err(CrebroError::Gateway(format!(
                                "failed to read request chunk: {err}"
                            ))),
                            (stream, sanitizer, registry, stats, stream_state, true),
                        ));
                    }
                    None => {
                        let state = stream_state.take()?;
                        let finished = {
                            let mut sanitizer = sanitizer.lock().await;
                            sanitizer.finish_stream(state, &mut registry)
                        };
                        match finished {
                            Ok((tail, _report)) if tail.is_empty() => return None,
                            Ok((tail, report)) => {
                                stats.record_sanitizer_report(&registry, &report);
                                return Some((
                                    Ok(Bytes::from(tail)),
                                    (stream, sanitizer, registry, stats, stream_state, true),
                                ));
                            }
                            Err(err) => {
                                stats.record_error(&err);
                                return Some((
                                    Err(err),
                                    (stream, sanitizer, registry, stats, stream_state, true),
                                ));
                            }
                        }
                    }
                }
            }
        },
    );
    Ok(ReqwestBody::wrap_stream(sanitized_stream))
}

fn stream_request_body(body: Body) -> ReqwestBody {
    let stream = body.into_data_stream().map(|chunk| {
        chunk.map_err(|err| CrebroError::Gateway(format!("failed to read request chunk: {err}")))
    });
    ReqwestBody::wrap_stream(stream)
}

fn should_skip_request_header(key: &HeaderName, is_json_request: bool) -> bool {
    *key == header::HOST
        || *key == header::CONTENT_LENGTH
        || *key == header::TRANSFER_ENCODING
        || (is_json_request && *key == header::CONTENT_ENCODING)
        || is_provider_auth_header(key)
}

fn should_stream_json(headers: &HeaderMap, threshold: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|len| len > threshold)
}

#[derive(Debug, Clone)]
struct ObservedAuth {
    secret_id: SecretId,
    kind: ObservedAuthKind,
}

#[derive(Debug, Clone)]
enum ObservedAuthKind {
    Bearer,
    Header(HeaderName),
}

impl ObservedAuth {
    fn apply(
        &self,
        request: reqwest::RequestBuilder,
        value: &[u8],
    ) -> Result<reqwest::RequestBuilder> {
        match &self.kind {
            ObservedAuthKind::Bearer => {
                Ok(request.header(header::AUTHORIZATION, bearer_header_value(value)?))
            }
            ObservedAuthKind::Header(name) => Ok(request.header(name, secret_header_value(value)?)),
        }
    }
}

async fn register_observed_auth_header(
    headers: &HeaderMap,
    registry: &Arc<RwLock<SecretRegistry>>,
    patterns: &CredentialPatternSet,
) -> Result<Option<ObservedAuth>> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(token) = bearer_token(value)
        && is_observable_secret("AUTHORIZATION", token.as_bytes(), patterns)
    {
        let id = registry.write().await.ingest(
            SecretLabel::new("AUTHORIZATION"),
            SecureBuf::from_slice(token.as_bytes()),
        )?;
        return Ok(Some(ObservedAuth {
            secret_id: id,
            kind: ObservedAuthKind::Bearer,
        }));
    }

    for name in [
        "x-api-key",
        "api-key",
        "x-goog-api-key",
        "anthropic-api-key",
    ] {
        let Some(header_name) = HeaderName::from_lowercase(name.as_bytes()).ok() else {
            continue;
        };
        let Some(value) = headers
            .get(&header_name)
            .and_then(|value| value.to_str().ok())
        else {
            continue;
        };
        if !is_observable_secret(name, value.as_bytes(), patterns) {
            continue;
        }
        let id = registry.write().await.ingest(
            SecretLabel::new(name),
            SecureBuf::from_slice(value.as_bytes()),
        )?;
        return Ok(Some(ObservedAuth {
            secret_id: id,
            kind: ObservedAuthKind::Header(header_name),
        }));
    }

    Ok(None)
}

fn bearer_token(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let split_at = value
        .char_indices()
        .find_map(|(index, ch)| ch.is_ascii_whitespace().then_some(index))?;
    let (scheme, token) = value.split_at(split_at);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

fn is_observable_secret(label: &str, value: &[u8], patterns: &CredentialPatternSet) -> bool {
    value != b"crebro-local-placeholder"
        && is_secret_candidate_with_patterns(label, value, patterns)
}

fn is_provider_auth_header(key: &HeaderName) -> bool {
    *key == header::AUTHORIZATION
        || key.as_str().eq_ignore_ascii_case("x-api-key")
        || key.as_str().eq_ignore_ascii_case("api-key")
        || key.as_str().eq_ignore_ascii_case("x-goog-api-key")
        || key.as_str().eq_ignore_ascii_case("anthropic-api-key")
}

fn apply_configured_provider_auth(
    provider: ProviderFamily,
    request: reqwest::RequestBuilder,
    value: &[u8],
) -> Result<reqwest::RequestBuilder> {
    match provider {
        ProviderFamily::Anthropic => Ok(request.header("x-api-key", secret_header_value(value)?)),
        ProviderFamily::Gemini => Ok(request.header("x-goog-api-key", secret_header_value(value)?)),
        ProviderFamily::OpenAi | ProviderFamily::Unknown => {
            Ok(request.header(header::AUTHORIZATION, bearer_header_value(value)?))
        }
    }
}

fn bearer_header_value(value: &[u8]) -> Result<HeaderValue> {
    let mut bearer = Vec::with_capacity(b"Bearer ".len() + value.len());
    bearer.extend_from_slice(b"Bearer ");
    bearer.extend_from_slice(value);
    let header = secret_header_value(&bearer);
    bearer.zeroize();
    header
}

fn secret_header_value(value: &[u8]) -> Result<HeaderValue> {
    HeaderValue::from_bytes(value)
        .map_err(|_| CrebroError::Gateway("provider auth contains invalid header bytes".into()))
}

#[derive(Debug)]
struct GatewayHttpError {
    status: StatusCode,
    message: String,
}

impl GatewayHttpError {
    fn bad_request(message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn bad_gateway(message: String) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
        }
    }
}

impl From<CrebroError> for GatewayHttpError {
    fn from(value: CrebroError) -> Self {
        match value {
            CrebroError::Redaction(message) => Self::bad_request(message),
            CrebroError::UnregisteredCredential { .. } => Self::bad_request(value.to_string()),
            other => Self::bad_gateway(other.to_string()),
        }
    }
}

impl From<reqwest::Error> for GatewayHttpError {
    fn from(value: reqwest::Error) -> Self {
        Self::bad_gateway(value.to_string())
    }
}

impl IntoResponse for GatewayHttpError {
    fn into_response(self) -> Response {
        tracing::warn!(status = %self.status, error = %self.message, "gateway request failed");
        (self.status, "crebro gateway error").into_response()
    }
}
