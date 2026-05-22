use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::Parser;
use crebro::gateway::provider::{ProviderFamily, infer_provider_from_path};
use serde::Serialize;
use serde_json::json;
use tokio::{net::TcpListener, sync::Mutex};

#[derive(Debug, Parser)]
#[command(
    about = "Local QA upstream that records requests and fails if forbidden canaries reach upstream"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:0")]
    listen_addr: String,

    #[arg(long = "forbid", env = "CREBRO_QA_FORBID", value_delimiter = ',')]
    forbidden: Vec<String>,

    #[arg(long, env = "CREBRO_QA_RECORD_PATH")]
    record_path: Option<PathBuf>,

    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    max_body_bytes: usize,
}

#[derive(Clone)]
struct QaState {
    forbidden: Arc<Vec<Vec<u8>>>,
    record_path: Option<PathBuf>,
    record_lock: Arc<Mutex<()>>,
    max_body_bytes: usize,
}

#[derive(Debug, Serialize)]
struct RecordedRequest {
    method: String,
    path_and_query: String,
    provider: String,
    headers: BTreeMap<String, Vec<String>>,
    body_len: usize,
    body_utf8_lossy: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let forbidden = args
        .forbidden
        .into_iter()
        .filter(|value| !value.is_empty())
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    let state = QaState {
        forbidden: Arc::new(forbidden),
        record_path: args.record_path,
        record_lock: Arc::new(Mutex::new(())),
        max_body_bytes: args.max_body_bytes,
    };

    let listener = TcpListener::bind(&args.listen_addr)
        .await
        .expect("failed to bind QA upstream");
    let addr = listener
        .local_addr()
        .expect("failed to read QA upstream address");
    println!("CREBRO_QA_UPSTREAM_URL=http://{addr}");

    let app = Router::new().fallback(any(handle)).with_state(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("QA upstream stopped with error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn handle(
    State(state): State<QaState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match to_bytes(body, state.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "crebro qa body too large").into_response();
        }
    };

    if contains_forbidden(&body, &state.forbidden) || headers_contain_forbidden(&headers, &state) {
        return (
            StatusCode::BAD_REQUEST,
            "crebro qa forbidden canary reached upstream",
        )
            .into_response();
    }

    let provider = infer_provider_from_path(uri.path());
    if let Err(err) = record_request(&state, &method, &uri, provider, &headers, &body).await {
        tracing::warn!(error = %err, "failed to record QA upstream request");
    }

    qa_response(provider, is_streaming_request(&uri, &body))
}

fn contains_forbidden(bytes: &[u8], forbidden: &[Vec<u8>]) -> bool {
    forbidden.iter().any(|needle| {
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
    })
}

fn headers_contain_forbidden(headers: &HeaderMap, state: &QaState) -> bool {
    headers.iter().any(|(name, value)| {
        !is_provider_auth_header(name) && contains_forbidden(value.as_bytes(), &state.forbidden)
    })
}

async fn record_request(
    state: &QaState,
    method: &Method,
    uri: &Uri,
    provider: ProviderFamily,
    headers: &HeaderMap,
    body: &Bytes,
) -> std::io::Result<()> {
    let Some(path) = &state.record_path else {
        return Ok(());
    };

    let record = RecordedRequest {
        method: method.to_string(),
        path_and_query: uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string(),
        provider: format!("{provider:?}"),
        headers: redacted_headers(headers),
        body_len: body.len(),
        body_utf8_lossy: String::from_utf8_lossy(body).to_string(),
    };
    let line = serde_json::to_vec(&record)
        .map_err(std::io::Error::other)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })?;

    let _guard = state.record_lock.lock().await;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &line).await
}

fn redacted_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        let value = if is_provider_auth_header(name) {
            "<redacted>".to_string()
        } else {
            value.to_str().unwrap_or("<non-utf8>").to_string()
        };
        out.entry(name.as_str().to_string())
            .or_default()
            .push(value);
    }
    out
}

fn is_provider_auth_header(name: &HeaderName) -> bool {
    *name == header::AUTHORIZATION
        || name.as_str().eq_ignore_ascii_case("x-api-key")
        || name.as_str().eq_ignore_ascii_case("api-key")
        || name.as_str().eq_ignore_ascii_case("x-goog-api-key")
        || name.as_str().eq_ignore_ascii_case("anthropic-api-key")
}

fn is_streaming_request(uri: &Uri, body: &[u8]) -> bool {
    uri.query().is_some_and(|query| query.contains("alt=sse"))
        || serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|value| json_contains_stream_true(&value))
}

fn json_contains_stream_true(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            (key == "stream" && value == &serde_json::Value::Bool(true))
                || json_contains_stream_true(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(json_contains_stream_true),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => false,
    }
}

fn qa_response(provider: ProviderFamily, streaming: bool) -> Response {
    if streaming {
        return streaming_response(provider);
    }

    let body = match provider {
        ProviderFamily::Anthropic => json!({
            "id": "msg_crebro_qa",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "crebro qa ok"}],
            "model": "crebro-qa",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 3}
        }),
        ProviderFamily::Gemini => json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "crebro qa ok"}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 3, "totalTokenCount": 4}
        }),
        ProviderFamily::OpenAi | ProviderFamily::Unknown => json!({
            "id": "chatcmpl-crebro-qa",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "crebro qa ok"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 3, "total_tokens": 4}
        }),
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn streaming_response(provider: ProviderFamily) -> Response {
    let body = match provider {
        ProviderFamily::Anthropic => concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_crebro_qa\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"crebro-qa\",\"stop_reason\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"crebro qa ok\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        )
        .to_string(),
        ProviderFamily::Gemini => {
            "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"crebro qa ok\"}]},\"finishReason\":\"STOP\"}]}\n\n".to_string()
        }
        ProviderFamily::OpenAi | ProviderFamily::Unknown => concat!(
            "data: {\"id\":\"chatcmpl-crebro-qa\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"crebro qa ok\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-crebro-qa\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        )
        .to_string(),
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{contains_forbidden, redacted_headers};

    #[test]
    fn detects_forbidden_canary_in_body_bytes() {
        assert!(contains_forbidden(
            b"prefix qa-canary-secret suffix",
            &[b"qa-canary-secret".to_vec()]
        ));
        assert!(!contains_forbidden(
            b"prefix {{CREBRO_SECRET:v1:TOKEN:x}} suffix",
            &[b"qa-canary-secret".to_vec()]
        ));
    }

    #[test]
    fn redacts_provider_auth_headers_in_records() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-real"),
        );
        headers.insert("x-goog-api-key", HeaderValue::from_static("gemini-real"));
        headers.insert("x-request-id", HeaderValue::from_static("kept"));

        let redacted = redacted_headers(&headers);
        assert_eq!(redacted["authorization"], vec!["<redacted>"]);
        assert_eq!(redacted["x-goog-api-key"], vec!["<redacted>"]);
        assert_eq!(redacted["x-request-id"], vec!["kept"]);
    }
}
