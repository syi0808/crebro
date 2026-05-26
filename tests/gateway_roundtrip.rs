use std::{
    convert::Infallible,
    io::Write,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::any,
};
use crebro::{
    cli::{Cli, infer_default_upstream_url, run_with_cli},
    gateway::{GatewayConfig, spawn_gateway},
    mode::RuntimeMode,
    process::sanitized_environment,
    secrets::{SecretId, SecretLabel, SecretRegistry, SecureBuf},
};
use futures_util::{StreamExt, stream};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock, oneshot},
};

fn unique_temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "crebro-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[derive(Clone)]
struct MockState {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    request_headers: Arc<Mutex<Vec<HeaderMap>>>,
    response: Arc<Vec<u8>>,
}

async fn mock_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.bodies.lock().await.push(body.to_vec());
    state.request_headers.lock().await.push(headers);
    (StatusCode::OK, state.response.as_ref().clone())
}

#[derive(Clone)]
struct HeaderedMockState {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    request_headers: Arc<Mutex<Vec<HeaderMap>>>,
    response: Arc<Vec<u8>>,
    response_headers: Arc<HeaderMap>,
}

async fn mock_headered_handler(
    State(state): State<HeaderedMockState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.bodies.lock().await.push(body.to_vec());
    state.request_headers.lock().await.push(headers);
    let mut response = (StatusCode::OK, state.response.as_ref().clone()).into_response();
    for (key, value) in state.response_headers.iter() {
        response.headers_mut().insert(key, value.clone());
    }
    response
}

async fn mock_echo_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.bodies.lock().await.push(body.to_vec());
    state.request_headers.lock().await.push(headers);
    (StatusCode::OK, body.to_vec())
}

async fn spawn_mock_upstream(
    response: Vec<u8>,
) -> (String, Arc<Mutex<Vec<Vec<u8>>>>, Arc<Mutex<Vec<HeaderMap>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let request_headers = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        bodies: Arc::clone(&bodies),
        request_headers: Arc::clone(&request_headers),
        response: Arc::new(response),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(mock_handler)).with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), bodies, request_headers)
}

async fn spawn_headered_mock_upstream(
    response: Vec<u8>,
    response_headers: HeaderMap,
) -> (String, Arc<Mutex<Vec<Vec<u8>>>>, Arc<Mutex<Vec<HeaderMap>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let request_headers = Arc::new(Mutex::new(Vec::new()));
    let state = HeaderedMockState {
        bodies: Arc::clone(&bodies),
        request_headers: Arc::clone(&request_headers),
        response: Arc::new(response),
        response_headers: Arc::new(response_headers),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any(mock_headered_handler))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), bodies, request_headers)
}

async fn spawn_echo_upstream() -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let request_headers = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        bodies: Arc::clone(&bodies),
        request_headers,
        response: Arc::new(Vec::new()),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any(mock_echo_handler))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), bodies)
}

async fn mock_chunked_handler(
    State(chunks): State<Arc<Vec<Vec<u8>>>>,
    _body: Bytes,
) -> impl IntoResponse {
    let chunks = (*chunks)
        .clone()
        .into_iter()
        .map(|chunk| Ok::<Bytes, Infallible>(Bytes::from(chunk)));
    (StatusCode::OK, Body::from_stream(stream::iter(chunks)))
}

async fn spawn_chunked_upstream(response_chunks: Vec<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any(mock_chunked_handler))
        .with_state(Arc::new(response_chunks));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn mock_delayed_chunked_handler(
    State(chunks): State<Arc<Vec<Vec<u8>>>>,
    _body: Bytes,
) -> impl IntoResponse {
    let chunks = (*chunks).clone();
    let stream = stream::unfold((chunks, 0usize), |(chunks, index)| async move {
        if index >= chunks.len() {
            return None;
        }
        if index > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Some((
            Ok::<Bytes, Infallible>(Bytes::from(chunks[index].clone())),
            (chunks, index + 1),
        ))
    });
    (StatusCode::OK, Body::from_stream(stream))
}

async fn spawn_delayed_chunked_upstream(response_chunks: Vec<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any(mock_delayed_chunked_handler))
        .with_state(Arc::new(response_chunks));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[derive(Clone)]
struct StreamingRequestObserver {
    first_chunk: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
}

async fn mock_streaming_request_observer_handler(
    State(state): State<StreamingRequestObserver>,
    body: Body,
) -> impl IntoResponse {
    let mut stream = body.into_data_stream();
    if let Some(Ok(chunk)) = stream.next().await
        && let Some(sender) = state.first_chunk.lock().await.take()
    {
        let _ = sender.send(chunk.to_vec());
    }
    (StatusCode::OK, "{}")
}

async fn spawn_streaming_request_observer_upstream() -> (String, oneshot::Receiver<Vec<u8>>) {
    let (sender, receiver) = oneshot::channel();
    let state = StreamingRequestObserver {
        first_chunk: Arc::new(Mutex::new(Some(sender))),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any(mock_streaming_request_observer_handler))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), receiver)
}

fn registry_with_secret() -> (SecretRegistry, SecretId, String) {
    let mut registry = SecretRegistry::with_generated_keys();
    let id = registry
        .ingest(
            SecretLabel::new("OPENAI_API_KEY"),
            SecureBuf::from_slice(b"sk-gateway-secret-1234567890"),
        )
        .unwrap();
    let placeholder = registry.placeholder_for(id).unwrap().as_str().to_string();
    (registry, id, placeholder)
}

#[test]
fn child_env_does_not_receive_provider_key() {
    let env = sanitized_environment(
        [
            (
                "OPENAI_API_KEY".to_string(),
                "sk-real-provider-key".to_string(),
            ),
            (
                "ANTHROPIC_AUTH_TOKEN".to_string(),
                "anthropic-real-provider-key".to_string(),
            ),
            (
                "OPENCODE_API_KEY".to_string(),
                "opencode-real-provider-key".to_string(),
            ),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ],
        "http://127.0.0.1:1234",
    );
    assert_eq!(
        env.get("OPENAI_API_KEY").unwrap(),
        "crebro-local-placeholder"
    );
    assert_ne!(env.get("OPENAI_API_KEY").unwrap(), "sk-real-provider-key");
    assert_eq!(
        env.get("ANTHROPIC_AUTH_TOKEN").unwrap(),
        "crebro-local-placeholder"
    );
    assert_ne!(
        env.get("ANTHROPIC_AUTH_TOKEN").unwrap(),
        "anthropic-real-provider-key"
    );
    assert_eq!(
        env.get("OPENCODE_API_KEY").unwrap(),
        "crebro-local-placeholder"
    );
    assert_ne!(
        env.get("OPENCODE_API_KEY").unwrap(),
        "opencode-real-provider-key"
    );
    assert_eq!(env.get("PATH").unwrap(), "/usr/bin");
    assert_eq!(env.get("OPENAI_BASE_URL").unwrap(), "http://127.0.0.1:1234");
    assert_eq!(
        env.get("CLAUDE_CODE_API_BASE_URL").unwrap(),
        "http://127.0.0.1:1234"
    );
    assert_eq!(
        env.get("GOOGLE_GEMINI_BASE_URL").unwrap(),
        "http://127.0.0.1:1234"
    );
}

#[tokio::test]
async fn gateway_redacts_before_upstream_and_restores_response() {
    let (registry, secret_id, placeholder) = registry_with_secret();
    let response = format!(r#"{{"echo":"{placeholder}"}}"#).into_bytes();
    let (upstream_url, bodies, request_headers) = spawn_mock_upstream(response).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: Some(secret_id),
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let client = reqwest::Client::new();
    let body = r#"{"messages":[{"role":"user","content":"use sk-gateway-secret-1234567890"}]}"#;
    let response_body = client
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    let upstream_bodies = bodies.lock().await;
    assert_eq!(upstream_bodies.len(), 1);
    let upstream_body = String::from_utf8_lossy(&upstream_bodies[0]);
    assert!(!upstream_body.contains("sk-gateway-secret-1234567890"));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:OPENAI_API_KEY:"));
    let request_headers = request_headers.lock().await;
    assert_eq!(
        request_headers[0]
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer sk-gateway-secret-1234567890")
    );
    assert!(response_body.contains("sk-gateway-secret-1234567890"));
    assert!(!response_body.contains("{{CREBRO_SECRET"));
}

#[tokio::test]
async fn gateway_redacts_user_declared_secret_before_upstream() {
    let registry = SecretRegistry::with_generated_keys();
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(
            r#"{"messages":[{"role":"user","content":"use <cb>manual-gateway-secret-1234567890</cb> and manual-gateway-secret-1234567890"}]}"#,
        )
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    tokio::time::sleep(Duration::from_millis(20)).await;
    let upstream_bodies = bodies.lock().await;
    assert_eq!(upstream_bodies.len(), 1);
    let upstream_body = String::from_utf8_lossy(&upstream_bodies[0]);
    assert!(!upstream_body.contains("manual-gateway-secret-1234567890"));
    assert!(!upstream_body.contains("<cb>"));
    assert!(!upstream_body.contains("</cb>"));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:USER:"));
}

#[tokio::test]
async fn gateway_rejects_malformed_user_secret_directive() {
    let registry = SecretRegistry::with_generated_keys();
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"use <cb>manual-gateway-secret-1234567890"}]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(bodies.lock().await.is_empty());
}

#[tokio::test]
async fn gateway_records_redaction_stats_without_raw_secret() {
    let (registry, _, placeholder) = registry_with_secret();
    let stats_dir = unique_temp_dir("redaction-stats");
    let stats_path = stats_dir.join("stats.json");
    let (upstream_url, _bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            stats_path: Some(stats_path.clone()),
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"use sk-gateway-secret-1234567890"}]}"#)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    tokio::time::sleep(Duration::from_millis(20)).await;
    let stats = std::fs::read_to_string(&stats_path).unwrap();
    assert!(stats.contains(&placeholder));
    assert!(stats.contains("OPENAI_API_KEY"));
    assert!(stats.contains("\"count\": 1"));
    assert!(!stats.contains("sk-gateway-secret-1234567890"));
}

#[tokio::test]
async fn gateway_records_unregistered_pattern_stats_on_reject() {
    let registry = SecretRegistry::with_generated_keys();
    let stats_dir = unique_temp_dir("pattern-stats");
    let stats_path = stats_dir.join("stats.json");
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            stats_path: Some(stats_path.clone()),
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let secret = "cloudflare api token abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
    let body = format!(r#"{{"messages":[{{"role":"user","content":"send {secret}"}}]}}"#);
    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(bodies.lock().await.is_empty());
    let stats = std::fs::read_to_string(&stats_path).unwrap();
    assert!(stats.contains("cloudflare_api_credential_context"));
    assert!(stats.contains("require_explicit_secret"));
    assert!(stats.contains("\"count\": 1"));
    assert!(!stats.contains(secret));
}

#[tokio::test]
async fn gateway_accepts_qa_tls_keylog_file_configuration() {
    let keylog_dir = unique_temp_dir("tls-keylog");
    std::fs::create_dir_all(&keylog_dir).unwrap();
    let keylog_path = keylog_dir.join("tls.keys");
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            tls_keylog_file: Some(keylog_path.clone()),
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(SecretRegistry::with_generated_keys())),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(keylog_path.exists());
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(bodies.lock().await.len(), 1);

    let _ = std::fs::remove_file(&keylog_path);
    let _ = std::fs::remove_dir(&keylog_dir);
}

#[tokio::test]
async fn gateway_sanitizes_json_content_type_case_insensitively() {
    let (registry, _, _) = registry_with_secret();
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "Application/JSON; charset=utf-8")
        .body(r#"{"messages":[{"role":"user","content":"use sk-gateway-secret-1234567890"}]}"#)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    tokio::time::sleep(Duration::from_millis(20)).await;
    let bodies = bodies.lock().await;
    let upstream_body = String::from_utf8_lossy(&bodies[0]);
    assert!(!upstream_body.contains("sk-gateway-secret-1234567890"));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:OPENAI_API_KEY:"));
}

#[tokio::test]
async fn gateway_strips_stale_request_content_encoding_after_json_redaction() {
    let (registry, _, _) = registry_with_secret();
    let (upstream_url, bodies, request_headers) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .header("x-local-marker", "kept")
        .body(r#"{"messages":[{"role":"user","content":"use sk-gateway-secret-1234567890"}]}"#)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    tokio::time::sleep(Duration::from_millis(20)).await;
    let bodies = bodies.lock().await;
    let upstream_body = String::from_utf8_lossy(&bodies[0]);
    assert!(!upstream_body.contains("sk-gateway-secret-1234567890"));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:OPENAI_API_KEY:"));
    let request_headers = request_headers.lock().await;
    assert!(request_headers[0].get("content-encoding").is_none());
    assert_eq!(
        request_headers[0]
            .get("x-local-marker")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
}

#[tokio::test]
async fn gateway_registers_observed_auth_header_and_invalidates_redaction_cache() {
    let registry = SecretRegistry::with_generated_keys();
    let (upstream_url, bodies, request_headers) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let client = reqwest::Client::new();
    let body = r#"{"messages":[{"role":"user","content":"use runtime-auth-secret-1234567890"}]}"#;
    let _ = client
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .bearer_auth("runtime-auth-secret-1234567890")
        .body(body)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    let upstream_bodies = bodies.lock().await;
    let upstream_body = String::from_utf8_lossy(&upstream_bodies[0]);
    assert!(!upstream_body.contains("runtime-auth-secret-1234567890"));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:AUTHORIZATION:"));
    let request_headers = request_headers.lock().await;
    assert_eq!(
        request_headers[0]
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer runtime-auth-secret-1234567890")
    );
}

#[tokio::test]
async fn gateway_registers_observed_bearer_auth_case_insensitively() {
    let registry = SecretRegistry::with_generated_keys();
    let (upstream_url, bodies, request_headers) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let secret = "runtime-lowercase-bearer-secret-1234567890";
    let body = format!(r#"{{"messages":[{{"role":"user","content":"use {secret}"}}]}}"#);
    let _ = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .header("authorization", format!("bearer    {secret}   "))
        .body(body)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    let upstream_bodies = bodies.lock().await;
    let upstream_body = String::from_utf8_lossy(&upstream_bodies[0]);
    assert!(!upstream_body.contains(secret));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:AUTHORIZATION:"));
    let request_headers = request_headers.lock().await;
    let expected_auth = format!("Bearer {secret}");
    assert_eq!(
        request_headers[0]
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(expected_auth.as_str())
    );
}

#[tokio::test]
async fn gateway_restores_placeholder_split_across_upstream_chunks() {
    let (registry, _, placeholder) = registry_with_secret();
    let split = placeholder.len() / 2;
    let upstream_url = spawn_chunked_upstream(vec![
        format!(r#"{{"echo":"{}"#, &placeholder[..split]).into_bytes(),
        format!(r#"{}"}}"#, &placeholder[split..]).into_bytes(),
    ])
    .await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let body = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[]}"#)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(body.contains("sk-gateway-secret-1234567890"));
    assert!(!body.contains("{{CREBRO_SECRET"));
}

#[tokio::test]
async fn gateway_strips_content_encoding_after_response_restore() {
    let (registry, _, placeholder) = registry_with_secret();
    let mut response_headers = HeaderMap::new();
    response_headers.insert("content-encoding", "identity".parse().unwrap());
    response_headers.insert("x-upstream-marker", "kept".parse().unwrap());
    let upstream_url = spawn_headered_mock_upstream(
        format!(r#"{{"echo":"{placeholder}"}}"#).into_bytes(),
        response_headers,
    )
    .await
    .0;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(r#"{"messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert!(response.headers().get("content-encoding").is_none());
    assert_eq!(
        response
            .headers()
            .get("x-upstream-marker")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("sk-gateway-secret-1234567890"));
    assert!(!body.contains("{{CREBRO_SECRET"));
}

#[tokio::test]
async fn gateway_streams_restored_response_before_upstream_finishes() {
    let (registry, _, placeholder) = registry_with_secret();
    let upstream_url = spawn_delayed_chunked_upstream(vec![
        format!("prefix {placeholder} suffix ").into_bytes(),
        b"tail".to_vec(),
    ])
    .await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = tokio::time::timeout(
        Duration::from_millis(500),
        reqwest::Client::new()
            .post(format!("{}/v1/chat/completions", gateway.url()))
            .header("content-type", "application/json")
            .body(r#"{"messages":[]}"#)
            .send(),
    )
    .await
    .expect("gateway should return response headers before upstream body finishes")
    .unwrap();
    let mut body_stream = response.bytes_stream();
    let first_chunk = tokio::time::timeout(Duration::from_millis(500), body_stream.next())
        .await
        .expect("gateway should stream the first restored body chunk before upstream finishes")
        .expect("response stream should yield a first chunk")
        .unwrap();
    let first_text = String::from_utf8_lossy(&first_chunk);

    assert!(first_text.contains("sk-gateway-secret-1234567890"));
    assert!(!first_text.contains("{{CREBRO_SECRET"));
}

#[tokio::test]
async fn configured_auth_uses_provider_specific_headers() {
    let cases = [
        (
            "/v1/chat/completions",
            "authorization",
            "Bearer configured-openai-secret-1234567890",
            "OPENAI_API_KEY",
            b"configured-openai-secret-1234567890".as_slice(),
        ),
        (
            "/v1/messages",
            "x-api-key",
            "configured-anthropic-secret-1234567890",
            "ANTHROPIC_API_KEY",
            b"configured-anthropic-secret-1234567890".as_slice(),
        ),
        (
            "/v1beta/models/gemini-1.5-pro:generateContent",
            "x-goog-api-key",
            "configured-gemini-secret-1234567890",
            "GEMINI_API_KEY",
            b"configured-gemini-secret-1234567890".as_slice(),
        ),
    ];

    for (path, header_name, expected_value, label, secret) in cases {
        let mut registry = SecretRegistry::with_generated_keys();
        let id = registry
            .ingest(SecretLabel::new(label), SecureBuf::from_slice(secret))
            .unwrap();
        let (upstream_url, _, request_headers) = spawn_mock_upstream(b"{}".to_vec()).await;
        let gateway = spawn_gateway(
            GatewayConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_base: upstream_url,
                provider_auth_secret: Some(id),
                cache_entries: 64,
                streaming_json_threshold_bytes: 256 * 1024,
                ..GatewayConfig::default()
            },
            Arc::new(RwLock::new(registry)),
        )
        .await
        .unwrap();

        let response = reqwest::Client::new()
            .post(format!("{}{}", gateway.url(), path))
            .header("content-type", "application/json")
            .body(r#"{"messages":[]}"#)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());

        tokio::time::sleep(Duration::from_millis(20)).await;
        let request_headers = request_headers.lock().await;
        assert_eq!(
            request_headers[0]
                .get(header_name)
                .and_then(|value| value.to_str().ok()),
            Some(expected_value)
        );
    }
}

#[tokio::test]
async fn configured_auth_uses_gemini_header_for_stable_gemini_routes() {
    let paths = [
        "/v1/models/gemini-1.5-pro:generateContent",
        "/v1/models/gemini-1.5-pro:streamGenerateContent",
        "/v1/models/gemini-1.5-pro:countTokens",
        "/v1/models/embedding-001:embedContent",
    ];

    for path in paths {
        let mut registry = SecretRegistry::with_generated_keys();
        let id = registry
            .ingest(
                SecretLabel::new("GEMINI_API_KEY"),
                SecureBuf::from_slice(b"configured-gemini-stable-secret-1234567890"),
            )
            .unwrap();
        let (upstream_url, _, request_headers) = spawn_mock_upstream(b"{}".to_vec()).await;
        let gateway = spawn_gateway(
            GatewayConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_base: upstream_url,
                provider_auth_secret: Some(id),
                cache_entries: 64,
                streaming_json_threshold_bytes: 256 * 1024,
                ..GatewayConfig::default()
            },
            Arc::new(RwLock::new(registry)),
        )
        .await
        .unwrap();

        let response = reqwest::Client::new()
            .post(format!("{}{}", gateway.url(), path))
            .header("content-type", "application/json")
            .body(r#"{"contents":[]}"#)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());

        tokio::time::sleep(Duration::from_millis(20)).await;
        let request_headers = request_headers.lock().await;
        assert_eq!(
            request_headers[0]
                .get("x-goog-api-key")
                .and_then(|value| value.to_str().ok()),
            Some("configured-gemini-stable-secret-1234567890")
        );
        assert!(request_headers[0].get("authorization").is_none());
    }
}

#[tokio::test]
async fn cli_one_shot_wrapper_returns_child_exit_status() {
    let (upstream_url, _, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let code = run_with_cli(Cli {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: Some(upstream_url),
        provider_api_key: None,
        env_file: std::env::temp_dir().join("crebro-test-missing.env"),
        patterns_file: None,
        stats_dir: Some(unique_temp_dir("cli-exit-stats")),
        tls_keylog_file: None,
        no_placeholder_guidance: false,
        mode: RuntimeMode::Native,
        command: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 7".to_string(),
        ],
    })
    .await
    .unwrap();

    assert_eq!(code, 7);
}

#[tokio::test]
async fn cli_wrapper_routes_child_request_through_gateway() {
    if std::process::Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return;
    }

    let secret = "cli-child-secret-1234567890";
    let (upstream_url, bodies) = spawn_echo_upstream().await;
    let script = format!(
        r#"
import json
import os
import sys
import urllib.request

secret = {secret:?}
url = os.environ["CREBRO_GATEWAY_URL"] + "/v1/chat/completions"
payload = json.dumps({{"messages": [{{"role": "user", "content": "use " + secret}}]}}).encode()
request = urllib.request.Request(url, data=payload, headers={{"content-type": "application/json"}}, method="POST")
body = urllib.request.urlopen(request, timeout=5).read().decode()
if secret not in body or "{{CREBRO_SECRET" in body:
    sys.exit(9)
"#
    );
    let code = run_with_cli(Cli {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: Some(upstream_url),
        provider_api_key: Some(secret.to_string()),
        env_file: std::env::temp_dir().join("crebro-test-missing.env"),
        patterns_file: None,
        stats_dir: Some(unique_temp_dir("cli-wrapper-stats")),
        tls_keylog_file: None,
        no_placeholder_guidance: false,
        mode: RuntimeMode::Native,
        command: vec!["python3".to_string(), "-c".to_string(), script],
    })
    .await
    .unwrap();

    assert_eq!(code, 0);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let bodies = bodies.lock().await;
    assert_eq!(bodies.len(), 1);
    let upstream_body = String::from_utf8_lossy(&bodies[0]);
    assert!(!upstream_body.contains(secret));
    assert!(upstream_body.contains("{{CREBRO_SECRET:v1:CREBRO_PROVIDER_API_KEY:"));
}

#[test]
fn zero_config_upstream_url_infers_supported_agent_defaults() {
    assert_eq!(
        infer_default_upstream_url(&["codex".to_string()]).unwrap(),
        "https://api.openai.com"
    );
    assert_eq!(
        infer_default_upstream_url(&["claude".to_string()]).unwrap(),
        "https://api.anthropic.com"
    );
    assert_eq!(
        infer_default_upstream_url(&["gemini".to_string()]).unwrap(),
        "https://generativelanguage.googleapis.com"
    );
    assert_eq!(
        infer_default_upstream_url(&["opencode".to_string()]).unwrap(),
        "https://api.openai.com"
    );
}

#[tokio::test]
async fn provider_schema_fixtures_redact_supported_payloads() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(
            SecretLabel::new("FIXTURE_TOKEN"),
            SecureBuf::from_slice(b"fixture-secret-1234567890"),
        )
        .unwrap();
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 128,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let client = reqwest::Client::new();
    let fixtures = [
        (
            "/v1/chat/completions",
            serde_json::json!({
                "messages": [{"role": "user", "content": "fixture-secret-1234567890"}],
                "tools": [{"name": "shell", "description": "fixture-secret-1234567890"}]
            }),
        ),
        (
            "/v1/messages",
            serde_json::json!({
                "system": "fixture-secret-1234567890",
                "messages": [{"role": "user", "content": "fixture-secret-1234567890"}],
                "tools": [{"name": "tool", "description": "fixture-secret-1234567890"}]
            }),
        ),
        (
            "/v1beta/models/gemini-1.5-pro:generateContent",
            serde_json::json!({
                "contents": [{
                    "parts": [
                        {"text": "fixture-secret-1234567890"},
                        {"inline_data": {"mime_type": "image/png", "data": "fixture-secret-1234567890"}}
                    ]
                }],
                "system_instruction": {"parts": [{"text": "fixture-secret-1234567890"}]}
            }),
        ),
    ];

    for (path, payload) in fixtures {
        let response = client
            .post(format!("{}{}", gateway.url(), path))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&payload).unwrap())
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }

    tokio::time::sleep(Duration::from_millis(20)).await;
    let bodies = bodies.lock().await;
    assert_eq!(bodies.len(), 3);
    for body in bodies.iter() {
        let body_text = String::from_utf8_lossy(body);
        assert!(body_text.contains("{{CREBRO_SECRET:v1:FIXTURE_TOKEN:"));
    }

    let gemini_body: serde_json::Value = serde_json::from_slice(&bodies[2]).unwrap();
    assert_eq!(
        gemini_body["contents"][0]["parts"][1]["inline_data"]["data"],
        "fixture-secret-1234567890"
    );
}

#[tokio::test]
async fn gateway_uses_streaming_redaction_for_large_json_body() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(
            SecretLabel::new("STREAM_GATEWAY_TOKEN"),
            SecureBuf::from_slice(b"gateway-stream-secret-1234567890"),
        )
        .unwrap();
    let (upstream_url, bodies, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 128,
            streaming_json_threshold_bytes: 1,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let payload = serde_json::json!({
        "messages": [{
            "role": "user",
            "content": format!("{} gateway-stream-secret-1234567890 {}", "x".repeat(4096), "y".repeat(4096))
        }],
        "contents": [{
            "parts": [{
                "inline_data": {
                    "mime_type": "image/png",
                    "data": "gateway-stream-secret-1234567890"
                }
            }, {
                "text": "gateway-stream-secret-1234567890"
            }]
        }]
    });
    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&payload).unwrap())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    tokio::time::sleep(Duration::from_millis(20)).await;
    let bodies = bodies.lock().await;
    let body = String::from_utf8_lossy(&bodies[0]);
    assert!(body.contains("{{CREBRO_SECRET:v1:STREAM_GATEWAY_TOKEN:"));
    let body_value: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
    assert!(
        body_value["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("{{CREBRO_SECRET:v1:STREAM_GATEWAY_TOKEN:")
    );
    assert_eq!(
        body_value["contents"][0]["parts"][0]["inline_data"]["data"],
        "gateway-stream-secret-1234567890"
    );
    assert!(
        body_value["contents"][0]["parts"][1]["text"]
            .as_str()
            .unwrap()
            .contains("{{CREBRO_SECRET:v1:STREAM_GATEWAY_TOKEN:")
    );
}

#[tokio::test]
async fn gateway_streams_sanitized_request_to_upstream_before_child_body_finishes() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(
            SecretLabel::new("STREAM_FORWARD_TOKEN"),
            SecureBuf::from_slice(b"gateway-stream-forward-secret-1234567890"),
        )
        .unwrap();
    let (upstream_url, first_chunk) = spawn_streaming_request_observer_upstream().await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 128,
            streaming_json_threshold_bytes: 1,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let request_stream = stream::unfold(0usize, |index| async move {
        match index {
            0 => Some((
                Ok::<Bytes, std::io::Error>(Bytes::from_static(br#"{"messages":[],"content":"#)),
                1,
            )),
            1 => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Some((
                    Ok(Bytes::from_static(
                        br#""gateway-stream-forward-secret-1234567890"}"#,
                    )),
                    2,
                ))
            }
            _ => None,
        }
    });

    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("{}/v1/chat/completions", gateway.url()))
            .header("content-type", "application/json")
            .body(reqwest::Body::wrap_stream(request_stream))
            .send()
            .await
    });

    let upstream_first_chunk = tokio::time::timeout(Duration::from_millis(500), first_chunk)
        .await
        .expect("upstream should receive sanitized request bytes before child body finishes")
        .unwrap();
    request.abort();

    assert_eq!(upstream_first_chunk, br#"{"messages":[],"content":"#);
}

#[derive(Clone)]
struct CapturedLogs(Arc<StdMutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogWriter(Arc::clone(&self.0))
    }
}

struct CapturedLogWriter(Arc<StdMutex<Vec<u8>>>);

impl Write for CapturedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn gateway_error_logs_do_not_include_raw_body_or_secret() {
    let raw_secret = "log-secret-1234567890";
    let logs = CapturedLogs(Arc::new(StdMutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(
            SecretLabel::new("LOG_TOKEN"),
            SecureBuf::from_slice(raw_secret.as_bytes()),
        )
        .unwrap();
    let (upstream_url, _, _) = spawn_mock_upstream(b"{}".to_vec()).await;
    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            upstream_base: upstream_url,
            provider_auth_secret: None,
            cache_entries: 64,
            streaming_json_threshold_bytes: 256 * 1024,
            ..GatewayConfig::default()
        },
        Arc::new(RwLock::new(registry)),
    )
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gateway.url()))
        .header("content-type", "application/json")
        .body(format!(r#"{{"messages":["{raw_secret}"]"#))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(response.text().await.unwrap(), "crebro gateway error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    let logs = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
    assert!(!logs.contains(raw_secret));
    assert!(!logs.contains(r#"{"messages""#));
}
