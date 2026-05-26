use std::{path::PathBuf, sync::Arc};

use crebro::{
    cli::{Cli, run_with_cli},
    mode::{EffectiveMode, resolve_effective_mode},
    patterns::CredentialPatternSet,
    process::{ProxyChildEnvConfig, proxy_sanitized_environment},
    proxy::{LocalCa, ProxyConfig, spawn_proxy},
    secrets::{SecretLabel, SecretRegistry, SecureBuf},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{RwLock, oneshot},
    time::{Duration, timeout},
};
use tokio_rustls::TlsConnector;

#[test]
fn mode_selection_uses_proxy_for_codex_without_provider_key() {
    assert_eq!(
        resolve_effective_mode(&["/opt/homebrew/bin/codex".to_string()], false),
        EffectiveMode::Proxy
    );
    assert_eq!(
        resolve_effective_mode(&["codex".to_string()], true),
        EffectiveMode::Native
    );
    assert_eq!(
        resolve_effective_mode(&["claude".to_string()], false),
        EffectiveMode::Native
    );
}

#[test]
fn proxy_child_environment_sets_proxy_ca_and_strips_provider_keys() {
    let env = proxy_sanitized_environment(
        [
            ("OPENAI_API_KEY".to_string(), "sk-real".to_string()),
            (
                "OPENAI_BASE_URL".to_string(),
                "https://api.openai.com".to_string(),
            ),
            ("PATH".to_string(), "/usr/bin".to_string()),
            (
                "NO_PROXY".to_string(),
                "metadata.google.internal".to_string(),
            ),
        ],
        &ProxyChildEnvConfig {
            proxy_url: "http://127.0.0.1:54321".to_string(),
            ca_bundle_path: Some(PathBuf::from("/tmp/crebro-ca.pem")),
        },
    );

    assert_eq!(env.get("PATH").unwrap(), "/usr/bin");
    assert!(!env.contains_key("OPENAI_API_KEY"));
    assert!(!env.contains_key("OPENAI_BASE_URL"));
    assert_eq!(env.get("HTTPS_PROXY").unwrap(), "http://127.0.0.1:54321");
    assert_eq!(env.get("HTTP_PROXY").unwrap(), "http://127.0.0.1:54321");
    assert_eq!(env.get("https_proxy").unwrap(), "http://127.0.0.1:54321");
    assert_eq!(env.get("http_proxy").unwrap(), "http://127.0.0.1:54321");
    assert_eq!(env.get("NODE_USE_ENV_PROXY").unwrap(), "1");
    assert_eq!(env.get("SSL_CERT_FILE").unwrap(), "/tmp/crebro-ca.pem");
    assert_eq!(
        env.get("NODE_EXTRA_CA_CERTS").unwrap(),
        "/tmp/crebro-ca.pem"
    );
    assert_eq!(env.get("REQUESTS_CA_BUNDLE").unwrap(), "/tmp/crebro-ca.pem");
    assert_eq!(env.get("CURL_CA_BUNDLE").unwrap(), "/tmp/crebro-ca.pem");
    assert_eq!(env.get("GIT_SSL_CAINFO").unwrap(), "/tmp/crebro-ca.pem");
    assert_eq!(env.get("DENO_CERT").unwrap(), "/tmp/crebro-ca.pem");
    assert_eq!(
        env.get("CREBRO_PROXY_URL").unwrap(),
        "http://127.0.0.1:54321"
    );
    let no_proxy = env.get("NO_PROXY").unwrap();
    assert!(no_proxy.contains("metadata.google.internal"));
    assert!(no_proxy.contains("localhost"));
    assert!(no_proxy.contains("127.0.0.1"));
    assert!(no_proxy.contains("::1"));
}

#[tokio::test]
async fn proxy_rejects_non_allowlisted_connect_target() {
    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec!["chatgpt.com:443".to_string()],
        ..ProxyConfig::default()
    })
    .await
    .unwrap();
    let mut stream = TcpStream::connect(proxy.url().trim_start_matches("http://"))
        .await
        .unwrap();

    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nhost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let response = read_http_response_head(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
}

#[tokio::test]
async fn proxy_tunnels_allowlisted_connect_target() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut upstream, _) = upstream_listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        upstream.read_exact(&mut buf).await.unwrap();
        seen_tx.send(buf).unwrap();
        upstream.write_all(b"pong").await.unwrap();
    });

    let target = upstream_addr.to_string();
    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        mitm: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();
    let mut stream = TcpStream::connect(proxy.url().trim_start_matches("http://"))
        .await
        .unwrap();

    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = read_http_response_head(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200 Connection Established"));

    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(seen_rx.await.unwrap(), *b"ping");
    assert_eq!(&response, b"pong");
}

#[tokio::test]
async fn cli_proxy_mode_runs_child_with_proxy_environment_without_upstream_url() {
    let codex = codex_shell_shim("proxy-child-env");
    let code = run_with_cli(Cli {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: None,
        provider_api_key: None,
        env_file: std::env::temp_dir().join("crebro-test-missing.env"),
        patterns_file: None,
        stats_dir: None,
        tls_keylog_file: None,
        no_placeholder_guidance: false,
        command: vec![
            codex.to_string_lossy().to_string(),
            "-c".to_string(),
            r#"test -n "$HTTPS_PROXY" && test "$HTTPS_PROXY" = "$CREBRO_PROXY_URL""#.to_string(),
        ],
    })
    .await
    .unwrap();

    assert_eq!(code, 0);
}

#[tokio::test]
async fn cli_proxy_mode_accepts_upstream_tls_keylog_file_configuration() {
    let keylog_dir = unique_temp_dir("proxy-tls-keylog");
    std::fs::create_dir_all(&keylog_dir).unwrap();
    let keylog_path = keylog_dir.join("tls.keys");
    let codex = codex_shell_shim("proxy-tls-keylog-child");
    let code = run_with_cli(Cli {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: None,
        provider_api_key: None,
        env_file: std::env::temp_dir().join("crebro-test-missing.env"),
        patterns_file: None,
        stats_dir: None,
        tls_keylog_file: Some(keylog_path.clone()),
        no_placeholder_guidance: false,
        command: vec![
            codex.to_string_lossy().to_string(),
            "-c".to_string(),
            "true".to_string(),
        ],
    })
    .await
    .unwrap();

    assert_eq!(code, 0);
    assert!(keylog_path.exists());

    let _ = std::fs::remove_file(&keylog_path);
    let _ = std::fs::remove_dir(&keylog_dir);
}

#[tokio::test]
async fn proxy_mitm_websocket_redacts_request_and_restores_response() {
    let secret = "ws-secret-1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let secret_id = registry
        .ingest(
            SecretLabel::new("WS_SECRET"),
            SecureBuf::from_slice(secret.as_bytes()),
        )
        .unwrap();
    let placeholder = registry
        .placeholder_for(secret_id)
        .unwrap()
        .as_str()
        .to_string();
    let registry = Arc::new(RwLock::new(registry));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let expected_placeholder = placeholder.clone();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let request = read_http_response_head(&mut stream).await;
        assert!(request.starts_with("GET /backend-api/test HTTP/1.1"));
        assert!(
            !request
                .to_ascii_lowercase()
                .contains("sec-websocket-extensions")
        );
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: test\r\n\
                  Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            )
            .await
            .unwrap();

        let frame = read_ws_frame(&mut stream, true).await;
        let text = String::from_utf8(frame).unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains("Crebro replaced local secrets with safe placeholders"));
        assert!(text.contains("{{CREBRO_SECRET:v1:WS_SECRET:"));

        let response = format!(r#"{{"restored":"{expected_placeholder}"}}"#);
        write_ws_frame(&mut stream, response.as_bytes(), false)
            .await
            .unwrap();
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(proxy.url().trim_start_matches("http://"))
        .await
        .unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let connect_response = read_http_response_head(&mut tcp).await;
    assert!(connect_response.starts_with("HTTP/1.1 200 Connection Established"));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.root_der()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(
        format!(
            "GET /backend-api/test HTTP/1.1\r\n\
             Host: {target}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: test\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let response = read_http_response_head(&mut tls).await;
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));
    assert!(
        !response
            .to_ascii_lowercase()
            .contains("sec-websocket-extensions")
    );

    write_ws_frame(
        &mut tls,
        format!(r#"{{"prompt":"use {secret}"}}"#).as_bytes(),
        true,
    )
    .await
    .unwrap();
    let restored = read_ws_frame(&mut tls, false).await;
    let restored = String::from_utf8(restored).unwrap();
    assert!(restored.contains(secret));
    assert!(!restored.contains("{{CREBRO_SECRET"));

    upstream.await.unwrap();
}

#[tokio::test]
async fn proxy_mitm_websocket_restores_placeholder_split_across_json_delta_messages() {
    let secret = "ws-delta-secret-1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let secret_id = registry
        .ingest(
            SecretLabel::new("WS_DELTA_SECRET"),
            SecureBuf::from_slice(secret.as_bytes()),
        )
        .unwrap();
    let placeholder = registry
        .placeholder_for(secret_id)
        .unwrap()
        .as_str()
        .to_string();
    let registry = Arc::new(RwLock::new(registry));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let request = read_http_response_head(&mut stream).await;
        assert!(request.starts_with("GET /backend-api/test HTTP/1.1"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: test\r\n\r\n",
            )
            .await
            .unwrap();

        let frame = read_ws_frame(&mut stream, true).await;
        let text = String::from_utf8(frame).unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains("{{CREBRO_SECRET:v1:WS_DELTA_SECRET:"));

        let split = placeholder.len() / 2;
        let first = format!(
            r#"{{"type":"delta","delta":"curl -H 'Authorization: Bearer {}"}}"#,
            &placeholder[..split]
        );
        let second = format!(r#"{{"type":"delta","delta":"{}'"}}"#, &placeholder[split..]);
        write_ws_frame(&mut stream, first.as_bytes(), false)
            .await
            .unwrap();
        write_ws_frame(&mut stream, second.as_bytes(), false)
            .await
            .unwrap();
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tls = connect_tls_through_proxy(&proxy.url(), &target, &ca).await;
    tls.write_all(
        format!(
            "GET /backend-api/test HTTP/1.1\r\n\
             Host: {target}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: test\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let response = read_http_response_head(&mut tls).await;
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

    write_ws_frame(
        &mut tls,
        format!(r#"{{"prompt":"use {secret}"}}"#).as_bytes(),
        true,
    )
    .await
    .unwrap();
    let first = String::from_utf8(read_ws_frame(&mut tls, false).await).unwrap();
    let second = String::from_utf8(read_ws_frame(&mut tls, false).await).unwrap();
    let combined = format!("{first}{second}");
    assert!(combined.contains(secret));
    assert!(!combined.contains("{{CREBRO_SECRET"));

    upstream.await.unwrap();
}

#[tokio::test]
async fn proxy_mitm_websocket_auto_redacts_cloudflare_user_token() {
    let cloudflare_token = "cfut_9hfLomXE30g151Zm1HoX6OmDm5pao1C1zsNhlQeA5cfcd85f";
    let registry = Arc::new(RwLock::new(SecretRegistry::with_generated_keys()));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let (payload_tx, payload_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let request = read_http_response_head(&mut stream).await;
        assert!(request.starts_with("GET /backend-api/test HTTP/1.1"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: test\r\n\r\n",
            )
            .await
            .unwrap();

        let frame = timeout(Duration::from_millis(300), read_ws_frame(&mut stream, true))
            .await
            .unwrap();
        payload_tx.send(String::from_utf8(frame).unwrap()).unwrap();
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(proxy.url().trim_start_matches("http://"))
        .await
        .unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let connect_response = read_http_response_head(&mut tcp).await;
    assert!(connect_response.starts_with("HTTP/1.1 200 Connection Established"));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.root_der()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(
        format!(
            "GET /backend-api/test HTTP/1.1\r\n\
             Host: {target}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: test\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let response = read_http_response_head(&mut tls).await;
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

    write_ws_frame(
        &mut tls,
        format!(r#"{{"prompt":"use {cloudflare_token}"}}"#).as_bytes(),
        true,
    )
    .await
    .unwrap();

    let forwarded_payload = payload_rx.await.unwrap();
    assert!(!forwarded_payload.contains(cloudflare_token));
    assert!(forwarded_payload.contains("Crebro replaced local secrets with safe placeholders"));
    assert!(forwarded_payload.contains("{{CREBRO_SECRET:v1:AUTO_CLOUDFLARE_USER_TOKEN:"));
    upstream.await.unwrap();
}

#[tokio::test]
async fn proxy_mitm_http_json_redacts_request_and_restores_response() {
    let secret = "http-secret-1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let secret_id = registry
        .ingest(
            SecretLabel::new("HTTP_SECRET"),
            SecureBuf::from_slice(secret.as_bytes()),
        )
        .unwrap();
    let placeholder = registry
        .placeholder_for(secret_id)
        .unwrap()
        .as_str()
        .to_string();
    let registry = Arc::new(RwLock::new(registry));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let expected_placeholder = placeholder.clone();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let (head, body) = read_http_message(&mut stream).await;
        assert!(head.starts_with("POST /backend-api/http HTTP/1.1"));
        assert!(!head.to_ascii_lowercase().contains("accept-encoding"));
        let body = String::from_utf8(body).unwrap();
        assert!(body.starts_with('{'));
        assert!(!body.contains(secret));
        assert!(body.contains("{{CREBRO_SECRET:v1:HTTP_SECRET:"));

        let response = format!(r#"{{"restored":"{expected_placeholder}"}}"#);
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    response.len(),
                    response
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tls = connect_tls_through_proxy(&proxy.url(), &target, &ca).await;
    let body = format!(r#"{{"prompt":"use {secret}"}}"#);
    tls.write_all(
        format!(
            "POST /backend-api/http HTTP/1.1\r\n\
             Host: {target}\r\n\
             content-type: application/json\r\n\
             accept-encoding: gzip\r\n\
             content-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let (_head, body) = read_http_message(&mut tls).await;
    let body = String::from_utf8(body).unwrap();
    assert!(body.starts_with('{'));
    assert!(body.contains(secret));
    assert!(!body.contains("{{CREBRO_SECRET"));

    upstream.await.unwrap();
}

#[tokio::test]
async fn proxy_mitm_chunked_http_response_restores_placeholders_across_chunks() {
    let secret = "chunked-secret-1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let secret_id = registry
        .ingest(
            SecretLabel::new("CHUNKED_SECRET"),
            SecureBuf::from_slice(secret.as_bytes()),
        )
        .unwrap();
    let placeholder = registry
        .placeholder_for(secret_id)
        .unwrap()
        .as_str()
        .to_string();
    let registry = Arc::new(RwLock::new(registry));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let (head, body) = read_http_message(&mut stream).await;
        assert!(head.starts_with("POST /backend-api/sse HTTP/1.1"));
        assert!(!head.to_ascii_lowercase().contains("accept-encoding"));
        let body = String::from_utf8(body).unwrap();
        assert!(!body.contains(secret));
        assert!(body.contains("{{CREBRO_SECRET:v1:CHUNKED_SECRET:"));

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        let split = placeholder.len() / 2;
        write_http_chunk(
            &mut stream,
            format!("data: {{\"delta\":\"curl {}", &placeholder[..split]).as_bytes(),
        )
        .await
        .unwrap();
        write_http_chunk(
            &mut stream,
            format!("{}\"}}\n\n", &placeholder[split..]).as_bytes(),
        )
        .await
        .unwrap();
        stream.write_all(b"0\r\n\r\n").await.unwrap();
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tls = connect_tls_through_proxy(&proxy.url(), &target, &ca).await;
    let body = format!(r#"{{"prompt":"use {secret}"}}"#);
    tls.write_all(
        format!(
            "POST /backend-api/sse HTTP/1.1\r\n\
             Host: {target}\r\n\
             content-type: application/json\r\n\
             accept-encoding: gzip\r\n\
             content-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let (_head, body) = read_http_chunked_message(&mut tls).await;
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains(secret));
    assert!(!body.contains("{{CREBRO_SECRET"));

    upstream.await.unwrap();
}

#[tokio::test]
async fn proxy_mitm_sse_response_restores_placeholder_split_across_delta_events() {
    let secret = "sse-secret-1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let secret_id = registry
        .ingest(
            SecretLabel::new("SSE_SECRET"),
            SecureBuf::from_slice(secret.as_bytes()),
        )
        .unwrap();
    let placeholder = registry
        .placeholder_for(secret_id)
        .unwrap()
        .as_str()
        .to_string();
    let registry = Arc::new(RwLock::new(registry));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let (head, body) = read_http_message(&mut stream).await;
        assert!(head.starts_with("POST /backend-api/sse-delta HTTP/1.1"));
        assert!(!head.to_ascii_lowercase().contains("accept-encoding"));
        let body = String::from_utf8(body).unwrap();
        assert!(!body.contains(secret));

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        let split = placeholder.len() / 2;
        write_http_chunk(
            &mut stream,
            format!(
                "data: {{\"type\":\"delta\",\"delta\":\"curl -H 'Authorization: Bearer {}\"}}\n\n",
                &placeholder[..split]
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        write_http_chunk(
            &mut stream,
            format!(
                "data: {{\"type\":\"delta\",\"delta\":\"{}'\"}}\n\n",
                &placeholder[split..]
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        stream.write_all(b"0\r\n\r\n").await.unwrap();
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tls = connect_tls_through_proxy(&proxy.url(), &target, &ca).await;
    let body = format!(r#"{{"prompt":"use {secret}"}}"#);
    tls.write_all(
        format!(
            "POST /backend-api/sse-delta HTTP/1.1\r\n\
             Host: {target}\r\n\
             content-type: application/json\r\n\
             accept-encoding: gzip\r\n\
             content-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let (_head, body) = read_http_chunked_message(&mut tls).await;
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains(secret));
    assert!(!body.contains("{{CREBRO_SECRET"));

    upstream.await.unwrap();
}

#[tokio::test]
async fn proxy_mitm_head_response_does_not_wait_for_declared_body() {
    let registry = Arc::new(RwLock::new(SecretRegistry::with_generated_keys()));
    let ca = Arc::new(LocalCa::generate_session().unwrap());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let target = format!("localhost:{}", upstream_addr.port());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let request = read_http_response_head(&mut stream).await;
        assert!(request.starts_with("HEAD /backend-api/ HTTP/1.1"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 999\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        allowlisted_connect_targets: vec![target.clone()],
        registry: Arc::clone(&registry),
        patterns: CredentialPatternSet::builtin(),
        ca: Some(Arc::clone(&ca)),
        upstream_tls: false,
        ..ProxyConfig::default()
    })
    .await
    .unwrap();

    let mut tls = connect_tls_through_proxy(&proxy.url(), &target, &ca).await;
    tls.write_all(
        format!("HEAD /backend-api/ HTTP/1.1\r\nHost: {target}\r\naccept-encoding: gzip\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();

    let response = timeout(
        Duration::from_millis(300),
        read_http_response_head(&mut tls),
    )
    .await
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-length: 999")
    );

    upstream.await.unwrap();
}

async fn read_http_response_head<S>(stream: &mut S) -> String
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut buf = [0u8; 1];
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}

async fn read_http_message<S>(stream: &mut S) -> (String, Vec<u8>)
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).await.unwrap();
        assert_ne!(n, 0);
        bytes.extend_from_slice(&buf[..n]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
    };
    let head = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let content_length = head
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    let mut body = bytes[body_start..].to_vec();
    if body.len() < content_length {
        let mut rest = vec![0u8; content_length - body.len()];
        stream.read_exact(&mut rest).await.unwrap();
        body.extend(rest);
    }
    (head, body)
}

async fn read_http_chunked_message<S>(stream: &mut S) -> (String, Vec<u8>)
where
    S: AsyncRead + Unpin,
{
    let head = read_http_response_head(stream).await;
    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    );
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(stream).await;
        let len = usize::from_str_radix(line.split(';').next().unwrap().trim(), 16).unwrap();
        if len == 0 {
            assert!(read_crlf_line(stream).await.is_empty());
            return (head, body);
        }
        let mut chunk = vec![0u8; len];
        stream.read_exact(&mut chunk).await.unwrap();
        let mut delimiter = [0u8; 2];
        stream.read_exact(&mut delimiter).await.unwrap();
        assert_eq!(&delimiter, b"\r\n");
        body.extend(chunk);
    }
}

async fn read_crlf_line<S>(stream: &mut S) -> String
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes).unwrap();
        }
    }
}

async fn write_http_chunk<S>(stream: &mut S, payload: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(format!("{:x}\r\n", payload.len()).as_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.write_all(b"\r\n").await
}

async fn connect_tls_through_proxy(
    proxy_url: &str,
    target: &str,
    ca: &LocalCa,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tcp = TcpStream::connect(proxy_url.trim_start_matches("http://"))
        .await
        .unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let connect_response = read_http_response_head(&mut tcp).await;
    assert!(connect_response.starts_with("HTTP/1.1 200 Connection Established"));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.root_der()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    connector.connect(server_name, tcp).await.unwrap()
}

async fn read_ws_frame<S>(stream: &mut S, masked: bool) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0] & 0x0f, 1);
    assert_eq!(header[1] & 0x80 != 0, masked);
    let len = match header[1] & 0x7f {
        126 => {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).await.unwrap();
            u16::from_be_bytes(extended) as usize
        }
        127 => {
            let mut extended = [0u8; 8];
            stream.read_exact(&mut extended).await.unwrap();
            usize::try_from(u64::from_be_bytes(extended)).unwrap()
        }
        len => len as usize,
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.unwrap();
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    if masked {
        apply_ws_mask(&mut payload, mask);
    }
    payload
}

async fn write_ws_frame<S>(stream: &mut S, payload: &[u8], masked: bool) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    assert!(payload.len() < 126);
    let mut frame = vec![0x81, payload.len() as u8 | if masked { 0x80 } else { 0 }];
    if masked {
        let mask = [1, 2, 3, 4];
        frame.extend_from_slice(&mask);
        let mut payload = payload.to_vec();
        apply_ws_mask(&mut payload, mask);
        frame.extend_from_slice(&payload);
    } else {
        frame.extend_from_slice(payload);
    }
    stream.write_all(&frame).await
}

fn apply_ws_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn codex_shell_shim(prefix: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = unique_temp_dir(prefix);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("codex");
    std::fs::write(&path, b"#!/bin/sh\nexec /bin/sh \"$@\"\n").unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();
    path
}
