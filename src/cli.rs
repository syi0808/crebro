use std::{path::Path, sync::Arc};

use clap::Parser;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use crate::{
    Result,
    gateway::{GatewayConfig, spawn_gateway},
    hardening,
    mode::{EffectiveMode, resolve_effective_mode},
    patterns::CredentialPatternSet,
    process::{
        ProxyChildEnvConfig, first_provider_key_from_env, provider_key_env_present,
        proxy_sanitized_environment, run_child, run_child_with_env,
    },
    proxy::{ProxyConfig, spawn_proxy},
    secrets::{
        SecretLabel, SecretRegistry, SecureBuf, discover_dotenv_candidates_with_patterns,
        discover_env_candidates_with_patterns,
    },
    stats,
};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, env = "CREBRO_LISTEN_ADDR", default_value = "127.0.0.1:0")]
    pub listen_addr: String,

    #[arg(long, env = "CREBRO_UPSTREAM_URL")]
    pub upstream_url: Option<String>,

    #[arg(long, env = "CREBRO_PROVIDER_API_KEY")]
    pub provider_api_key: Option<String>,

    #[arg(long, env = "CREBRO_ENV_FILE", default_value = ".env")]
    pub env_file: std::path::PathBuf,

    #[arg(long, env = "CREBRO_PATTERNS_FILE")]
    pub patterns_file: Option<std::path::PathBuf>,

    #[arg(long, env = "CREBRO_STATS_DIR")]
    pub stats_dir: Option<std::path::PathBuf>,

    #[arg(long, env = "CREBRO_TLS_KEYLOG_FILE")]
    pub tls_keylog_file: Option<std::path::PathBuf>,

    #[arg(long, env = "CREBRO_NO_PLACEHOLDER_GUIDANCE")]
    pub no_placeholder_guidance: bool,

    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

pub async fn run() -> Result<i32> {
    let cli = Cli::parse();
    run_with_cli(cli).await
}

pub async fn run_with_cli(mut cli: Cli) -> Result<i32> {
    let hardening_status = hardening::harden_process();
    for failure in &hardening_status.failed {
        tracing::warn!(operation = failure.operation, "process hardening degraded");
    }

    let patterns = if let Some(path) = &cli.patterns_file {
        std::sync::Arc::new(CredentialPatternSet::from_path(path)?)
    } else {
        CredentialPatternSet::builtin()
    };

    let mut registry = SecretRegistry::with_generated_keys();
    for candidate in discover_env_candidates_with_patterns(512, &patterns) {
        registry.ingest(candidate.label, candidate.value)?;
    }
    for candidate in discover_dotenv_candidates_with_patterns(&cli.env_file, 512, &patterns)? {
        registry.ingest(candidate.label, candidate.value)?;
    }

    let has_provider_key = cli
        .provider_api_key
        .as_ref()
        .is_some_and(|key| !key.is_empty())
        || provider_key_env_present();
    let effective_mode = resolve_effective_mode(&cli.command, has_provider_key);

    let provider_auth_secret = if let Some(mut key) = cli.provider_api_key.take() {
        let id = registry.ingest(
            SecretLabel::new("CREBRO_PROVIDER_API_KEY"),
            SecureBuf::from_slice(key.as_bytes()),
        )?;
        key.zeroize();
        Some(id)
    } else if let Some((label, key)) = first_provider_key_from_env() {
        Some(registry.ingest(SecretLabel::new(label), key)?)
    } else {
        None
    };

    if effective_mode == EffectiveMode::Proxy {
        tracing::warn!(
            "Crebro proxy mode selected for child process; local MITM is enabled for allowlisted targets and ChatGPT auth tokens remain visible to the child and upstream"
        );
        let proxy = spawn_proxy(ProxyConfig {
            listen_addr: cli.listen_addr,
            registry: Arc::new(RwLock::new(registry)),
            patterns: Arc::clone(&patterns),
            tls_keylog_file: cli.tls_keylog_file,
            placeholder_guidance: !cli.no_placeholder_guidance,
            ..ProxyConfig::default()
        })
        .await?;
        let ca_bundle_path = proxy.ca_bundle_path().map(|path| path.to_path_buf());
        let child_env = proxy_sanitized_environment(
            std::env::vars(),
            &ProxyChildEnvConfig {
                proxy_url: proxy.url(),
                ca_bundle_path,
            },
        );
        let status = run_child_with_env(&cli.command, child_env).await?;
        return if status.success() {
            Ok(0)
        } else {
            Ok(status.code().unwrap_or(1))
        };
    }

    let upstream_url = cli
        .upstream_url
        .take()
        .map(Ok)
        .unwrap_or_else(|| infer_default_upstream_url(&cli.command))?;

    let gateway = spawn_gateway(
        GatewayConfig {
            listen_addr: cli.listen_addr,
            upstream_base: upstream_url,
            provider_auth_secret,
            cache_entries: 4096,
            streaming_json_threshold_bytes: 256 * 1024,
            patterns,
            stats_path: stats::stats_path(cli.stats_dir.as_deref()),
            tls_keylog_file: cli.tls_keylog_file,
            placeholder_guidance: !cli.no_placeholder_guidance,
        },
        Arc::new(RwLock::new(registry)),
    )
    .await?;

    let status = run_child(&cli.command, &gateway.url()).await?;
    if status.success() {
        Ok(0)
    } else {
        Ok(status.code().unwrap_or(1))
    }
}

pub fn infer_default_upstream_url(command: &[String]) -> Result<String> {
    let program = command
        .first()
        .ok_or_else(|| crate::CrebroError::Config("missing child command".into()))?;
    let name = Path::new(program)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();

    if name.contains("claude") {
        return Ok("https://api.anthropic.com".to_string());
    }
    if name.contains("gemini") {
        return Ok("https://generativelanguage.googleapis.com".to_string());
    }
    if name.contains("codex") {
        return Ok("https://api.openai.com".to_string());
    }
    if name.contains("opencode") {
        if std::env::var_os("ANTHROPIC_API_KEY").is_some()
            && std::env::var_os("OPENAI_API_KEY").is_none()
        {
            return Ok("https://api.anthropic.com".to_string());
        }
        return Ok("https://api.openai.com".to_string());
    }

    if std::env::var_os("OPENAI_API_KEY").is_some() {
        return Ok("https://api.openai.com".to_string());
    }
    if std::env::var_os("ANTHROPIC_API_KEY").is_some()
        || std::env::var_os("ANTHROPIC_AUTH_TOKEN").is_some()
    {
        return Ok("https://api.anthropic.com".to_string());
    }
    if std::env::var_os("GEMINI_API_KEY").is_some()
        || std::env::var_os("GOOGLE_API_KEY").is_some()
        || std::env::var_os("GOOGLE_GENERATIVE_AI_API_KEY").is_some()
    {
        return Ok("https://generativelanguage.googleapis.com".to_string());
    }

    Err(crate::CrebroError::Config(
        "could not infer upstream URL; pass --upstream-url or use codex, claude, gemini, or opencode"
            .into(),
    ))
}
