use std::{path::Path, sync::Arc};

use clap::Parser;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use crate::{
    Result,
    gateway::{GatewayConfig, spawn_gateway},
    hardening,
    process::{first_provider_key_from_env, run_child},
    secrets::{
        SecretLabel, SecretRegistry, SecureBuf, discover_dotenv_candidates, discover_env_candidates,
    },
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

    let mut registry = SecretRegistry::with_generated_keys();
    for candidate in discover_env_candidates(512) {
        registry.ingest(candidate.label, candidate.value)?;
    }
    for candidate in discover_dotenv_candidates(&cli.env_file, 512)? {
        registry.ingest(candidate.label, candidate.value)?;
    }

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
