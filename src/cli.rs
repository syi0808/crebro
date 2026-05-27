use std::sync::Arc;

use clap::Parser;
use tokio::sync::RwLock;

use crate::{
    Result, hardening,
    patterns::CredentialPatternSet,
    process::{ProxyChildEnvConfig, proxy_child_environment, run_child_with_env},
    proxy::{ProxyConfig, spawn_proxy},
    secrets::{
        SecretRegistry, discover_dotenv_candidates_with_patterns,
        discover_env_candidates_with_patterns,
    },
    stats,
};

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, env = "CREBRO_LISTEN_ADDR", default_value = "127.0.0.1:0")]
    pub listen_addr: String,

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

pub async fn run_with_cli(cli: Cli) -> Result<i32> {
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

    tracing::warn!(
        "Crebro proxy mode selected for child process; local MITM is enabled for allowlisted targets and auth tokens remain visible to the child and upstream"
    );
    let proxy = spawn_proxy(ProxyConfig {
        listen_addr: cli.listen_addr,
        registry: Arc::new(RwLock::new(registry)),
        patterns: Arc::clone(&patterns),
        stats_path: stats::stats_path(cli.stats_dir.as_deref()),
        tls_keylog_file: cli.tls_keylog_file,
        placeholder_guidance: !cli.no_placeholder_guidance,
        ..ProxyConfig::default()
    })
    .await?;
    let ca_bundle_path = proxy.ca_bundle_path().map(|path| path.to_path_buf());
    let child_env = proxy_child_environment(
        std::env::vars(),
        &ProxyChildEnvConfig {
            proxy_url: proxy.url(),
            ca_bundle_path,
        },
    );
    let status = run_child_with_env(&cli.command, child_env).await?;
    if status.success() {
        Ok(0)
    } else {
        Ok(status.code().unwrap_or(1))
    }
}
