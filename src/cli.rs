use std::{ffi::OsString, sync::Arc};

use clap::{Parser, ValueEnum};
use tokio::sync::RwLock;

use crate::{
    Result, hardening,
    patterns::CredentialPatternSet,
    process::{ProxyChildEnvConfig, proxy_child_environment, run_child_with_env},
    proxy::{ProxyConfig, spawn_proxy},
    sanitize::{SanitizeAgent, SanitizeConfig, run_sanitize_conversations},
    secrets::{
        SecretRegistry, discover_dotenv_candidates_with_patterns,
        discover_env_candidates_with_patterns,
    },
    stats,
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about,
    after_help = "Maintenance commands:\n  crebro sanitize-conversations [OPTIONS]    Replace credentials in local agent conversation stores"
)]
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

#[derive(Debug, Parser)]
#[command(
    name = "sanitize-conversations",
    about = "Replace credentials in local agent conversation stores with random non-secret values"
)]
pub struct SanitizeConversationsCli {
    #[arg(long)]
    pub write: bool,

    #[arg(long, value_enum)]
    pub agent: Vec<SanitizeAgentArg>,

    #[arg(long)]
    pub path: Vec<std::path::PathBuf>,

    #[arg(long, env = "CREBRO_ENV_FILE", default_value = ".env")]
    pub env_file: std::path::PathBuf,

    #[arg(long, env = "CREBRO_PATTERNS_FILE")]
    pub patterns_file: Option<std::path::PathBuf>,

    #[arg(long)]
    pub backup_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SanitizeAgentArg {
    All,
    Codex,
    Claude,
    Gemini,
    Opencode,
}

pub async fn run() -> Result<i32> {
    run_from_args(std::env::args_os()).await
}

pub async fn run_from_args(args: impl IntoIterator<Item = OsString>) -> Result<i32> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args
        .get(1)
        .and_then(|arg| arg.to_str())
        .is_some_and(|arg| arg == "sanitize-conversations")
    {
        let mut subcommand_args = Vec::with_capacity(args.len().saturating_sub(1));
        subcommand_args.push(OsString::from("crebro sanitize-conversations"));
        subcommand_args.extend(args.into_iter().skip(2));
        let cli = SanitizeConversationsCli::parse_from(subcommand_args);
        return run_with_sanitize_cli(cli).await;
    }

    let cli = Cli::parse_from(args);
    run_with_cli(cli).await
}

pub async fn run_with_sanitize_cli(cli: SanitizeConversationsCli) -> Result<i32> {
    let patterns = if let Some(path) = &cli.patterns_file {
        std::sync::Arc::new(CredentialPatternSet::from_path(path)?)
    } else {
        CredentialPatternSet::builtin()
    };
    let report = run_sanitize_conversations(SanitizeConfig {
        write: cli.write,
        agents: sanitize_agents(cli.agent),
        paths: cli.path,
        env_file: cli.env_file,
        backup_dir: cli.backup_dir,
        patterns,
        strict: cli.strict,
    })?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "scanned {} files and {} sqlite databases; {} files changed, {} sqlite rows changed; {} redactions{}",
            report.files_scanned,
            report.sqlite_databases_scanned,
            report.files_changed,
            report.sqlite_rows_changed,
            report.redactions,
            if report.write { "" } else { " (dry run)" }
        );
        if !report.unregistered_pattern_matches.is_empty() {
            println!(
                "reported {} unregistered credential-like pattern matches",
                report.unregistered_pattern_matches.len()
            );
        }
        if !report.errors.is_empty() {
            println!("reported {} non-fatal errors", report.errors.len());
        }
    }
    Ok(if report.errors.is_empty() { 0 } else { 1 })
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

fn sanitize_agents(args: Vec<SanitizeAgentArg>) -> Vec<SanitizeAgent> {
    if args.is_empty() || args.contains(&SanitizeAgentArg::All) {
        return vec![
            SanitizeAgent::Codex,
            SanitizeAgent::Claude,
            SanitizeAgent::Gemini,
            SanitizeAgent::Opencode,
        ];
    }
    args.into_iter()
        .map(|agent| match agent {
            SanitizeAgentArg::All => SanitizeAgent::Codex,
            SanitizeAgentArg::Codex => SanitizeAgent::Codex,
            SanitizeAgentArg::Claude => SanitizeAgent::Claude,
            SanitizeAgentArg::Gemini => SanitizeAgent::Gemini,
            SanitizeAgentArg::Opencode => SanitizeAgent::Opencode,
        })
        .collect()
}
