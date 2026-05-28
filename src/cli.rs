use std::{ffi::OsString, path::Path, sync::Arc};

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
    after_help = "Maintenance commands:\n  crebro detect-pattern [OPTIONS] <TEXT>     Check whether text matches a credential pattern\n  crebro sanitize-conversations [OPTIONS]    Replace credentials in local agent conversation stores"
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

    #[arg(long, value_enum, required = true)]
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

#[derive(Debug, Parser)]
#[command(
    name = "detect-pattern",
    about = "Check whether supplied text matches a Crebro credential pattern"
)]
pub struct DetectPatternCli {
    #[arg(long, env = "CREBRO_PATTERNS_FILE")]
    pub patterns_file: Option<std::path::PathBuf>,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub quiet: bool,

    pub text: String,
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
    match args.get(1).and_then(|arg| arg.to_str()) {
        Some("detect-pattern") => {
            let cli = DetectPatternCli::parse_from(subcommand_args(&args, "crebro detect-pattern"));
            return run_with_detect_pattern_cli(cli).await;
        }
        Some("sanitize-conversations") => {
            let cli = SanitizeConversationsCli::parse_from(subcommand_args(
                &args,
                "crebro sanitize-conversations",
            ));
            return run_with_sanitize_cli(cli).await;
        }
        _ => {}
    }

    let cli = Cli::parse_from(args);
    run_with_cli(cli).await
}

pub async fn run_with_detect_pattern_cli(cli: DetectPatternCli) -> Result<i32> {
    let patterns = load_credential_patterns(cli.patterns_file.as_deref())?;
    let report = detect_pattern_report(&patterns, &cli.text);

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !cli.quiet {
        println!("{}", format_detect_pattern_human(&report));
    }

    Ok(if report.matched { 0 } else { 1 })
}

pub async fn run_with_sanitize_cli(cli: SanitizeConversationsCli) -> Result<i32> {
    let patterns = load_credential_patterns(cli.patterns_file.as_deref())?;
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

    let patterns = load_credential_patterns(cli.patterns_file.as_deref())?;

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

fn subcommand_args(args: &[OsString], command_name: &str) -> Vec<OsString> {
    let mut subcommand_args = Vec::with_capacity(args.len().saturating_sub(1));
    subcommand_args.push(OsString::from(command_name));
    subcommand_args.extend(args.iter().skip(2).cloned());
    subcommand_args
}

fn load_credential_patterns(path: Option<&Path>) -> Result<Arc<CredentialPatternSet>> {
    if let Some(path) = path {
        Ok(Arc::new(CredentialPatternSet::from_path(path)?))
    } else {
        Ok(CredentialPatternSet::builtin())
    }
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct DetectPatternReport {
    matched: bool,
    matches: Vec<DetectPatternMatchReport>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct DetectPatternMatchReport {
    pattern_id: String,
    start: usize,
    end: usize,
}

fn detect_pattern_report(patterns: &CredentialPatternSet, text: &str) -> DetectPatternReport {
    let matches = patterns
        .auto_redact_matches(text)
        .into_iter()
        .map(|matched| DetectPatternMatchReport {
            pattern_id: matched.pattern_id,
            start: matched.start,
            end: matched.end,
        })
        .collect::<Vec<_>>();
    DetectPatternReport {
        matched: !matches.is_empty(),
        matches,
    }
}

fn format_detect_pattern_human(report: &DetectPatternReport) -> String {
    if report.matches.is_empty() {
        return "no credential pattern match".to_string();
    }
    let pattern_ids = report
        .matches
        .iter()
        .map(|matched| matched.pattern_id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "matched {} credential pattern(s): {}",
        report.matches.len(),
        pattern_ids
    )
}

fn sanitize_agents(args: Vec<SanitizeAgentArg>) -> Vec<SanitizeAgent> {
    if args.contains(&SanitizeAgentArg::All) {
        return vec![
            SanitizeAgent::Codex,
            SanitizeAgent::Claude,
            SanitizeAgent::Gemini,
            SanitizeAgent::Opencode,
        ];
    }
    args.into_iter()
        .map(|agent| match agent {
            SanitizeAgentArg::All => unreachable!("all is handled before individual mapping"),
            SanitizeAgentArg::Codex => SanitizeAgent::Codex,
            SanitizeAgentArg::Claude => SanitizeAgent::Claude,
            SanitizeAgentArg::Gemini => SanitizeAgent::Gemini,
            SanitizeAgentArg::Opencode => SanitizeAgent::Opencode,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "crebro-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn detect_pattern_cli_parses_text_and_options() {
        let cli = DetectPatternCli::try_parse_from([
            "crebro detect-pattern",
            "--json",
            "--quiet",
            "not-a-secret",
        ])
        .unwrap();

        assert!(cli.json);
        assert!(cli.quiet);
        assert_eq!(cli.text, "not-a-secret");
    }

    #[tokio::test]
    async fn detect_pattern_builtin_match_returns_success() {
        let code = run_with_detect_pattern_cli(DetectPatternCli {
            patterns_file: None,
            json: false,
            quiet: true,
            text: "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        })
        .await
        .unwrap();

        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn detect_pattern_dispatch_is_intercepted_before_wrapper_mode() {
        let code = run_from_args([
            OsString::from("crebro"),
            OsString::from("detect-pattern"),
            OsString::from("--quiet"),
            OsString::from("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"),
        ])
        .await
        .unwrap();

        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn detect_pattern_nonmatch_returns_one() {
        let code = run_with_detect_pattern_cli(DetectPatternCli {
            patterns_file: None,
            json: false,
            quiet: true,
            text: "not-a-secret".to_string(),
        })
        .await
        .unwrap();

        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn detect_pattern_uses_custom_pattern_file() {
        let path = temp_path("detect-pattern.toml");
        std::fs::write(
            &path,
            r#"
[env]
key_markers = ["KEY"]
common_values = ["true"]
min_value_len = 4
min_entropy = 1.0

[[credential_patterns]]
id = "custom_token"
regex = '''CUSTOM_[A-Za-z0-9]{8,}'''
"#,
        )
        .unwrap();

        let code = run_with_detect_pattern_cli(DetectPatternCli {
            patterns_file: Some(path.clone()),
            json: false,
            quiet: true,
            text: "CUSTOM_ABC123456".to_string(),
        })
        .await
        .unwrap();

        assert_eq!(code, 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn detect_pattern_report_excludes_raw_match_text() {
        let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
        let report = detect_pattern_report(&CredentialPatternSet::builtin(), secret);

        assert!(report.matched);
        assert_eq!(report.matches[0].pattern_id, "openai_modern_key");

        let human = format_detect_pattern_human(&report);
        assert!(human.contains("openai_modern_key"));
        assert!(!human.contains(secret));

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("openai_modern_key"));
        assert!(!json.contains(secret));
    }

    #[test]
    fn explicit_all_selects_every_supported_sanitize_agent() {
        assert_eq!(
            sanitize_agents(vec![SanitizeAgentArg::All]),
            vec![
                SanitizeAgent::Codex,
                SanitizeAgent::Claude,
                SanitizeAgent::Gemini,
                SanitizeAgent::Opencode,
            ]
        );
    }

    #[test]
    fn empty_sanitize_agent_list_stays_empty_for_programmatic_callers() {
        assert!(sanitize_agents(Vec::new()).is_empty());
    }
}
