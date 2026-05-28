use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{CommandFactory, Parser, error::ErrorKind};
use crebro::{
    cli::{Cli, SanitizeAgentArg, SanitizeConversationsCli},
    patterns::CredentialPatternSet,
    sanitize::{SanitizeConfig, run_sanitize_conversations},
};
use rusqlite::Connection;

fn unique_temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "crebro-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_env_file(dir: &Path, secret: &str) -> PathBuf {
    let env_file = dir.join(".env");
    fs::write(&env_file, format!("OPENAI_API_KEY={secret}\n")).unwrap();
    env_file
}

fn sanitize_config(
    root: &Path,
    env_file: &Path,
    backup_dir: Option<PathBuf>,
    write: bool,
) -> SanitizeConfig {
    SanitizeConfig {
        write,
        agents: Vec::new(),
        paths: vec![root.to_path_buf()],
        env_file: env_file.to_path_buf(),
        backup_dir,
        patterns: CredentialPatternSet::builtin(),
        strict: false,
    }
}

#[test]
fn fixture_directories_are_sanitized_only_when_write_is_enabled() {
    let root = unique_temp_dir("sanitize-fixtures");
    let backup_dir = root.join("backups");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
    let env_file = write_env_file(&root, secret);

    let files = [
        root.join(".codex/sessions/2026/05/27/rollout.jsonl"),
        root.join(".claude/projects/-tmp-project/session.jsonl"),
        root.join(".gemini/tmp/project/chats/session.json"),
        root.join(".local/share/opencode/storage/session/project/ses_test.json"),
    ];
    for file in &files {
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(
            file,
            format!(r#"{{"message":"use {secret} and <cb>manual-secret-1234567890</cb>"}}"#),
        )
        .unwrap();
    }

    let dry_report =
        run_sanitize_conversations(sanitize_config(&root, &env_file, None, false)).unwrap();
    assert_eq!(dry_report.files_changed, 4);
    assert!(dry_report.redactions >= 8);
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        assert!(text.contains(secret));
        assert!(text.contains("manual-secret-1234567890"));
    }

    let write_report =
        run_sanitize_conversations(sanitize_config(&root, &env_file, Some(backup_dir), true))
            .unwrap();
    assert_eq!(write_report.files_changed, 4);
    assert_eq!(write_report.backups.len(), 4);
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        assert!(!text.contains(secret));
        assert!(!text.contains("manual-secret-1234567890"));
        assert!(!text.contains("<cb>"));
        assert!(!text.contains("CREBRO_SECRET"));
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn sqlite_text_columns_are_sanitized_with_backup() {
    let root = unique_temp_dir("sanitize-sqlite");
    let backup_dir = root.join("backups");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
    let env_file = write_env_file(&root, secret);
    let db_path = root.join("opencode.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute(
        "CREATE TABLE message (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE part (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO message (id, data) VALUES ('msg_1', ?1)",
        [format!(r#"{{"text":"{secret}"}}"#)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO part (id, data) VALUES ('prt_1', ?1)",
        ["ordinary text"],
    )
    .unwrap();
    drop(conn);

    let dry_report =
        run_sanitize_conversations(sanitize_config(&db_path, &env_file, None, false)).unwrap();
    assert_eq!(dry_report.sqlite_rows_changed, 1);
    let kept: String = Connection::open(&db_path)
        .unwrap()
        .query_row("SELECT data FROM message WHERE id = 'msg_1'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(kept.contains(secret));

    let write_report =
        run_sanitize_conversations(sanitize_config(&db_path, &env_file, Some(backup_dir), true))
            .unwrap();
    assert_eq!(write_report.sqlite_rows_changed, 1);
    assert!(!write_report.backups.is_empty());
    let updated: String = Connection::open(&db_path)
        .unwrap()
        .query_row("SELECT data FROM message WHERE id = 'msg_1'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(!updated.contains(secret));
    assert_eq!(updated.len(), kept.len());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn binary_files_use_exact_registered_secret_replacement_only() {
    let root = unique_temp_dir("sanitize-binary");
    let backup_dir = root.join("backups");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
    let env_file = write_env_file(&root, secret);
    let pb_path = root.join("conversation.pb");
    let mut bytes = vec![0, 159, 146, 150, b'x'];
    bytes.extend_from_slice(secret.as_bytes());
    bytes.extend_from_slice(&[0, 1, 2]);
    fs::write(&pb_path, &bytes).unwrap();

    let report =
        run_sanitize_conversations(sanitize_config(&pb_path, &env_file, Some(backup_dir), true))
            .unwrap();
    assert_eq!(report.files_changed, 1);
    assert_eq!(report.redactions, 1);
    let updated = fs::read(&pb_path).unwrap();
    assert_eq!(updated.len(), bytes.len());
    assert!(
        !updated
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn cli_parsing_keeps_legacy_wrapper_and_exposes_sanitize_help() {
    let legacy = Cli::try_parse_from(["crebro", "--", "claude"]).unwrap();
    assert_eq!(legacy.command, vec!["claude".to_string()]);

    let sanitize = SanitizeConversationsCli::try_parse_from([
        "crebro sanitize-conversations",
        "--agent",
        "codex",
        "--path",
        "/tmp/example",
        "--json",
    ])
    .unwrap();
    assert!(sanitize.json);
    assert_eq!(sanitize.path, vec![PathBuf::from("/tmp/example")]);

    let all = SanitizeConversationsCli::try_parse_from([
        "crebro sanitize-conversations",
        "--agent",
        "all",
    ])
    .unwrap();
    assert_eq!(all.agent, vec![SanitizeAgentArg::All]);

    let missing_agent = SanitizeConversationsCli::try_parse_from(["crebro sanitize-conversations"]);
    assert_eq!(
        missing_agent.unwrap_err().kind(),
        ErrorKind::MissingRequiredArgument
    );

    let help = SanitizeConversationsCli::command().try_get_matches_from(["crebro", "--help"]);
    assert_eq!(help.unwrap_err().kind(), ErrorKind::DisplayHelp);
}
