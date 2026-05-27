use std::{
    collections::{BTreeSet, HashMap, HashSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    CrebroError, Result,
    patterns::{CredentialPatternSet, OnUnregisteredMatch},
    redact::{
        directive::DirectivePart, directive::parse_user_secret_directives, scan_string_token,
    },
    secrets::{
        SecretId, SecretLabel, SecretRegistry, SecureBuf, discover_dotenv_candidates_with_patterns,
        discover_env_candidates_with_patterns,
    },
};

const REPLACEMENT_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SanitizeAgent {
    Codex,
    Claude,
    Gemini,
    Opencode,
}

#[derive(Debug, Clone)]
pub struct SanitizeConfig {
    pub write: bool,
    pub agents: Vec<SanitizeAgent>,
    pub paths: Vec<PathBuf>,
    pub env_file: PathBuf,
    pub backup_dir: Option<PathBuf>,
    pub patterns: Arc<CredentialPatternSet>,
    pub strict: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SanitizeReport {
    pub write: bool,
    pub backup_dir: Option<PathBuf>,
    pub files_scanned: u64,
    pub files_changed: u64,
    pub sqlite_databases_scanned: u64,
    pub sqlite_rows_changed: u64,
    pub redactions: u64,
    pub unique_replacements: usize,
    pub backups: Vec<BackupRecord>,
    pub targets: Vec<TargetReport>,
    pub unregistered_pattern_matches: Vec<PatternFinding>,
    pub unsupported_binary_files: Vec<PathBuf>,
    pub errors: Vec<SanitizeErrorReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRecord {
    pub source: PathBuf,
    pub backup: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub path: PathBuf,
    pub kind: String,
    pub changed: bool,
    pub redactions: u64,
    pub rows_changed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternFinding {
    pub path: PathBuf,
    pub pattern_id: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SanitizeErrorReport {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextSanitizeResult {
    pub text: String,
    pub redactions: usize,
    pub unregistered_patterns: Vec<UnregisteredPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnregisteredPattern {
    pub pattern_id: String,
    pub action: OnUnregisteredMatch,
}

pub fn run_sanitize_conversations(config: SanitizeConfig) -> Result<SanitizeReport> {
    let backup_dir = if config.write {
        Some(resolve_backup_dir(config.backup_dir.as_deref())?)
    } else {
        config.backup_dir.clone()
    };
    let mut report = SanitizeReport {
        write: config.write,
        backup_dir: backup_dir.clone(),
        ..SanitizeReport::default()
    };

    let mut engine = ConversationSanitizer::with_patterns(Arc::clone(&config.patterns));
    for candidate in discover_env_candidates_with_patterns(512, &config.patterns) {
        engine.ingest(candidate.label, candidate.value)?;
    }
    for candidate in
        discover_dotenv_candidates_with_patterns(&config.env_file, 512, &config.patterns)?
    {
        engine.ingest(candidate.label, candidate.value)?;
    }

    let mut roots = Vec::new();
    for agent in config.agents {
        roots.extend(
            default_agent_paths(agent)
                .into_iter()
                .map(|path| (path, false)),
        );
    }
    roots.extend(config.paths.into_iter().map(|path| (path, true)));

    let mut seen = HashSet::new();
    for (root, explicit) in roots {
        let key = normalized_path_key(&root);
        if !seen.insert(key) {
            continue;
        }
        process_path(
            &root,
            explicit,
            config.write,
            backup_dir.as_deref(),
            config.strict,
            &mut engine,
            &mut report,
        );
    }

    report.unique_replacements = engine.replacement_count();
    Ok(report)
}

pub struct ConversationSanitizer {
    registry: SecretRegistry,
    patterns: Arc<CredentialPatternSet>,
    replacements: HashMap<SecretId, Vec<u8>>,
}

impl ConversationSanitizer {
    pub fn with_patterns(patterns: Arc<CredentialPatternSet>) -> Self {
        Self {
            registry: SecretRegistry::with_generated_keys(),
            patterns,
            replacements: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, label: SecretLabel, secret: SecureBuf) -> Result<SecretId> {
        self.registry.ingest(label, secret)
    }

    pub fn replacement_count(&self) -> usize {
        self.replacements.len()
    }

    pub fn sanitize_text(&mut self, text: &str, strict: bool) -> Result<TextSanitizeResult> {
        let (normalized, directive_placeholders) = self.normalize_directives(text)?;
        self.auto_register_pattern_matches(&normalized)?;

        let mut spans = Vec::new();
        for span in scan_string_token(normalized.as_bytes(), &self.registry)? {
            spans.push(ReplacementSpan {
                start: span.start,
                end: span.end(),
                secret_id: span.secret_id,
            });
        }

        for (placeholder, secret_id) in directive_placeholders {
            for start in find_bytes(normalized.as_bytes(), placeholder.as_bytes()) {
                spans.push(ReplacementSpan {
                    start,
                    end: start + placeholder.len(),
                    secret_id,
                });
            }
        }

        let spans = select_replacement_spans(spans);
        let out = self.apply_replacement_spans(normalized.as_bytes(), &spans)?;
        let out = String::from_utf8(out)
            .map_err(|_| CrebroError::Redaction("sanitized text is not valid UTF-8".into()))?;
        let unregistered_patterns = self.inspect_unregistered_patterns(&out, strict)?;

        Ok(TextSanitizeResult {
            text: out,
            redactions: spans.len(),
            unregistered_patterns,
        })
    }

    pub fn sanitize_bytes_exact(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
        let spans = scan_string_token(bytes, &self.registry)?
            .into_iter()
            .map(|span| ReplacementSpan {
                start: span.start,
                end: span.end(),
                secret_id: span.secret_id,
            })
            .collect::<Vec<_>>();
        let spans = select_replacement_spans(spans);
        let out = self.apply_replacement_spans(bytes, &spans)?;
        Ok((out, spans.len()))
    }

    fn normalize_directives(&mut self, text: &str) -> Result<(String, Vec<(String, SecretId)>)> {
        let Some(replacement) = parse_user_secret_directives(text, &mut self.registry)? else {
            return Ok((text.to_string(), Vec::new()));
        };

        let mut out = String::with_capacity(text.len());
        let mut placeholders = Vec::new();
        for part in replacement.parts {
            match part {
                DirectivePart::Plain(text) => out.push_str(text),
                DirectivePart::Secret {
                    placeholder,
                    secret_id,
                } => {
                    out.push_str(&placeholder);
                    placeholders.push((placeholder, secret_id));
                }
            }
        }
        Ok((out, placeholders))
    }

    fn auto_register_pattern_matches(&mut self, text: &str) -> Result<()> {
        for matched in self.patterns.auto_redact_matches(text) {
            let Some(secret) = text.get(matched.start..matched.end) else {
                continue;
            };
            self.registry.ingest(
                SecretLabel::new(format!("AUTO_{}", matched.pattern_id.to_ascii_uppercase())),
                SecureBuf::from_slice(secret.as_bytes()),
            )?;
        }
        Ok(())
    }

    fn inspect_unregistered_patterns(
        &self,
        text: &str,
        strict: bool,
    ) -> Result<Vec<UnregisteredPattern>> {
        let mut patterns = Vec::new();
        for pattern_match in self.patterns.inspect_unregistered_text(text) {
            if strict
                && pattern_match.on_unregistered_match == OnUnregisteredMatch::RequireExplicitSecret
            {
                return Err(CrebroError::UnregisteredCredential {
                    pattern_id: pattern_match.id,
                });
            }
            patterns.push(UnregisteredPattern {
                pattern_id: pattern_match.id,
                action: pattern_match.on_unregistered_match,
            });
        }
        Ok(patterns)
    }

    fn apply_replacement_spans(
        &mut self,
        bytes: &[u8],
        spans: &[ReplacementSpan],
    ) -> Result<Vec<u8>> {
        if spans.is_empty() {
            return Ok(bytes.to_vec());
        }

        let mut out = Vec::with_capacity(bytes.len());
        let mut cursor = 0usize;
        for span in spans {
            if span.start > cursor {
                out.extend_from_slice(&bytes[cursor..span.start]);
            }
            let replacement = self.replacement_for(span.secret_id)?;
            out.extend_from_slice(&replacement);
            cursor = span.end;
        }
        if cursor < bytes.len() {
            out.extend_from_slice(&bytes[cursor..]);
        }
        Ok(out)
    }

    fn replacement_for(&mut self, id: SecretId) -> Result<Vec<u8>> {
        if let Some(replacement) = self.replacements.get(&id) {
            return Ok(replacement.clone());
        }

        let len = self
            .registry
            .entry(id)
            .ok_or_else(|| CrebroError::Secret(format!("unknown secret id {}", id.get())))?
            .len;
        let mut original = Vec::new();
        self.registry.restore_to_vec(id, &mut original)?;

        let mut replacement = random_ascii(len);
        for _ in 0..8 {
            if replacement != original {
                break;
            }
            replacement = random_ascii(len);
        }
        if replacement == original && !replacement.is_empty() {
            replacement[0] = if replacement[0] == b'a' { b'b' } else { b'a' };
        }
        original.zeroize();
        self.replacements.insert(id, replacement.clone());
        Ok(replacement)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplacementSpan {
    start: usize,
    end: usize,
    secret_id: SecretId,
}

impl ReplacementSpan {
    fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

fn process_path(
    path: &Path,
    explicit: bool,
    write: bool,
    backup_dir: Option<&Path>,
    strict: bool,
    engine: &mut ConversationSanitizer,
    report: &mut SanitizeReport,
) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            if explicit {
                report_error(report, path, err);
            }
            return;
        }
    };

    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(err) => {
                report_error(report, path, err);
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    report_error(report, path, err);
                    continue;
                }
            };
            let child = entry.path();
            if child.is_dir() && should_skip_dir(&child) {
                continue;
            }
            process_path(&child, false, write, backup_dir, strict, engine, report);
        }
        return;
    }

    if metadata.is_file() {
        process_file(path, explicit, write, backup_dir, strict, engine, report);
    }
}

fn process_file(
    path: &Path,
    explicit: bool,
    write: bool,
    backup_dir: Option<&Path>,
    strict: bool,
    engine: &mut ConversationSanitizer,
    report: &mut SanitizeReport,
) {
    if is_sqlite_path(path) {
        if let Err(err) = process_sqlite(path, write, backup_dir, strict, engine, report) {
            report_error(report, path, err);
        }
        return;
    }

    if !explicit && !is_candidate_text_path(path) && !is_candidate_binary_path(path) {
        return;
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            report_error(report, path, err);
            return;
        }
    };

    match String::from_utf8(bytes.clone()) {
        Ok(text) => {
            report.files_scanned = report.files_scanned.saturating_add(1);
            match engine.sanitize_text(&text, strict) {
                Ok(result) => {
                    record_pattern_findings(report, path, &result.unregistered_patterns);
                    if result.text != text {
                        report.redactions =
                            report.redactions.saturating_add(result.redactions as u64);
                        report.files_changed = report.files_changed.saturating_add(1);
                        report.targets.push(TargetReport {
                            path: path.to_path_buf(),
                            kind: "text-file".to_string(),
                            changed: true,
                            redactions: result.redactions as u64,
                            rows_changed: 0,
                        });
                        if write {
                            if let Err(err) = backup_and_write_file(
                                path,
                                result.text.as_bytes(),
                                backup_dir,
                                report,
                            ) {
                                report_error(report, path, err);
                            }
                        }
                    }
                }
                Err(err) => report_error(report, path, err),
            }
        }
        Err(_) => process_binary_file(path, &bytes, write, backup_dir, strict, engine, report),
    }
}

fn process_binary_file(
    path: &Path,
    bytes: &[u8],
    write: bool,
    backup_dir: Option<&Path>,
    strict: bool,
    engine: &mut ConversationSanitizer,
    report: &mut SanitizeReport,
) {
    report.files_scanned = report.files_scanned.saturating_add(1);
    let (out, redactions) = match engine.sanitize_bytes_exact(bytes) {
        Ok(result) => result,
        Err(err) => {
            report_error(report, path, err);
            return;
        }
    };

    let unsupported = unsupported_binary_patterns(bytes, &engine.patterns);
    if !unsupported.is_empty() {
        report.unsupported_binary_files.push(path.to_path_buf());
        for pattern in unsupported {
            report.unregistered_pattern_matches.push(PatternFinding {
                path: path.to_path_buf(),
                pattern_id: pattern,
                action: "unsupported_binary_pattern_scan".to_string(),
            });
        }
        if strict {
            report_error(
                report,
                path,
                CrebroError::Redaction(
                    "binary file contains credential-like patterns that cannot be pattern-redacted safely"
                        .into(),
                ),
            );
            return;
        }
    }

    if out != bytes {
        report.redactions = report.redactions.saturating_add(redactions as u64);
        report.files_changed = report.files_changed.saturating_add(1);
        report.targets.push(TargetReport {
            path: path.to_path_buf(),
            kind: "binary-file".to_string(),
            changed: true,
            redactions: redactions as u64,
            rows_changed: 0,
        });
        if write && let Err(err) = backup_and_write_file(path, &out, backup_dir, report) {
            report_error(report, path, err);
        }
    }
}

fn process_sqlite(
    path: &Path,
    write: bool,
    backup_dir: Option<&Path>,
    strict: bool,
    engine: &mut ConversationSanitizer,
    report: &mut SanitizeReport,
) -> Result<()> {
    report.sqlite_databases_scanned = report.sqlite_databases_scanned.saturating_add(1);
    let flags = if write {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let mut conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(Duration::from_secs(2))?;

    let mut updates = Vec::new();
    let mut db_redactions = 0u64;
    for (table, column) in sqlite_text_columns(&conn)? {
        let query = format!(
            "SELECT rowid, {} FROM {} WHERE {} IS NOT NULL",
            quote_identifier(&column),
            quote_identifier(&table),
            quote_identifier(&column)
        );
        let mut stmt = match conn.prepare(&query) {
            Ok(stmt) => stmt,
            Err(_) => continue,
        };
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        for row in rows {
            let (rowid, text) = row?;
            let result = engine.sanitize_text(&text, strict)?;
            record_pattern_findings(report, path, &result.unregistered_patterns);
            if result.text != text {
                db_redactions = db_redactions.saturating_add(result.redactions as u64);
                updates.push(SqliteUpdate {
                    table: table.clone(),
                    column: column.clone(),
                    rowid,
                    text: result.text,
                });
            }
        }
    }

    if updates.is_empty() {
        return Ok(());
    }

    report.redactions = report.redactions.saturating_add(db_redactions);
    report.sqlite_rows_changed = report
        .sqlite_rows_changed
        .saturating_add(updates.len() as u64);
    report.targets.push(TargetReport {
        path: path.to_path_buf(),
        kind: "sqlite-database".to_string(),
        changed: true,
        redactions: db_redactions,
        rows_changed: updates.len() as u64,
    });

    if !write {
        return Ok(());
    }

    backup_sqlite(path, backup_dir, report)?;
    let tx = conn.transaction()?;
    for update in updates {
        let sql = format!(
            "UPDATE {} SET {} = ?1 WHERE rowid = ?2",
            quote_identifier(&update.table),
            quote_identifier(&update.column)
        );
        tx.execute(&sql, (&update.text, update.rowid))?;
    }
    tx.commit()?;
    Ok(())
}

#[derive(Debug)]
struct SqliteUpdate {
    table: String,
    column: String,
    rowid: i64,
    text: String,
}

fn sqlite_text_columns(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut available = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let tables = stmt.query_map([], |row| row.get::<_, String>(0))?;
    for table in tables {
        let table = table?;
        let pragma = format!("PRAGMA table_info({})", quote_identifier(&table));
        let mut pragma_stmt = conn.prepare(&pragma)?;
        let columns = pragma_stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            let column_type: String = row.get(2)?;
            Ok((name, column_type))
        })?;
        for column in columns {
            let (column, column_type) = column?;
            if column_type.to_ascii_uppercase().contains("TEXT") {
                available.insert((table.clone(), column));
            }
        }
    }

    Ok(KNOWN_SQLITE_TEXT_COLUMNS
        .iter()
        .filter_map(|(table, column)| {
            let entry = ((*table).to_string(), (*column).to_string());
            available.contains(&entry).then_some(entry)
        })
        .collect())
}

const KNOWN_SQLITE_TEXT_COLUMNS: &[(&str, &str)] = &[
    ("message", "data"),
    ("part", "data"),
    ("session_message", "data"),
    ("event", "data"),
    ("logs", "feedback_log_body"),
    ("threads", "first_user_message"),
    ("threads", "preview"),
    ("threads", "title"),
    ("stage1_outputs", "raw_memory"),
    ("stage1_outputs", "rollout_summary"),
    ("agent_jobs", "instruction"),
    ("agent_jobs", "last_error"),
    ("agent_job_items", "row_json"),
    ("agent_job_items", "result_json"),
    ("agent_job_items", "last_error"),
    ("session", "title"),
    ("session", "summary_diffs"),
    ("todo", "content"),
];

fn backup_and_write_file(
    path: &Path,
    bytes: &[u8],
    backup_dir: Option<&Path>,
    report: &mut SanitizeReport,
) -> Result<()> {
    backup_file(path, backup_dir, report)?;
    write_file_atomic(path, bytes)?;
    Ok(())
}

fn backup_sqlite(
    path: &Path,
    backup_dir: Option<&Path>,
    report: &mut SanitizeReport,
) -> Result<()> {
    backup_file(path, backup_dir, report)?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = append_os_suffix(path, suffix);
        if sidecar.exists() {
            backup_file(&sidecar, backup_dir, report)?;
        }
    }
    Ok(())
}

fn backup_file(path: &Path, backup_dir: Option<&Path>, report: &mut SanitizeReport) -> Result<()> {
    let Some(backup_dir) = backup_dir else {
        return Ok(());
    };
    let digest = path_digest(path);
    let file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("file"));
    let backup_path = backup_dir.join(digest).join(file_name);
    if let Some(parent) = backup_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(path, &backup_path)?;
    report.backups.push(BackupRecord {
        source: path.to_path_buf(),
        backup: backup_path,
    });
    Ok(())
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "crebro-file".to_string());
    let tmp = parent.join(format!(".{file_name}.crebro-tmp-{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    if let Ok(metadata) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp, metadata.permissions());
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn record_pattern_findings(
    report: &mut SanitizeReport,
    path: &Path,
    patterns: &[UnregisteredPattern],
) {
    for pattern in patterns {
        report.unregistered_pattern_matches.push(PatternFinding {
            path: path.to_path_buf(),
            pattern_id: pattern.pattern_id.clone(),
            action: pattern_action(pattern.action).to_string(),
        });
    }
}

fn report_error(report: &mut SanitizeReport, path: &Path, error: impl std::error::Error) {
    report.errors.push(SanitizeErrorReport {
        path: path.to_path_buf(),
        error: error.to_string(),
    });
}

fn default_agent_paths(agent: SanitizeAgent) -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    match agent {
        SanitizeAgent::Codex => {
            let codex = home.join(".codex");
            vec![
                codex.join("sessions"),
                codex.join("archived_sessions"),
                codex.join("history.jsonl"),
                codex.join("session_index.jsonl"),
                codex.join("logs_2.sqlite"),
                codex.join("state_5.sqlite"),
            ]
        }
        SanitizeAgent::Claude => {
            let claude = home.join(".claude");
            vec![
                claude.join("projects"),
                claude.join("transcripts"),
                claude.join("sessions"),
                claude.join("history.jsonl"),
            ]
        }
        SanitizeAgent::Gemini => {
            let gemini = home.join(".gemini");
            vec![
                gemini.join("history"),
                gemini.join("tmp"),
                gemini.join("antigravity").join("brain"),
                gemini.join("antigravity").join("conversations"),
                gemini.join("antigravity").join("implicit"),
            ]
        }
        SanitizeAgent::Opencode => {
            let opencode = home.join(".local").join("share").join("opencode");
            vec![opencode.join("storage"), opencode.join("opencode.db")]
        }
    }
}

fn resolve_backup_dir(configured: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = configured {
        return Ok(path.to_path_buf());
    }
    let home = home_dir()
        .ok_or_else(|| CrebroError::Config("HOME is not set; pass --backup-dir".into()))?;
    Ok(home
        .join(".crebro")
        .join("backups")
        .join("conversations")
        .join(now_unix().to_string()))
}

fn is_candidate_text_path(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|name| name.to_str())
        && matches!(name, "history.jsonl" | "session_index.jsonl")
    {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("json" | "jsonl" | "md" | "txt" | "log" | "toml" | "yaml" | "yml")
    )
}

fn is_candidate_binary_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("pb" | "bin")
    )
}

fn is_sqlite_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("sqlite" | "db")
    )
}

fn should_skip_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "node_modules" | "target" | "vendor")
    )
}

fn unsupported_binary_patterns(bytes: &[u8], patterns: &CredentialPatternSet) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut ids = BTreeSet::new();
    for matched in patterns.auto_redact_matches(&text) {
        ids.insert(matched.pattern_id);
    }
    for matched in patterns.inspect_unregistered_text(&text) {
        ids.insert(matched.id);
    }
    ids.into_iter().collect()
}

fn select_replacement_spans(mut spans: Vec<ReplacementSpan>) -> Vec<ReplacementSpan> {
    spans.sort_by(|left, right| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.secret_id.cmp(&right.secret_id))
    });

    let mut selected: Vec<ReplacementSpan> = Vec::new();
    'candidate: for span in spans {
        for existing in &selected {
            if existing.overlaps(&span) {
                continue 'candidate;
            }
        }
        selected.push(span);
    }
    selected.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.len().cmp(&left.len()))
            .then_with(|| left.secret_id.cmp(&right.secret_id))
    });
    selected
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn random_ascii(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    for byte in &mut bytes {
        let index = (OsRng.next_u32() as usize) % REPLACEMENT_ALPHABET.len();
        *byte = REPLACEMENT_ALPHABET[index];
    }
    bytes
}

fn normalized_path_key(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn path_digest(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn append_os_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = OsString::from(path.as_os_str());
    os.push(suffix);
    PathBuf::from(os)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn pattern_action(action: OnUnregisteredMatch) -> &'static str {
    match action {
        OnUnregisteredMatch::RequireExplicitSecret => "require_explicit_secret",
        OnUnregisteredMatch::AutoRedact => "auto_redact",
        OnUnregisteredMatch::Allow => "allow",
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> ConversationSanitizer {
        ConversationSanitizer::with_patterns(CredentialPatternSet::builtin())
    }

    #[test]
    fn text_replacement_is_same_length_and_stable() {
        let mut engine = engine();
        engine
            .ingest(
                SecretLabel::new("OPENAI_API_KEY"),
                SecureBuf::from_slice(b"sk-stable-secret-1234567890"),
            )
            .unwrap();

        let result = engine
            .sanitize_text(
                "first sk-stable-secret-1234567890 second sk-stable-secret-1234567890",
                false,
            )
            .unwrap();

        assert!(!result.text.contains("sk-stable-secret-1234567890"));
        let parts = result.text.split_whitespace().collect::<Vec<_>>();
        assert_eq!(parts[1], parts[3]);
        assert_eq!(parts[1].len(), "sk-stable-secret-1234567890".len());
        assert_eq!(result.redactions, 2);
    }

    #[test]
    fn user_directive_is_replaced_without_tags() {
        let mut engine = engine();
        let result = engine
            .sanitize_text(
                "use <cb>manual-secret-1234567890</cb> then manual-secret-1234567890",
                false,
            )
            .unwrap();

        assert!(!result.text.contains("manual-secret-1234567890"));
        assert!(!result.text.contains("<cb>"));
        assert!(!result.text.contains("CREBRO_SECRET"));
        assert_eq!(result.redactions, 2);
    }

    #[test]
    fn auto_redact_patterns_are_replaced_with_random_values() {
        let mut engine = engine();
        let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
        let result = engine
            .sanitize_text(&format!("send {secret}"), false)
            .unwrap();

        assert!(!result.text.contains(secret));
        assert!(!result.text.contains("CREBRO_SECRET"));
        assert_eq!(result.redactions, 1);
        assert_eq!(result.text.trim_start_matches("send ").len(), secret.len());
    }
}
