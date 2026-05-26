use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crebro::{
    CrebroError,
    redact::SanitizerReport,
    secrets::{SecretLabel, SecretRegistry, SecureBuf},
    stats::{StatsRecorder, stats_path},
};
use serde_json::Value;

#[test]
fn stats_path_appends_stats_json_to_override_dir() {
    let dir = Path::new("crebro-custom-stats");

    assert_eq!(stats_path(Some(dir)), Some(dir.join("stats.json")));
}

#[test]
fn recorder_ignores_empty_reports_without_creating_file() {
    let dir = unique_temp_dir("empty-stats");
    let stats_file = dir.join("stats.json");
    let recorder = StatsRecorder::new(Some(stats_file.clone()));
    let registry = SecretRegistry::with_generated_keys();

    recorder.record_sanitizer_report(&registry, &SanitizerReport::default());

    assert!(!stats_file.exists());
}

#[test]
fn recorder_accumulates_secret_redaction_counts_without_raw_secret() {
    let dir = unique_temp_dir("secret-counts");
    let stats_file = dir.join("stats.json");
    let recorder = StatsRecorder::new(Some(stats_file.clone()));
    let mut registry = SecretRegistry::with_generated_keys();
    let raw_secret = "sk-stats-secret-1234567890";
    let secret_id = registry
        .ingest(
            SecretLabel::new("OPENAI_API_KEY"),
            SecureBuf::from_slice(raw_secret.as_bytes()),
        )
        .unwrap();
    let placeholder = registry
        .placeholder_for(secret_id)
        .unwrap()
        .as_str()
        .to_string();
    let report = SanitizerReport {
        redacted_secret_ids: vec![secret_id],
        ..SanitizerReport::default()
    };

    recorder.record_sanitizer_report(&registry, &report);
    recorder.record_sanitizer_report(&registry, &report);

    let stats_text = fs::read_to_string(&stats_file).unwrap();
    assert!(!stats_text.contains(raw_secret));
    let stats = parse_stats(&stats_file);
    let counter = stats["secret_redactions"]
        .as_object()
        .unwrap()
        .get(&placeholder)
        .unwrap();
    assert_eq!(counter["label"], "OPENAI_API_KEY");
    assert_eq!(counter["count"], 2);
    assert_eq!(stats["version"], 1);
    assert!(stats["updated_at_unix"].as_u64().unwrap() > 0);
}

#[test]
fn recorder_accumulates_allowed_pattern_counts() {
    let dir = unique_temp_dir("allow-counts");
    let stats_file = dir.join("stats.json");
    let recorder = StatsRecorder::new(Some(stats_file.clone()));
    let registry = SecretRegistry::with_generated_keys();
    let report = SanitizerReport {
        unregistered_pattern_ids: vec!["public_project_id".to_string()],
        ..SanitizerReport::default()
    };

    recorder.record_sanitizer_report(&registry, &report);
    recorder.record_sanitizer_report(&registry, &report);

    let stats = parse_stats(&stats_file);
    let counter = &stats["unregistered_pattern_matches"]["public_project_id"];
    assert_eq!(counter["on_unregistered_match"], "allow");
    assert_eq!(counter["count"], 2);
}

#[test]
fn recorder_records_unregistered_credential_errors() {
    let dir = unique_temp_dir("reject-counts");
    let stats_file = dir.join("stats.json");
    let recorder = StatsRecorder::new(Some(stats_file.clone()));
    let error = CrebroError::UnregisteredCredential {
        pattern_id: "provider_api_key".to_string(),
    };

    recorder.record_error(&error);
    recorder.record_error(&error);
    recorder.record_error(&CrebroError::Config("not recorded".to_string()));

    let stats = parse_stats(&stats_file);
    let counter = &stats["unregistered_pattern_matches"]["provider_api_key"];
    assert_eq!(counter["on_unregistered_match"], "require_explicit_secret");
    assert_eq!(counter["count"], 2);
}

fn parse_stats(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("crebro-{label}-{}-{nanos}", std::process::id()))
}
