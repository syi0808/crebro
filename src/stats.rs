use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    CrebroError, patterns::OnUnregisteredMatch, redact::SanitizerReport, secrets::SecretRegistry,
};

#[derive(Debug, Clone)]
pub struct StatsRecorder {
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StatsFile {
    version: u32,
    updated_at_unix: u64,
    #[serde(default)]
    secret_redactions: BTreeMap<String, SecretRedactionCounter>,
    #[serde(default)]
    unregistered_pattern_matches: BTreeMap<String, PatternMatchCounter>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SecretRedactionCounter {
    label: String,
    count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatternMatchCounter {
    on_unregistered_match: String,
    count: u64,
}

impl Default for PatternMatchCounter {
    fn default() -> Self {
        Self {
            on_unregistered_match: "require_explicit_secret".to_string(),
            count: 0,
        }
    }
}

impl StatsRecorder {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    pub fn record_sanitizer_report(&self, registry: &SecretRegistry, report: &SanitizerReport) {
        if report.redacted_secret_ids.is_empty() && report.unregistered_pattern_ids.is_empty() {
            return;
        }
        self.update(|stats| {
            for id in &report.redacted_secret_ids {
                let Some((placeholder, label)) = registry.stats_identity_for(*id) else {
                    continue;
                };
                let counter = stats
                    .secret_redactions
                    .entry(placeholder.to_string())
                    .or_insert_with(|| SecretRedactionCounter {
                        label: label.to_string(),
                        count: 0,
                    });
                counter.label = label.to_string();
                counter.count = counter.count.saturating_add(1);
            }

            for pattern_id in &report.unregistered_pattern_ids {
                increment_pattern(stats, pattern_id, OnUnregisteredMatch::Allow);
            }
        });
    }

    pub fn record_error(&self, error: &CrebroError) {
        let CrebroError::UnregisteredCredential { pattern_id } = error else {
            return;
        };
        self.update(|stats| {
            increment_pattern(
                stats,
                pattern_id,
                OnUnregisteredMatch::RequireExplicitSecret,
            );
        });
    }

    fn update(&self, update: impl FnOnce(&mut StatsFile)) {
        let Some(path) = &self.path else {
            return;
        };
        if let Err(err) = update_stats_file(path, update) {
            tracing::warn!(error = %err, path = %path.display(), "failed to update crebro stats");
        }
    }
}

pub fn default_stats_path() -> Option<PathBuf> {
    stats_path(None)
}

pub fn stats_path(stats_dir: Option<&Path>) -> Option<PathBuf> {
    let dir = stats_dir
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("CREBRO_STATS_DIR").map(PathBuf::from))
        .or_else(|| Some(home_dir()?.join(".crebro")))?;
    Some(dir.join("stats.json"))
}

fn update_stats_file(path: &Path, update: impl FnOnce(&mut StatsFile)) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        set_private_dir_permissions(parent);
    }

    let mut stats = read_stats_file(path).unwrap_or_default();
    stats.version = 1;
    update(&mut stats);
    stats.updated_at_unix = now_unix();

    let bytes = serde_json::to_vec_pretty(&stats).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)?;
    set_private_file_permissions(path);
    Ok(())
}

fn read_stats_file(path: &Path) -> Option<StatsFile> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn increment_pattern(stats: &mut StatsFile, pattern_id: &str, action: OnUnregisteredMatch) {
    let action = action_name(action).to_string();
    let counter = stats
        .unregistered_pattern_matches
        .entry(pattern_id.to_string())
        .or_insert_with(|| PatternMatchCounter {
            on_unregistered_match: action.clone(),
            count: 0,
        });
    counter.on_unregistered_match = action;
    counter.count = counter.count.saturating_add(1);
}

fn action_name(action: OnUnregisteredMatch) -> &'static str {
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

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) {
    use std::{fs, os::unix::fs::PermissionsExt};

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) {}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) {
    use std::{fs, os::unix::fs::PermissionsExt};

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) {}
