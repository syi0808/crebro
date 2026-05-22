use thiserror::Error;

pub type Result<T> = std::result::Result<T, CrebroError>;

#[derive(Debug, Error)]
pub enum CrebroError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("hardening error: {0}")]
    Hardening(String),
    #[error("secret error: {0}")]
    Secret(String),
    #[error("redaction error: {0}")]
    Redaction(String),
    #[error(
        "unregistered credential-like value matched pattern `{pattern_id}`; wrap it with <cb>...</cb> or register it through env/.env"
    )]
    UnregisteredCredential { pattern_id: String },
    #[error("restore error: {0}")]
    Restore(String),
    #[error("gateway error: {0}")]
    Gateway(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("child process error: {0}")]
    Child(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
