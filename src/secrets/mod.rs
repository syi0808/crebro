pub mod capsule;
pub mod discovery;
pub mod fingerprint;
pub mod placeholder;
pub mod registry;
pub mod secure_buf;

pub use capsule::{SecretCapsule, SessionKeys};
pub use discovery::{
    SecretCandidate, discover_dotenv_candidates, discover_dotenv_candidates_with_patterns,
    discover_env_candidates, discover_env_candidates_with_patterns, is_secret_candidate,
    is_secret_candidate_with_patterns,
};
pub use placeholder::Placeholder;
pub use registry::{SecretId, SecretLabel, SecretRegistry};
pub use secure_buf::SecureBuf;
