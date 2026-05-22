use crebro::{
    hardening,
    secrets::{
        SecretLabel, SecretRegistry, SecureBuf, SessionKeys, discover_dotenv_candidates,
        discover_env_candidates, is_secret_candidate,
    },
};

#[test]
fn secure_buf_zeroizes() {
    let mut buf = SecureBuf::from_slice(b"super-secret-value");
    assert_eq!(buf.expose(), b"super-secret-value");
    buf.zeroize_now();
    assert!(buf.expose().iter().all(|byte| *byte == 0));
}

#[test]
fn capsule_and_registry_do_not_expose_plaintext_after_ingest() {
    let raw_secret = "ghp_real_secret_1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let id = registry
        .ingest(
            SecretLabel::new("GITHUB_TOKEN"),
            SecureBuf::from_slice(raw_secret.as_bytes()),
        )
        .unwrap();

    let debug = format!("{registry:?}");
    assert!(!debug.contains(raw_secret));
    assert!(!debug.contains("by_len_and_prefilter"));
    assert!(!debug.contains("by_placeholder"));
    assert!(debug.contains("RollingFingerprint(..)"));
    assert!(debug.contains("KeyedDigest(..)"));

    let entry = registry.entry(id).unwrap();
    assert!(
        !entry
            .capsule
            .ciphertext()
            .windows(raw_secret.len())
            .any(|window| { window == raw_secret.as_bytes() })
    );

    let mut restored = Vec::new();
    registry.restore_to_vec(id, &mut restored).unwrap();
    assert_eq!(restored, raw_secret.as_bytes());
}

#[test]
fn placeholder_is_stable_within_session_and_unstable_across_sessions() {
    let raw_secret = b"sk-session-secret-1234567890";

    let mut registry = SecretRegistry::new(SessionKeys::generate());
    let id1 = registry
        .ingest(
            SecretLabel::new("OPENAI_API_KEY"),
            SecureBuf::from_slice(raw_secret),
        )
        .unwrap();
    let id2 = registry
        .ingest(
            SecretLabel::new("OPENAI_API_KEY"),
            SecureBuf::from_slice(raw_secret),
        )
        .unwrap();
    assert_eq!(id1, id2);
    let placeholder1 = registry.placeholder_for(id1).unwrap().as_str().to_string();

    let mut second_registry = SecretRegistry::new(SessionKeys::generate());
    let second_id = second_registry
        .ingest(
            SecretLabel::new("OPENAI_API_KEY"),
            SecureBuf::from_slice(raw_secret),
        )
        .unwrap();
    let placeholder2 = second_registry
        .placeholder_for(second_id)
        .unwrap()
        .as_str()
        .to_string();

    assert_ne!(placeholder1, placeholder2);
}

#[test]
fn secret_candidate_filtering_accepts_keys_and_rejects_common_values() {
    assert!(is_secret_candidate(
        "OPENAI_API_KEY",
        b"sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
    ));
    assert!(is_secret_candidate(
        "DATABASE_URL",
        b"postgres://user:password@localhost/db"
    ));
    assert!(is_secret_candidate(
        "NEXTAUTH_SECRET",
        b"next-auth-secret-1234567890"
    ));
    assert!(is_secret_candidate(
        "PGPASSWORD",
        b"postgres-password-1234567890"
    ));
    assert!(is_secret_candidate(
        "MONGODB_URI",
        b"mongodb://user:password@example.com/app"
    ));
    assert!(is_secret_candidate(
        "SLACK_WEBHOOK_URL",
        b"https://hooks.slack.com/services/T000/B000/secret"
    ));
    assert!(is_secret_candidate(
        "KUBECONFIG_DATA",
        b"apiVersion: v1\nusers:\n- token: secret-token"
    ));
    assert!(is_secret_candidate(
        "GOOGLE_APPLICATION_CREDENTIALS_JSON",
        br#"{"private_key":"-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"}"#
    ));
    assert!(!is_secret_candidate("NODE_ENV", b"development"));
    assert!(!is_secret_candidate("PORT", b"3000"));
    assert!(!is_secret_candidate("DEBUG", b"true"));
    assert!(!is_secret_candidate("API_KEY", b"short"));
    assert!(!is_secret_candidate("OPENAI_API_KEY", b"your_api_key_here"));
    assert!(!is_secret_candidate("WEBHOOK_SECRET", b"dummy-secret"));
    assert!(!is_secret_candidate(
        "MYSQL_PWD",
        b"replace_with_your_api_key"
    ));
    assert!(!is_secret_candidate(
        "PIP_INDEX_URL",
        b"https://pypi.org/simple"
    ));
    assert!(!is_secret_candidate(
        "SERVICE_ACCOUNT_EMAIL",
        b"bot@example.iam.gserviceaccount.com"
    ));
    assert!(!is_secret_candidate(
        "AWS_SHARED_CREDENTIALS_FILE",
        b"/Users/me/.aws/credentials"
    ));
    assert!(!is_secret_candidate(
        "SENTRY_DSN",
        b"https://public@example.ingest.sentry.io/1"
    ));
}

#[test]
fn hardening_runs_and_reports_attempted_operations() {
    let status = hardening::harden_process();
    assert!(status.attempted.contains(&"setrlimit_core_zero") || !status.unsupported.is_empty());
}

#[test]
fn env_discovery_respects_max_count() {
    let candidates = discover_env_candidates(1);
    assert!(candidates.len() <= 1);
}

#[test]
fn dotenv_discovery_reads_secret_candidates_without_required_file() {
    let missing = std::env::temp_dir().join("crebro-missing-env-file");
    assert!(discover_dotenv_candidates(&missing, 10).unwrap().is_empty());

    let path = std::env::temp_dir().join(format!("crebro-test-{}.env", std::process::id()));
    std::fs::write(
        &path,
        b"NODE_ENV=development\nexport OPENAI_API_KEY=sk-dotenv-secret-1234567890\n",
    )
    .unwrap();
    let candidates = discover_dotenv_candidates(&path, 10).unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(candidates.len(), 1);
    assert_eq!(
        format!("{:?}", candidates[0].label),
        "SecretLabel(\"OPENAI_API_KEY\")"
    );
}
