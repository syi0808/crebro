use bytes::Bytes;
use crebro::{
    patterns::CredentialPatternSet,
    redact::{JsonSanitizer, RedactionCache, apply_spans, scan_string_token},
    secrets::{SecretLabel, SecretRegistry, SecureBuf},
};
use serde_json::json;
use std::sync::Arc;

fn registry_with(label: &str, secret: &[u8]) -> SecretRegistry {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(SecretLabel::new(label), SecureBuf::from_slice(secret))
        .unwrap();
    registry
}

#[test]
fn scanner_longest_match_first() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(SecretLabel::new("A"), SecureBuf::from_slice(b"abcdef"))
        .unwrap();
    registry
        .ingest(SecretLabel::new("B"), SecureBuf::from_slice(b"cde"))
        .unwrap();

    let spans = scan_string_token(b"xxabcdefyy", &registry).unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start, 2);
    assert_eq!(spans[0].len, 6);
    let out = apply_spans(b"xxabcdefyy", &spans);
    assert!(!String::from_utf8_lossy(&out).contains("abcdef"));
}

#[test]
fn scanner_longest_match_wins_even_when_later_overlap_starts_inside_shorter_secret() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(SecretLabel::new("SHORT"), SecureBuf::from_slice(b"abc"))
        .unwrap();
    registry
        .ingest(SecretLabel::new("LONG"), SecureBuf::from_slice(b"bcdefgh"))
        .unwrap();

    let spans = scan_string_token(b"abcdefgh", &registry).unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start, 1);
    assert_eq!(spans[0].len, 7);
    let out = apply_spans(b"abcdefgh", &spans);
    let out_text = String::from_utf8_lossy(&out);
    assert!(out_text.contains("a{{CREBRO_SECRET:v1:LONG:"));
    assert!(!out_text.contains("bcdefgh"));
}

#[test]
fn redacts_without_plaintext_secret_table() {
    let raw_secret = b"ghp_real_secret_1234567890";
    let registry = registry_with("GITHUB_TOKEN", raw_secret);
    let request = b"use ghp_real_secret_1234567890 now";
    let spans = scan_string_token(request, &registry).unwrap();
    let out = apply_spans(request, &spans);
    let out_text = String::from_utf8_lossy(&out);
    assert!(!out_text.contains("ghp_real_secret_1234567890"));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:GITHUB_TOKEN:"));
    assert!(!format!("{registry:?}").contains("ghp_real_secret_1234567890"));
}

#[test]
fn no_secret_cache_hit_skips_scan() {
    let registry = registry_with("OPENAI_API_KEY", b"sk-test-secret-1234567890");
    let mut cache = RedactionCache::new(32);
    let input = b"ordinary long prompt without the registered value";
    let first = cache.sanitize_string(input, &registry).unwrap();
    let stats_after_first = cache.stats();
    let second = cache.sanitize_string(input, &registry).unwrap();
    let stats_after_second = cache.stats();

    assert_eq!(first, second);
    assert_eq!(stats_after_first.scanner_runs, 1);
    assert_eq!(stats_after_second.scanner_runs, 1);
    assert_eq!(stats_after_second.hits, stats_after_first.hits + 1);
}

#[test]
fn span_cache_reuses_redaction_offsets() {
    let registry = registry_with("OPENAI_API_KEY", b"sk-test-secret-1234567890");
    let mut cache = RedactionCache::new(32);
    let input = b"secret sk-test-secret-1234567890 appears";
    let first = cache.sanitize_string(input, &registry).unwrap();
    let stats_after_first = cache.stats();
    let second = cache.sanitize_string(input, &registry).unwrap();
    let stats_after_second = cache.stats();

    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&second).contains("sk-test-secret-1234567890"));
    assert_eq!(stats_after_first.scanner_runs, 1);
    assert_eq!(stats_after_second.scanner_runs, 1);
    assert_eq!(stats_after_second.hits, stats_after_first.hits + 1);
}

#[test]
fn bounded_cache_evicts_least_recently_used_entry() {
    let registry = registry_with("OPENAI_API_KEY", b"sk-test-secret-1234567890");
    let mut cache = RedactionCache::new(2);
    let first = b"first ordinary prompt long enough";
    let second = b"second ordinary prompt long enough";
    let third = b"third ordinary prompt long enough";

    cache.sanitize_string(first, &registry).unwrap();
    cache.sanitize_string(second, &registry).unwrap();
    cache.sanitize_string(first, &registry).unwrap();
    let before_eviction = cache.stats();
    cache.sanitize_string(third, &registry).unwrap();
    let after_eviction = cache.stats();
    cache.sanitize_string(first, &registry).unwrap();
    let after_first_reuse = cache.stats();
    cache.sanitize_string(second, &registry).unwrap();
    let after_second_reuse = cache.stats();

    assert_eq!(after_eviction.evictions, before_eviction.evictions + 1);
    assert_eq!(after_first_reuse.hits, after_eviction.hits + 1);
    assert_eq!(
        after_second_reuse.scanner_runs,
        after_first_reuse.scanner_runs + 1
    );
}

#[test]
fn no_secret_cache_invalidates_on_registry_change() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(
            SecretLabel::new("FIRST"),
            SecureBuf::from_slice(b"first-secret-123456"),
        )
        .unwrap();
    let mut cache = RedactionCache::new(32);
    let input = b"contains second-secret-123456 but not the first";
    let first = cache.sanitize_string(input, &registry).unwrap();
    assert!(String::from_utf8_lossy(&first).contains("second-secret-123456"));

    registry
        .ingest(
            SecretLabel::new("SECOND"),
            SecureBuf::from_slice(b"second-secret-123456"),
        )
        .unwrap();
    let second = cache.sanitize_string(input, &registry).unwrap();
    assert!(!String::from_utf8_lossy(&second).contains("second-secret-123456"));
    assert!(cache.stats().flushes >= 2);
}

#[test]
fn json_sanitizer_redacts_string_tokens_only() {
    let mut registry = registry_with("GITHUB_TOKEN", b"ghp_real_secret_1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "messages": [
            {"role": "user", "content": "token ghp_real_secret_1234567890"},
            {"role": "assistant", "content": 42}
        ],
        "temperature": 0,
        "stream": true
    });
    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(!String::from_utf8_lossy(&out).contains("ghp_real_secret_1234567890"));
    assert_eq!(out_value["temperature"], 0);
    assert_eq!(out_value["stream"], true);
}

#[test]
fn field_policy_skips_known_binary_fields() {
    let mut registry = registry_with("TOKEN", b"secret-in-binary-field");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "contents": [{
            "parts": [{
                "inline_data": {
                    "mime_type": "image/png",
                    "data": "secret-in-binary-field"
                }
            }, {
                "text": "secret-in-binary-field"
            }]
        }]
    });
    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let stats_after_first = sanitizer.cache_stats();
    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        out_value["contents"][0]["parts"][0]["inline_data"]["data"],
        "secret-in-binary-field"
    );
    assert!(
        out_value["contents"][0]["parts"][1]["text"]
            .as_str()
            .unwrap()
            .contains("{{CREBRO_SECRET:v1:TOKEN:")
    );
    assert_eq!(stats_after_first.misses, 1);
    assert_eq!(stats_after_first.scanner_runs, 1);
}

#[test]
fn user_secret_directive_redacts_repeated_plaintext_in_same_string() {
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "messages": [{
            "role": "user",
            "content": "use <cb>manual-secret-1234567890</cb> and manual-secret-1234567890 again"
        }]
    });

    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_text = String::from_utf8_lossy(&out);

    assert!(!out_text.contains("manual-secret-1234567890"));
    assert!(!out_text.contains("<cb>"));
    assert!(!out_text.contains("</cb>"));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:USER:"));
    assert!(!format!("{registry:?}").contains("manual-secret-1234567890"));
}

#[test]
fn user_secret_directive_rejects_malformed_tags() {
    for content in [
        "use <cb>manual-secret-1234567890",
        "use manual-secret-1234567890</cb>",
        "use <cb></cb>",
        "use <cb>outer <cb>inner</cb></cb>",
    ] {
        let mut registry = SecretRegistry::with_generated_keys();
        let mut sanitizer = JsonSanitizer::new(64);
        let payload = json!({"messages": [{"role": "user", "content": content}]});
        let err = sanitizer
            .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
            .unwrap_err();

        assert!(
            err.to_string().contains("directive"),
            "unexpected error for {content:?}: {err}"
        );
    }
}

#[test]
fn user_secret_directive_does_not_rescan_inserted_placeholder() {
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "messages": [{
            "role": "user",
            "content": "<cb>CREBRO_SECRET</cb> then CREBRO_SECRET"
        }]
    });

    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_text = String::from_utf8_lossy(&out);

    assert!(out_text.contains("{{CREBRO_SECRET:v1:USER:"));
    assert!(!out_text.contains("{{{{CREBRO_SECRET"));
    serde_json::from_slice::<serde_json::Value>(&out).unwrap();
}

#[test]
fn field_policy_processes_user_secret_directives_in_known_binary_fields() {
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "contents": [{
            "parts": [{
                "inline_data": {
                    "mime_type": "image/png",
                    "data": "<cb>binary-secret-1234567890</cb>"
                }
            }, {
                "text": "<cb>text-secret-1234567890</cb>"
            }]
        }]
    });

    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();

    let binary_data = out_value["contents"][0]["parts"][0]["inline_data"]["data"]
        .as_str()
        .unwrap();
    assert!(!binary_data.contains("binary-secret-1234567890"));
    assert!(!binary_data.contains("<cb>"));
    assert!(binary_data.contains("{{CREBRO_SECRET:v1:USER:"));
    assert!(
        out_value["contents"][0]["parts"][1]["text"]
            .as_str()
            .unwrap()
            .contains("{{CREBRO_SECRET:v1:USER:")
    );
}

#[test]
fn custom_credential_pattern_requires_explicit_secret() {
    let patterns = Arc::new(
        CredentialPatternSet::from_toml(
            r#"
[env]
key_markers = ["KEY"]
common_values = ["true"]
min_value_len = 4
min_entropy = 1.0

[[credential_patterns]]
id = "test_credential"
regex = '''TESTCRED_[A-Za-z0-9]{8,}'''
on_unregistered_match = "require_explicit_secret"
"#,
        )
        .unwrap(),
    );
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::with_patterns(64, patterns);
    let payload = json!({
        "messages": [{"role": "user", "content": "send TESTCRED_ABC123456"}]
    });

    let err = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap_err();

    assert!(err.to_string().contains("test_credential"));
    assert!(!err.to_string().contains("TESTCRED_ABC123456"));
}

#[test]
fn user_secret_directive_satisfies_credential_pattern_detector() {
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    let payload = json!({
        "messages": [{"role": "user", "content": format!("send <cb>{secret}</cb>")}]
    });

    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_text = String::from_utf8_lossy(&out);

    assert!(!out_text.contains(secret));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:USER:"));
}

#[test]
fn built_in_credential_patterns_auto_redact_common_provider_prefixes() {
    let pypi_token = format!("pypi-{}", "A".repeat(85));
    let sendgrid_token = format!("SG.{}.{}", "A".repeat(22), "B".repeat(43));
    let cases = [
        (
            "github_fine_grained_pat",
            "github_pat_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "openai_modern_key",
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "anthropic_key",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "stripe_secret_or_restricted_key",
            "sk_live_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "stripe_webhook_secret",
            "whsec_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "npm_access_token",
            "npm_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        ("pypi_api_token", pypi_token),
        (
            "huggingface_token",
            "hf_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "linear_token",
            "lin_api_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "sentry_auth_token",
            "sntrys_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        ("sendgrid_api_key", sendgrid_token),
        (
            "supabase_secret_key",
            "sb_secret_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        (
            "cloudflare_api_credential_assignment",
            "CLOUDFLARE_API_TOKEN=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN".to_string(),
        ),
        (
            "private_key_block",
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                "A".repeat(64)
            ),
        ),
        (
            "credentialed_database_url",
            "postgres://alice:supersecret1234@example.com/db".to_string(),
        ),
    ];

    for (pattern_id, credential) in cases {
        let mut registry = SecretRegistry::with_generated_keys();
        let mut sanitizer = JsonSanitizer::new(64);
        let payload = json!({
            "messages": [{"role": "user", "content": format!("send {credential}")}]
        });

        let (out, report) = sanitizer
            .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        let expected_label = format!("AUTO_{}", pattern_id.to_ascii_uppercase());

        assert!(!out.contains(credential.as_str()));
        assert!(
            out.contains(&expected_label),
            "expected {expected_label}, got {out}"
        );
        assert!(!report.redacted_secret_ids.is_empty());
        assert!(report.unregistered_pattern_ids.is_empty());
    }
}

#[test]
fn built_in_suspicious_context_patterns_require_explicit_secret() {
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let credential = "cloudflare api token abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
    let payload = json!({
        "messages": [{"role": "user", "content": format!("send {credential}")}]
    });

    let err = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap_err();
    let err_text = err.to_string();

    assert!(err_text.contains("cloudflare_api_credential_context"));
    assert!(!err_text.contains(credential));
}

#[test]
fn built_in_auto_redacts_cloudflare_user_token() {
    let cloudflare_token = "cfut_9hfLomXE30g151Zm1HoX6OmDm5pao1C1zsNhlQeA5cfcd85f";
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "messages": [{"role": "user", "content": format!("send {cloudflare_token}")}]
    });

    let (out, report) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out = String::from_utf8(out).unwrap();

    assert!(!out.contains(cloudflare_token));
    assert!(out.contains("{{CREBRO_SECRET:v1:AUTO_CLOUDFLARE_USER_TOKEN:"));
    assert_eq!(report.redacted_secret_ids.len(), 1);
    assert!(report.unregistered_pattern_ids.is_empty());
}

#[test]
fn placeholder_guidance_is_injected_when_redaction_occurs() {
    let prompt = include_str!("../prompts/placeholder-guidance.md");
    let mut registry = registry_with("GITHUB_TOKEN", b"ghp_real_secret_1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "messages": [{"role": "user", "content": "send ghp_real_secret_1234567890"}]
    });

    let (out, report) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let out_text = String::from_utf8(out).unwrap();

    assert_eq!(out_value["messages"][0]["role"], "user");
    assert!(
        out_value["messages"][0]["content"]
            .as_str()
            .unwrap()
            .starts_with(prompt)
    );
    assert!(!out_text.contains("ghp_real_secret_1234567890"));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:GITHUB_TOKEN:"));
    assert!(!report.redacted_secret_ids.is_empty());
}

#[test]
fn placeholder_guidance_can_be_disabled() {
    let mut registry = registry_with("GITHUB_TOKEN", b"ghp_real_secret_1234567890");
    let mut sanitizer = JsonSanitizer::with_patterns_and_placeholder_guidance(
        64,
        CredentialPatternSet::builtin(),
        false,
    );
    let payload = json!({
        "messages": [{"role": "user", "content": "send ghp_real_secret_1234567890"}]
    });

    let (out, report) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_text = String::from_utf8(out).unwrap();

    assert!(!out_text.contains("Crebro replaced local secrets with safe placeholders"));
    assert!(!out_text.contains("ghp_real_secret_1234567890"));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:GITHUB_TOKEN:"));
    assert!(!report.redacted_secret_ids.is_empty());
}

#[test]
fn placeholder_guidance_uses_instructions_for_responses_payloads() {
    let prompt = include_str!("../prompts/placeholder-guidance.md");
    let mut registry = registry_with("OPENAI_API_KEY", b"openai-test-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "input": [{"role": "user", "content": "use openai-test-secret-1234567890"}]
    });

    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();

    assert_eq!(out_value["instructions"], prompt);
    assert!(
        out_value["input"][0]["content"]
            .as_str()
            .unwrap()
            .contains("{{CREBRO_SECRET:v1:OPENAI_API_KEY:")
    );
}

#[test]
fn placeholder_guidance_falls_back_to_prompt_field() {
    let prompt = include_str!("../prompts/placeholder-guidance.md");
    let mut registry = registry_with("PROMPT_TOKEN", b"prompt-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "prompt": "use prompt-secret-1234567890"
    });

    let (out, _) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();
    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let prompt_value = out_value["prompt"].as_str().unwrap();

    assert!(prompt_value.starts_with(prompt));
    assert!(!prompt_value.contains("prompt-secret-1234567890"));
    assert!(prompt_value.contains("{{CREBRO_SECRET:v1:PROMPT_TOKEN:"));
}

#[test]
fn built_in_structural_patterns_avoid_common_placeholders() {
    let cases = [
        "-----BEGIN PRIVATE KEY-----",
        "postgres://user:password@localhost/db",
    ];

    for content in cases {
        let mut registry = SecretRegistry::with_generated_keys();
        let mut sanitizer = JsonSanitizer::new(64);
        let payload = json!({
            "messages": [{"role": "user", "content": content}]
        });

        let (out, report) = sanitizer
            .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
            .unwrap();

        assert!(String::from_utf8_lossy(&out).contains(content));
        assert!(report.unregistered_pattern_ids.is_empty());
    }
}

#[test]
fn built_in_allow_patterns_report_without_blocking() {
    let google_key = format!("AIza{}", "A".repeat(35));
    let twilio_sid = format!("AC{}", "a".repeat(32));
    let cases = [
        (
            "openai_legacy_key",
            "sk-abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        ("aws_access_key_id", "AKIA1234567890ABCDEF".to_string()),
        (
            "stripe_publishable_key",
            "pk_live_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        ("google_api_key", google_key),
        (
            "supabase_publishable_key",
            "sb_publishable_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ),
        ("twilio_sid_identifier", twilio_sid),
    ];

    for (pattern_id, credential) in cases {
        let mut registry = SecretRegistry::with_generated_keys();
        let mut sanitizer = JsonSanitizer::new(64);
        let payload = json!({
            "messages": [{"role": "user", "content": format!("send {credential}")}]
        });

        let (out, report) = sanitizer
            .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
            .unwrap();

        assert!(String::from_utf8_lossy(&out).contains(credential.as_str()));
        assert!(
            report
                .unregistered_pattern_ids
                .contains(&pattern_id.to_string()),
            "missing allow report for {pattern_id}: {:?}",
            report.unregistered_pattern_ids
        );
    }
}

#[test]
fn allow_credential_pattern_reports_unregistered_match() {
    let patterns = Arc::new(
        CredentialPatternSet::from_toml(
            r#"
[env]
key_markers = ["KEY"]
common_values = ["true"]
min_value_len = 4
min_entropy = 1.0

[[credential_patterns]]
id = "allowed_test_credential"
regex = '''ALLOWCRED_[A-Za-z0-9]{8,}'''
on_unregistered_match = "allow"
"#,
        )
        .unwrap(),
    );
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::with_patterns(64, patterns);
    let payload = json!({
        "messages": [{"role": "user", "content": "send ALLOWCRED_ABC123456"}]
    });

    let (out, report) = sanitizer
        .sanitize_json(&serde_json::to_vec(&payload).unwrap(), &mut registry)
        .unwrap();

    assert!(String::from_utf8_lossy(&out).contains("ALLOWCRED_ABC123456"));
    assert_eq!(
        report.unregistered_pattern_ids,
        vec!["allowed_test_credential".to_string()]
    );
}

#[test]
fn tool_schema_cache_reuses_sanitized_output() {
    let mut registry = registry_with("TOOL_TOKEN", b"tool-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "tools": [{
            "name": "shell",
            "description": "do not leak tool-secret-1234567890",
            "parameters": {"type": "object"}
        }]
    });
    let body = serde_json::to_vec(&payload).unwrap();
    let (_, _) = sanitizer.sanitize_json(&body, &mut registry).unwrap();
    let stats_after_first = sanitizer.cache_stats();
    let (_, _) = sanitizer.sanitize_json(&body, &mut registry).unwrap();
    let stats_after_second = sanitizer.cache_stats();
    assert_eq!(
        stats_after_second.scanner_runs,
        stats_after_first.scanner_runs
    );
    assert!(stats_after_second.hits > stats_after_first.hits);
}

#[test]
fn message_object_cache_reuses_sanitized_output() {
    let mut registry = registry_with("MESSAGE_TOKEN", b"message-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "messages": [{
            "role": "user",
            "content": "do not leak message-secret-1234567890"
        }]
    });
    let body = serde_json::to_vec(&payload).unwrap();

    let (_, _) = sanitizer.sanitize_json(&body, &mut registry).unwrap();
    let stats_after_first = sanitizer.cache_stats();
    let (out, _) = sanitizer.sanitize_json(&body, &mut registry).unwrap();
    let stats_after_second = sanitizer.cache_stats();

    assert!(!String::from_utf8_lossy(&out).contains("message-secret-1234567890"));
    assert_eq!(
        stats_after_second.scanner_runs,
        stats_after_first.scanner_runs
    );
    assert!(stats_after_second.hits > stats_after_first.hits);
}

#[test]
fn sanitizer_debug_does_not_expose_cached_prompt_or_streaming_string_bytes() {
    let mut registry = registry_with("DEBUG_TOKEN", b"debug-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let payload = json!({
        "tools": [{
            "name": "shell",
            "description": "private prompt debug-secret-1234567890"
        }]
    });
    let body = serde_json::to_vec(&payload).unwrap();
    sanitizer.sanitize_json(&body, &mut registry).unwrap();

    let sanitizer_debug = format!("{sanitizer:?}");
    assert!(!sanitizer_debug.contains("private prompt"));
    assert!(!sanitizer_debug.contains("debug-secret-1234567890"));
    assert!(!sanitizer_debug.contains("{{CREBRO_SECRET"));

    let mut state = sanitizer.streaming_state();
    sanitizer
        .push_stream_chunk(
            &mut state,
            &Bytes::from_static(br#"{"messages":["debug-secret-1234567890"#),
            &mut registry,
        )
        .unwrap();
    let state_debug = format!("{state:?}");
    assert!(!state_debug.contains("debug-secret-1234567890"));
    assert!(state_debug.contains("raw_string_len"));
}

#[test]
fn chunk_cache_redacts_secret_across_large_string_boundary() {
    let registry = registry_with("BOUNDARY_TOKEN", b"boundary-secret-1234567890");
    let mut cache = RedactionCache::new_with_chunk_size(64, 1024);
    let mut input = vec![b'a'; 1010];
    input.extend_from_slice(b"boundary-secret-1234567890");
    input.extend_from_slice(&[b'z'; 1200]);

    let first = cache.sanitize_string(&input, &registry).unwrap();
    let stats_after_first = cache.stats();
    let second = cache.sanitize_string(&input, &registry).unwrap();
    let stats_after_second = cache.stats();

    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&second).contains("boundary-secret-1234567890"));
    assert!(String::from_utf8_lossy(&second).contains("{{CREBRO_SECRET:v1:BOUNDARY_TOKEN:"));
    assert_eq!(
        stats_after_second.scanner_runs,
        stats_after_first.scanner_runs
    );
    assert!(stats_after_second.hits > stats_after_first.hits);
}

#[test]
fn chunk_cache_resolves_overlapping_spans_across_windows_longest_first() {
    let mut registry = SecretRegistry::with_generated_keys();
    registry
        .ingest(SecretLabel::new("SHORT"), SecureBuf::from_slice(b"abc"))
        .unwrap();
    registry
        .ingest(SecretLabel::new("LONG"), SecureBuf::from_slice(b"bcdefgh"))
        .unwrap();
    let mut cache = RedactionCache::new_with_chunk_size(64, 1024);
    let mut input = vec![b'x'; 1023];
    input.extend_from_slice(b"abcdefgh");
    input.extend_from_slice(&[b'y'; 1200]);

    let out = cache.sanitize_string(&input, &registry).unwrap();
    let out_text = String::from_utf8_lossy(&out);

    assert!(out_text.contains("a{{CREBRO_SECRET:v1:LONG:"));
    assert!(!out_text.contains("bcdefgh"));
    assert_eq!(cache.stats().scanner_runs, 3);
}

#[test]
fn streaming_json_sanitizer_redacts_string_split_across_chunks() {
    let mut registry = registry_with("STREAM_TOKEN", b"stream-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let mut state = sanitizer.streaming_state();
    let mut out = Vec::new();

    for chunk in [
        Bytes::from_static(br#"{"messages":["prefix stream-"#),
        Bytes::from_static(br#"secret-1234567890 suffix"]}"#),
    ] {
        out.extend(
            sanitizer
                .push_stream_chunk(&mut state, &chunk, &mut registry)
                .unwrap(),
        );
    }
    out.extend(sanitizer.finish_stream(state, &mut registry).unwrap().0);

    let out_text = String::from_utf8_lossy(&out);
    assert!(!out_text.contains("stream-secret-1234567890"));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:STREAM_TOKEN:"));
    serde_json::from_slice::<serde_json::Value>(&out).unwrap();
}

#[test]
fn streaming_json_sanitizer_handles_user_secret_directive_split_across_chunks() {
    let mut registry = SecretRegistry::with_generated_keys();
    let mut sanitizer = JsonSanitizer::new(64);
    let mut state = sanitizer.streaming_state();
    let mut out = Vec::new();

    for chunk in [
        Bytes::from_static(br#"{"messages":["prefix <cb>manual-"#),
        Bytes::from_static(br#"secret-1234567890</cb> and manual-secret-1234567890"]}"#),
    ] {
        out.extend(
            sanitizer
                .push_stream_chunk(&mut state, &chunk, &mut registry)
                .unwrap(),
        );
    }
    out.extend(sanitizer.finish_stream(state, &mut registry).unwrap().0);

    let out_text = String::from_utf8_lossy(&out);
    assert!(!out_text.contains("manual-secret-1234567890"));
    assert!(!out_text.contains("<cb>"));
    assert!(!out_text.contains("</cb>"));
    assert!(out_text.contains("{{CREBRO_SECRET:v1:USER:"));
    serde_json::from_slice::<serde_json::Value>(&out).unwrap();
}

#[test]
fn streaming_json_sanitizer_empty_registry_forwards_bytes_unchanged() {
    let mut registry = SecretRegistry::with_generated_keys();
    let patterns = Arc::new(
        CredentialPatternSet::from_toml(
            r#"
[env]
key_markers = ["KEY"]
common_values = ["true"]
min_value_len = 4
min_entropy = 1.0
"#,
        )
        .unwrap(),
    );
    let mut sanitizer = JsonSanitizer::with_patterns(64, patterns);
    let mut state = sanitizer.streaming_state();
    let mut out = Vec::new();

    for chunk in [
        Bytes::from_static(br#"{"message":"keeps\noriginal\u0020escapes","#),
        Bytes::from_static(br#""unterminated_for_parser_fast_path""#),
    ] {
        out.extend(
            sanitizer
                .push_stream_chunk(&mut state, &chunk, &mut registry)
                .unwrap(),
        );
    }
    out.extend(sanitizer.finish_stream(state, &mut registry).unwrap().0);

    assert_eq!(
        out,
        br#"{"message":"keeps\noriginal\u0020escapes","unterminated_for_parser_fast_path""#
    );
}

#[test]
fn streaming_json_sanitizer_honors_binary_field_policy() {
    let mut registry = registry_with("STREAM_BINARY_TOKEN", b"stream-binary-secret-1234567890");
    let mut sanitizer = JsonSanitizer::new(64);
    let mut state = sanitizer.streaming_state();
    let mut out = Vec::new();

    for chunk in [
        Bytes::from_static(br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"image/png","data":"stream-binary-"#),
        Bytes::from_static(br#"secret-1234567890"}},{"text":"stream-binary-secret-1234567890"}]}]}"#),
    ] {
        out.extend(
            sanitizer
                .push_stream_chunk(&mut state, &chunk, &mut registry)
                .unwrap(),
        );
    }
    out.extend(sanitizer.finish_stream(state, &mut registry).unwrap().0);

    let out_value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        out_value["contents"][0]["parts"][0]["inline_data"]["data"],
        "stream-binary-secret-1234567890"
    );
    assert!(
        out_value["contents"][0]["parts"][1]["text"]
            .as_str()
            .unwrap()
            .contains("{{CREBRO_SECRET:v1:STREAM_BINARY_TOKEN:")
    );
}
