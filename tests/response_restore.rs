use crebro::{
    restore::{PlaceholderMatcher, ResponseRestorer},
    secrets::{SecretLabel, SecretRegistry, SecureBuf},
};

fn registry_with_secret() -> (SecretRegistry, String) {
    let raw_secret = b"sk-restore-secret-1234567890";
    let mut registry = SecretRegistry::with_generated_keys();
    let id = registry
        .ingest(
            SecretLabel::new("OPENAI_API_KEY"),
            SecureBuf::from_slice(raw_secret),
        )
        .unwrap();
    let placeholder = registry.placeholder_for(id).unwrap().as_str().to_string();
    (registry, placeholder)
}

#[test]
fn placeholder_matcher_finds_registered_placeholders() {
    let (registry, placeholder) = registry_with_secret();
    let matcher = PlaceholderMatcher::new(&registry).unwrap();
    let haystack = format!("before {placeholder} after");
    let matches = matcher.find_in(haystack.as_bytes());
    assert_eq!(matches.len(), 1);
}

#[test]
fn restores_placeholder_across_chunk_boundary() {
    let (registry, placeholder) = registry_with_secret();
    let split = placeholder.len() / 2;
    let mut restorer = ResponseRestorer::new(&registry).unwrap();
    let first = restorer
        .push_chunk(&placeholder.as_bytes()[..split], &registry)
        .unwrap();
    let second = restorer
        .push_chunk(&placeholder.as_bytes()[split..], &registry)
        .unwrap();
    let finish = restorer.finish(&registry).unwrap();
    let restored = [first, second, finish].concat();
    assert_eq!(restored, b"sk-restore-secret-1234567890");
}

#[test]
fn restores_adjacent_placeholders_and_plaintext_pass_through() {
    let (registry, placeholder) = registry_with_secret();
    let input = format!("a{placeholder}{placeholder}z");
    let mut restorer = ResponseRestorer::new(&registry).unwrap();
    let out = restorer.push_chunk(input.as_bytes(), &registry).unwrap();
    let tail = restorer.finish(&registry).unwrap();
    let restored = [out, tail].concat();

    assert_eq!(
        restored,
        b"ask-restore-secret-1234567890sk-restore-secret-1234567890z"
    );
}

#[test]
fn restores_placeholder_split_across_three_chunks() {
    let (registry, placeholder) = registry_with_secret();
    let first = placeholder.len() / 3;
    let second = placeholder.len() * 2 / 3;
    let mut restorer = ResponseRestorer::new(&registry).unwrap();
    let a = restorer
        .push_chunk(&placeholder.as_bytes()[..first], &registry)
        .unwrap();
    let b = restorer
        .push_chunk(&placeholder.as_bytes()[first..second], &registry)
        .unwrap();
    let c = restorer
        .push_chunk(&placeholder.as_bytes()[second..], &registry)
        .unwrap();
    let tail = restorer.finish(&registry).unwrap();
    let restored = [a, b, c, tail].concat();

    assert_eq!(restored, b"sk-restore-secret-1234567890");
}

#[test]
fn passes_through_partial_placeholder_prefix_on_finish() {
    let (registry, placeholder) = registry_with_secret();
    let partial = &placeholder.as_bytes()[..placeholder.len() / 2];
    let mut restorer = ResponseRestorer::new(&registry).unwrap();
    let first = restorer.push_chunk(partial, &registry).unwrap();
    let finish = restorer.finish(&registry).unwrap();
    let restored = [first, finish].concat();
    assert_eq!(restored, partial);
}
