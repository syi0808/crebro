pub fn join_upstream_url(base: &str, path_and_query: &str) -> String {
    let base = base.trim_end_matches('/');
    if path_and_query.starts_with('/') {
        format!("{base}{path_and_query}")
    } else {
        format!("{base}/{path_and_query}")
    }
}

#[cfg(test)]
mod tests {
    use super::join_upstream_url;

    #[test]
    fn joins_base_with_path_and_query_without_losing_provider_params() {
        assert_eq!(
            join_upstream_url("https://api.openai.com", "/v1/chat/completions?stream=true"),
            "https://api.openai.com/v1/chat/completions?stream=true"
        );
        assert_eq!(
            join_upstream_url(
                "https://generativelanguage.googleapis.com/",
                "/v1/models/gemini-1.5-pro:streamGenerateContent?alt=sse",
            ),
            "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            join_upstream_url("http://127.0.0.1:8080/proxy", "v1/messages"),
            "http://127.0.0.1:8080/proxy/v1/messages"
        );
    }
}
