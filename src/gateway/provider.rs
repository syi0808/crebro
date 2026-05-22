#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFamily {
    OpenAi,
    Anthropic,
    Gemini,
    Unknown,
}

pub fn infer_provider_from_path(path: &str) -> ProviderFamily {
    if path.contains("/v1/messages") {
        ProviderFamily::Anthropic
    } else if is_gemini_path(path) {
        ProviderFamily::Gemini
    } else if path.contains("/v1/") {
        ProviderFamily::OpenAi
    } else {
        ProviderFamily::Unknown
    }
}

fn is_gemini_path(path: &str) -> bool {
    if path.contains("/v1beta/") {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.contains(":generatecontent")
        || lower.contains(":streamgeneratecontent")
        || lower.contains(":counttokens")
        || lower.contains(":embedcontent")
        || lower.contains(":batchembedcontents")
}

#[cfg(test)]
mod tests {
    use super::{ProviderFamily, infer_provider_from_path};

    #[test]
    fn infers_common_provider_routes() {
        assert_eq!(
            infer_provider_from_path("/v1/chat/completions"),
            ProviderFamily::OpenAi
        );
        assert_eq!(
            infer_provider_from_path("/v1/responses"),
            ProviderFamily::OpenAi
        );
        assert_eq!(
            infer_provider_from_path("/v1/messages"),
            ProviderFamily::Anthropic
        );
        assert_eq!(
            infer_provider_from_path("/v1beta/models/gemini-1.5-pro:generateContent"),
            ProviderFamily::Gemini
        );
    }

    #[test]
    fn infers_gemini_stable_v1_routes_before_openai_v1_fallback() {
        for path in [
            "/v1/models/gemini-1.5-pro:generateContent",
            "/v1/models/gemini-1.5-pro:streamGenerateContent",
            "/v1/models/gemini-1.5-pro:countTokens",
            "/v1/models/embedding-001:embedContent",
            "/v1/models/embedding-001:batchEmbedContents",
        ] {
            assert_eq!(infer_provider_from_path(path), ProviderFamily::Gemini);
        }
    }
}
