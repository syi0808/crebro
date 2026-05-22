use crate::{
    CrebroError, Result,
    secrets::{SecretLabel, SecretRegistry, SecureBuf},
};

pub(crate) const OPEN_TAG: &str = "<cb>";
pub(crate) const CLOSE_TAG: &str = "</cb>";

const USER_DIRECTIVE_LABEL: &str = "USER";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectivePart<'a> {
    Plain(&'a str),
    Placeholder(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectiveReplacement<'a> {
    pub(crate) parts: Vec<DirectivePart<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedPart {
    Plain { start: usize, end: usize },
    Secret { start: usize, end: usize },
}

pub(crate) fn parse_user_secret_directives<'a>(
    input: &'a str,
    registry: &mut SecretRegistry,
) -> Result<Option<DirectiveReplacement<'a>>> {
    if !input.contains(OPEN_TAG) && !input.contains(CLOSE_TAG) {
        return Ok(None);
    }

    let parsed = parse_ranges(input)?;
    if parsed
        .iter()
        .all(|part| matches!(part, ParsedPart::Plain { .. }))
    {
        return Ok(None);
    }

    let mut parts = Vec::with_capacity(parsed.len());
    for part in parsed {
        match part {
            ParsedPart::Plain { start, end } => {
                if start < end {
                    parts.push(DirectivePart::Plain(&input[start..end]));
                }
            }
            ParsedPart::Secret { start, end } => {
                let secret = &input[start..end];
                let id = registry.ingest(
                    SecretLabel::new(USER_DIRECTIVE_LABEL),
                    SecureBuf::from_slice(secret.as_bytes()),
                )?;
                let placeholder = registry
                    .placeholder_for(id)
                    .ok_or_else(|| {
                        CrebroError::Redaction("registered directive secret is missing".into())
                    })?
                    .as_str()
                    .to_string();
                parts.push(DirectivePart::Placeholder(placeholder));
            }
        }
    }

    Ok(Some(DirectiveReplacement { parts }))
}

pub(crate) fn might_contain_directive_bytes(bytes: &[u8]) -> bool {
    contains_bytes(bytes, OPEN_TAG.as_bytes())
        || contains_bytes(bytes, CLOSE_TAG.as_bytes())
        || contains_ascii_case_insensitive(bytes, b"\\u003c")
}

fn parse_ranges(input: &str) -> Result<Vec<ParsedPart>> {
    let mut parts = Vec::new();
    let mut cursor = 0usize;

    while cursor < input.len() {
        let rest = &input[cursor..];
        let next_open = rest.find(OPEN_TAG).map(|index| cursor + index);
        let next_close = rest.find(CLOSE_TAG).map(|index| cursor + index);

        match (next_open, next_close) {
            (None, None) => {
                parts.push(ParsedPart::Plain {
                    start: cursor,
                    end: input.len(),
                });
                break;
            }
            (None, Some(_)) => {
                return Err(CrebroError::Redaction(
                    "stray </cb> secret directive close tag".into(),
                ));
            }
            (Some(open), Some(close)) if close < open => {
                return Err(CrebroError::Redaction(
                    "stray </cb> secret directive close tag".into(),
                ));
            }
            (Some(open), _) => {
                if cursor < open {
                    parts.push(ParsedPart::Plain {
                        start: cursor,
                        end: open,
                    });
                }

                let secret_start = open + OPEN_TAG.len();
                let Some(close_rel) = input[secret_start..].find(CLOSE_TAG) else {
                    return Err(CrebroError::Redaction(
                        "unclosed <cb> secret directive".into(),
                    ));
                };
                let secret_end = secret_start + close_rel;
                let secret = &input[secret_start..secret_end];
                if secret.is_empty() {
                    return Err(CrebroError::Redaction("empty <cb> secret directive".into()));
                }
                if secret.contains(OPEN_TAG) {
                    return Err(CrebroError::Redaction(
                        "nested <cb> secret directive".into(),
                    ));
                }
                parts.push(ParsedPart::Secret {
                    start: secret_start,
                    end: secret_end,
                });
                cursor = secret_end + CLOSE_TAG.len();
            }
        }
    }

    Ok(parts)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}
