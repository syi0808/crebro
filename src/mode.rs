use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveMode {
    Native,
    Proxy,
}

pub fn resolve_effective_mode(command: &[String], has_provider_key: bool) -> EffectiveMode {
    if is_default_auth_command(command) && !has_provider_key {
        EffectiveMode::Proxy
    } else {
        EffectiveMode::Native
    }
}

pub fn is_default_auth_command(command: &[String]) -> bool {
    let Some(program) = command.first() else {
        return false;
    };
    let name = Path::new(program)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    name.contains("codex")
        || name.contains("claude")
        || name.contains("gemini")
        || name.contains("opencode")
}

#[cfg(test)]
mod tests {
    use super::{EffectiveMode, resolve_effective_mode};

    #[test]
    fn auto_selects_proxy_for_codex_without_provider_key() {
        assert_eq!(
            resolve_effective_mode(&["/opt/bin/codex".to_string()], false),
            EffectiveMode::Proxy
        );
    }

    #[test]
    fn auto_selects_proxy_for_default_auth_agents_without_provider_key() {
        for command in ["codex", "claude", "gemini", "opencode"] {
            assert_eq!(
                resolve_effective_mode(&[command.to_string()], false),
                EffectiveMode::Proxy
            );
        }
    }

    #[test]
    fn auto_keeps_native_for_supported_agents_with_provider_key() {
        for command in ["codex", "claude", "gemini", "opencode"] {
            assert_eq!(
                resolve_effective_mode(&[command.to_string()], true),
                EffectiveMode::Native
            );
        }
    }

    #[test]
    fn auto_keeps_native_for_unknown_commands() {
        assert_eq!(
            resolve_effective_mode(&["custom-agent".to_string()], false),
            EffectiveMode::Native
        );
    }
}
