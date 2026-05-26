use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveMode {
    Native,
    Proxy,
}

pub fn resolve_effective_mode(command: &[String], has_provider_key: bool) -> EffectiveMode {
    if is_codex_command(command) && !has_provider_key {
        EffectiveMode::Proxy
    } else {
        EffectiveMode::Native
    }
}

pub fn is_codex_command(command: &[String]) -> bool {
    let Some(program) = command.first() else {
        return false;
    };
    let name = Path::new(program)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    name.contains("codex")
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
    fn auto_keeps_native_for_codex_with_provider_key() {
        assert_eq!(
            resolve_effective_mode(&["codex".to_string()], true),
            EffectiveMode::Native
        );
    }

    #[test]
    fn auto_keeps_native_for_other_commands() {
        assert_eq!(
            resolve_effective_mode(&["claude".to_string()], false),
            EffectiveMode::Native
        );
    }
}
