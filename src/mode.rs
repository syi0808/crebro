use std::path::Path;

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RuntimeMode {
    Auto,
    Native,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveMode {
    Native,
    Proxy,
}

impl RuntimeMode {
    pub fn resolve(self, command: &[String], has_provider_key: bool) -> EffectiveMode {
        match self {
            RuntimeMode::Native => EffectiveMode::Native,
            RuntimeMode::Proxy => EffectiveMode::Proxy,
            RuntimeMode::Auto => {
                if is_codex_command(command) && !has_provider_key {
                    EffectiveMode::Proxy
                } else {
                    EffectiveMode::Native
                }
            }
        }
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
    use super::{EffectiveMode, RuntimeMode};

    #[test]
    fn forced_modes_resolve_directly() {
        assert_eq!(
            RuntimeMode::Native.resolve(&["codex".to_string()], false),
            EffectiveMode::Native
        );
        assert_eq!(
            RuntimeMode::Proxy.resolve(&["claude".to_string()], true),
            EffectiveMode::Proxy
        );
    }

    #[test]
    fn auto_selects_proxy_for_codex_without_provider_key() {
        assert_eq!(
            RuntimeMode::Auto.resolve(&["/opt/bin/codex".to_string()], false),
            EffectiveMode::Proxy
        );
    }

    #[test]
    fn auto_keeps_native_for_codex_with_provider_key() {
        assert_eq!(
            RuntimeMode::Auto.resolve(&["codex".to_string()], true),
            EffectiveMode::Native
        );
    }

    #[test]
    fn auto_keeps_native_for_other_commands() {
        assert_eq!(
            RuntimeMode::Auto.resolve(&["claude".to_string()], false),
            EffectiveMode::Native
        );
    }
}
