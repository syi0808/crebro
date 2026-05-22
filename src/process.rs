use std::{collections::HashMap, env, process::ExitStatus};

use tokio::process::Command;

use zeroize::Zeroize;

use crate::{CrebroError, Result, secrets::SecureBuf};

pub const PROVIDER_KEY_ENV_NAMES: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY",
    "OPENCODE_API_KEY",
];

pub fn child_env_overrides(gateway_url: &str) -> HashMap<String, String> {
    let mut env = PROVIDER_KEY_ENV_NAMES
        .iter()
        .map(|key| ((*key).to_string(), "crebro-local-placeholder".to_string()))
        .collect::<HashMap<_, _>>();
    env.extend([
        ("OPENAI_BASE_URL".to_string(), gateway_url.to_string()),
        ("ANTHROPIC_BASE_URL".to_string(), gateway_url.to_string()),
        (
            "CLAUDE_CODE_API_BASE_URL".to_string(),
            gateway_url.to_string(),
        ),
        ("GEMINI_BASE_URL".to_string(), gateway_url.to_string()),
        (
            "GOOGLE_GEMINI_BASE_URL".to_string(),
            gateway_url.to_string(),
        ),
        ("CREBRO_GATEWAY_URL".to_string(), gateway_url.to_string()),
    ]);
    env
}

pub fn sanitized_environment<I>(base_env: I, gateway_url: &str) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env = base_env.into_iter().collect::<HashMap<_, _>>();
    for key in PROVIDER_KEY_ENV_NAMES {
        env.remove(*key);
    }
    env.extend(child_env_overrides(gateway_url));
    env
}

pub fn first_provider_key_from_env() -> Option<(String, SecureBuf)> {
    for key in PROVIDER_KEY_ENV_NAMES {
        let Ok(mut value) = env::var(key) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let buf = SecureBuf::from_slice(value.as_bytes());
        value.zeroize();
        return Some(((*key).to_string(), buf));
    }
    None
}

pub fn build_child_command(command: &[String], gateway_url: &str) -> Result<Command> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CrebroError::Child("missing child command".into()))?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    cmd.envs(sanitized_environment(env::vars(), gateway_url));
    Ok(cmd)
}

pub async fn run_child(command: &[String], gateway_url: &str) -> Result<ExitStatus> {
    let status = build_child_command(command, gateway_url)?
        .status()
        .await
        .map_err(|err| CrebroError::Child(format!("failed to run child command: {err}")))?;
    Ok(status)
}
