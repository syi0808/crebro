use std::{collections::HashMap, path::PathBuf, process::ExitStatus};

use tokio::process::Command;

use crate::{CrebroError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyChildEnvConfig {
    pub proxy_url: String,
    pub ca_bundle_path: Option<PathBuf>,
}

pub fn proxy_child_env_overrides(config: &ProxyChildEnvConfig) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.extend([
        ("HTTPS_PROXY".to_string(), config.proxy_url.clone()),
        ("HTTP_PROXY".to_string(), config.proxy_url.clone()),
        ("https_proxy".to_string(), config.proxy_url.clone()),
        ("http_proxy".to_string(), config.proxy_url.clone()),
        ("NODE_USE_ENV_PROXY".to_string(), "1".to_string()),
        ("CREBRO_PROXY_URL".to_string(), config.proxy_url.clone()),
    ]);
    if let Some(path) = &config.ca_bundle_path {
        let ca_bundle_path = path.to_string_lossy().to_string();
        env.extend([
            ("SSL_CERT_FILE".to_string(), ca_bundle_path.clone()),
            ("NODE_EXTRA_CA_CERTS".to_string(), ca_bundle_path.clone()),
            ("REQUESTS_CA_BUNDLE".to_string(), ca_bundle_path.clone()),
            ("CURL_CA_BUNDLE".to_string(), ca_bundle_path.clone()),
            ("GIT_SSL_CAINFO".to_string(), ca_bundle_path.clone()),
            ("DENO_CERT".to_string(), ca_bundle_path),
        ]);
    }
    env
}

pub fn proxy_child_environment<I>(
    base_env: I,
    config: &ProxyChildEnvConfig,
) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env = base_env.into_iter().collect::<HashMap<_, _>>();
    env.extend(proxy_child_env_overrides(config));
    merge_loopback_no_proxy(&mut env, "NO_PROXY");
    merge_loopback_no_proxy(&mut env, "no_proxy");
    env
}

fn merge_loopback_no_proxy(env: &mut HashMap<String, String>, key: &str) {
    const LOOPBACKS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];
    let mut values = env
        .get(key)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for loopback in LOOPBACKS {
        if !values.iter().any(|value| value == loopback) {
            values.push(loopback.to_string());
        }
    }
    env.insert(key.to_string(), values.join(","));
}

pub fn build_child_command_with_env(
    command: &[String],
    child_env: HashMap<String, String>,
) -> Result<Command> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CrebroError::Child("missing child command".into()))?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    cmd.envs(child_env);
    Ok(cmd)
}

pub async fn run_child_with_env(
    command: &[String],
    child_env: HashMap<String, String>,
) -> Result<ExitStatus> {
    let status = build_child_command_with_env(command, child_env)?
        .status()
        .await
        .map_err(|err| CrebroError::Child(format!("failed to run child command: {err}")))?;
    Ok(status)
}
