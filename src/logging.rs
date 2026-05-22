use tracing_subscriber::{EnvFilter, fmt};

pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("crebro=info,warn"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}
