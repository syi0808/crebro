use crebro::{cli, logging};

#[tokio::main]
async fn main() {
    logging::init();

    match cli::run().await {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            tracing::error!(error = %err, "crebro failed");
            std::process::exit(1);
        }
    }
}
