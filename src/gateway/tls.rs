use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::{CrebroError, Result};

pub fn build_upstream_client(tls_keylog_file: Option<&Path>) -> Result<reqwest::Client> {
    let Some(path) = tls_keylog_file else {
        return Ok(reqwest::Client::new());
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| CrebroError::Config(format!("invalid rustls protocol versions: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls.key_log = Arc::new(FileKeyLog::open(path)?);

    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .map_err(Into::into)
}

#[derive(Debug)]
struct FileKeyLog {
    file: Mutex<File>,
}

impl FileKeyLog {
    fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let Ok(mut file) = self.file.lock() else {
            tracing::warn!("failed to lock TLS key log file");
            return;
        };
        if let Err(err) = writeln!(
            file,
            "{} {} {}",
            label,
            hex::encode(client_random),
            hex::encode(secret)
        ) {
            tracing::warn!(error = %err, "failed to write TLS key log entry");
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::KeyLog;

    use super::FileKeyLog;

    #[test]
    fn file_key_log_writes_nss_compatible_line() {
        let path = std::env::temp_dir().join(format!(
            "crebro-keylog-{}-{}.keys",
            std::process::id(),
            unique_suffix()
        ));
        let key_log = FileKeyLog::open(&path).unwrap();
        key_log.log("CLIENT_RANDOM", &[0xab, 0xcd], &[0x12, 0x34]);
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(text, "CLIENT_RANDOM abcd 1234\n");
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
