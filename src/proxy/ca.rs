use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
};

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use crate::{CrebroError, Result};

pub struct LocalCa {
    cert: Certificate,
    key_pair: KeyPair,
    pem_path: PathBuf,
}

impl LocalCa {
    pub fn generate_session() -> Result<Self> {
        let key_pair = KeyPair::generate().map_err(|err| {
            CrebroError::Gateway(format!("failed to generate local CA key: {err}"))
        })?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).map_err(|err| {
            CrebroError::Gateway(format!("failed to generate local CA certificate: {err}"))
        })?;
        let pem_path = default_ca_pem_path();
        if let Some(parent) = pem_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private_file(&pem_path, cert.pem().as_bytes())?;
        Ok(Self {
            cert,
            key_pair,
            pem_path,
        })
    }

    pub fn pem_path(&self) -> &PathBuf {
        &self.pem_path
    }

    pub fn root_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    pub fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let leaf_key = KeyPair::generate().map_err(|err| {
            CrebroError::Gateway(format!("failed to generate MITM leaf key: {err}"))
        })?;
        let params = CertificateParams::new(vec![host.to_string()]).map_err(|err| {
            CrebroError::Gateway(format!("failed to build MITM leaf params: {err}"))
        })?;
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key_pair)
            .map_err(|err| {
                CrebroError::Gateway(format!("failed to sign MITM leaf certificate: {err}"))
            })?;

        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|err| CrebroError::Config(format!("invalid rustls protocol versions: {err}")))?
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone(), self.root_der()], key)
        .map_err(|err| {
            CrebroError::Gateway(format!("failed to build MITM server config: {err}"))
        })?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(server_config))
    }
}

fn default_ca_pem_path() -> PathBuf {
    let base = std::env::var_os("CREBRO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".crebro")))
        .unwrap_or_else(|| std::env::temp_dir().join("crebro"));
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    base.join("ca")
        .join(format!("session-root-{}-{suffix}.pem", std::process::id()))
}

fn write_private_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
