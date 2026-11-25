use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use notes_syncd::config::{Config, TlsConfig};
use notes_syncd::{api, gc, AppState, BoxError};

/// TLS 1.3 only, with the `ring` crypto provider.
fn tls_config(tls: &TlsConfig) -> Result<rustls::ServerConfig, BoxError> {
    fn open(path: &Path) -> Result<std::io::BufReader<std::fs::File>, BoxError> {
        let file = std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        Ok(std::io::BufReader::new(file))
    }
    let certs = rustls_pemfile::certs(&mut open(&tls.cert)?).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificate found in {}", tls.cert.display()).into());
    }
    let key = rustls_pemfile::private_key(&mut open(&tls.key)?)?
        .ok_or_else(|| format!("no private key found in {}", tls.key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

async fn run() -> Result<(), BoxError> {
    let path = std::env::args_os()
        .nth(1)
        .or_else(|| std::env::var_os("NOTES_SYNCD_CONFIG"))
        .map(PathBuf::from)
        .ok_or("usage: notes-syncd <config.toml>  (or set NOTES_SYNCD_CONFIG)")?;
    let config = Config::load(&path)?;
    let listen = config.server.listen;
    let tls = config.tls.clone();

    let state = AppState::new(config).await?;
    gc::spawn(state.clone());
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();

    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        // Ctrl-C when run by hand, SIGTERM when stopped by systemd or Kubernetes.
        #[cfg(unix)]
        {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("cannot install the SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });

    match tls {
        Some(tls) => {
            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(&tls)?));
            tracing::info!(%listen, "listening with TLS 1.3");
            axum_server::bind_rustls(listen, rustls_config).handle(handle).serve(app).await?;
        }
        None => {
            tracing::warn!(%listen, "listening WITHOUT TLS: only safe on loopback or behind a TLS-terminating proxy");
            axum_server::bind(listen).handle(handle).serve(app).await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    if let Err(e) = run().await {
        eprintln!("notes-syncd: {e}");
        std::process::exit(1);
    }
}
