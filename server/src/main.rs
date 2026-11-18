//! nrzPGP – Server.
//!
//! Ein Programm: JSON-API (`/api/v1`), Cap-Endpunkte (`/api/cap`) und die Weboberflaeche
//! (Dioxus/WASM, statisch). Daten in SQLite; private Schluessel nur passphrase-geschuetzt UND
//! versiegelt (siehe `seal.rs`). Konfiguration per Umgebungsvariablen (README).

mod api;
mod auth;
mod cap;
mod config;
mod db;
mod error;
mod pgp;
mod seal;
mod security;
mod vault;
mod web;

#[cfg(test)]
mod tests;

use axum::{Router, extract::DefaultBodyLimit, http::Uri, middleware};
use config::Config;
use db::Db;
use security::RateLimiter;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower_http::{compression::CompressionLayer, limit::RequestBodyLimitLayer};

/// Groesste Anfrage (Nachrichten/Schluessel bis 1,5 MB Text + JSON).
const BODY_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
  pub config: Arc<Config>,
  pub db: Db,
  pub limiter: Arc<RateLimiter>,
  pub cap: Option<Arc<cap::Cap>>,
  pub sealer: Arc<seal::Sealer>,
  pub vaults: Arc<vault::Vaults>,
}

pub fn app(state: AppState, web: Option<Arc<web::WebUi>>) -> Router {
  let mut router = api::router();
  router = match web {
    Some(ui) => router.fallback(move |method, uri: Uri| ui.clone().serve(method, uri)),
    None => router.fallback(|| async { error::AppError::not_found() }),
  };
  router
    .layer(middleware::from_fn_with_state(state.clone(), security::guard))
    .layer(DefaultBodyLimit::max(BODY_LIMIT))
    .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
    .layer(CompressionLayer::new())
    .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,nrzpgp=info".into()),
    )
    .init();

  let config = Config::from_env();
  let Some(master) = config.master_key.clone().filter(|m| m.chars().count() >= 32) else {
    tracing::error!("NRZPGP_MASTER_KEY fehlt oder ist kuerzer als 32 Zeichen – ohne ihn startet nrzPGP nicht.");
    std::process::exit(2);
  };
  let db = Db::open(&config.database)?;
  {
    let c = db.conn().map_err(|e| format!("{e:?}"))?;
    auth::ensure_admin(&c, &config.admin_name, config.admin_password.as_deref(), config.admin_password_reset)
      .map_err(|e| format!("{e:?}"))?;
    c.execute("DELETE FROM sessions WHERE expires_at < ?1", [db::now()])?;
  }

  let state = AppState {
    cap: cap::Cap::new(config.cap_url.as_deref(), config.cap_seed.as_deref()).map(Arc::new),
    config: Arc::new(config.clone()),
    db: db.clone(),
    limiter: Arc::new(RateLimiter::default()),
    sealer: Arc::new(seal::Sealer::new(&master)),
    vaults: Arc::new(vault::Vaults::default()),
  };
  if state.cap.is_none() && config.cap_required {
    tracing::error!("NRZPGP_CAP_REQUIRED ist gesetzt, aber Cap ist nicht konfiguriert (NRZPGP_CAP_URL/NRZPGP_CAP_SEED).");
    std::process::exit(2);
  }
  if state.cap.is_none() {
    tracing::warn!("Cap-Captcha ist AUS (NRZPGP_CAP_URL/NRZPGP_CAP_SEED fehlen) – nur für Entwicklung!");
  }
  let web = config.web_dir.as_deref().and_then(web::WebUi::load);
  if web.is_none() {
    tracing::warn!("Keine Weboberflaeche gefunden (NRZPGP_WEB_DIR), nur API aktiv");
  }

  // Aufraeumen: Rate-Limit-Speicher und abgelaufene Sitzungen.
  {
    let limiter = state.limiter.clone();
    let db = db.clone();
    tokio::spawn(async move {
      let mut tick = tokio::time::interval(Duration::from_secs(600));
      loop {
        tick.tick().await;
        limiter.prune();
        let _ = db
          .run(|c| {
            c.execute("DELETE FROM sessions WHERE expires_at < ?1", [db::now()])?;
            Ok(())
          })
          .await;
      }
    });
  }

  let listener = tokio::net::TcpListener::bind(config.bind).await?;
  tracing::info!("nrzPGP laeuft auf http://{}", config.bind);
  axum::serve(listener, app(state, web).into_make_service_with_connect_info::<SocketAddr>())
    .with_graceful_shutdown(shutdown())
    .await?;
  Ok(())
}

async fn shutdown() {
  let ctrl_c = async {
    let _ = tokio::signal::ctrl_c().await;
  };
  #[cfg(unix)]
  let term = async {
    if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
      s.recv().await;
    }
  };
  #[cfg(not(unix))]
  let term = std::future::pending::<()>();
  tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}
