//! JSON-API unter `/api/v1` (Tabelle aller Endpunkte: `shared/src/lib.rs`).

mod account;
mod contacts;
mod keys;
mod profiles;
mod tools;
mod vault;

use crate::{AppState, auth::Viewer, cap, error::AppResult};
use axum::{
  Json, Router,
  extract::State,
  routing::{get, post},
};
use nrzpgp_shared::{Me, SiteInfo};

pub fn router() -> Router<AppState> {
  Router::new()
    .route("/api/v1/site", get(site))
    // Konto
    .route("/api/v1/auth/login", post(account::login))
    .route("/api/v1/auth/logout", post(account::logout))
    .route("/api/v1/account/password", post(account::change_password))
    .route("/api/v1/account/logout-all", post(account::logout_all))
    .route("/api/v1/audit", get(account::audit_log))
    // Profile
    .route("/api/v1/profiles", get(profiles::list).post(profiles::create))
    .route("/api/v1/profiles/import", post(profiles::import))
    .route("/api/v1/profiles/{id}", get(profiles::detail).patch(profiles::update))
    .route("/api/v1/profiles/{id}/delete", post(profiles::delete))
    .route("/api/v1/profiles/{id}/passphrase", post(profiles::change_passphrase))
    .route("/api/v1/profiles/{id}/riddle", post(profiles::change_riddle))
    // Tresor
    .route("/api/v1/vault/start", post(vault::start))
    .route("/api/v1/vault/answer", post(vault::answer))
    .route("/api/v1/vault/finish", post(vault::finish))
    .route("/api/v1/vault/cancel", post(vault::cancel))
    // Kontakte
    .route("/api/v1/contacts", get(contacts::list).post(contacts::import))
    .route("/api/v1/contacts/{id}", get(contacts::detail).patch(contacts::update).delete(contacts::delete))
    // Werkzeuge
    .route("/api/v1/tools/encrypt", post(tools::encrypt))
    .route("/api/v1/tools/decrypt", post(tools::decrypt))
    .route("/api/v1/tools/sign", post(tools::sign))
    .route("/api/v1/tools/verify", post(tools::verify))
    .route("/api/v1/tools/inspect-key", post(tools::inspect_key))
    .route("/api/v1/tools/inspect-message", post(tools::inspect_message))
    // Cap-Widget
    .route("/api/cap/{scope}/challenge", post(cap::challenge))
    .route("/api/cap/{scope}/redeem", post(cap::redeem))
}

async fn site(State(state): State<AppState>, Viewer(user): Viewer) -> AppResult<Json<SiteInfo>> {
  Ok(Json(SiteInfo {
    name: "nrzPGP".into(),
    version: env!("CARGO_PKG_VERSION").into(),
    captcha: state.cap.is_some(),
    me: user.map(|(u, expires)| Me { name: u.name, session_expires_at: expires }),
  }))
}

/// CPU-lastige Arbeit (Argon2, OpenPGP) im Blocking-Pool.
pub async fn blocking<T, F>(f: F) -> AppResult<T>
where
  T: Send + 'static,
  F: FnOnce() -> AppResult<T> + Send + 'static,
{
  tokio::task::spawn_blocking(f).await?
}
