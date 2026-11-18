//! Einheitliche Fehler: `{"error": "<code>", "message": "..."}` mit passendem HTTP-Status.
//! Interne Fehler werden geloggt, aber nie im Detail an den Client gegeben.

use axum::{
  Json,
  http::StatusCode,
  response::{IntoResponse, Response},
};
use nrzpgp_shared::{ApiError, codes};

#[derive(Debug)]
pub struct AppError {
  pub status: StatusCode,
  pub code: &'static str,
  pub message: Option<String>,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
  pub fn new(status: StatusCode, code: &'static str) -> Self {
    Self { status, code, message: None }
  }
  pub fn msg(mut self, m: impl Into<String>) -> Self {
    self.message = Some(m.into());
    self
  }
  pub fn invalid(m: impl Into<String>) -> Self {
    Self::new(StatusCode::BAD_REQUEST, codes::INVALID_INPUT).msg(m)
  }
  pub fn not_found() -> Self {
    Self::new(StatusCode::NOT_FOUND, codes::NOT_FOUND)
  }
  pub fn forbidden() -> Self {
    Self::new(StatusCode::FORBIDDEN, codes::FORBIDDEN)
  }
  pub fn unauthorized() -> Self {
    Self::new(StatusCode::UNAUTHORIZED, codes::NOT_LOGGED_IN)
  }
  pub fn rate_limited() -> Self {
    Self::new(StatusCode::TOO_MANY_REQUESTS, codes::RATE_LIMITED)
      .msg("Zu viele Anfragen. Bitte warte einen Moment.")
  }
  pub fn internal() -> Self {
    Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal")
  }
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    let body = ApiError { error: self.code.to_string(), message: self.message };
    let mut res = (self.status, Json(body)).into_response();
    res.headers_mut().insert(
      axum::http::header::CACHE_CONTROL,
      axum::http::HeaderValue::from_static("no-store"),
    );
    res
  }
}

impl From<rusqlite::Error> for AppError {
  fn from(e: rusqlite::Error) -> Self {
    if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
      return Self::not_found();
    }
    tracing::error!("Datenbank: {e}");
    Self::internal()
  }
}

impl From<r2d2::Error> for AppError {
  fn from(e: r2d2::Error) -> Self {
    tracing::error!("Datenbank-Pool: {e}");
    Self::internal()
  }
}

impl From<tokio::task::JoinError> for AppError {
  fn from(e: tokio::task::JoinError) -> Self {
    tracing::error!("Task: {e}");
    Self::internal()
  }
}

impl AppError {
  pub fn wrong_password() -> Self {
    Self::new(StatusCode::BAD_REQUEST, codes::WRONG_PASSWORD).msg("Das Konto-Passwort ist falsch.")
  }
  pub fn wrong_passphrase() -> Self {
    Self::new(StatusCode::BAD_REQUEST, codes::WRONG_PASSPHRASE).msg("Die Passphrase ist falsch.")
  }
}

impl From<crate::pgp::PgpError> for AppError {
  fn from(e: crate::pgp::PgpError) -> Self {
    match e {
      crate::pgp::PgpError::WrongPassphrase => Self::wrong_passphrase(),
      crate::pgp::PgpError::Invalid(m) => Self::new(StatusCode::BAD_REQUEST, codes::PGP_ERROR).msg(m),
    }
  }
}
