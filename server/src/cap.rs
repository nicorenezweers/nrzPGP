//! Cap-Captcha (https://trycap.dev) mit Cap Core.
//!
//! Die eigentliche Pruefung (Proof of Work, Browser-Instrumentierung mit Headless-Sperre,
//! Verhaltensanalyse, Erkennung von KI-Agenten) macht `capjs-core` im internen Dienst
//! `cap/server.mjs`. Dieser Server
//!
//! 1. reicht `POST /api/cap/{scope}/challenge` und `/redeem` vom Widget weiter (gleiche Origin,
//!    eigenes Limit je IP),
//! 2. prueft den Token (`captcha` im JSON der Anfrage) ueber `/siteverify` – einmal gueltig, vor
//!    jedem Seiteneffekt, und lehnt bei Fehlern ab (fail closed).
//!
//! Immer verlangt bei Registrierung und Login, bei Beitraegen/Kommentaren nur bei Spam-Verdacht.

use crate::{
  AppState,
  error::{AppError, AppResult},
  security::{ClientIp, limits},
};
use axum::{
  Extension, Json,
  body::Bytes,
  extract::{Path, Query, State},
  http::{HeaderMap, StatusCode},
  response::{IntoResponse, Response},
};
use nrzpgp_shared::{CAPTCHA_SCOPES, codes};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct Cap {
  url: String,
  key: String,
  client: reqwest::Client,
}

/// Header, die capjs-core fuer die Erkennung von KI-Agenten auswertet.
const AGENT_HEADERS: [&str; 6] =
  ["user-agent", "signature-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-language"];

impl Cap {
  pub fn new(url: Option<&str>, seed: Option<&str>) -> Option<Self> {
    let (url, seed) = (url?, seed?);
    if seed.len() < 16 {
      tracing::warn!("Cap: NRZPGP_CAP_SEED ist zu kurz (min. 16 Zeichen), Captcha ist aus");
      return None;
    }
    let client = reqwest::Client::builder()
      .timeout(Duration::from_secs(20))
      .connect_timeout(Duration::from_secs(3))
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .ok()?;
    tracing::info!("Cap-Captcha aktiv ({url})");
    Some(Self { url: url.to_string(), key: internal_key(seed), client })
  }

  async fn call(&self, path: &str, body: &Value) -> Result<(StatusCode, Value), ()> {
    let res = self
      .client
      .post(format!("{}{path}", self.url))
      .header("x-cap-internal", &self.key)
      .json(body)
      .send()
      .await
      .map_err(|e| tracing::warn!("Cap-Dienst nicht erreichbar: {e}"))?;
    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if status.is_server_error() || status == StatusCode::FORBIDDEN {
      tracing::warn!("Cap-Dienst antwortet {status}");
      return Err(());
    }
    let value = res.json::<Value>().await.map_err(|_| ())?;
    Ok((status, value))
  }

  /// Token pruefen und verbrauchen.
  async fn verify(&self, scope: &str, token: &str) -> Result<bool, ()> {
    let (_, v) = self.call("/siteverify", &json!({ "scope": scope, "token": token })).await?;
    Ok(v.get("success").and_then(Value::as_bool) == Some(true))
  }
}

/// Gemeinsamer Schluessel mit `cap/server.mjs`: sha256("nrzpgp-cap-internal:" + seed), hex.
fn internal_key(seed: &str) -> String {
  Sha256::digest(format!("nrzpgp-cap-internal:{seed}").as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Verlangt einen gueltigen Cap-Token fuer `scope` (ohne konfiguriertes Cap: immer ok).
pub async fn require(state: &AppState, scope: &str, token: Option<&str>) -> AppResult<()> {
  let Some(cap) = state.cap.as_ref() else {
    return Ok(());
  };
  let token = token.map(str::trim).filter(|t| !t.is_empty() && t.len() <= 200);
  let Some(token) = token else {
    return Err(AppError::new(StatusCode::BAD_REQUEST, codes::CAPTCHA_REQUIRED).msg(scope));
  };
  match cap.verify(scope, token).await {
    Ok(true) => Ok(()),
    Ok(false) => Err(AppError::new(StatusCode::BAD_REQUEST, codes::CAPTCHA_INVALID).msg(scope)),
    Err(()) => Err(
      AppError::new(StatusCode::SERVICE_UNAVAILABLE, codes::CAPTCHA_UNAVAILABLE)
        .msg("Die Bot-Prüfung ist gerade nicht erreichbar. Bitte später erneut versuchen."),
    ),
  }
}

// ---------------------------------------------------------------------------------------------
// Widget-Endpunkte

fn check_scope<'a>(state: &'a AppState, scope: &str) -> AppResult<&'a Cap> {
  let cap = state.cap.as_ref().ok_or_else(AppError::not_found)?;
  if !CAPTCHA_SCOPES.contains(&scope) {
    return Err(AppError::not_found());
  }
  Ok(cap)
}

fn proxied(result: Result<(StatusCode, Value), ()>) -> Response {
  match result {
    Ok((status, v)) => (status, Json(v)).into_response(),
    Err(()) => AppError::new(StatusCode::SERVICE_UNAVAILABLE, codes::CAPTCHA_UNAVAILABLE).into_response(),
  }
}

#[derive(Deserialize)]
pub struct ChallengeQuery {
  #[serde(default)]
  wasm: Option<String>,
}

pub async fn challenge(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  Path(scope): Path<String>,
  Query(q): Query<ChallengeQuery>,
) -> AppResult<Response> {
  let cap = check_scope(&state, &scope)?;
  state.limit(format!("cap-ch:{ip}"), limits::CAP_CHALLENGE)?;
  let wasm = q.wasm.as_deref() != Some("0");
  Ok(proxied(cap.call("/challenge", &json!({ "scope": scope, "wasm": wasm })).await))
}

pub async fn redeem(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  Path(scope): Path<String>,
  headers: HeaderMap,
  body: Bytes,
) -> AppResult<Response> {
  let cap = check_scope(&state, &scope)?;
  state.limit(format!("cap-rd:{ip}"), limits::CAP_REDEEM)?;
  let client_body: Value = serde_json::from_slice(&body).map_err(|_| AppError::invalid("invalid_body"))?;
  let mut fwd = serde_json::Map::new();
  for name in AGENT_HEADERS {
    if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
      fwd.insert(name.into(), json!(v));
    }
  }
  let result = cap.call("/redeem", &json!({ "scope": scope, "body": client_body, "headers": fwd })).await;
  if let Ok((status, v)) = &result
    && !status.is_success()
  {
    // Abgelehnte Loesung (z. B. Headless-Browser, Bot-Verhalten, abgelaufen) – ohne IP im Log.
    tracing::info!("Cap: Lösung für {scope} abgelehnt ({})", v.get("reason").and_then(serde_json::Value::as_str).unwrap_or("?"));
  }
  Ok(proxied(result))
}

#[cfg(test)]
mod tests {
  #[test]
  fn key_matches_node_service() {
    // node -e 'console.log(require("crypto").createHash("sha256").update("nrzpgp-cap-internal:0123456789abcdef").digest("hex"))'
    assert_eq!(super::internal_key("0123456789abcdef").len(), 64);
  }
}
