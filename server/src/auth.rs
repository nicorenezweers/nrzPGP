//! Konto und Sitzungen.
//!
//! - Passwoerter und Raetsel-Antworten: Argon2id (OWASP-Parameter), Pruefung im Blocking-Pool. Bei
//!   unbekanntem Namen wird gegen einen Dummy-Hash geprueft, damit die Antwortzeit nichts verraet.
//! - Sitzungen: 256-Bit-Zufallstoken im HttpOnly-Cookie (`SameSite=Strict`), in der Datenbank nur
//!   als SHA-256. Feste Laufzeit (Standard 12 h, nicht gleitend); Logout und Passwortwechsel beenden sie.

use crate::{AppState, db::now, error::{AppError, AppResult}};
use argon2::{
  Algorithm, Argon2, Params, Version,
  password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
  extract::{FromRef, FromRequestParts},
  http::{HeaderMap, HeaderValue, header, request::Parts},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nrzpgp_shared::SESSION_COOKIE;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

fn argon() -> Argon2<'static> {
  // 19 MiB, 2 Durchlaeufe, 1 Thread (OWASP-Empfehlung fuer Argon2id).
  let params = Params::new(19 * 1024, 2, 1, None).expect("argon2 params");
  Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(pw: &str) -> AppResult<String> {
  let salt = SaltString::generate(&mut OsRng);
  argon().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| {
    tracing::error!("argon2: {e}");
    AppError::internal()
  })
}

static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| hash_password("nrzpgp-dummy-password").unwrap_or_default());

pub fn verify_password(pw: &str, hash: Option<&str>) -> bool {
  let hash = hash.unwrap_or(DUMMY_HASH.as_str());
  let Ok(parsed) = PasswordHash::new(hash) else {
    return false;
  };
  argon().verify_password(pw.as_bytes(), &parsed).is_ok()
}

pub fn random_token() -> String {
  let mut b = [0u8; 32];
  OsRng.fill_bytes(&mut b);
  URL_SAFE_NO_PAD.encode(b)
}

pub fn sha256_hex(s: &str) -> String {
  hex::encode(Sha256::digest(s.as_bytes()))
}

#[derive(Clone, Debug)]
pub struct User {
  pub id: i64,
  pub name: String,
}

/// Neue Sitzung anlegen, liefert (Klartext-Token fuers Cookie, Ablauf).
pub fn create_session(c: &Connection, user_id: i64, hours: i64) -> AppResult<(String, i64)> {
  let token = random_token();
  let t = now();
  let expires = t + hours * 3600;
  c.execute(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
    params![sha256_hex(&token), user_id, t, expires],
  )?;
  // Hoechstens 10 Geraete gleichzeitig.
  c.execute(
    "DELETE FROM sessions WHERE user_id = ?1 AND token_hash NOT IN
       (SELECT token_hash FROM sessions WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 10)",
    [user_id],
  )?;
  Ok((token, expires))
}

pub fn session_cookie(token: &str, secure: bool, hours: i64) -> HeaderValue {
  let secure = if secure { "; Secure" } else { "" };
  let max_age = hours * 3600;
  HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"))
    .expect("cookie")
}

pub fn clear_cookie(secure: bool) -> HeaderValue {
  let secure = if secure { "; Secure" } else { "" };
  HeaderValue::from_str(&format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")).expect("cookie")
}

pub fn session_token(headers: &HeaderMap) -> Option<String> {
  headers
    .get_all(header::COOKIE)
    .iter()
    .filter_map(|v| v.to_str().ok())
    .flat_map(|v| v.split(';'))
    .filter_map(|kv| kv.trim().split_once('='))
    .find(|(k, _)| *k == SESSION_COOKIE)
    .map(|(_, v)| v.to_string())
    .filter(|v| v.len() == 43 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

fn user_for_token(c: &Connection, token: &str) -> AppResult<Option<(User, i64)>> {
  let found = c
    .query_row(
      "SELECT u.id, u.name, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?1 AND s.expires_at > ?2",
      params![sha256_hex(token), now()],
      |r| Ok((User { id: r.get(0)?, name: r.get(1)? }, r.get::<_, i64>(2)?)),
    )
    .optional()?;
  Ok(found)
}

// ---------------------------------------------------------------------------------------------
// Extraktoren

/// Betrachter (angemeldet oder nicht), mit Sitzungsablauf.
pub struct Viewer(pub Option<(User, i64)>);

/// Angemeldetes Konto, sonst `401`. `session` ist der SHA-256 des Sitzungs-Tokens.
pub struct Auth {
  pub user: User,
  pub session: String,
}

impl<S> FromRequestParts<S> for Viewer
where
  S: Send + Sync,
  AppState: FromRef<S>,
{
  type Rejection = AppError;

  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
    let Some(token) = session_token(&parts.headers) else {
      return Ok(Viewer(None));
    };
    let state = AppState::from_ref(state);
    let user = state.db.run(move |c| user_for_token(c, &token)).await?;
    Ok(Viewer(user))
  }
}

impl<S> FromRequestParts<S> for Auth
where
  S: Send + Sync,
  AppState: FromRef<S>,
{
  type Rejection = AppError;

  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
    let token = session_token(&parts.headers).ok_or_else(AppError::unauthorized)?;
    let session = sha256_hex(&token);
    let state = AppState::from_ref(state);
    match state.db.run(move |c| user_for_token(c, &token)).await? {
      Some((user, _)) => Ok(Auth { user, session }),
      None => Err(AppError::unauthorized()),
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Konto beim Start

/// Legt das Konto an, falls es fehlt. Ohne `NRZPGP_ADMIN_PASSWORD` wird ein zufaelliges Passwort
/// erzeugt und einmalig ins Log geschrieben. Ein bestehendes Passwort wird nur mit
/// `NRZPGP_ADMIN_PASSWORD_RESET=true` ueberschrieben (danach in der App aendern).
pub fn ensure_admin(c: &Connection, name: &str, password: Option<&str>, reset: bool) -> AppResult<()> {
  let existing: Option<i64> = c.query_row("SELECT id FROM users WHERE name = ?1", [name], |r| r.get(0)).optional()?;
  match (existing, password) {
    (Some(id), Some(pw)) if reset => {
      c.execute("UPDATE users SET password_hash = ?2 WHERE id = ?1", params![id, hash_password(pw)?])?;
      c.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
      tracing::warn!("Konto {name}: Passwort aus NRZPGP_ADMIN_PASSWORD zurückgesetzt");
    }
    (Some(_), _) => {}
    (None, pw) => {
      let generated;
      let pw = match pw {
        Some(p) => p,
        None => {
          generated = random_token()[..20].to_string();
          tracing::warn!("Konto {name} angelegt, Passwort: {generated} (bitte in der App ändern)");
          &generated
        }
      };
      c.execute(
        "INSERT INTO users (name, password_hash, created_at) VALUES (?1, ?2, ?3)",
        params![name, hash_password(pw)?, now()],
      )?;
      tracing::info!("Konto {name} angelegt");
    }
  }
  Ok(())
}

/// Eintrag ins Protokoll (ohne Inhalte). Haelt hoechstens 5000 Eintraege je Konto.
pub fn audit(c: &Connection, user_id: Option<i64>, action: &str, detail: &str, ip: &str) {
  let r = c.execute(
    "INSERT INTO audit (user_id, at, action, detail, ip) VALUES (?1, ?2, ?3, ?4, ?5)",
    params![user_id, now(), action, detail, ip],
  );
  if let Err(e) = r {
    tracing::error!("Protokoll: {e}");
    return;
  }
  let _ = c.execute(
    "DELETE FROM audit WHERE user_id IS ?1 AND id <= (SELECT id FROM audit WHERE user_id IS ?1 ORDER BY id DESC LIMIT 1 OFFSET 5000)",
    params![user_id],
  );
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn password_roundtrip() {
    let h = hash_password("Pferd-Batterie-42").unwrap();
    assert!(h.starts_with("$argon2id$"));
    assert!(verify_password("Pferd-Batterie-42", Some(&h)));
    assert!(!verify_password("falsch", Some(&h)));
    assert!(!verify_password("irgendwas", None));
  }

  #[test]
  fn cookie_parsing() {
    let tok = random_token();
    let mut h = HeaderMap::new();
    h.insert(header::COOKIE, HeaderValue::from_str(&format!("a=b; {SESSION_COOKIE}={tok}")).unwrap());
    assert_eq!(session_token(&h).as_deref(), Some(tok.as_str()));
    let mut bad = HeaderMap::new();
    bad.insert(header::COOKIE, HeaderValue::from_static("nrzpgp_session=../../etc"));
    assert!(session_token(&bad).is_none());
  }
}
