//! Anmeldung, Abmeldung, Passwort, Protokoll.

use super::{blocking, keys::{check, confirm_password}};
use crate::{
  AppState,
  auth::{self, Auth},
  cap,
  db::now,
  error::{AppError, AppResult},
  security::{ClientIp, limits},
};
use axum::{
  Extension, Json,
  extract::State,
  http::{HeaderMap, header},
  response::{IntoResponse, Response},
};
use nrzpgp_shared::{AuditEntry, ChangePassword, LoginRequest, Me, Ok as OkResp, rules};
use rusqlite::{OptionalExtension, params};

pub async fn login(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  Json(body): Json<LoginRequest>,
) -> AppResult<Response> {
  let name = body.name.trim().to_string();
  if name.is_empty() || name.len() > 100 || body.password.is_empty() || body.password.len() > rules::PASSWORD_MAX {
    return Err(AppError::invalid("Bitte Name und Passwort eingeben."));
  }
  state.limit(format!("login-ip:{ip}"), limits::LOGIN_IP)?;
  let account_key = format!("login-fail:{}", name.to_lowercase());
  if !state.limiter.peek(&account_key, limits::LOGIN_FAIL_ACCOUNT) {
    return Err(AppError::rate_limited().msg("Zu viele Fehlversuche. Bitte 15 Minuten warten."));
  }
  // Bot-Pruefung vor allem anderen (Token einmal gueltig).
  cap::require(&state, "login", body.captcha.as_deref()).await?;

  let lookup = name.clone();
  let found: Option<(i64, String, String)> = state
    .db
    .run(move |c| {
      Ok(
        c.query_row("SELECT id, name, password_hash FROM users WHERE name = ?1", [&lookup], |r| {
          Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?,
      )
    })
    .await?;
  let pw = body.password.clone();
  let hash = found.as_ref().map(|f| f.2.clone());
  let ok = blocking(move || Ok(auth::verify_password(&pw, hash.as_deref()))).await?;
  let Some((user_id, user_name, _)) = found.filter(|_| ok) else {
    state.limiter.hit(&account_key, limits::LOGIN_FAIL_ACCOUNT);
    let ip2 = ip.clone();
    state
      .db
      .run(move |c| {
        auth::audit(c, None, "login_failed", &format!("Fehlgeschlagene Anmeldung als \"{name}\""), &ip2);
        Ok(())
      })
      .await?;
    return Err(AppError::wrong_password().msg("Name oder Passwort ist falsch."));
  };
  state.limiter.reset(&account_key);
  let hours = state.config.session_hours;
  let (token, expires) = state
    .db
    .run(move |c| {
      let s = auth::create_session(c, user_id, hours)?;
      auth::audit(c, Some(user_id), "login", "Angemeldet", &ip);
      Ok(s)
    })
    .await?;
  let mut res = Json(Me { name: user_name, session_expires_at: expires }).into_response();
  res.headers_mut().insert(header::SET_COOKIE, auth::session_cookie(&token, state.config.secure_cookies, hours));
  Ok(res)
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
  if let Some(token) = auth::session_token(&headers) {
    let hash = auth::sha256_hex(&token);
    state.db.run(move |c| Ok(c.execute("DELETE FROM sessions WHERE token_hash = ?1", [hash])?)).await?;
  }
  let mut res = Json(OkResp::yes()).into_response();
  res.headers_mut().insert(header::SET_COOKIE, auth::clear_cookie(state.config.secure_cookies));
  Ok(res)
}

pub async fn change_password(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(body): Json<ChangePassword>,
) -> AppResult<Json<OkResp>> {
  state.limit(format!("settings:{}", auth.user.id), limits::SETTINGS)?;
  check(rules::password(&body.new))?;
  if body.new == body.current {
    return Err(AppError::invalid("Das neue Passwort muss sich vom alten unterscheiden."));
  }
  confirm_password(&state, &auth.user, &body.current).await?;
  let new = body.new.clone();
  let hash = blocking(move || auth::hash_password(&new)).await?;
  let uid = auth.user.id;
  let session = auth.session.clone();
  state
    .db
    .run(move |c| {
      c.execute("UPDATE users SET password_hash = ?2 WHERE id = ?1", params![uid, hash])?;
      // Andere Geraete abmelden, diese Sitzung behalten.
      c.execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", params![uid, session])?;
      auth::audit(c, Some(uid), "password_changed", "Konto-Passwort geändert, andere Geräte abgemeldet", &ip);
      Ok(())
    })
    .await?;
  Ok(Json(OkResp::yes()))
}

pub async fn logout_all(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
) -> AppResult<Response> {
  let uid = auth.user.id;
  state
    .db
    .run(move |c| {
      c.execute("DELETE FROM sessions WHERE user_id = ?1", [uid])?;
      auth::audit(c, Some(uid), "logout_all", "Alle Geräte abgemeldet", &ip);
      Ok(())
    })
    .await?;
  let mut res = Json(OkResp::yes()).into_response();
  res.headers_mut().insert(header::SET_COOKIE, auth::clear_cookie(state.config.secure_cookies));
  Ok(res)
}

pub async fn audit_log(State(state): State<AppState>, auth: Auth) -> AppResult<Json<Vec<AuditEntry>>> {
  let uid = auth.user.id;
  let since = now() - 365 * 86_400;
  let entries = state
    .db
    .run(move |c| {
      // Eigene Eintraege und fehlgeschlagene Anmeldungen (ohne Konto).
      let mut st = c.prepare(
        "SELECT id, at, action, detail, ip FROM audit WHERE (user_id = ?1 OR user_id IS NULL) AND at > ?2
          ORDER BY id DESC LIMIT 300",
      )?;
      let rows = st
        .query_map(params![uid, since], |r| {
          Ok(AuditEntry { id: r.get(0)?, at: r.get(1)?, action: r.get(2)?, detail: r.get(3)?, ip: r.get(4)? })
        })?
        .collect::<Result<Vec<_>, _>>()?;
      Ok(rows)
    })
    .await?;
  Ok(Json(entries))
}
