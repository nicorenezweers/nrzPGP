//! Tresor-Endpunkte: Raetsel → Cap → Konto-Passwort → privater Schluessel.
//!
//! Der private Schluessel verlaesst den Server nur in der Antwort von `vault/finish` – nie in HTML,
//! nie vorher. Ablauf und Raetsel siehe `crate::vault`.

use super::{
  blocking,
  keys::{self, confirm_password, ctx_revocation},
};
use crate::{
  AppState,
  auth::{self, Auth, random_token},
  cap,
  error::{AppError, AppResult},
  pgp,
  security::{ClientIp, limits},
  vault::{self, Kind, MAX_ATTEMPTS, Session},
};
use axum::{
  Extension, Json,
  extract::State,
  http::StatusCode,
};
use nrzpgp_shared::{Ok as OkResp, VaultAnswer, VaultCancel, VaultFinish, VaultSecret, VaultStart, VaultState, codes, rules};
use std::time::Instant;

fn expired() -> AppError {
  AppError::new(StatusCode::GONE, codes::VAULT_EXPIRED)
    .msg("Der Vorgang ist abgelaufen oder ungültig. Bitte neu beginnen.")
}

fn locked() -> AppError {
  AppError::new(StatusCode::FORBIDDEN, codes::VAULT_LOCKED)
    .msg("Zu viele falsche Antworten. Der Tresor dieses Profils ist für 30 Minuten gesperrt.")
}

fn lock_key(profile_id: i64) -> String {
  format!("vault-lock:{profile_id}")
}

pub async fn start(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<VaultStart>,
) -> AppResult<Json<VaultState>> {
  if !state.limiter.peek(&lock_key(b.profile_id), limits::VAULT_LOCK) {
    return Err(locked());
  }
  let uid = auth.user.id;
  let pid = b.profile_id;
  let row = state.db.run(move |c| keys::profile(c, uid, pid)).await?;
  state.limit(format!("vault-start:{uid}"), limits::VAULT_START)?;
  let riddle = keys::unseal_riddle(&state, &row)?;
  let plan = vault::plan();
  let mut session = Session {
    session_hash: auth.session.clone(),
    profile_id: row.id,
    profile_label: row.summary.label.clone(),
    riddle_question: riddle.question,
    current: vault::generate(plan[0]),
    plan,
    step: 0,
    attempts_left: MAX_ATTEMPTS,
    last_wrong: false,
    started: Instant::now(),
    started_unix: crate::db::now(),
  };
  session.roll();
  let id = random_token();
  let st = session.state(&id);
  state.vaults.with(|m| {
    // Je Sitzung nur ein offener Vorgang.
    m.retain(|_, s| s.session_hash != auth.session);
    m.insert(id, session);
  });
  let label = row.summary.label.clone();
  state
    .db
    .run(move |c| {
      auth::audit(c, Some(uid), "vault_start", &format!("Tresor für \"{label}\" geöffnet"), &ip);
      Ok(())
    })
    .await?;
  Ok(Json(st))
}

/// Fehlversuch zaehlen; bei 0 Vorgang beenden und Profil sperren.
async fn wrong(state: &AppState, id: &str, uid: i64, ip: &str) -> AppResult<Option<VaultState>> {
  let outcome = state.vaults.with(|m| {
    let s = m.get_mut(id)?;
    s.attempts_left = s.attempts_left.saturating_sub(1);
    s.last_wrong = true;
    if s.attempts_left == 0 {
      let s = m.remove(id)?;
      Some(Err((s.profile_id, s.profile_label)))
    } else {
      s.roll();
      Some(Ok(s.state(id)))
    }
  });
  match outcome {
    None => Err(expired()),
    Some(Ok(st)) => Ok(Some(st)),
    Some(Err((pid, label))) => {
      state.limiter.hit(&lock_key(pid), limits::VAULT_LOCK);
      let ip = ip.to_string();
      state
        .db
        .run(move |c| {
          auth::audit(c, Some(uid), "vault_failed", &format!("Tresor für \"{label}\" nach 3 Fehlversuchen gesperrt"), &ip);
          Ok(())
        })
        .await?;
      Err(locked())
    }
  }
}

pub async fn answer(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<VaultAnswer>,
) -> AppResult<Json<VaultState>> {
  if b.answer.trim().is_empty() || b.answer.chars().count() > rules::ANSWER_MAX {
    return Err(AppError::invalid("Bitte eine Antwort eingeben."));
  }
  // Aktuellen Schritt lesen (ohne den Zustand schon zu aendern).
  let current = state.vaults.with(|m| {
    m.get(&b.vault_id)
      .filter(|s| s.session_hash == auth.session && !s.done())
      .map(|s| (s.kind(), s.current.answer.clone(), s.profile_id, s.step))
  });
  let Some((kind, expected, profile_id, step)) = current else {
    return Err(expired());
  };
  let correct = if kind == Some(Kind::Personal) {
    let uid = auth.user.id;
    let row = state.db.run(move |c| keys::profile(c, uid, profile_id)).await?;
    let riddle = keys::unseal_riddle(&state, &row)?;
    let given = rules::normalize_answer(&b.answer);
    blocking(move || Ok(auth::verify_password(&given, Some(&riddle.answer_hash)))).await?
  } else {
    vault::matches(&expected, &b.answer)
  };
  if !correct {
    let st = wrong(&state, &b.vault_id, auth.user.id, &ip).await?;
    return st.map(Json).ok_or_else(expired);
  }
  let st = state.vaults.with(|m| {
    let s = m.get_mut(&b.vault_id)?;
    // Parallele Antworten auf denselben Schritt zaehlen nur einmal.
    if s.step != step {
      return Some(s.state(&b.vault_id));
    }
    s.step += 1;
    s.last_wrong = false;
    s.roll();
    Some(s.state(&b.vault_id))
  });
  st.map(Json).ok_or_else(expired)
}

pub async fn finish(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<VaultFinish>,
) -> AppResult<Json<VaultSecret>> {
  let ready = state.vaults.with(|m| {
    m.get(&b.vault_id).filter(|s| s.session_hash == auth.session && s.done()).map(|s| s.profile_id)
  });
  let Some(profile_id) = ready else {
    return Err(expired());
  };
  if b.password.is_empty() || b.password.len() > rules::PASSWORD_MAX {
    return Err(AppError::invalid("Bitte das Konto-Passwort eingeben."));
  }
  // 1. Bot-Pruefung (einmal gueltiger Token), 2. Konto-Passwort.
  cap::require(&state, "vault", b.captcha.as_deref()).await?;
  if let Err(e) = confirm_password(&state, &auth.user, &b.password).await {
    if e.code == codes::WRONG_PASSWORD {
      wrong(&state, &b.vault_id, auth.user.id, &ip).await?;
    }
    return Err(e);
  }
  // Vorgang verbrauchen: ein zweiter Aufruf mit derselben ID scheitert.
  let taken = state.vaults.with(|m| m.remove(&b.vault_id));
  if taken.is_none() {
    return Err(expired());
  }
  let uid = auth.user.id;
  let row = state.db.run(move |c| keys::profile(c, uid, profile_id)).await?;
  let key = keys::unseal_secret(&state, &row)?;
  let revocation = state
    .sealer
    .open(&ctx_revocation(&row.uid), &row.sealed_revocation)
    .map(|b| String::from_utf8_lossy(&b).into_owned())
    .ok_or_else(AppError::internal)?;
  let secret_key = blocking(move || Ok(pgp::armor_secret(&key)?)).await?;
  let fingerprint = row.summary.fingerprint.clone();
  let label = row.summary.label.clone();
  state
    .db
    .run(move |c| {
      c.execute("UPDATE profiles SET exports = exports + 1, last_used_at = ?2 WHERE id = ?1", rusqlite::params![profile_id, crate::db::now()])?;
      auth::audit(c, Some(uid), "vault_export", &format!("Privater Schlüssel von \"{label}\" herausgegeben"), &ip);
      Ok(())
    })
    .await?;
  Ok(Json(VaultSecret { fingerprint, secret_key, revocation_certificate: revocation }))
}

pub async fn cancel(State(state): State<AppState>, auth: Auth, Json(b): Json<VaultCancel>) -> AppResult<Json<OkResp>> {
  state.vaults.with(|m| {
    if m.get(&b.vault_id).is_some_and(|s| s.session_hash == auth.session) {
      m.remove(&b.vault_id);
    }
  });
  Ok(Json(OkResp::yes()))
}
