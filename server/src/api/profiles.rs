//! Profile: eigene Schluesselpaare fuer verschiedene Adressen und Zwecke.

use super::{
  blocking,
  keys::{self, check, confirm_password, ctx_revocation, ctx_secret},
};
use crate::{
  AppState,
  auth::{self, Auth, random_token},
  db::now,
  error::{AppError, AppResult},
  pgp,
  security::{ClientIp, limits},
};
use axum::{
  Extension, Json,
  extract::{Path, State},
};
use nrzpgp_shared::{
  ChangePassphrase, ChangeRiddle, CreateProfile, DeleteProfile, ImportProfile, Ok as OkResp, ProfileDetail,
  ProfileSummary, UpdateProfile, rules,
};
use ::pgp::composed::SignedSecretKey;
use rusqlite::params;

pub async fn list(State(state): State<AppState>, auth: Auth) -> AppResult<Json<Vec<ProfileSummary>>> {
  let uid = auth.user.id;
  let rows = state.db.run(move |c| keys::profiles(c, uid)).await?;
  Ok(Json(rows.into_iter().map(|r| r.summary).collect()))
}

fn detail_of(state: &AppState, row: keys::ProfileRow) -> AppResult<ProfileDetail> {
  let public = pgp::parse_public(row.public_key.as_bytes())?;
  let riddle = keys::unseal_riddle(state, &row)?;
  Ok(ProfileDetail {
    key: pgp::key_info(&public),
    public_key: row.public_key,
    riddle_question: riddle.question,
    exports: row.exports,
    summary: row.summary,
  })
}

pub async fn detail(State(state): State<AppState>, auth: Auth, Path(id): Path<i64>) -> AppResult<Json<ProfileDetail>> {
  let uid = auth.user.id;
  let row = state.db.run(move |c| keys::profile(c, uid, id)).await?;
  Ok(Json(detail_of(&state, row)?))
}

fn check_meta(label: &str, purpose: &str) -> AppResult<()> {
  check(rules::label(label))?;
  check(rules::purpose(purpose))
}

/// Gemeinsamer Teil von Erzeugen und Import: versiegeln und speichern.
#[allow(clippy::too_many_arguments)]
async fn store(
  state: &AppState,
  user_id: i64,
  ip: String,
  label: String,
  purpose: String,
  key: SignedSecretKey,
  passphrase: String,
  riddle: (String, String),
  action: &'static str,
) -> AppResult<ProfileDetail> {
  let uid = random_token()[..24].to_string();
  let (public_armor, info, secret_bytes, revocation) = blocking(move || {
    let public = key.to_public_key();
    let revocation = pgp::revocation_certificate(&key, &passphrase)?;
    Ok((pgp::armor_public(&public)?, public, pgp::to_bytes_secret(&key)?, revocation))
  })
  .await?;
  let sealed_secret = state.sealer.seal(&ctx_secret(&uid), &secret_bytes);
  let sealed_revocation = state.sealer.seal(&ctx_revocation(&uid), revocation.as_bytes());
  let sealed_riddle = {
    let (q, a, s, u) = (riddle.0, riddle.1, state.clone(), uid.clone());
    blocking(move || keys::seal_riddle(&s, &u, &q, &a)).await?
  };
  let key_uid = pgp::primary_uid(&info);
  let email = pgp::email_of(&key_uid);
  let fingerprint = pgp::fingerprint_of(&info.primary_key);
  let key_id = pgp::key_id_of(&info.primary_key);
  let algorithm = pgp::algorithm_label(&info);
  let key_created = pgp::key_info(&info).created_at;
  let id = state
    .db
    .run(move |c| {
      let exists: bool = c.query_row(
        "SELECT EXISTS (SELECT 1 FROM profiles WHERE user_id = ?1 AND fingerprint = ?2)",
        params![user_id, fingerprint],
        |r| r.get(0),
      )?;
      if exists {
        return Err(AppError::invalid("Dieser Schlüssel ist schon als Profil gespeichert."));
      }
      c.execute(
        "INSERT INTO profiles (uid, user_id, label, purpose, key_uid, email, fingerprint, key_id, algorithm, key_created_at,
                               public_key, sealed_secret, sealed_revocation, sealed_riddle, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
          uid, user_id, label.trim(), purpose.trim(), key_uid, email, fingerprint, key_id, algorithm, key_created,
          public_armor, sealed_secret, sealed_revocation, sealed_riddle, now()
        ],
      )?;
      let id = c.last_insert_rowid();
      let what = if action == "profile_created" { "erzeugt" } else { "importiert" };
      auth::audit(c, Some(user_id), action, &format!("Profil \"{}\" ({fingerprint}) {what}", label.trim()), &ip);
      Ok(id)
    })
    .await?;
  let row = state.db.run(move |c| keys::profile(c, user_id, id)).await?;
  detail_of(state, row)
}

pub async fn create(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<CreateProfile>,
) -> AppResult<Json<ProfileDetail>> {
  check_meta(&b.label, &b.purpose)?;
  check(rules::uid_name(&b.name))?;
  check(rules::email(&b.email))?;
  check(rules::comment(&b.comment))?;
  check(rules::passphrase(&b.passphrase))?;
  check(rules::riddle(&b.riddle_question, &b.riddle_answer))?;
  if !nrzpgp_shared::algorithms::ALL.iter().any(|(a, _)| *a == b.algorithm) {
    return Err(AppError::invalid("Unbekannte Schlüsselart."));
  }
  if rules::normalize_answer(&b.riddle_answer) == rules::normalize_answer(&b.passphrase) {
    return Err(AppError::invalid("Die Rätsel-Antwort darf nicht die Passphrase sein."));
  }
  state.limit(format!("keygen:{}", auth.user.id), limits::KEYGEN)?;
  let uid_str = if b.comment.trim().is_empty() {
    format!("{} <{}>", b.name.trim(), b.email.trim())
  } else {
    format!("{} ({}) <{}>", b.name.trim(), b.comment.trim(), b.email.trim())
  };
  let (alg, pass) = (b.algorithm.clone(), b.passphrase.clone());
  let key = blocking(move || Ok(pgp::generate(&alg, &uid_str, &pass)?)).await?;
  let d = store(
    &state,
    auth.user.id,
    ip,
    b.label,
    b.purpose,
    key,
    b.passphrase,
    (b.riddle_question, b.riddle_answer),
    "profile_created",
  )
  .await?;
  Ok(Json(d))
}

pub async fn import(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<ImportProfile>,
) -> AppResult<Json<ProfileDetail>> {
  check_meta(&b.label, &b.purpose)?;
  check(rules::message(&b.secret_key))?;
  check(rules::riddle(&b.riddle_question, &b.riddle_answer))?;
  if b.passphrase.is_empty() || b.passphrase.len() > rules::PASSPHRASE_MAX {
    return Err(AppError::invalid("Bitte die Passphrase des Schlüssels angeben."));
  }
  state.limit(format!("keygen:{}", auth.user.id), limits::KEYGEN)?;
  let (text, pass) = (b.secret_key.clone(), b.passphrase.clone());
  let key = blocking(move || {
    let key = pgp::parse_secret(text.as_bytes())?;
    if pgp::is_protected(&key) {
      pgp::check_passphrase(&key, &pass)?;
      Ok(key)
    } else {
      // Ungeschuetzter Schluessel: mit der angegebenen Passphrase schuetzen (Regeln wie beim Erzeugen).
      rules::passphrase(&pass).map_err(AppError::invalid)?;
      let mut key = key;
      let pw = ::pgp::types::Password::from(pass.as_str());
      key.primary_key.set_password(rand::rngs::OsRng, &pw).map_err(|_| AppError::invalid("Schutz fehlgeschlagen."))?;
      for s in key.secret_subkeys.iter_mut() {
        s.key.set_password(rand::rngs::OsRng, &pw).map_err(|_| AppError::invalid("Schutz fehlgeschlagen."))?;
      }
      Ok(key)
    }
  })
  .await?;
  let d = store(
    &state,
    auth.user.id,
    ip,
    b.label,
    b.purpose,
    key,
    b.passphrase,
    (b.riddle_question, b.riddle_answer),
    "profile_imported",
  )
  .await?;
  Ok(Json(d))
}

pub async fn update(
  State(state): State<AppState>,
  auth: Auth,
  Path(id): Path<i64>,
  Json(b): Json<UpdateProfile>,
) -> AppResult<Json<ProfileDetail>> {
  check_meta(&b.label, &b.purpose)?;
  let uid = auth.user.id;
  let row = state
    .db
    .run(move |c| {
      let n = c.execute(
        "UPDATE profiles SET label = ?3, purpose = ?4 WHERE user_id = ?1 AND id = ?2",
        params![uid, id, b.label.trim(), b.purpose.trim()],
      )?;
      if n == 0 {
        return Err(AppError::not_found());
      }
      keys::profile(c, uid, id)
    })
    .await?;
  Ok(Json(detail_of(&state, row)?))
}

pub async fn delete(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Path(id): Path<i64>,
  Json(b): Json<DeleteProfile>,
) -> AppResult<Json<OkResp>> {
  confirm_password(&state, &auth.user, &b.password).await?;
  let uid = auth.user.id;
  state
    .db
    .run(move |c| {
      let row = keys::profile(c, uid, id)?;
      c.execute("DELETE FROM profiles WHERE id = ?1 AND user_id = ?2", params![id, uid])?;
      auth::audit(
        c,
        Some(uid),
        "profile_deleted",
        &format!("Profil \"{}\" ({}) gelöscht", row.summary.label, row.summary.fingerprint),
        &ip,
      );
      Ok(())
    })
    .await?;
  Ok(Json(OkResp::yes()))
}

pub async fn change_passphrase(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Path(id): Path<i64>,
  Json(b): Json<ChangePassphrase>,
) -> AppResult<Json<OkResp>> {
  check(rules::passphrase(&b.new))?;
  if b.new == b.current {
    return Err(AppError::invalid("Die neue Passphrase muss sich von der alten unterscheiden."));
  }
  let (row, key) = keys::unlock_profile(&state, &auth.user, id, &b.current).await?;
  let (cur, new) = (b.current.clone(), b.new.clone());
  let (secret, revocation) = blocking(move || {
    let changed = pgp::change_passphrase(&key, &cur, &new)?;
    let rev = pgp::revocation_certificate(&changed, &new)?;
    Ok((pgp::to_bytes_secret(&changed)?, rev))
  })
  .await?;
  let sealed_secret = state.sealer.seal(&ctx_secret(&row.uid), &secret);
  let sealed_revocation = state.sealer.seal(&ctx_revocation(&row.uid), revocation.as_bytes());
  let uid = auth.user.id;
  state
    .db
    .run(move |c| {
      c.execute(
        "UPDATE profiles SET sealed_secret = ?3, sealed_revocation = ?4 WHERE id = ?1 AND user_id = ?2",
        params![id, uid, sealed_secret, sealed_revocation],
      )?;
      auth::audit(c, Some(uid), "passphrase_changed", &format!("Passphrase von \"{}\" geändert", row.summary.label), &ip);
      Ok(())
    })
    .await?;
  Ok(Json(OkResp::yes()))
}

pub async fn change_riddle(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Path(id): Path<i64>,
  Json(b): Json<ChangeRiddle>,
) -> AppResult<Json<OkResp>> {
  check(rules::riddle(&b.question, &b.answer))?;
  confirm_password(&state, &auth.user, &b.password).await?;
  let uid = auth.user.id;
  let row = state.db.run(move |c| keys::profile(c, uid, id)).await?;
  let (s, u, q, a) = (state.clone(), row.uid.clone(), b.question.clone(), b.answer.clone());
  let sealed = blocking(move || keys::seal_riddle(&s, &u, &q, &a)).await?;
  state
    .db
    .run(move |c| {
      c.execute("UPDATE profiles SET sealed_riddle = ?3 WHERE id = ?1 AND user_id = ?2", params![id, uid, sealed])?;
      auth::audit(c, Some(uid), "riddle_changed", &format!("Rätsel von \"{}\" geändert", row.summary.label), &ip);
      Ok(())
    })
    .await?;
  Ok(Json(OkResp::yes()))
}
