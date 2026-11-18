//! Gemeinsame Helfer: Profile/Kontakte laden, Siegel oeffnen, Passphrase- und Passwortpruefung mit
//! Sperre gegen Durchprobieren.

use super::blocking;
use crate::{
  AppState,
  auth::{self, User},
  error::{AppError, AppResult},
  pgp::{self, KnownKey, PgpError},
  security::limits,
};
use nrzpgp_shared::{Contact, ProfileSummary};
use ::pgp::composed::SignedSecretKey;
use rusqlite::{Connection, OptionalExtension, params};

/// Kontexte fuer die Siegel (siehe `seal.rs`).
pub fn ctx_secret(uid: &str) -> String {
  format!("profile:{uid}:secret")
}
pub fn ctx_revocation(uid: &str) -> String {
  format!("profile:{uid}:revocation")
}
pub fn ctx_riddle(uid: &str) -> String {
  format!("profile:{uid}:riddle")
}

/// Persoenliches Raetsel (versiegelt gespeichert): Frage im Klartext, Antwort als Argon2-Hash.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Riddle {
  pub question: String,
  pub answer_hash: String,
}

pub struct ProfileRow {
  pub id: i64,
  pub uid: String,
  pub summary: ProfileSummary,
  pub public_key: String,
  pub sealed_secret: Vec<u8>,
  pub sealed_revocation: Vec<u8>,
  pub sealed_riddle: Vec<u8>,
  pub exports: i64,
}

const PROFILE_COLS: &str = "id, uid, label, purpose, key_uid, email, fingerprint, key_id, algorithm, key_created_at, \
  last_used_at, public_key, sealed_secret, sealed_revocation, sealed_riddle, exports";

fn profile_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRow> {
  Ok(ProfileRow {
    id: r.get(0)?,
    uid: r.get(1)?,
    summary: ProfileSummary {
      id: r.get(0)?,
      label: r.get(2)?,
      purpose: r.get(3)?,
      user_id: r.get(4)?,
      email: r.get(5)?,
      fingerprint: r.get(6)?,
      key_id: r.get(7)?,
      algorithm: r.get(8)?,
      created_at: r.get(9)?,
      last_used_at: r.get(10)?,
    },
    public_key: r.get(11)?,
    sealed_secret: r.get(12)?,
    sealed_revocation: r.get(13)?,
    sealed_riddle: r.get(14)?,
    exports: r.get(15)?,
  })
}

pub fn profiles(c: &Connection, user_id: i64) -> AppResult<Vec<ProfileRow>> {
  let mut st = c.prepare(&format!("SELECT {PROFILE_COLS} FROM profiles WHERE user_id = ?1 ORDER BY label COLLATE NOCASE, id"))?;
  let rows = st.query_map([user_id], profile_from_row)?.collect::<Result<Vec<_>, _>>()?;
  Ok(rows)
}

pub fn profile(c: &Connection, user_id: i64, id: i64) -> AppResult<ProfileRow> {
  c.query_row(&format!("SELECT {PROFILE_COLS} FROM profiles WHERE user_id = ?1 AND id = ?2"), params![user_id, id], profile_from_row)
    .optional()?
    .ok_or_else(AppError::not_found)
}

pub fn touch_profile(c: &Connection, id: i64) {
  let _ = c.execute("UPDATE profiles SET last_used_at = ?2 WHERE id = ?1", params![id, crate::db::now()]);
}

pub struct ContactRow {
  pub contact: Contact,
  pub public_key: String,
}

const CONTACT_COLS: &str =
  "id, label, user_ids, fingerprint, key_id, algorithm, key_created_at, added_at, note, verified, public_key";

fn contact_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContactRow> {
  let uids: String = r.get(2)?;
  let public_key: String = r.get(10)?;
  let can_encrypt = pgp::parse_public(public_key.as_bytes()).map(|k| pgp::key_info(&k).can_encrypt).unwrap_or(false);
  Ok(ContactRow {
    contact: Contact {
      id: r.get(0)?,
      label: r.get(1)?,
      user_ids: serde_json::from_str(&uids).unwrap_or_default(),
      fingerprint: r.get(3)?,
      key_id: r.get(4)?,
      algorithm: r.get(5)?,
      created_at: r.get(6)?,
      added_at: r.get(7)?,
      can_encrypt,
      note: r.get(8)?,
      verified: r.get(9)?,
    },
    public_key,
  })
}

pub fn contacts(c: &Connection, user_id: i64) -> AppResult<Vec<ContactRow>> {
  let mut st = c.prepare(&format!("SELECT {CONTACT_COLS} FROM contacts WHERE user_id = ?1 ORDER BY label COLLATE NOCASE, id"))?;
  let rows = st.query_map([user_id], contact_from_row)?.collect::<Result<Vec<_>, _>>()?;
  Ok(rows)
}

pub fn contact(c: &Connection, user_id: i64, id: i64) -> AppResult<ContactRow> {
  c.query_row(&format!("SELECT {CONTACT_COLS} FROM contacts WHERE user_id = ?1 AND id = ?2"), params![user_id, id], contact_from_row)
    .optional()?
    .ok_or_else(AppError::not_found)
}

/// Alle eigenen und gespeicherten oeffentlichen Schluessel (zum Pruefen von Signaturen).
pub fn known_keys(c: &Connection, user_id: i64) -> AppResult<Vec<KnownKey>> {
  let mut out = Vec::new();
  for p in profiles(c, user_id)? {
    if let Ok(key) = pgp::parse_public(p.public_key.as_bytes()) {
      out.push(KnownKey { key, source: "profile", label: format!("{} (eigenes Profil \"{}\")", p.summary.user_id, p.summary.label) });
    }
  }
  for k in contacts(c, user_id)? {
    if let Ok(key) = pgp::parse_public(k.public_key.as_bytes()) {
      let verified = if k.contact.verified { ", Fingerabdruck geprüft" } else { "" };
      out.push(KnownKey { key, source: "contact", label: format!("{} (Kontakt{verified})", k.contact.label) });
    }
  }
  Ok(out)
}

/// Privaten Schluessel eines Profils entsiegeln (bleibt passphrase-geschuetzt).
pub fn unseal_secret(state: &AppState, row: &ProfileRow) -> AppResult<SignedSecretKey> {
  let bytes = state.sealer.open(&ctx_secret(&row.uid), &row.sealed_secret).ok_or_else(|| {
    tracing::error!("Profil {}: Siegel lässt sich nicht öffnen (falscher NRZPGP_MASTER_KEY?)", row.id);
    AppError::internal().msg("Der private Schlüssel lässt sich nicht entsiegeln. Wurde der Hauptschlüssel geändert?")
  })?;
  Ok(pgp::parse_secret(&bytes)?)
}

pub fn unseal_riddle(state: &AppState, row: &ProfileRow) -> AppResult<Riddle> {
  let bytes = state.sealer.open(&ctx_riddle(&row.uid), &row.sealed_riddle).ok_or_else(AppError::internal)?;
  serde_json::from_slice(&bytes).map_err(|_| AppError::internal())
}

pub fn seal_riddle(state: &AppState, uid: &str, question: &str, answer: &str) -> AppResult<Vec<u8>> {
  let r = Riddle {
    question: question.trim().to_string(),
    answer_hash: auth::hash_password(&nrzpgp_shared::rules::normalize_answer(answer))?,
  };
  let json = serde_json::to_vec(&r).map_err(|_| AppError::internal())?;
  Ok(state.sealer.seal(&ctx_riddle(uid), &json))
}

/// Laedt Profil + entsiegelten Schluessel und prueft die Passphrase (mit Sperre je Profil).
pub async fn unlock_profile(
  state: &AppState,
  user: &User,
  profile_id: i64,
  passphrase: &str,
) -> AppResult<(ProfileRow, SignedSecretKey)> {
  let limit_key = format!("pp:{profile_id}");
  if !state.limiter.peek(&limit_key, limits::PASSPHRASE_FAIL) {
    return Err(AppError::rate_limited().msg("Zu viele falsche Passphrasen. Bitte 15 Minuten warten."));
  }
  let uid = user.id;
  let row = state.db.run(move |c| profile(c, uid, profile_id)).await?;
  let key = unseal_secret(state, &row)?;
  let pass = passphrase.to_string();
  let (key, ok) = blocking(move || {
    let ok = pgp::check_passphrase(&key, &pass);
    Ok((key, ok))
  })
  .await?;
  match ok {
    Ok(()) => Ok((row, key)),
    Err(PgpError::WrongPassphrase) => {
      state.limiter.hit(&limit_key, limits::PASSPHRASE_FAIL);
      Err(AppError::wrong_passphrase())
    }
    Err(e) => Err(e.into()),
  }
}

/// Konto-Passwort bestaetigen (mit Sperre).
pub async fn confirm_password(state: &AppState, user: &User, password: &str) -> AppResult<()> {
  let limit_key = format!("pwc:{}", user.id);
  if !state.limiter.peek(&limit_key, limits::PASSWORD_CONFIRM_FAIL) {
    return Err(AppError::rate_limited().msg("Zu viele falsche Passwörter. Bitte 15 Minuten warten."));
  }
  let uid = user.id;
  let hash: String = state.db.run(move |c| Ok(c.query_row("SELECT password_hash FROM users WHERE id = ?1", [uid], |r| r.get(0))?)).await?;
  let pw = password.to_string();
  let ok = blocking(move || Ok(auth::verify_password(&pw, Some(&hash)))).await?;
  if ok {
    Ok(())
  } else {
    state.limiter.hit(&limit_key, limits::PASSWORD_CONFIRM_FAIL);
    Err(AppError::wrong_password())
  }
}

pub fn check(r: Result<(), &'static str>) -> AppResult<()> {
  r.map_err(AppError::invalid)
}
