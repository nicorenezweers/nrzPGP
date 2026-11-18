//! Kontakte: oeffentliche Schluessel anderer (Schluesselbund).

use super::{blocking, keys::{self, check}};
use crate::{
  AppState,
  auth::{self, Auth},
  db::now,
  error::{AppError, AppResult},
  pgp,
  security::{ClientIp, limits},
};
use axum::{
  Extension, Json,
  extract::{Path, State},
};
use nrzpgp_shared::{Contact, ContactDetail, ImportContact, Ok as OkResp, UpdateContact, rules};
use rusqlite::params;

pub async fn list(State(state): State<AppState>, auth: Auth) -> AppResult<Json<Vec<Contact>>> {
  let uid = auth.user.id;
  let rows = state.db.run(move |c| keys::contacts(c, uid)).await?;
  Ok(Json(rows.into_iter().map(|r| r.contact).collect()))
}

fn detail_of(row: keys::ContactRow) -> AppResult<ContactDetail> {
  let key = pgp::parse_public(row.public_key.as_bytes())?;
  Ok(ContactDetail { key: pgp::key_info(&key), public_key: row.public_key, contact: row.contact })
}

pub async fn detail(State(state): State<AppState>, auth: Auth, Path(id): Path<i64>) -> AppResult<Json<ContactDetail>> {
  let uid = auth.user.id;
  let row = state.db.run(move |c| keys::contact(c, uid, id)).await?;
  Ok(Json(detail_of(row)?))
}

/// Name aus der User-ID ohne E-Mail-Teil.
fn label_from_uid(uid: &str) -> String {
  let name = uid.split('<').next().unwrap_or(uid).trim();
  let name = if name.is_empty() { uid.trim() } else { name };
  name.chars().take(rules::LABEL_MAX).collect()
}

pub async fn import(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<ImportContact>,
) -> AppResult<Json<Vec<Contact>>> {
  check(rules::message(&b.armored))?;
  check(rules::note(&b.note))?;
  state.limit(format!("tools:{}", auth.user.id), limits::TOOLS)?;
  let text = b.armored.clone();
  let parsed = blocking(move || {
    let keys = pgp::parse_public_many(&text)?;
    keys
      .into_iter()
      .map(|k| {
        let info = pgp::key_info(&k);
        Ok((info, pgp::armor_public(&k)?, pgp::algorithm_label(&k), pgp::primary_uid(&k)))
      })
      .collect::<AppResult<Vec<_>>>()
  })
  .await?;
  let uid = auth.user.id;
  let note = b.note.trim().to_string();
  let ids = state
    .db
    .run(move |c| {
      let mut ids = Vec::new();
      for (info, armored, algorithm, primary) in parsed {
        let label = if primary.is_empty() { info.key_id.clone() } else { label_from_uid(&primary) };
        let uids = serde_json::to_string(&info.user_ids).unwrap_or_else(|_| "[]".into());
        // Neu anlegen oder Schluessel aktualisieren (z. B. neue Teilschluessel, verlaengert, widerrufen).
        c.execute(
          "INSERT INTO contacts (user_id, label, fingerprint, key_id, user_ids, algorithm, key_created_at, public_key, note, added_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
           ON CONFLICT (user_id, fingerprint) DO UPDATE SET public_key = excluded.public_key, user_ids = excluded.user_ids,
             algorithm = excluded.algorithm",
          params![uid, label, info.fingerprint, info.key_id, uids, algorithm, info.created_at, armored, note, now()],
        )?;
        let id: i64 = c.query_row(
          "SELECT id FROM contacts WHERE user_id = ?1 AND fingerprint = ?2",
          params![uid, info.fingerprint],
          |r| r.get(0),
        )?;
        auth::audit(c, Some(uid), "contact_added", &format!("Kontakt \"{label}\" ({}) gespeichert", info.fingerprint), &ip);
        ids.push(id);
      }
      let all = keys::contacts(c, uid)?;
      Ok(all.into_iter().filter(|r| ids.contains(&r.contact.id)).map(|r| r.contact).collect::<Vec<_>>())
    })
    .await?;
  Ok(Json(ids))
}

pub async fn update(
  State(state): State<AppState>,
  auth: Auth,
  Path(id): Path<i64>,
  Json(b): Json<UpdateContact>,
) -> AppResult<Json<ContactDetail>> {
  check(rules::label(&b.label))?;
  check(rules::note(&b.note))?;
  let uid = auth.user.id;
  let row = state
    .db
    .run(move |c| {
      let n = c.execute(
        "UPDATE contacts SET label = ?3, note = ?4, verified = ?5 WHERE user_id = ?1 AND id = ?2",
        params![uid, id, b.label.trim(), b.note.trim(), b.verified],
      )?;
      if n == 0 {
        return Err(AppError::not_found());
      }
      keys::contact(c, uid, id)
    })
    .await?;
  Ok(Json(detail_of(row)?))
}

pub async fn delete(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Path(id): Path<i64>,
) -> AppResult<Json<OkResp>> {
  let uid = auth.user.id;
  state
    .db
    .run(move |c| {
      let row = keys::contact(c, uid, id)?;
      c.execute("DELETE FROM contacts WHERE id = ?1 AND user_id = ?2", params![id, uid])?;
      auth::audit(c, Some(uid), "contact_deleted", &format!("Kontakt \"{}\" gelöscht", row.contact.label), &ip);
      Ok(())
    })
    .await?;
  Ok(Json(OkResp::yes()))
}
