//! PGP-Werkzeuge: verschluesseln, entschluesseln, signieren, pruefen, analysieren.
//!
//! Entschluesseln und Signieren laufen nur hier auf dem Server: die Oberflaeche schickt Nachricht
//! und Passphrase, bekommt nur das Ergebnis. Nichts davon wird gespeichert oder geloggt.

use super::{
  blocking,
  keys::{self, check},
};
use crate::{
  AppState,
  auth::{self, Auth},
  error::{AppError, AppResult},
  pgp::{self, KnownKey},
  security::{ClientIp, limits},
};
use axum::{Extension, Json, extract::State};
use base64::{Engine, engine::general_purpose::STANDARD};
use nrzpgp_shared::{
  DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, InspectKeyRequest, InspectMessageRequest, KeyInfo,
  MessageInfo, RecipientInfo, SignRequest, SignResponse, VerifyRequest, VerifyResponse, rules, sign_modes,
};

fn limit(state: &AppState, auth: &Auth) -> AppResult<()> {
  state.limit(format!("tools:{}", auth.user.id), limits::TOOLS)
}

async fn known(state: &AppState, auth: &Auth) -> AppResult<Vec<KnownKey>> {
  let uid = auth.user.id;
  state.db.run(move |c| keys::known_keys(c, uid)).await
}

async fn log(state: &AppState, uid: i64, action: &'static str, detail: String, ip: String) -> AppResult<()> {
  state
    .db
    .run(move |c| {
      auth::audit(c, Some(uid), action, &detail, &ip);
      Ok(())
    })
    .await
}

pub async fn encrypt(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<EncryptRequest>,
) -> AppResult<Json<EncryptResponse>> {
  check(rules::message(&b.text))?;
  if b.extra_keys.len() > rules::MESSAGE_MAX || b.password.len() > rules::PASSWORD_MAX {
    return Err(AppError::invalid("Eingabe zu lang."));
  }
  if b.profile_ids.len() + b.contact_ids.len() > 100 {
    return Err(AppError::invalid("Zu viele Empfänger."));
  }
  limit(&state, &auth)?;
  let uid = auth.user.id;
  let (pids, cids) = (b.profile_ids.clone(), b.contact_ids.clone());
  let selected: Vec<(String, String)> = state
    .db
    .run(move |c| {
      let mut out = Vec::new();
      for id in pids {
        let p = keys::profile(c, uid, id)?;
        out.push((format!("{} (eigenes Profil)", p.summary.user_id), p.public_key));
      }
      for id in cids {
        let k = keys::contact(c, uid, id)?;
        out.push((k.contact.user_ids.first().cloned().unwrap_or(k.contact.label), k.public_key));
      }
      Ok(out)
    })
    .await?;
  let signer = match b.sign_profile {
    Some(pid) => Some(keys::unlock_profile(&state, &auth.user, pid, &b.passphrase).await?),
    None => None,
  };
  let signer_label = signer.as_ref().map(|(row, _)| row.summary.label.clone());
  let (text, extra, password, passphrase) = (b.text.clone(), b.extra_keys.clone(), b.password.clone(), b.passphrase.clone());
  let (armored, recipients) = blocking(move || {
    let mut keys = Vec::new();
    let mut labels = Vec::new();
    for (label, armored) in &selected {
      keys.push(pgp::parse_public(armored.as_bytes())?);
      labels.push(label.clone());
    }
    if !extra.trim().is_empty() {
      for k in pgp::parse_public_many(&extra)? {
        labels.push(format!("{} (eingefügt)", pgp::primary_uid(&k)));
        keys.push(k);
      }
    }
    let pw = (!password.is_empty()).then_some(password.as_str());
    if pw.is_some() {
      labels.push("Passwort".into());
    }
    let signer = signer.as_ref().map(|(_, key)| pgp::Signer { key, passphrase: &passphrase });
    let armored = pgp::encrypt(&text, &keys, pw, signer)?;
    Ok((armored, labels))
  })
  .await?;
  let signed = signer_label.is_some();
  let detail = match &signer_label {
    Some(l) => format!("Nachricht an {} Empfänger verschlüsselt, signiert mit \"{l}\"", recipients.len()),
    None => format!("Nachricht an {} Empfänger verschlüsselt", recipients.len()),
  };
  log(&state, uid, "encrypt", detail, ip).await?;
  Ok(Json(EncryptResponse { armored, recipients, signed }))
}

pub async fn decrypt(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<DecryptRequest>,
) -> AppResult<Json<DecryptResponse>> {
  check(rules::message(&b.message))?;
  if b.passphrase.len() > rules::PASSPHRASE_MAX || b.password.len() > rules::PASSWORD_MAX {
    return Err(AppError::invalid("Eingabe zu lang."));
  }
  limit(&state, &auth)?;
  let known = known(&state, &auth).await?;
  let unlocked = match b.profile_id {
    Some(pid) => Some(keys::unlock_profile(&state, &auth.user, pid, &b.passphrase).await?),
    None => None,
  };
  if unlocked.is_none() && b.password.is_empty() {
    return Err(AppError::invalid("Bitte ein Profil (mit Passphrase) oder das Passwort der Nachricht angeben."));
  }
  // Passwort-Versuche fuer symmetrische Nachrichten ebenfalls begrenzen.
  let pw_key = format!("msgpw:{}", auth.user.id);
  if unlocked.is_none() && !state.limiter.peek(&pw_key, limits::PASSPHRASE_FAIL) {
    return Err(AppError::rate_limited().msg("Zu viele falsche Passwörter. Bitte 15 Minuten warten."));
  }
  let label = unlocked.as_ref().map(|(row, _)| (row.id, row.summary.label.clone()));
  let (message, passphrase, password) = (b.message.clone(), b.passphrase.clone(), b.password.clone());
  let result = blocking(move || {
    let key = unlocked.as_ref().map(|(_, k)| (k, passphrase.as_str()));
    let pw = (!password.is_empty()).then_some(password.as_str());
    Ok(pgp::decrypt(&message, key, pw, &known))
  })
  .await?;
  let d = match result {
    Ok(d) => d,
    Err(pgp::PgpError::WrongPassphrase) if label.is_none() => {
      state.limiter.hit(&pw_key, limits::PASSPHRASE_FAIL);
      return Err(AppError::wrong_passphrase().msg("Das Passwort der Nachricht ist falsch."));
    }
    Err(e) => return Err(e.into()),
  };
  let uid = auth.user.id;
  let detail = match &label {
    Some((id, l)) => {
      let id = *id;
      state.db.run(move |c| {
        keys::touch_profile(c, id);
        Ok(())
      }).await?;
      format!("Nachricht mit \"{l}\" entschlüsselt")
    }
    None => "Nachricht mit Passwort entschlüsselt".into(),
  };
  log(&state, uid, "decrypt", detail, ip).await?;
  let (text, binary) = match String::from_utf8(d.data) {
    Ok(t) => (t, false),
    Err(e) => (STANDARD.encode(e.into_bytes()), true),
  };
  Ok(Json(DecryptResponse { text, binary, file_name: d.file_name, signatures: d.signatures }))
}

pub async fn sign(
  State(state): State<AppState>,
  Extension(ClientIp(ip)): Extension<ClientIp>,
  auth: Auth,
  Json(b): Json<SignRequest>,
) -> AppResult<Json<SignResponse>> {
  check(rules::message(&b.text))?;
  if ![sign_modes::CLEARTEXT, sign_modes::DETACHED, sign_modes::INLINE].contains(&b.mode.as_str()) {
    return Err(AppError::invalid("Unbekannte Signatur-Art."));
  }
  limit(&state, &auth)?;
  let (row, key) = keys::unlock_profile(&state, &auth.user, b.profile_id, &b.passphrase).await?;
  let (text, pass, mode) = (b.text.clone(), b.passphrase.clone(), b.mode.clone());
  let armored = blocking(move || Ok(pgp::sign(&text, &key, &pass, &mode)?)).await?;
  let id = row.id;
  state.db.run(move |c| {
    keys::touch_profile(c, id);
    Ok(())
  }).await?;
  log(&state, auth.user.id, "sign", format!("Text mit \"{}\" signiert", row.summary.label), ip).await?;
  Ok(Json(SignResponse { armored }))
}

pub async fn verify(State(state): State<AppState>, auth: Auth, Json(b): Json<VerifyRequest>) -> AppResult<Json<VerifyResponse>> {
  check(rules::message(&b.message))?;
  if b.data.len() > rules::MESSAGE_MAX || b.extra_key.len() > rules::MESSAGE_MAX {
    return Err(AppError::invalid("Eingabe zu lang."));
  }
  limit(&state, &auth)?;
  let mut known = known(&state, &auth).await?;
  let (message, data, extra) = (b.message.clone(), b.data.clone(), b.extra_key.clone());
  let v = blocking(move || {
    if !extra.trim().is_empty() {
      for k in pgp::parse_public_many(&extra)? {
        let label = format!("{} (eingefügter Schlüssel)", pgp::primary_uid(&k));
        known.push(KnownKey { key: k, source: "extra", label });
      }
    }
    Ok(pgp::verify(&message, (!data.is_empty()).then_some(data.as_str()), &known)?)
  })
  .await?;
  Ok(Json(VerifyResponse { kind: v.kind.into(), text: v.text, signatures: v.signatures }))
}

pub async fn inspect_key(State(state): State<AppState>, auth: Auth, Json(b): Json<InspectKeyRequest>) -> AppResult<Json<Vec<KeyInfo>>> {
  check(rules::message(&b.armored))?;
  limit(&state, &auth)?;
  let text = b.armored.clone();
  let infos = blocking(move || {
    let mut out = Vec::new();
    // Private Schluessel werden nur gelesen, nie gespeichert.
    if text.contains("PRIVATE KEY BLOCK")
      && let Ok(k) = pgp::parse_secret(text.as_bytes())
    {
      out.push(pgp::secret_key_info(&k));
    }
    if out.is_empty() {
      out = pgp::parse_public_many(&text)?.iter().map(pgp::key_info).collect();
    }
    Ok(out)
  })
  .await?;
  Ok(Json(infos))
}

pub async fn inspect_message(
  State(state): State<AppState>,
  auth: Auth,
  Json(b): Json<InspectMessageRequest>,
) -> AppResult<Json<MessageInfo>> {
  check(rules::message(&b.message))?;
  limit(&state, &auth)?;
  let uid = auth.user.id;
  let (profiles, contacts) = state.db.run(move |c| Ok((keys::profiles(c, uid)?, keys::contacts(c, uid)?))).await?;
  let text = b.message.clone();
  let info = blocking(move || {
    let a = pgp::analyze(&text)?;
    let parsed_profiles: Vec<_> = profiles
      .iter()
      .filter_map(|p| pgp::parse_public(p.public_key.as_bytes()).ok().map(|k| (p.id, p.summary.label.clone(), k)))
      .collect();
    let parsed_contacts: Vec<_> = contacts
      .iter()
      .filter_map(|c| pgp::parse_public(c.public_key.as_bytes()).ok().map(|k| (c.contact.id, c.contact.label.clone(), k)))
      .collect();
    let recipients: Vec<RecipientInfo> = a
      .recipients
      .iter()
      .map(|(id, alg)| {
        let p = parsed_profiles.iter().find(|(_, _, k)| pgp::key_matches(k, id));
        let c = parsed_contacts.iter().find(|(_, _, k)| pgp::key_matches(k, id));
        RecipientInfo {
          key_id: id.clone(),
          algorithm: alg.clone(),
          profile_id: p.map(|x| x.0),
          profile_label: p.map(|x| x.1.clone()),
          contact_id: c.map(|x| x.0),
          contact_label: c.map(|x| x.1.clone()),
        }
      })
      .collect();
    let suggested_profile = recipients.iter().find_map(|r| r.profile_id);
    let mut details = a.details;
    for sid in &a.signer_key_ids {
      let who = parsed_profiles
        .iter()
        .find(|(_, _, k)| pgp::key_matches(k, sid))
        .map(|x| format!("eigenes Profil \"{}\"", x.1))
        .or_else(|| parsed_contacts.iter().find(|(_, _, k)| pgp::key_matches(k, sid)).map(|x| format!("Kontakt \"{}\"", x.1)))
        .unwrap_or_else(|| "unbekannter Schlüssel".into());
      details.push(format!("Signiert von {sid} ({who})"));
    }
    Ok(MessageInfo {
      kind: a.kind.into(),
      recipients,
      password_encrypted: a.password_encrypted,
      signer_key_ids: a.signer_key_ids,
      suggested_profile,
      details,
    })
  })
  .await?;
  Ok(Json(info))
}
