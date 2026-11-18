//! OpenPGP-Funktionen mit rPGP (reines Rust): Schluessel erzeugen/importieren, Passphrase aendern,
//! Widerrufszertifikat, verschluesseln, entschluesseln, signieren, pruefen, analysieren.
//!
//! Private Schluessel liegen hier nur als [`SignedSecretKey`] im Speicher und sind immer mit der
//! Passphrase des Profils geschuetzt (S2K). Entsperrt wird nur fuer die einzelne Operation.

use nrzpgp_shared::{KeyInfo, SubkeyInfo, algorithms};
use pgp::{
  composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, EncryptionCaps, Esk, KeyType,
    Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
  },
  crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
  packet::{RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData},
  ser::Serialize,
  types::{KeyDetails, KeyVersion, Password, PublicParams, SecretParams, StringToKey, Timestamp},
};
use rand::rngs::OsRng;
use std::io::Cursor;

/// Fehler fuer die Oberflaeche (deutsch, ohne interne Details).
#[derive(Debug, PartialEq)]
pub enum PgpError {
  /// Passphrase passt nicht zum Schluessel.
  WrongPassphrase,
  /// Eingabe ist kein (passendes) OpenPGP-Material.
  Invalid(String),
}

pub type Result<T> = std::result::Result<T, PgpError>;

fn invalid(msg: impl Into<String>) -> PgpError {
  PgpError::Invalid(msg.into())
}

fn ts(t: Timestamp) -> i64 {
  i64::from(t.as_secs())
}

pub fn hex_upper(b: &[u8]) -> String {
  hex::encode_upper(b)
}

pub fn fingerprint_of(k: &impl KeyDetails) -> String {
  hex_upper(k.fingerprint().as_bytes())
}

pub fn key_id_of(k: &impl KeyDetails) -> String {
  hex_upper(k.legacy_key_id().as_ref())
}

// ---------------------------------------------------------------------------------------------
// Erzeugen und Laden

/// Neues Schluesselpaar mit Passphrase-Schutz. `uid` z. B. `Max Muster <max@example.com>`.
pub fn generate(algorithm: &str, uid: &str, passphrase: &str) -> Result<SignedSecretKey> {
  let (version, primary, sub, seipd_v2) = match algorithm {
    algorithms::ED25519 => {
      (KeyVersion::V4, KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy), false)
    }
    algorithms::RSA4096 => (KeyVersion::V4, KeyType::Rsa(4096), KeyType::Rsa(4096), false),
    algorithms::V6 => (KeyVersion::V6, KeyType::Ed25519, KeyType::X25519, true),
    _ => return Err(invalid("Unbekannte Schlüsselart.")),
  };
  let mut enc = SubkeyParamsBuilder::default();
  enc
    .version(version)
    .key_type(sub)
    .can_sign(false)
    .can_encrypt(EncryptionCaps::All)
    .passphrase(Some(passphrase.to_string()));
  let enc = enc.build().map_err(|e| invalid(format!("Teilschlüssel: {e}")))?;

  let mut params = SecretKeyParamsBuilder::default();
  params
    .version(version)
    .key_type(primary)
    .can_certify(true)
    .can_sign(true)
    .can_encrypt(EncryptionCaps::None)
    .feature_seipd_v2(seipd_v2)
    .preferred_symmetric_algorithms(
      [SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES192, SymmetricKeyAlgorithm::AES128].into_iter().collect(),
    )
    .preferred_hash_algorithms([HashAlgorithm::Sha512, HashAlgorithm::Sha384, HashAlgorithm::Sha256].into_iter().collect())
    .primary_user_id(uid.to_string())
    .passphrase(Some(passphrase.to_string()))
    .subkeys(vec![enc]);
  if seipd_v2 {
    params.preferred_aead_algorithms(
      [(SymmetricKeyAlgorithm::AES256, pgp::crypto::aead::AeadAlgorithm::Ocb)].into_iter().collect(),
    );
  }
  let params = params.build().map_err(|e| invalid(format!("Parameter: {e}")))?;
  let key = params.generate(OsRng).map_err(|e| invalid(format!("Erzeugen fehlgeschlagen: {e}")))?;
  key.verify_bindings().map_err(|e| invalid(format!("Selbstprüfung fehlgeschlagen: {e}")))?;
  Ok(key)
}

/// Privaten Schluessel aus ASCII-Armor (oder binaer) lesen.
pub fn parse_secret(input: &[u8]) -> Result<SignedSecretKey> {
  let (key, _) = SignedSecretKey::from_reader_single(Cursor::new(input))
    .map_err(|_| invalid("Das ist kein gültiger privater OpenPGP-Schlüssel."))?;
  key.verify_bindings().map_err(|_| invalid("Die Selbstsignaturen des Schlüssels sind ungültig."))?;
  Ok(key)
}

/// Einen oeffentlichen Schluessel lesen.
pub fn parse_public(input: &[u8]) -> Result<SignedPublicKey> {
  let (key, _) = SignedPublicKey::from_reader_single(Cursor::new(input))
    .map_err(|_| invalid("Das ist kein gültiger öffentlicher OpenPGP-Schlüssel."))?;
  Ok(key)
}

/// Alle oeffentlichen Schluessel aus einem Text (mehrere Armor-Bloecke oder ein Schluesselbund).
/// Private Schluessel werden als oeffentliche gelesen (privates Material wird verworfen).
pub fn parse_public_many(text: &str) -> Result<Vec<SignedPublicKey>> {
  let mut out = Vec::new();
  for block in armor_blocks(text) {
    if block.contains("PRIVATE KEY BLOCK") {
      if let Ok((keys, _)) = SignedSecretKey::from_armor_many(Cursor::new(block.as_bytes())) {
        out.extend(keys.flatten().map(|k| k.to_public_key()));
      }
    } else if let Ok((keys, _)) = SignedPublicKey::from_armor_many(Cursor::new(block.as_bytes())) {
      out.extend(keys.flatten());
    }
  }
  if out.is_empty() {
    // Binaer oder ohne Armor-Kopf.
    if let Ok(keys) = SignedPublicKey::from_bytes_many(Cursor::new(text.as_bytes())) {
      out.extend(keys.flatten());
    }
  }
  if out.is_empty() {
    return Err(invalid("Kein öffentlicher OpenPGP-Schlüssel gefunden."));
  }
  Ok(out)
}

/// Einzelne `-----BEGIN PGP …-----`-Bloecke aus einem Text holen.
fn armor_blocks(text: &str) -> Vec<String> {
  let mut out = Vec::new();
  let mut rest = text;
  while let Some(start) = rest.find("-----BEGIN PGP ") {
    let after = &rest[start..];
    let Some(head_end) = after.find('\n') else { break };
    let kind = after[..head_end].trim().trim_start_matches("-----BEGIN ").trim_end_matches("-----").to_string();
    let end_marker = format!("-----END {kind}-----");
    let Some(end) = after.find(&end_marker) else { break };
    let stop = end + end_marker.len();
    out.push(after[..stop].to_string());
    rest = &after[stop..];
  }
  out
}

pub fn armor_public(key: &SignedPublicKey) -> Result<String> {
  key.to_armored_string(ArmorOptions::default()).map_err(|e| invalid(format!("Armor: {e}")))
}

pub fn armor_secret(key: &SignedSecretKey) -> Result<String> {
  key.to_armored_string(ArmorOptions::default()).map_err(|e| invalid(format!("Armor: {e}")))
}

pub fn to_bytes_secret(key: &SignedSecretKey) -> Result<Vec<u8>> {
  key.to_bytes().map_err(|e| invalid(format!("Serialisieren: {e}")))
}

/// Alle Teile des Schluessels sind mit einer Passphrase geschuetzt?
pub fn is_protected(key: &SignedSecretKey) -> bool {
  key.primary_key.secret_params().is_encrypted()
    && key.secret_subkeys.iter().all(|s| s.key.secret_params().is_encrypted())
}

/// Prueft die Passphrase, indem der Hauptschluessel probeweise entsperrt wird.
pub fn check_passphrase(key: &SignedSecretKey, passphrase: &str) -> Result<()> {
  let pw = Password::from(passphrase);
  match key.primary_key.unlock(&pw, |_, _| Ok(())) {
    Ok(Ok(())) => {}
    _ => return Err(PgpError::WrongPassphrase),
  }
  for sub in &key.secret_subkeys {
    match sub.key.unlock(&pw, |_, _| Ok(())) {
      Ok(Ok(())) => {}
      _ => return Err(PgpError::WrongPassphrase),
    }
  }
  Ok(())
}

/// Passphrase aendern (alle Teilschluessel). Bei v6 mit Argon2, bei v4 iteriert+gesalzen (GnuPG).
pub fn change_passphrase(key: &SignedSecretKey, current: &str, new: &str) -> Result<SignedSecretKey> {
  check_passphrase(key, current)?;
  let old = Password::from(current);
  let new = Password::from(new);
  let mut key = key.clone();
  key.primary_key.remove_password(&old).map_err(|_| PgpError::WrongPassphrase)?;
  key.primary_key.set_password(OsRng, &new).map_err(|e| invalid(format!("Passphrase setzen: {e}")))?;
  for sub in key.secret_subkeys.iter_mut() {
    sub.key.remove_password(&old).map_err(|_| PgpError::WrongPassphrase)?;
    sub.key.set_password(OsRng, &new).map_err(|e| invalid(format!("Passphrase setzen: {e}")))?;
  }
  Ok(key)
}

/// Widerrufszertifikat ("Schlüssel wird nicht mehr verwendet"), mit dem Hauptschluessel signiert.
pub fn revocation_certificate(key: &SignedSecretKey, passphrase: &str) -> Result<String> {
  let pw = Password::from(passphrase);
  let mut config = SignatureConfig::from_key(OsRng, &key.primary_key, SignatureType::KeyRevocation)
    .map_err(|e| invalid(format!("Widerruf: {e}")))?;
  config.hashed_subpackets = vec![
    Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).map_err(|e| invalid(e.to_string()))?,
    Subpacket::regular(SubpacketData::IssuerFingerprint(key.primary_key.fingerprint()))
      .map_err(|e| invalid(e.to_string()))?,
    Subpacket::regular(SubpacketData::RevocationReason(
      RevocationCode::NoReason,
      "Widerrufszertifikat, erstellt von nrzPGP".into(),
    ))
    .map_err(|e| invalid(e.to_string()))?,
  ];
  if key.primary_key.version() == KeyVersion::V4 {
    config.unhashed_subpackets = vec![
      Subpacket::regular(SubpacketData::IssuerKeyId(key.primary_key.legacy_key_id()))
        .map_err(|e| invalid(e.to_string()))?,
    ];
  }
  let sig = config
    .sign_key(&key.primary_key, &pw, key.primary_key.public_key())
    .map_err(|_| PgpError::WrongPassphrase)?;
  let packet = pgp::packet::Packet::from(sig);
  let mut buf = Vec::new();
  packet.to_writer(&mut buf).map_err(|e| invalid(e.to_string()))?;
  let mut out = Vec::new();
  pgp::armor::write(
    &packet,
    pgp::armor::BlockType::PublicKey,
    &mut out,
    Some(
      &[("Comment".to_string(), vec!["Widerrufszertifikat - nur im Notfall importieren".to_string()])]
        .into_iter()
        .collect(),
    ),
    true,
  )
  .map_err(|e| invalid(e.to_string()))?;
  String::from_utf8(out).map_err(|e| invalid(e.to_string()))
}

// ---------------------------------------------------------------------------------------------
// Informationen (Pruefer)

fn alg_name(alg: PublicKeyAlgorithm, params: &PublicParams) -> (String, Option<u32>) {
  match params {
    PublicParams::RSA(p) => {
      use rsa::traits::PublicKeyParts;
      let bits = (p.key.size() * 8) as u32;
      (format!("RSA {bits}"), Some(bits))
    }
    PublicParams::DSA(_) => ("DSA".into(), None),
    PublicParams::Elgamal(_) => ("ElGamal".into(), None),
    PublicParams::EdDSALegacy(_) => ("Ed25519 (EdDSA, v4)".into(), Some(256)),
    PublicParams::Ed25519(_) => ("Ed25519".into(), Some(256)),
    PublicParams::X25519(_) => ("X25519".into(), Some(256)),
    PublicParams::Ed448(_) => ("Ed448".into(), Some(448)),
    PublicParams::X448(_) => ("X448".into(), Some(448)),
    PublicParams::ECDH(p) => (format!("ECDH {}", p.curve().name()), None),
    PublicParams::ECDSA(p) => (format!("ECDSA {}", p.curve().name()), None),
    _ => (format!("{alg:?}"), None),
  }
}

fn flag_names(flags: &pgp::packet::KeyFlags) -> Vec<String> {
  let mut out = Vec::new();
  if flags.certify() {
    out.push("certify".into());
  }
  if flags.sign() {
    out.push("sign".into());
  }
  if flags.encrypt_comms() || flags.encrypt_storage() {
    out.push("encrypt".into());
  }
  if flags.authentication() {
    out.push("authenticate".into());
  }
  out
}

fn now_secs() -> i64 {
  crate::db::now()
}

/// Uebersicht ueber einen oeffentlichen Schluessel (inkl. Warnungen).
pub fn key_info(key: &SignedPublicKey) -> KeyInfo {
  let pk = &key.primary_key;
  let (algorithm, bits) = alg_name(pk.algorithm(), pk.public_params());
  let created_at = ts(pk.created_at());
  let mut warnings = Vec::new();

  // Selbstsignaturen der User-IDs bzw. Direkt-Signatur: Flags und Ablauf.
  let mut primary_flags = pgp::packet::KeyFlags::default();
  let mut expires_at = None;
  let mut user_ids = Vec::new();
  for u in &key.details.users {
    user_ids.push(String::from_utf8_lossy(u.id.id()).into_owned());
    if let Some(sig) = u.signatures.iter().filter(|s| s.created().is_some()).max_by_key(|s| s.created()) {
      let f = sig.key_flags();
      if flag_names(&f).len() > flag_names(&primary_flags).len() {
        primary_flags = f;
      }
      if let Some(d) = sig.key_expiration_time() {
        expires_at = Some(created_at + i64::from(d.as_secs()));
      }
    }
  }
  for sig in &key.details.direct_signatures {
    let f = sig.key_flags();
    if flag_names(&f).len() > flag_names(&primary_flags).len() {
      primary_flags = f;
    }
    if let Some(d) = sig.key_expiration_time() {
      expires_at = Some(created_at + i64::from(d.as_secs()));
    }
  }
  let revoked = !key.details.revocation_signatures.is_empty();
  let bindings_valid = key.verify_bindings().is_ok();

  let mut subkeys = Vec::new();
  for sk in &key.public_subkeys {
    let (alg, b) = alg_name(sk.key.algorithm(), sk.key.public_params());
    let sub_created = ts(sk.key.created_at());
    let binding = sk
      .signatures
      .iter()
      .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
      .filter(|s| s.created().is_some())
      .max_by_key(|s| s.created());
    let flags = binding.map(|s| flag_names(&s.key_flags())).unwrap_or_default();
    let sub_expires = binding.and_then(|s| s.key_expiration_time()).map(|d| sub_created + i64::from(d.as_secs()));
    let sub_revoked = sk.signatures.iter().any(|s| s.typ() == Some(SignatureType::SubkeyRevocation));
    if let Some(e) = sub_expires
      && e < now_secs()
    {
      warnings.push(format!("Teilschlüssel {} ist abgelaufen.", key_id_of(&sk.key)));
    }
    weak_alg_warning(&alg, b, &mut warnings);
    subkeys.push(SubkeyInfo {
      fingerprint: fingerprint_of(&sk.key),
      key_id: key_id_of(&sk.key),
      algorithm: alg,
      bits: b,
      created_at: sub_created,
      expires_at: sub_expires,
      flags,
      revoked: sub_revoked,
    });
  }

  let can_encrypt = !revoked && !encryption_keys(key).is_empty();
  let primary_flag_names = flag_names(&primary_flags);
  let can_sign = !revoked && (primary_flag_names.iter().any(|f| f == "sign") || subkeys.iter().any(|s| !s.revoked && s.flags.iter().any(|f| f == "sign")));

  weak_alg_warning(&algorithm, bits, &mut warnings);
  if revoked {
    warnings.push("Der Schlüssel wurde widerrufen.".into());
  }
  if !bindings_valid {
    warnings.push("Mindestens eine Selbstsignatur ist ungültig.".into());
  }
  if let Some(e) = expires_at
    && e < now_secs()
  {
    warnings.push("Der Schlüssel ist abgelaufen.".into());
  }
  if !can_encrypt && !revoked {
    warnings.push("Kein gültiger Teilschlüssel zum Verschlüsseln.".into());
  }
  if user_ids.is_empty() {
    warnings.push("Der Schlüssel hat keine User-ID.".into());
  }
  let version = match pk.version() {
    KeyVersion::V2 => 2,
    KeyVersion::V3 => 3,
    KeyVersion::V4 => 4,
    KeyVersion::V6 => 6,
    _ => 0,
  };
  if version < 4 {
    warnings.push("Veralteter Schlüssel (v3 oder älter).".into());
  }

  KeyInfo {
    version,
    fingerprint: fingerprint_of(pk),
    key_id: key_id_of(pk),
    algorithm,
    bits,
    created_at,
    expires_at,
    user_ids,
    flags: primary_flag_names,
    subkeys,
    revoked,
    bindings_valid,
    is_secret: false,
    secret_protected: None,
    can_encrypt,
    can_sign,
    warnings,
  }
}

fn weak_alg_warning(alg: &str, bits: Option<u32>, warnings: &mut Vec<String>) {
  if alg.starts_with("RSA") && bits.is_some_and(|b| b < 2048) {
    warnings.push(format!("{alg} ist zu schwach (mindestens 2048, besser 3072 Bit)."));
  } else if alg.starts_with("DSA") || alg.starts_with("ElGamal") {
    warnings.push(format!("{alg} gilt als veraltet."));
  }
}

/// Wie [`key_info`], fuer private Schluessel (zeigt den Passphrase-Schutz an).
pub fn secret_key_info(key: &SignedSecretKey) -> KeyInfo {
  let mut info = key_info(&key.to_public_key());
  info.is_secret = true;
  let protected = is_protected(key);
  info.secret_protected = Some(protected);
  if !protected {
    info.warnings.push("Der private Schlüssel ist NICHT mit einer Passphrase geschützt.".into());
  }
  info
}

/// Primaere User-ID (oder die erste).
pub fn primary_uid(key: &SignedPublicKey) -> String {
  key
    .details
    .users
    .iter()
    .find(|u| u.is_primary())
    .or_else(|| key.details.users.first())
    .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
    .unwrap_or_default()
}

/// E-Mail-Adresse aus `Name <mail>`.
pub fn email_of(uid: &str) -> String {
  match (uid.rfind('<'), uid.rfind('>')) {
    (Some(a), Some(b)) if a < b => uid[a + 1..b].trim().to_string(),
    _ if uid.contains('@') && !uid.contains(' ') => uid.trim().to_string(),
    _ => String::new(),
  }
}

/// Algorithmus-Kurzname des Hauptschluessels.
pub fn algorithm_label(key: &SignedPublicKey) -> String {
  let enc = key.public_subkeys.first().map(|s| alg_name(s.key.algorithm(), s.key.public_params()).0);
  let primary = alg_name(key.primary_key.algorithm(), key.primary_key.public_params()).0;
  match enc {
    Some(e) if e != primary => format!("{primary} + {e}"),
    _ => primary,
  }
}

// ---------------------------------------------------------------------------------------------
// Verschluesseln

/// Gueltige Teilschluessel zum Verschluesseln (nicht widerrufen, nicht abgelaufen). Hat der Schluessel
/// keine, wird der Hauptschluessel genommen, falls er verschluesseln kann (alte RSA-Schluessel).
pub fn encryption_keys(key: &SignedPublicKey) -> Vec<&pgp::composed::SignedPublicSubKey> {
  let now = now_secs();
  key
    .public_subkeys
    .iter()
    .filter(|sk| sk.key.algorithm().can_encrypt())
    .filter(|sk| !sk.signatures.iter().any(|s| s.typ() == Some(SignatureType::SubkeyRevocation)))
    .filter(|sk| {
      let created = ts(sk.key.created_at());
      let Some(binding) = sk
        .signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created())
      else {
        return false;
      };
      let f = binding.key_flags();
      let usable = f.encrypt_comms() || f.encrypt_storage() || (!f.sign() && !f.certify() && !f.authentication());
      let alive = binding.key_expiration_time().is_none_or(|d| created + i64::from(d.as_secs()) > now);
      usable && alive && binding.verify_subkey_binding(&key.primary_key, &sk.key).is_ok()
    })
    .collect()
}

pub struct Signer<'a> {
  pub key: &'a SignedSecretKey,
  pub passphrase: &'a str,
}

/// Text an Schluessel und/oder mit Passwort verschluesseln, optional signieren. Liefert ASCII-Armor.
pub fn encrypt(
  text: &str,
  recipients: &[SignedPublicKey],
  password: Option<&str>,
  signer: Option<Signer<'_>>,
) -> Result<String> {
  if recipients.is_empty() && password.is_none() {
    return Err(invalid("Bitte mindestens einen Empfänger oder ein Passwort angeben."));
  }
  let mut subkeys = Vec::new();
  for r in recipients {
    let keys = encryption_keys(r);
    if keys.is_empty() {
      return Err(invalid(format!(
        "An {} kann nicht verschlüsselt werden (kein gültiger Teilschlüssel).",
        primary_uid(r)
      )));
    }
    subkeys.extend(keys);
  }
  if let Some(s) = &signer {
    check_passphrase(s.key, s.passphrase)?;
  }
  // v2 (AEAD) nur, wenn alle Empfaenger v6-Schluessel haben und kein Passwort-Empfaenger dabei ist.
  let all_v6 = !subkeys.is_empty() && subkeys.iter().all(|k| k.key.version() == KeyVersion::V6) && password.is_none();
  let builder = MessageBuilder::from_bytes("", text.as_bytes().to_vec());
  let armored = if all_v6 {
    let mut b = builder.seipd_v2(
      OsRng,
      SymmetricKeyAlgorithm::AES256,
      pgp::crypto::aead::AeadAlgorithm::Ocb,
      pgp::crypto::aead::ChunkSize::default(),
    );
    for k in &subkeys {
      b.encrypt_to_key(OsRng, k).map_err(|e| invalid(format!("Verschlüsseln: {e}")))?;
    }
    if let Some(s) = &signer {
      b.sign(&s.key.primary_key, Password::from(s.passphrase), HashAlgorithm::Sha512);
    }
    b.to_armored_string(OsRng, ArmorOptions::default()).map_err(|e| sign_error(&e))?
  } else {
    let mut b = builder.seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
    for k in &subkeys {
      b.encrypt_to_key(OsRng, k).map_err(|e| invalid(format!("Verschlüsseln: {e}")))?;
    }
    if let Some(p) = password {
      let s2k = StringToKey::new_iterated(OsRng, HashAlgorithm::Sha256, 255);
      b.encrypt_with_password(s2k, &Password::from(p)).map_err(|e| invalid(format!("Passwort: {e}")))?;
    }
    if let Some(s) = &signer {
      b.sign(&s.key.primary_key, Password::from(s.passphrase), HashAlgorithm::Sha512);
    }
    b.to_armored_string(OsRng, ArmorOptions::default()).map_err(|e| sign_error(&e))?
  };
  Ok(armored)
}

fn sign_error(e: &pgp::errors::Error) -> PgpError {
  tracing::debug!("pgp: {e}");
  invalid("Die Nachricht konnte nicht erstellt werden.")
}

// ---------------------------------------------------------------------------------------------
// Entschluesseln und Pruefen

/// Ein bekannter oeffentlicher Schluessel zum Pruefen von Signaturen.
pub struct KnownKey {
  pub key: SignedPublicKey,
  /// `profile`, `contact`, `extra`
  pub source: &'static str,
  pub label: String,
}

#[derive(Debug)]
pub struct Decrypted {
  pub data: Vec<u8>,
  pub file_name: String,
  pub signatures: Vec<nrzpgp_shared::SignatureCheck>,
}

fn parse_message(text: &str) -> Result<Message<'_>> {
  let trimmed = text.trim();
  if trimmed.starts_with("-----BEGIN") {
    Message::from_string(trimmed).map(|(m, _)| m).map_err(|_| invalid("Das ist keine gültige OpenPGP-Nachricht."))
  } else {
    Err(invalid("Bitte die Nachricht mit -----BEGIN PGP MESSAGE----- einfügen."))
  }
}

/// Nachricht mit privatem Schluessel (und Passphrase) oder mit Passwort entschluesseln.
pub fn decrypt(
  text: &str,
  key: Option<(&SignedSecretKey, &str)>,
  password: Option<&str>,
  known: &[KnownKey],
) -> Result<Decrypted> {
  let msg = parse_message(text)?;
  if !msg.is_encrypted() {
    return Err(invalid("Die Nachricht ist nicht verschlüsselt (zum Prüfen den PGP-Prüfer nutzen)."));
  }
  let mut msg = match (key, password) {
    (Some((k, pass)), _) => {
      check_passphrase(k, pass)?;
      msg.decrypt(&Password::from(pass), k).map_err(|e| {
        tracing::debug!("decrypt: {e}");
        invalid("Die Nachricht ist nicht an diesen Schlüssel verschlüsselt oder beschädigt.")
      })?
    }
    (None, Some(pw)) => msg.decrypt_with_password(&Password::from(pw)).map_err(|e| {
      tracing::debug!("decrypt pw: {e}");
      PgpError::WrongPassphrase
    })?,
    (None, None) => return Err(invalid("Bitte ein Profil oder ein Passwort angeben.")),
  };
  if msg.is_compressed() {
    msg = msg.decompress().map_err(|_| invalid("Entpacken fehlgeschlagen."))?;
  }
  read_and_verify(msg, known)
}

/// Inhalt lesen und alle Signaturen gegen bekannte Schluessel pruefen.
fn read_and_verify(mut msg: Message<'_>, known: &[KnownKey]) -> Result<Decrypted> {
  let data = msg.as_data_vec().map_err(|e| {
    tracing::debug!("read: {e}");
    invalid("Die Nachricht ist beschädigt (Integritätsprüfung fehlgeschlagen).")
  })?;
  let file_name = msg
    .literal_data_header()
    .map(|h| String::from_utf8_lossy(h.file_name()).into_owned())
    .unwrap_or_default();
  let mut signatures = Vec::new();
  if let Message::Signed { reader, .. } = &msg {
    for i in 0..reader.num_signatures() {
      let sig = reader.signature(i);
      let issuer = sig.map(issuer_of).unwrap_or_default();
      let mut check = None;
      'outer: for k in known {
        for vk in verifying_keys(&k.key) {
          if let Ok(s) = msg.verify_nested_explicit(i, vk.as_ref()) {
            check = Some(nrzpgp_shared::SignatureCheck {
              valid: true,
              key_id: key_id_of(&k.key.primary_key),
              fingerprint: Some(fingerprint_of(&k.key.primary_key)),
              signer: Some(k.label.clone()),
              source: k.source.into(),
              created_at: s.created().map(ts),
              message: "Gültige Signatur.".into(),
            });
            break 'outer;
          }
        }
      }
      signatures.push(check.unwrap_or_else(|| unknown_signature(sig, &issuer, known)));
    }
  }
  Ok(Decrypted { data, file_name, signatures })
}

fn issuer_of(sig: &pgp::packet::Signature) -> String {
  if let Some(fp) = sig.issuer_fingerprint().first() {
    return hex_upper(fp.as_bytes());
  }
  sig.issuer_key_id().first().map(|k| hex_upper(k.as_ref())).unwrap_or_default()
}

/// Signatur eines unbekannten Schluessels – oder eines bekannten, aber ungueltig.
fn unknown_signature(sig: Option<&pgp::packet::Signature>, issuer: &str, known: &[KnownKey]) -> nrzpgp_shared::SignatureCheck {
  let owner = known.iter().find(|k| key_matches(&k.key, issuer));
  match owner {
    Some(k) => nrzpgp_shared::SignatureCheck {
      valid: false,
      key_id: key_id_of(&k.key.primary_key),
      fingerprint: Some(fingerprint_of(&k.key.primary_key)),
      signer: Some(k.label.clone()),
      source: k.source.into(),
      created_at: sig.and_then(|s| s.created()).map(ts),
      message: "UNGÜLTIGE Signatur: Inhalt wurde verändert oder die Signatur ist beschädigt.".into(),
    },
    None => nrzpgp_shared::SignatureCheck {
      valid: false,
      key_id: issuer.to_string(),
      fingerprint: None,
      signer: None,
      source: "unknown".into(),
      created_at: sig.and_then(|s| s.created()).map(ts),
      message: "Signatur von einem unbekannten Schlüssel – zum Prüfen den öffentlichen Schlüssel des Absenders hinzufügen.".into(),
    },
  }
}

/// Passt eine Key-ID oder ein Fingerabdruck zum Schluessel oder einem Teilschluessel?
pub fn key_matches(key: &SignedPublicKey, id: &str) -> bool {
  if id.is_empty() {
    return false;
  }
  let id = id.to_uppercase();
  let m = |k: &dyn KeyDetailsDyn| id == k.fp() || id == k.kid() || k.fp().ends_with(&id);
  m(&key.primary_key) || key.public_subkeys.iter().any(|s| m(&s.key))
}

trait KeyDetailsDyn {
  fn fp(&self) -> String;
  fn kid(&self) -> String;
}

impl<T: KeyDetails> KeyDetailsDyn for T {
  fn fp(&self) -> String {
    fingerprint_of(self)
  }
  fn kid(&self) -> String {
    key_id_of(self)
  }
}

/// Pruefen gegen Hauptschluessel und alle Teilschluessel.
fn sig_verifies(key: &SignedPublicKey, sig: &pgp::packet::Signature, data: &[u8]) -> bool {
  sig.verify(&key.primary_key, data).is_ok() || key.public_subkeys.iter().any(|s| sig.verify(&s.key, data).is_ok())
}

/// Hauptschluessel und alle Teilschluessel als Pruefschluessel.
fn verifying_keys(key: &SignedPublicKey) -> Vec<Box<dyn pgp::types::VerifyingKey + '_>> {
  let mut out: Vec<Box<dyn pgp::types::VerifyingKey + '_>> = vec![Box::new(&key.primary_key)];
  for sk in &key.public_subkeys {
    out.push(Box::new(&sk.key));
  }
  out
}

#[derive(Debug)]
pub struct Verified {
  pub kind: &'static str,
  pub text: Option<String>,
  pub signatures: Vec<nrzpgp_shared::SignatureCheck>,
}

/// Klartext-Signatur, signierte Nachricht oder abgetrennte Signatur (mit `data`) pruefen.
pub fn verify(message: &str, data: Option<&str>, known: &[KnownKey]) -> Result<Verified> {
  let trimmed = message.trim();
  if trimmed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
    let (msg, _) = CleartextSignedMessage::from_string(trimmed)
      .map_err(|_| invalid("Die Klartext-Signatur ist beschädigt."))?;
    let mut signatures = Vec::new();
    for sig in msg.signatures() {
      let issuer = issuer_of(sig);
      let mut check = None;
      let signed = msg.signed_text();
      if let Some(k) = known.iter().find(|k| sig_verifies(&k.key, sig, signed.as_bytes())) {
        check = Some(valid_check(k, sig));
      }
      signatures.push(check.unwrap_or_else(|| unknown_signature(Some(sig), &issuer, known)));
    }
    return Ok(Verified { kind: "cleartext", text: Some(msg.text().to_string()), signatures });
  }
  if trimmed.starts_with("-----BEGIN PGP SIGNATURE-----") {
    let data = data.filter(|d| !d.is_empty()).ok_or_else(|| invalid("Bitte den signierten Text angeben."))?;
    let (sig, _) =
      DetachedSignature::from_string(trimmed).map_err(|_| invalid("Die Signatur ist beschädigt."))?;
    let issuer = issuer_of(&sig.signature);
    // Text-Signaturen normalisieren Zeilenenden selbst; zusaetzlich mit CRLF/LF-Varianten probieren.
    let variants = [data.to_string(), data.replace("\r\n", "\n"), data.replace("\r\n", "\n").replace('\n', "\r\n")];
    let mut check = None;
    if let Some(k) = known.iter().find(|k| variants.iter().any(|v| sig_verifies(&k.key, &sig.signature, v.as_bytes()))) {
      check = Some(valid_check(k, &sig.signature));
    }
    let sigs = vec![check.unwrap_or_else(|| unknown_signature(Some(&sig.signature), &issuer, known))];
    return Ok(Verified { kind: "detached", text: None, signatures: sigs });
  }
  let mut msg = parse_message(trimmed)?;
  if msg.is_encrypted() {
    return Err(invalid("Die Nachricht ist verschlüsselt – bitte zuerst entschlüsseln."));
  }
  if msg.is_compressed() {
    msg = msg.decompress().map_err(|_| invalid("Entpacken fehlgeschlagen."))?;
  }
  if !msg.is_signed() {
    return Err(invalid("Die Nachricht ist nicht signiert."));
  }
  let d = read_and_verify(msg, known)?;
  Ok(Verified { kind: "inline", text: Some(String::from_utf8_lossy(&d.data).into_owned()), signatures: d.signatures })
}

fn valid_check(k: &KnownKey, sig: &pgp::packet::Signature) -> nrzpgp_shared::SignatureCheck {
  nrzpgp_shared::SignatureCheck {
    valid: true,
    key_id: key_id_of(&k.key.primary_key),
    fingerprint: Some(fingerprint_of(&k.key.primary_key)),
    signer: Some(k.label.clone()),
    source: k.source.into(),
    created_at: sig.created().map(ts),
    message: "Gültige Signatur.".into(),
  }
}

// ---------------------------------------------------------------------------------------------
// Signieren

pub fn sign(text: &str, key: &SignedSecretKey, passphrase: &str, mode: &str) -> Result<String> {
  check_passphrase(key, passphrase)?;
  let pw = Password::from(passphrase);
  match mode {
    nrzpgp_shared::sign_modes::CLEARTEXT => {
      let msg = CleartextSignedMessage::sign(OsRng, text, &key.primary_key, &pw).map_err(|e| sign_error(&e))?;
      msg.to_armored_string(ArmorOptions::default()).map_err(|e| sign_error(&e))
    }
    nrzpgp_shared::sign_modes::DETACHED => {
      let sig = DetachedSignature::sign_text_data(OsRng, &key.primary_key, &pw, HashAlgorithm::Sha512, text.as_bytes())
        .map_err(|e| sign_error(&e))?;
      sig.to_armored_string(ArmorOptions::default()).map_err(|e| sign_error(&e))
    }
    nrzpgp_shared::sign_modes::INLINE => {
      let mut b = MessageBuilder::from_bytes("", text.as_bytes().to_vec());
      b.sign_text();
      b.sign(&key.primary_key, pw, HashAlgorithm::Sha512);
      b.to_armored_string(OsRng, ArmorOptions::default()).map_err(|e| sign_error(&e))
    }
    _ => Err(invalid("Unbekannte Signatur-Art.")),
  }
}

// ---------------------------------------------------------------------------------------------
// Nachricht analysieren

pub struct Analysis {
  pub kind: &'static str,
  /// (Key-ID, Algorithmus)
  pub recipients: Vec<(String, String)>,
  pub password_encrypted: bool,
  pub signer_key_ids: Vec<String>,
  pub details: Vec<String>,
}

/// Erkennt die Art eines OpenPGP-Textes, ohne etwas zu entschluesseln.
pub fn analyze(text: &str) -> Result<Analysis> {
  let t = text.trim();
  let mut a = Analysis { kind: "literal", recipients: vec![], password_encrypted: false, signer_key_ids: vec![], details: vec![] };
  if t.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
    a.kind = "public_key";
    a.details.push("Öffentlicher Schlüssel – Details unter \"Schlüssel prüfen\".".into());
    return Ok(a);
  }
  if t.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
    a.kind = "secret_key";
    a.details.push("Privater Schlüssel – nicht weitergeben!".into());
    return Ok(a);
  }
  if t.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
    let (msg, _) = CleartextSignedMessage::from_string(t).map_err(|_| invalid("Die Klartext-Signatur ist beschädigt."))?;
    a.kind = "cleartext_signed";
    a.signer_key_ids = msg.signatures().iter().map(issuer_of).collect();
    a.details.push(format!("{} Signatur(en), {} Zeichen Text.", msg.signatures().len(), msg.text().chars().count()));
    return Ok(a);
  }
  if t.starts_with("-----BEGIN PGP SIGNATURE-----") {
    let (sig, _) = DetachedSignature::from_string(t).map_err(|_| invalid("Die Signatur ist beschädigt."))?;
    a.kind = "signature";
    a.signer_key_ids = vec![issuer_of(&sig.signature)];
    if let Some(c) = sig.signature.created() {
      a.details.push(format!("Erstellt: {}", ts(c)));
    }
    if let Some(h) = sig.signature.hash_alg() {
      a.details.push(format!("Hash: {h:?}"));
    }
    return Ok(a);
  }
  let msg = parse_message(t)?;
  match &msg {
    Message::Encrypted { esk, edata, .. } => {
      a.kind = "encrypted";
      for e in esk {
        match e {
          Esk::PublicKeyEncryptedSessionKey(p) => {
            let id = p
              .fingerprint()
              .ok()
              .flatten()
              .map(|f| hex_upper(f.as_bytes()))
              .or_else(|| p.id().ok().map(|k| hex_upper(k.as_ref())))
              .unwrap_or_else(|| "0000000000000000".into());
            let alg = p.algorithm().map(|a| format!("{a:?}")).unwrap_or_default();
            a.recipients.push((id, alg));
          }
          Esk::SymKeyEncryptedSessionKey(_) => a.password_encrypted = true,
        }
      }
      let container = match edata {
        pgp::composed::Edata::SymEncryptedProtectedData { .. } => "SEIPD (mit Integritätsschutz)",
        pgp::composed::Edata::SymEncryptedData { .. } => "SED (OHNE Integritätsschutz, veraltet!)",
        _ => "verschlüsselte Daten",
      };
      a.details.push(format!("Container: {container}"));
      a.details.push(format!("{} Empfänger-Schlüssel, Passwort: {}", a.recipients.len(), if a.password_encrypted { "ja" } else { "nein" }));
    }
    Message::Signed { reader, .. } => {
      a.kind = "signed";
      for i in 0..reader.num_signatures() {
        if let Some(s) = reader.signature(i) {
          a.signer_key_ids.push(issuer_of(s));
        }
      }
      a.details.push("Signierte Nachricht (Inhalt eingebettet).".into());
    }
    Message::Compressed { .. } => {
      a.kind = "compressed";
      a.details.push("Komprimierte Nachricht.".into());
    }
    Message::Literal { .. } => {
      a.details.push("Unverschlüsselte, unsignierte Daten.".into());
    }
  }
  Ok(a)
}

/// Entsperrt den Schluessel probeweise – dient nur dazu, `SecretParams` sicher zu nutzen.
#[allow(dead_code)]
fn _assert_types(p: &SecretParams) -> bool {
  p.is_encrypted()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn known(key: &SignedSecretKey, label: &str) -> KnownKey {
    KnownKey { key: key.to_public_key(), source: "profile", label: label.into() }
  }

  #[test]
  fn ed25519_roundtrip() {
    let key = generate(algorithms::ED25519, "Test <test@example.com>", "richtig-lange-passphrase").unwrap();
    assert!(is_protected(&key));
    assert_eq!(check_passphrase(&key, "falsch-falsch-falsch"), Err(PgpError::WrongPassphrase));
    check_passphrase(&key, "richtig-lange-passphrase").unwrap();

    let pubkey = key.to_public_key();
    let info = key_info(&pubkey);
    assert!(info.can_encrypt, "{info:?}");
    assert!(info.can_sign, "{info:?}");
    assert_eq!(info.user_ids, vec!["Test <test@example.com>".to_string()]);
    assert!(info.warnings.is_empty(), "{:?}", info.warnings);

    let signer = Signer { key: &key, passphrase: "richtig-lange-passphrase" };
    let armored = encrypt("Hallo Welt äöü", &[pubkey.clone()], None, Some(signer)).unwrap();
    assert!(armored.contains("BEGIN PGP MESSAGE"));

    let a = analyze(&armored).unwrap();
    assert_eq!(a.kind, "encrypted");
    assert_eq!(a.recipients.len(), 1);
    assert!(key_matches(&pubkey, &a.recipients[0].0));

    assert_eq!(
      decrypt(&armored, Some((&key, "nein-nein-nein-nein")), None, &[]).unwrap_err(),
      PgpError::WrongPassphrase
    );
    let d = decrypt(&armored, Some((&key, "richtig-lange-passphrase")), None, &[known(&key, "Ich")]).unwrap();
    assert_eq!(String::from_utf8(d.data).unwrap(), "Hallo Welt äöü");
    assert_eq!(d.signatures.len(), 1);
    assert!(d.signatures[0].valid, "{:?}", d.signatures);

    // Armor-Runde fuer den privaten Schluessel.
    let again = parse_secret(armor_secret(&key).unwrap().as_bytes()).unwrap();
    assert_eq!(fingerprint_of(&again.primary_key), fingerprint_of(&key.primary_key));
  }

  #[test]
  fn sign_and_verify_all_modes() {
    let key = generate(algorithms::ED25519, "Signer <s@example.com>", "passphrase-123456").unwrap();
    let k = [known(&key, "Signer")];
    for mode in [nrzpgp_shared::sign_modes::CLEARTEXT, nrzpgp_shared::sign_modes::INLINE] {
      let s = sign("Zeile 1\nZeile 2\n", &key, "passphrase-123456", mode).unwrap();
      let v = verify(&s, None, &k).unwrap();
      assert!(v.signatures.iter().all(|c| c.valid), "{mode}: {:?}", v.signatures);
      assert!(v.text.unwrap().contains("Zeile 2"));
      // Ohne bekannten Schluessel: unbekannt.
      let v = verify(&s, None, &[]).unwrap();
      assert!(!v.signatures[0].valid);
      assert_eq!(v.signatures[0].source, "unknown");
    }
    let det = sign("Daten", &key, "passphrase-123456", nrzpgp_shared::sign_modes::DETACHED).unwrap();
    assert!(verify(&det, Some("Daten"), &k).unwrap().signatures[0].valid);
    assert!(!verify(&det, Some("Daten!"), &k).unwrap().signatures[0].valid);

    // Manipulierte Klartext-Signatur.
    let s = sign("Betrag: 10 CHF", &key, "passphrase-123456", nrzpgp_shared::sign_modes::CLEARTEXT).unwrap();
    let forged = s.replace("Betrag: 10 CHF", "Betrag: 99 CHF");
    let v = verify(&forged, None, &k).unwrap();
    assert!(!v.signatures[0].valid);
    assert_eq!(v.signatures[0].source, "profile");
  }

  #[test]
  fn passphrase_change_and_revocation() {
    let key = generate(algorithms::ED25519, "R <r@example.com>", "alte-passphrase-1").unwrap();
    let changed = change_passphrase(&key, "alte-passphrase-1", "neue-passphrase-2").unwrap();
    assert!(check_passphrase(&changed, "alte-passphrase-1").is_err());
    check_passphrase(&changed, "neue-passphrase-2").unwrap();
    assert!(is_protected(&changed));
    let rev = revocation_certificate(&changed, "neue-passphrase-2").unwrap();
    assert!(rev.contains("BEGIN PGP PUBLIC KEY BLOCK"), "{rev}");
    assert!(revocation_certificate(&changed, "falsch-falsch-1").is_err());
  }

  #[test]
  fn password_encryption() {
    let armored = encrypt("geheim", &[], Some("ein-passwort"), None).unwrap();
    let a = analyze(&armored).unwrap();
    assert!(a.password_encrypted);
    let d = decrypt(&armored, None, Some("ein-passwort"), &[]).unwrap();
    assert_eq!(d.data, b"geheim");
    assert!(decrypt(&armored, None, Some("falsch"), &[]).is_err());
  }

  #[test]
  fn v6_roundtrip() {
    let key = generate(algorithms::V6, "Neu <neu@example.com>", "v6-passphrase-lang").unwrap();
    let info = key_info(&key.to_public_key());
    assert_eq!(info.version, 6);
    let armored = encrypt("v6!", &[key.to_public_key()], None, None).unwrap();
    let d = decrypt(&armored, Some((&key, "v6-passphrase-lang")), None, &[]).unwrap();
    assert_eq!(d.data, b"v6!");
  }

  #[test]
  fn many_public_keys() {
    let a = generate(algorithms::ED25519, "A <a@example.com>", "aaaaaaaaaaaaaa").unwrap();
    let b = generate(algorithms::ED25519, "B <b@example.com>", "bbbbbbbbbbbbbb").unwrap();
    let text = format!(
      "Hier zwei Schlüssel:\n{}\nund\n{}",
      armor_public(&a.to_public_key()).unwrap(),
      armor_public(&b.to_public_key()).unwrap()
    );
    let keys = parse_public_many(&text).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(email_of(&primary_uid(&keys[1])), "b@example.com");
  }
}

/// Austausch mit GnuPG (manuell): `INTEROP_DIR=/tmp/x cargo test -p nrzpgp interop -- --ignored`
/// schreibt Schluessel und Nachrichten; `scripts/gpg-interop.sh` prueft sie mit GnuPG und schreibt
/// dessen Antwort zurueck, die der zweite Lauf (mit vorhandener `from_gpg.asc`) entschluesselt.
#[cfg(test)]
mod interop {
  use super::*;

  #[test]
  #[ignore]
  fn interop() {
    let Ok(dir) = std::env::var("INTEROP_DIR") else { return };
    let dir = std::path::PathBuf::from(dir);
    let pass = "interop-passphrase-123";
    let sec_path = dir.join("sec.asc");
    let key = if sec_path.exists() {
      parse_secret(&std::fs::read(&sec_path).unwrap()).unwrap()
    } else {
      let alg = std::env::var("INTEROP_ALG").unwrap_or_else(|_| algorithms::ED25519.into());
      let key = generate(&alg, "Interop <interop@example.com>", pass).unwrap();
      std::fs::write(&sec_path, armor_secret(&key).unwrap()).unwrap();
      std::fs::write(dir.join("pub.asc"), armor_public(&key.to_public_key()).unwrap()).unwrap();
      std::fs::write(dir.join("revocation.asc"), revocation_certificate(&key, pass).unwrap()).unwrap();
      let signer = Signer { key: &key, passphrase: pass };
      std::fs::write(dir.join("from_rpgp.asc"), encrypt("Hallo GnuPG, gruss von nrzPGP", &[key.to_public_key()], None, Some(signer)).unwrap()).unwrap();
      std::fs::write(dir.join("clear.asc"), sign("Klartext von nrzPGP\n", &key, pass, nrzpgp_shared::sign_modes::CLEARTEXT).unwrap()).unwrap();
      std::fs::write(dir.join("pw.asc"), encrypt("Passwort-Nachricht", &[], Some("pw-123"), None).unwrap()).unwrap();
      key
    };
    let reply = dir.join("from_gpg.asc");
    if reply.exists() {
      let known = [KnownKey { key: key.to_public_key(), source: "profile", label: "Interop".into() }];
      let d = decrypt(&std::fs::read_to_string(&reply).unwrap(), Some((&key, pass)), None, &known).unwrap();
      assert_eq!(String::from_utf8(d.data).unwrap().trim(), "Antwort von GnuPG");
      assert!(d.signatures.iter().all(|s| s.valid), "{:?}", d.signatures);
      let v = verify(&std::fs::read_to_string(dir.join("gpg_clear.asc")).unwrap(), None, &known).unwrap();
      assert!(v.signatures[0].valid, "{:?}", v.signatures);
      let d = decrypt(&std::fs::read_to_string(dir.join("gpg_pw.asc")).unwrap(), None, Some("gpg-pw-456"), &[]).unwrap();
      assert_eq!(String::from_utf8(d.data).unwrap().trim(), "GnuPG Passwort");
    }
  }
}
