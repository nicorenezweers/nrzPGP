//! nrzPGP – API-Typen und Eingaberegeln, gemeinsam fuer Server (`server/`) und Oberflaeche (`web/`).
//!
//! Alle Endpunkte liegen unter `/api/v1` (JSON). Schreibende Anfragen brauchen den Header
//! [`CSRF_HEADER`]. Antwortet der Server mit `captcha_required` (Feld `message` = Bereich), loest die
//! Oberflaeche das Cap-Widget fuer diesen Bereich und schickt die Anfrage mit `captcha` erneut.
//!
//! | Methode | Pfad | Body → Antwort |
//! |---------|------|----------------|
//! | GET  | `/api/v1/site` | → [`SiteInfo`] |
//! | POST | `/api/v1/auth/login` | [`LoginRequest`] → [`Me`] (Cap `login`) |
//! | POST | `/api/v1/auth/logout` | `{}` → [`Ok`] |
//! | POST | `/api/v1/account/password` | [`ChangePassword`] → [`Ok`] (meldet andere Geraete ab) |
//! | POST | `/api/v1/account/logout-all` | `{}` → [`Ok`] |
//! | GET  | `/api/v1/audit` | → `Vec<`[`AuditEntry`]`>` |
//! | GET  | `/api/v1/profiles` | → `Vec<`[`ProfileSummary`]`>` |
//! | POST | `/api/v1/profiles` | [`CreateProfile`] → [`ProfileDetail`] (Schluessel wird erzeugt) |
//! | POST | `/api/v1/profiles/import` | [`ImportProfile`] → [`ProfileDetail`] |
//! | GET  | `/api/v1/profiles/{id}` | → [`ProfileDetail`] |
//! | PATCH| `/api/v1/profiles/{id}` | [`UpdateProfile`] → [`ProfileDetail`] |
//! | POST | `/api/v1/profiles/{id}/delete` | [`DeleteProfile`] → [`Ok`] |
//! | POST | `/api/v1/profiles/{id}/passphrase` | [`ChangePassphrase`] → [`Ok`] |
//! | POST | `/api/v1/profiles/{id}/riddle` | [`ChangeRiddle`] → [`Ok`] |
//! | POST | `/api/v1/vault/start` | [`VaultStart`] → [`VaultState`] |
//! | POST | `/api/v1/vault/answer` | [`VaultAnswer`] → [`VaultState`] |
//! | POST | `/api/v1/vault/finish` | [`VaultFinish`] → [`VaultSecret`] (Cap `vault`) |
//! | POST | `/api/v1/vault/cancel` | [`VaultCancel`] → [`Ok`] |
//! | GET  | `/api/v1/contacts` | → `Vec<`[`Contact`]`>` |
//! | POST | `/api/v1/contacts` | [`ImportContact`] → `Vec<`[`Contact`]`>` (neu importierte) |
//! | GET  | `/api/v1/contacts/{id}` | → [`ContactDetail`] |
//! | PATCH| `/api/v1/contacts/{id}` | [`UpdateContact`] → [`ContactDetail`] |
//! | DELETE | `/api/v1/contacts/{id}` | → [`Ok`] |
//! | POST | `/api/v1/tools/encrypt` | [`EncryptRequest`] → [`EncryptResponse`] |
//! | POST | `/api/v1/tools/decrypt` | [`DecryptRequest`] → [`DecryptResponse`] |
//! | POST | `/api/v1/tools/sign` | [`SignRequest`] → [`SignResponse`] |
//! | POST | `/api/v1/tools/verify` | [`VerifyRequest`] → [`VerifyResponse`] |
//! | POST | `/api/v1/tools/inspect-key` | [`InspectKeyRequest`] → `Vec<`[`KeyInfo`]`>` |
//! | POST | `/api/v1/tools/inspect-message` | [`InspectMessageRequest`] → [`MessageInfo`] |
//! | POST | `/api/cap/{scope}/challenge` und `/redeem` | Cap-Widget (gleiche Origin) |

use serde::{Deserialize, Serialize};

pub mod rules;

/// Header, den jede schreibende API-Anfrage tragen muss (CSRF-Schutz).
pub const CSRF_HEADER: &str = "x-nrz-pgp";
/// Name des HttpOnly-Sitzungs-Cookies.
pub const SESSION_COOKIE: &str = "nrzpgp_session";
/// Bereiche fuer das Cap-Captcha: Anmeldung und Herausgabe eines privaten Schluessels.
pub const CAPTCHA_SCOPES: [&str; 2] = ["login", "vault"];

/// Fehlercodes (`error` in [`ApiError`]).
pub mod codes {
  pub const INVALID_INPUT: &str = "invalid_input";
  pub const NOT_FOUND: &str = "not_found";
  pub const FORBIDDEN: &str = "forbidden";
  pub const NOT_LOGGED_IN: &str = "not_logged_in";
  pub const RATE_LIMITED: &str = "rate_limited";
  pub const WRONG_PASSWORD: &str = "wrong_password";
  pub const WRONG_PASSPHRASE: &str = "wrong_passphrase";
  pub const PGP_ERROR: &str = "pgp_error";
  pub const VAULT_EXPIRED: &str = "vault_expired";
  pub const VAULT_LOCKED: &str = "vault_locked";
  pub const CAPTCHA_REQUIRED: &str = "captcha_required";
  pub const CAPTCHA_INVALID: &str = "captcha_invalid";
  pub const CAPTCHA_UNAVAILABLE: &str = "captcha_unavailable";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
  pub error: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub message: Option<String>,
}

/// Leere Erfolgsantwort `{"ok": true}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ok {
  pub ok: bool,
}

impl Ok {
  pub const fn yes() -> Self {
    Self { ok: true }
  }
}

// ---------------------------------------------------------------------------------------------
// Seite und Konto

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SiteInfo {
  pub name: String,
  pub version: String,
  /// Cap-Captcha aktiv?
  pub captcha: bool,
  /// Angemeldetes Konto (`None` = Anmeldeseite zeigen).
  pub me: Option<Me>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Me {
  pub name: String,
  /// Unix-Sekunden, wann die Sitzung endet.
  pub session_expires_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginRequest {
  pub name: String,
  pub password: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub captcha: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangePassword {
  pub current: String,
  pub new: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
  pub id: i64,
  pub at: i64,
  /// Kurzer Code, z. B. `login`, `login_failed`, `decrypt`, `vault_export`, `vault_failed`.
  pub action: String,
  /// Lesbare Beschreibung (nie Nachrichteninhalte oder Schluessel).
  pub detail: String,
  pub ip: String,
}

// ---------------------------------------------------------------------------------------------
// Profile (eigene Schluesselpaare)

/// Verfuegbare Schluesselarten beim Erzeugen.
pub mod algorithms {
  /// Ed25519 (Signieren) + Curve25519 (Verschluesseln), OpenPGP v4 – kompatibel mit GnuPG. Standard.
  pub const ED25519: &str = "ed25519";
  /// RSA 4096 Bit (v4) – fuer alte Gegenstellen. Erzeugen dauert einige Sekunden.
  pub const RSA4096: &str = "rsa4096";
  /// Ed25519 + X25519 nach RFC 9580 (v6, AEAD, Argon2) – modern, aber nicht mit aelterem GnuPG.
  pub const V6: &str = "v6";
  pub const ALL: [(&str, &str); 3] = [
    (ED25519, "Ed25519 / Curve25519 (empfohlen, GnuPG-kompatibel)"),
    (RSA4096, "RSA 4096 (für alte Programme)"),
    (V6, "OpenPGP v6: Ed25519 / X25519 (RFC 9580, modern)"),
  ];
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileSummary {
  pub id: i64,
  /// Eigener Name des Profils, z. B. "Arbeit" oder "Privat".
  pub label: String,
  /// Wofuer das Profil gedacht ist (frei).
  pub purpose: String,
  /// Primaere User-ID des Schluessels, z. B. `Max <max@example.com>`.
  pub user_id: String,
  pub email: String,
  /// Fingerabdruck, Grossbuchstaben ohne Leerzeichen.
  pub fingerprint: String,
  pub key_id: String,
  pub algorithm: String,
  pub created_at: i64,
  pub last_used_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileDetail {
  pub summary: ProfileSummary,
  /// Oeffentlicher Schluessel (ASCII-Armor) – darf weitergegeben werden.
  pub public_key: String,
  pub key: KeyInfo,
  /// Frage des persoenlichen Raetsels (die Antwort liegt nur als Argon2-Hash vor).
  pub riddle_question: String,
  /// Wie oft der private Schluessel schon herausgegeben wurde.
  pub exports: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CreateProfile {
  pub label: String,
  pub purpose: String,
  pub name: String,
  pub email: String,
  #[serde(default)]
  pub comment: String,
  /// Siehe [`algorithms`].
  pub algorithm: String,
  /// Passphrase des privaten Schluessels (OpenPGP-S2K). Wird nirgends gespeichert.
  pub passphrase: String,
  /// Persoenliches Raetsel fuer die Herausgabe des privaten Schluessels.
  pub riddle_question: String,
  pub riddle_answer: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportProfile {
  pub label: String,
  pub purpose: String,
  /// Privater Schluessel (ASCII-Armor), muss mit `passphrase` geschuetzt sein.
  pub secret_key: String,
  pub passphrase: String,
  pub riddle_question: String,
  pub riddle_answer: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UpdateProfile {
  pub label: String,
  pub purpose: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeleteProfile {
  /// Konto-Passwort zur Bestaetigung.
  pub password: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangePassphrase {
  pub current: String,
  pub new: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangeRiddle {
  /// Konto-Passwort zur Bestaetigung.
  pub password: String,
  pub question: String,
  pub answer: String,
}

// ---------------------------------------------------------------------------------------------
// Tresor: privaten Schluessel nach mehreren Raetseln + Cap herausgeben

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VaultStart {
  pub profile_id: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VaultAnswer {
  pub vault_id: String,
  pub answer: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VaultCancel {
  pub vault_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VaultFinish {
  pub vault_id: String,
  /// Konto-Passwort.
  pub password: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub captcha: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Puzzle {
  /// `math`, `sequence`, `anagram`, `caesar`, `personal`
  pub kind: String,
  pub title: String,
  /// Aufgabe (reiner Text).
  pub prompt: String,
  #[serde(default)]
  pub hint: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultState {
  pub vault_id: String,
  pub profile_label: String,
  /// Erledigte Raetsel.
  pub solved: u32,
  /// Anzahl Raetsel insgesamt.
  pub total: u32,
  /// Aktuelles Raetsel; `None`, wenn alle geloest sind (dann folgt `vault/finish`).
  pub puzzle: Option<Puzzle>,
  /// Verbleibende Fehlversuche, danach ist der Tresor fuer dieses Profil gesperrt.
  pub attempts_left: u32,
  /// Letzte Antwort war falsch (neues Raetsel derselben Art).
  pub last_wrong: bool,
  /// Unix-Sekunden, wann der Vorgang verfaellt.
  pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultSecret {
  pub fingerprint: String,
  /// Privater Schluessel (ASCII-Armor), weiterhin mit der Passphrase geschuetzt.
  pub secret_key: String,
  /// Widerrufszertifikat (ASCII-Armor).
  pub revocation_certificate: String,
}

// ---------------------------------------------------------------------------------------------
// Kontakte (oeffentliche Schluessel anderer)

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Contact {
  pub id: i64,
  pub label: String,
  pub user_ids: Vec<String>,
  pub fingerprint: String,
  pub key_id: String,
  pub algorithm: String,
  pub created_at: i64,
  pub added_at: i64,
  /// Kann man an diesen Schluessel verschluesseln (gueltig, nicht abgelaufen/widerrufen)?
  pub can_encrypt: bool,
  pub note: String,
  /// Fingerabdruck persoenlich geprueft?
  pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactDetail {
  pub contact: Contact,
  pub public_key: String,
  pub key: KeyInfo,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportContact {
  /// Ein oder mehrere oeffentliche Schluessel (ASCII-Armor).
  pub armored: String,
  #[serde(default)]
  pub note: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UpdateContact {
  pub label: String,
  pub note: String,
  pub verified: bool,
}

// ---------------------------------------------------------------------------------------------
// Schluessel-Informationen (Pruefer)

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyInfo {
  /// 4 oder 6
  pub version: u8,
  pub fingerprint: String,
  pub key_id: String,
  pub algorithm: String,
  pub bits: Option<u32>,
  pub created_at: i64,
  pub expires_at: Option<i64>,
  pub user_ids: Vec<String>,
  /// Faehigkeiten des Hauptschluessels: `certify`, `sign`, `encrypt`, `authenticate`.
  pub flags: Vec<String>,
  pub subkeys: Vec<SubkeyInfo>,
  pub revoked: bool,
  /// Alle Selbstsignaturen gueltig?
  pub bindings_valid: bool,
  /// Enthaelt privates Material?
  pub is_secret: bool,
  /// Privates Material mit Passphrase geschuetzt? (`None` bei oeffentlichen Schluesseln)
  pub secret_protected: Option<bool>,
  pub can_encrypt: bool,
  pub can_sign: bool,
  /// Hinweise, z. B. schwache Algorithmen oder abgelaufene Teilschluessel.
  pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SubkeyInfo {
  pub fingerprint: String,
  pub key_id: String,
  pub algorithm: String,
  pub bits: Option<u32>,
  pub created_at: i64,
  pub expires_at: Option<i64>,
  pub flags: Vec<String>,
  pub revoked: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct InspectKeyRequest {
  pub armored: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct InspectMessageRequest {
  pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MessageInfo {
  /// `encrypted`, `signed`, `cleartext_signed`, `signature`, `literal`, `compressed`, `public_key`,
  /// `secret_key`
  pub kind: String,
  pub recipients: Vec<RecipientInfo>,
  /// Mit Passwort (symmetrisch) verschluesselt?
  pub password_encrypted: bool,
  /// Key-IDs der Signaturen (bei signierten Nachrichten/Signaturen, soweit lesbar).
  pub signer_key_ids: Vec<String>,
  /// Zum Entschluesseln vorgeschlagenes Profil.
  pub suggested_profile: Option<i64>,
  pub details: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecipientInfo {
  /// Key-ID des Empfaengers (`0000000000000000` = anonym).
  pub key_id: String,
  pub algorithm: String,
  /// Passendes eigenes Profil.
  pub profile_id: Option<i64>,
  pub profile_label: Option<String>,
  /// Passender Kontakt.
  pub contact_id: Option<i64>,
  pub contact_label: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Werkzeuge

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EncryptRequest {
  pub text: String,
  /// Eigene Profile als Empfaenger (z. B. an sich selbst).
  #[serde(default)]
  pub profile_ids: Vec<i64>,
  #[serde(default)]
  pub contact_ids: Vec<i64>,
  /// Zusaetzliche oeffentliche Schluessel (ASCII-Armor), nur fuer diese Nachricht.
  #[serde(default)]
  pub extra_keys: String,
  /// Statt/zusaetzlich zu Schluesseln mit Passwort verschluesseln.
  #[serde(default)]
  pub password: String,
  /// Mit diesem Profil signieren (braucht `passphrase`).
  #[serde(default)]
  pub sign_profile: Option<i64>,
  #[serde(default)]
  pub passphrase: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptResponse {
  pub armored: String,
  /// Lesbare Empfaenger.
  pub recipients: Vec<String>,
  pub signed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DecryptRequest {
  pub message: String,
  /// Profil zum Entschluesseln (sonst nur `password`).
  #[serde(default)]
  pub profile_id: Option<i64>,
  #[serde(default)]
  pub passphrase: String,
  /// Passwort fuer symmetrisch verschluesselte Nachrichten.
  #[serde(default)]
  pub password: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecryptResponse {
  pub text: String,
  /// Inhalt war kein gueltiges UTF-8 (dann `text` als Base64).
  pub binary: bool,
  pub file_name: String,
  pub signatures: Vec<SignatureCheck>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignatureCheck {
  pub valid: bool,
  /// Key-ID/Fingerabdruck des Signierenden (soweit bekannt).
  pub key_id: String,
  pub fingerprint: Option<String>,
  /// Name aus Profil/Kontakt/User-ID.
  pub signer: Option<String>,
  /// `profile`, `contact`, `extra`, `unknown`
  pub source: String,
  pub created_at: Option<i64>,
  pub message: String,
}

/// Signatur-Arten beim Signieren.
pub mod sign_modes {
  /// Klartext-Signatur (`BEGIN PGP SIGNED MESSAGE`).
  pub const CLEARTEXT: &str = "cleartext";
  /// Abgetrennte Signatur (`BEGIN PGP SIGNATURE`).
  pub const DETACHED: &str = "detached";
  /// Signierte Nachricht (`BEGIN PGP MESSAGE`, Inhalt eingebettet).
  pub const INLINE: &str = "inline";
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
  pub text: String,
  pub profile_id: i64,
  pub passphrase: String,
  /// Siehe [`sign_modes`].
  pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignResponse {
  pub armored: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VerifyRequest {
  /// Signierte Nachricht, Klartext-Signatur oder abgetrennte Signatur.
  pub message: String,
  /// Signierter Text bei abgetrennter Signatur.
  #[serde(default)]
  pub data: String,
  /// Zusaetzlicher oeffentlicher Schluessel des Absenders (ASCII-Armor).
  #[serde(default)]
  pub extra_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyResponse {
  /// `cleartext`, `inline`, `detached`
  pub kind: String,
  /// Signierter Text (bei Klartext- und eingebetteter Signatur).
  pub text: Option<String>,
  pub signatures: Vec<SignatureCheck>,
}
