//! API-Tests gegen die echte App (Router + SQLite im Speicher).

use crate::{AppState, app, auth, cap::Cap, config::Config, db::Db, security::RateLimiter, seal::Sealer, vault::Vaults};
use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use nrzpgp_shared::CSRF_HEADER;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const PW: &str = "Konto-Passwort-123";
const PASS: &str = "meine-lange-passphrase";
const MASTER: &str = "test-hauptschlüssel-mit-mehr-als-32-zeichen";

fn config() -> Config {
  Config {
    bind: "127.0.0.1:0".parse().unwrap(),
    database: ":memory:".into(),
    web_dir: None,
    admin_name: "nrz".into(),
    admin_password: Some(PW.into()),
    admin_password_reset: false,
    master_key: Some(MASTER.into()),
    session_hours: 12,
    secure_cookies: false,
    trust_proxy: false,
    cap_url: None,
    cap_seed: None,
    cap_required: false,
  }
}

fn setup_with(cap: Option<Cap>) -> (Router, AppState) {
  let db = Db::memory();
  {
    let c = db.conn().unwrap();
    auth::ensure_admin(&c, "nrz", Some(PW), false).unwrap();
  }
  let state = AppState {
    config: Arc::new(config()),
    db,
    limiter: Arc::new(RateLimiter::default()),
    cap: cap.map(Arc::new),
    sealer: Arc::new(Sealer::new(MASTER)),
    vaults: Arc::new(Vaults::default()),
  };
  (app(state.clone(), None), state)
}

struct Res {
  status: StatusCode,
  json: Value,
  cookie: Option<String>,
}

async fn call(app: &Router, method: &str, path: &str, cookie: Option<&str>, body: Option<Value>) -> Res {
  let mut req = Request::builder().method(method).uri(path).header(header::HOST, "pgp.test");
  if method != "GET" {
    req = req.header(CSRF_HEADER, "1");
  }
  if let Some(c) = cookie {
    req = req.header(header::COOKIE, c);
  }
  let req = match body {
    Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())).unwrap(),
    None => req.body(Body::empty()).unwrap(),
  };
  let res = app.clone().oneshot(req).await.unwrap();
  let status = res.status();
  let cookie = res
    .headers()
    .get(header::SET_COOKIE)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.split(';').next())
    .map(str::to_string);
  let bytes = res.into_body().collect().await.unwrap().to_bytes();
  let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
  Res { status, json, cookie }
}

async fn login(app: &Router) -> String {
  let r = call(app, "POST", "/api/v1/auth/login", None, Some(json!({"name": "nrz", "password": PW}))).await;
  assert_eq!(r.status, StatusCode::OK, "{}", r.json);
  r.cookie.expect("cookie")
}

async fn create_profile(app: &Router, cookie: &str, label: &str, email: &str) -> Value {
  let r = call(
    app,
    "POST",
    "/api/v1/profiles",
    Some(cookie),
    Some(json!({
      "label": label, "purpose": "Tests", "name": "Max Muster", "email": email, "comment": "",
      "algorithm": "ed25519", "passphrase": PASS,
      "riddle_question": "Wie hiess mein erstes Haustier?", "riddle_answer": "Bello der Hund"
    })),
  )
  .await;
  assert_eq!(r.status, StatusCode::OK, "{}", r.json);
  r.json
}

#[tokio::test]
async fn auth_and_csrf() {
  let (app, _) = setup_with(None);
  assert_eq!(call(&app, "GET", "/api/v1/profiles", None, None).await.status, StatusCode::UNAUTHORIZED);
  let bad = call(&app, "POST", "/api/v1/auth/login", None, Some(json!({"name": "nrz", "password": "falsch-falsch"}))).await;
  assert_eq!(bad.status, StatusCode::BAD_REQUEST);
  assert_eq!(bad.json["error"], "wrong_password");
  let cookie = login(&app).await;
  let site = call(&app, "GET", "/api/v1/site", Some(&cookie), None).await;
  assert_eq!(site.json["me"]["name"], "nrz");
  // Ohne CSRF-Header: abgelehnt.
  let req = Request::builder()
    .method("POST")
    .uri("/api/v1/auth/logout")
    .header(header::COOKIE, &cookie)
    .body(Body::empty())
    .unwrap();
  assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
  // Abmelden beendet die Sitzung.
  call(&app, "POST", "/api/v1/auth/logout", Some(&cookie), Some(json!({}))).await;
  assert_eq!(call(&app, "GET", "/api/v1/profiles", Some(&cookie), None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn private_key_never_in_plaintext_in_db() {
  let (app, state) = setup_with(None);
  let cookie = login(&app).await;
  let p = create_profile(&app, &cookie, "Arbeit", "max@firma.example").await;
  assert!(p["public_key"].as_str().unwrap().contains("BEGIN PGP PUBLIC KEY BLOCK"));
  assert!(p["key"]["can_encrypt"].as_bool().unwrap());
  assert_eq!(p["riddle_question"], "Wie hiess mein erstes Haustier?");
  // Keine Antwort enthaelt privates Material.
  assert!(!p.to_string().contains("PRIVATE KEY"));

  // Alle Werte aller Tabellen durchsuchen.
  let dump: Vec<Vec<u8>> = state
    .db
    .run(|c| {
      let mut out = Vec::new();
      for table in ["users", "sessions", "profiles", "contacts", "audit"] {
        let mut st = c.prepare(&format!("SELECT * FROM {table}"))?;
        let n = st.column_count();
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
          for i in 0..n {
            match r.get_ref(i)? {
              rusqlite::types::ValueRef::Text(t) | rusqlite::types::ValueRef::Blob(t) => out.push(t.to_vec()),
              _ => {}
            }
          }
        }
      }
      Ok(out)
    })
    .await
    .unwrap();
  let all: Vec<u8> = dump.concat();
  let contains = |needle: &[u8]| all.windows(needle.len()).any(|w| w == needle);
  assert!(!contains(b"PRIVATE KEY"));
  assert!(!contains(PASS.as_bytes()));
  assert!(!contains(b"Bello"));
  assert!(!contains(b"bello"));
  assert!(!contains(b"Haustier"), "Rätselfrage liegt nur versiegelt vor");

  // Das Siegel ist ohne Hauptschluessel nicht als OpenPGP lesbar.
  let sealed: Vec<u8> =
    state.db.run(|c| Ok(c.query_row("SELECT sealed_secret FROM profiles", [], |r| r.get(0))?)).await.unwrap();
  assert!(crate::pgp::parse_secret(&sealed).is_err());
  assert!(Sealer::new("ein-falscher-hauptschlüssel-mit-32-zeichen!").open("profile:x:secret", &sealed).is_none());
}

#[tokio::test]
async fn encrypt_decrypt_sign_verify() {
  let (app, _) = setup_with(None);
  let cookie = login(&app).await;
  let p = create_profile(&app, &cookie, "Privat", "max@privat.example").await;
  let id = p["summary"]["id"].as_i64().unwrap();

  let enc = call(
    &app,
    "POST",
    "/api/v1/tools/encrypt",
    Some(&cookie),
    Some(json!({"text": "Treffen um 8", "profile_ids": [id], "sign_profile": id, "passphrase": PASS})),
  )
  .await;
  assert_eq!(enc.status, StatusCode::OK, "{}", enc.json);
  let armored = enc.json["armored"].as_str().unwrap().to_string();
  assert!(enc.json["signed"].as_bool().unwrap());

  let info = call(&app, "POST", "/api/v1/tools/inspect-message", Some(&cookie), Some(json!({"message": armored}))).await;
  assert_eq!(info.json["kind"], "encrypted");
  assert_eq!(info.json["suggested_profile"], id);

  let wrong = call(
    &app,
    "POST",
    "/api/v1/tools/decrypt",
    Some(&cookie),
    Some(json!({"message": armored, "profile_id": id, "passphrase": "falsche-passphrase"})),
  )
  .await;
  assert_eq!(wrong.json["error"], "wrong_passphrase");

  let dec = call(
    &app,
    "POST",
    "/api/v1/tools/decrypt",
    Some(&cookie),
    Some(json!({"message": armored, "profile_id": id, "passphrase": PASS})),
  )
  .await;
  assert_eq!(dec.status, StatusCode::OK, "{}", dec.json);
  assert_eq!(dec.json["text"], "Treffen um 8");
  assert_eq!(dec.json["signatures"][0]["valid"], true);
  assert_eq!(dec.json["signatures"][0]["source"], "profile");

  let signed = call(
    &app,
    "POST",
    "/api/v1/tools/sign",
    Some(&cookie),
    Some(json!({"text": "Ich bestätige.", "profile_id": id, "passphrase": PASS, "mode": "cleartext"})),
  )
  .await;
  let s = signed.json["armored"].as_str().unwrap();
  let v = call(&app, "POST", "/api/v1/tools/verify", Some(&cookie), Some(json!({"message": s}))).await;
  assert_eq!(v.json["signatures"][0]["valid"], true, "{}", v.json);
  let forged = s.replace("Ich bestätige.", "Ich bestätige nicht.");
  let v = call(&app, "POST", "/api/v1/tools/verify", Some(&cookie), Some(json!({"message": forged}))).await;
  assert_eq!(v.json["signatures"][0]["valid"], false);

  // Passphrase aendern: alte gilt nicht mehr.
  let ch = call(
    &app,
    "POST",
    &format!("/api/v1/profiles/{id}/passphrase"),
    Some(&cookie),
    Some(json!({"current": PASS, "new": "eine-ganz-neue-passphrase"})),
  )
  .await;
  assert_eq!(ch.status, StatusCode::OK, "{}", ch.json);
  let dec = call(
    &app,
    "POST",
    "/api/v1/tools/decrypt",
    Some(&cookie),
    Some(json!({"message": armored, "profile_id": id, "passphrase": "eine-ganz-neue-passphrase"})),
  )
  .await;
  assert_eq!(dec.json["text"], "Treffen um 8");
}

#[tokio::test]
async fn contacts_and_inspector() {
  let (app, _) = setup_with(None);
  let cookie = login(&app).await;
  let other = crate::pgp::generate("ed25519", "Erika <erika@example.com>", "erikas-passphrase").unwrap();
  let public = crate::pgp::armor_public(&other.to_public_key()).unwrap();
  let r = call(&app, "POST", "/api/v1/contacts", Some(&cookie), Some(json!({"armored": public, "note": "Kollegin"}))).await;
  assert_eq!(r.status, StatusCode::OK, "{}", r.json);
  assert_eq!(r.json[0]["label"], "Erika");
  assert_eq!(r.json[0]["can_encrypt"], true);
  let cid = r.json[0]["id"].as_i64().unwrap();
  let enc =
    call(&app, "POST", "/api/v1/tools/encrypt", Some(&cookie), Some(json!({"text": "Hallo Erika", "contact_ids": [cid]}))).await;
  let armored = enc.json["armored"].as_str().unwrap();
  let d = crate::pgp::decrypt(armored, Some((&other, "erikas-passphrase")), None, &[]).unwrap();
  assert_eq!(d.data, b"Hallo Erika");

  let i = call(&app, "POST", "/api/v1/tools/inspect-key", Some(&cookie), Some(json!({"armored": public}))).await;
  assert_eq!(i.json[0]["user_ids"][0], "Erika <erika@example.com>");
  assert_eq!(i.json[0]["is_secret"], false);
}

/// Antwort des aktuellen Raetsels aus dem Server-Zustand (nur im Test moeglich).
fn current_answer(state: &AppState, id: &str) -> (String, String) {
  state.vaults.with(|m| {
    let s = m.get(id).unwrap();
    (s.current.puzzle.kind.clone(), s.current.answer.clone())
  })
}

#[tokio::test]
async fn vault_flow() {
  let (app, state) = setup_with(None);
  let cookie = login(&app).await;
  let p = create_profile(&app, &cookie, "Tresor", "max@tresor.example").await;
  let id = p["summary"]["id"].as_i64().unwrap();

  let st = call(&app, "POST", "/api/v1/vault/start", Some(&cookie), Some(json!({"profile_id": id}))).await;
  assert_eq!(st.status, StatusCode::OK, "{}", st.json);
  let vid = st.json["vault_id"].as_str().unwrap().to_string();
  assert_eq!(st.json["total"], 4);
  assert_eq!(st.json["attempts_left"], 3);

  // Zu frueh fertig werden geht nicht.
  let early = call(&app, "POST", "/api/v1/vault/finish", Some(&cookie), Some(json!({"vault_id": vid, "password": PW}))).await;
  assert_eq!(early.json["error"], "vault_expired");

  // Eine falsche Antwort kostet einen Versuch und gibt ein neues Raetsel.
  let w = call(&app, "POST", "/api/v1/vault/answer", Some(&cookie), Some(json!({"vault_id": vid, "answer": "quatsch"}))).await;
  assert_eq!(w.json["attempts_left"], 2);
  assert_eq!(w.json["last_wrong"], true);

  let mut last = w.json;
  for _ in 0..4 {
    assert!(!last.to_string().contains("PRIVATE KEY"));
    let (kind, answer) = current_answer(&state, &vid);
    let answer = if kind == "personal" { "  BELLO der  hund ".to_string() } else { answer };
    let r = call(&app, "POST", "/api/v1/vault/answer", Some(&cookie), Some(json!({"vault_id": vid, "answer": answer}))).await;
    assert_eq!(r.status, StatusCode::OK, "{kind}: {}", r.json);
    last = r.json;
  }
  assert_eq!(last["solved"], 4);
  assert!(last["puzzle"].is_null());

  // Falsches Konto-Passwort kostet ebenfalls einen Versuch.
  let bad = call(&app, "POST", "/api/v1/vault/finish", Some(&cookie), Some(json!({"vault_id": vid, "password": "falsch-falsch"}))).await;
  assert_eq!(bad.json["error"], "wrong_password");

  let ok = call(&app, "POST", "/api/v1/vault/finish", Some(&cookie), Some(json!({"vault_id": vid, "password": PW}))).await;
  assert_eq!(ok.status, StatusCode::OK, "{}", ok.json);
  let secret = ok.json["secret_key"].as_str().unwrap();
  assert!(secret.contains("BEGIN PGP PRIVATE KEY BLOCK"));
  assert!(ok.json["revocation_certificate"].as_str().unwrap().contains("BEGIN PGP PUBLIC KEY BLOCK"));
  // Herausgegebener Schluessel ist weiterhin mit der Passphrase geschuetzt.
  let key = crate::pgp::parse_secret(secret.as_bytes()).unwrap();
  assert!(crate::pgp::is_protected(&key));
  crate::pgp::check_passphrase(&key, PASS).unwrap();

  // Vorgang ist verbraucht.
  let again = call(&app, "POST", "/api/v1/vault/finish", Some(&cookie), Some(json!({"vault_id": vid, "password": PW}))).await;
  assert_eq!(again.json["error"], "vault_expired");
  let d = call(&app, "GET", &format!("/api/v1/profiles/{id}"), Some(&cookie), None).await;
  assert_eq!(d.json["exports"], 1);
}

#[tokio::test]
async fn vault_locks_after_three_mistakes() {
  let (app, _) = setup_with(None);
  let cookie = login(&app).await;
  let p = create_profile(&app, &cookie, "Sperre", "max@sperre.example").await;
  let id = p["summary"]["id"].as_i64().unwrap();
  let st = call(&app, "POST", "/api/v1/vault/start", Some(&cookie), Some(json!({"profile_id": id}))).await;
  let vid = st.json["vault_id"].as_str().unwrap().to_string();
  for _ in 0..2 {
    let r = call(&app, "POST", "/api/v1/vault/answer", Some(&cookie), Some(json!({"vault_id": vid, "answer": "nein"}))).await;
    assert_eq!(r.status, StatusCode::OK);
  }
  let r = call(&app, "POST", "/api/v1/vault/answer", Some(&cookie), Some(json!({"vault_id": vid, "answer": "nein"}))).await;
  assert_eq!(r.json["error"], "vault_locked");
  let again = call(&app, "POST", "/api/v1/vault/start", Some(&cookie), Some(json!({"profile_id": id}))).await;
  assert_eq!(again.json["error"], "vault_locked");
}

#[tokio::test]
async fn vault_is_bound_to_session() {
  let (app, _) = setup_with(None);
  let a = login(&app).await;
  let b = login(&app).await;
  let p = create_profile(&app, &a, "Bindung", "max@bindung.example").await;
  let id = p["summary"]["id"].as_i64().unwrap();
  let st = call(&app, "POST", "/api/v1/vault/start", Some(&a), Some(json!({"profile_id": id}))).await;
  let vid = st.json["vault_id"].as_str().unwrap().to_string();
  let r = call(&app, "POST", "/api/v1/vault/answer", Some(&b), Some(json!({"vault_id": vid, "answer": "1"}))).await;
  assert_eq!(r.json["error"], "vault_expired");
}

#[tokio::test]
async fn captcha_fails_closed() {
  // Cap konfiguriert, Dienst aber nicht erreichbar.
  let cap = Cap::new(Some("http://127.0.0.1:9"), Some("0123456789abcdef0123")).unwrap();
  let (app, _) = setup_with(Some(cap));
  let r = call(&app, "POST", "/api/v1/auth/login", None, Some(json!({"name": "nrz", "password": PW}))).await;
  assert_eq!(r.json["error"], "captcha_required");
  assert_eq!(r.json["message"], "login");
  let r = call(&app, "POST", "/api/v1/auth/login", None, Some(json!({"name": "nrz", "password": PW, "captcha": "x:y"}))).await;
  assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
  assert!(r.cookie.is_none());
}
