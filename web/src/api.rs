//! HTTP-Client fuer die nrzPGP-API (fetch, gleiche Origin, Cookie-Sitzung).
//!
//! Jede schreibende Anfrage traegt den CSRF-Header. Antwortet der Server `captcha_required`,
//! zeigt [`crate::captcha::solve`] das Cap-Widget und die Anfrage wird mit Token wiederholt.

use nrzpgp_shared::{ApiError, CSRF_HEADER, codes};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestCredentials, RequestInit, Response};

#[derive(Clone, Debug, PartialEq)]
pub struct Error {
  pub status: u16,
  pub code: String,
  pub message: Option<String>,
}

impl Error {
  fn network() -> Self {
    Self { status: 0, code: "network".into(), message: Some("Keine Verbindung zum Server.".into()) }
  }

  /// Lesbarer Text fuer die Oberflaeche.
  pub fn text(&self) -> String {
    if let Some(m) = &self.message
      && !matches!(self.code.as_str(), codes::CAPTCHA_REQUIRED | codes::CAPTCHA_INVALID)
      && m != "csrf"
    {
      return m.clone();
    }
    match self.code.as_str() {
      codes::NOT_LOGGED_IN => "Bitte melde dich zuerst an.".into(),
      codes::FORBIDDEN => "Dafür fehlen dir die Rechte.".into(),
      codes::NOT_FOUND => "Nicht gefunden.".into(),
      codes::RATE_LIMITED => "Zu viele Anfragen. Bitte warte einen Moment.".into(),
      codes::CAPTCHA_REQUIRED => "Bitte bestätige, dass du ein Mensch bist.".into(),
      codes::CAPTCHA_INVALID => "Die Bot-Prüfung ist fehlgeschlagen. Bitte erneut versuchen.".into(),
      codes::CAPTCHA_UNAVAILABLE => "Die Bot-Prüfung ist gerade nicht erreichbar.".into(),
      codes::WRONG_PASSWORD => "Das Passwort ist falsch.".into(),
      codes::WRONG_PASSPHRASE => "Die Passphrase ist falsch.".into(),
      codes::PGP_ERROR => "PGP-Fehler: Die Eingabe konnte nicht verarbeitet werden.".into(),
      codes::VAULT_EXPIRED => "Der Tresor-Vorgang ist abgelaufen. Bitte neu starten.".into(),
      codes::VAULT_LOCKED => "Der Tresor ist wegen zu vieler Fehlversuche vorübergehend gesperrt.".into(),
      codes::INVALID_INPUT => "Ungültige Eingabe.".into(),
      "captcha_cancelled" => "Bestätigung abgebrochen.".into(),
      _ => "Etwas ist schiefgelaufen. Bitte erneut versuchen.".into(),
    }
  }
}

pub type Result<T> = std::result::Result<T, Error>;

async fn raw(method: &str, path: &str, body: Option<&Value>) -> Result<(u16, String)> {
  let window = web_sys::window().ok_or_else(Error::network)?;
  let init = RequestInit::new();
  init.set_method(method);
  init.set_credentials(RequestCredentials::SameOrigin);
  if let Some(b) = body {
    init.set_body(&JsValue::from_str(&b.to_string()));
  }
  let req = Request::new_with_str_and_init(path, &init).map_err(|_| Error::network())?;
  let h = req.headers();
  let _ = h.set("accept", "application/json");
  if method != "GET" {
    let _ = h.set(CSRF_HEADER, "1");
    let _ = h.set("content-type", "application/json");
  }
  let resp = JsFuture::from(window.fetch_with_request(&req)).await.map_err(|_| Error::network())?;
  let resp: Response = resp.dyn_into().map_err(|_| Error::network())?;
  let status = resp.status();
  let text = match resp.text() {
    Ok(p) => JsFuture::from(p).await.ok().and_then(|v| v.as_string()).unwrap_or_default(),
    Err(_) => String::new(),
  };
  Ok((status, text))
}

fn parse<T: DeserializeOwned>(status: u16, text: &str) -> Result<T> {
  if (200..300).contains(&status) {
    return serde_json::from_str(text).map_err(|_| Error {
      status,
      code: "invalid_response".into(),
      message: None,
    });
  }
  let e: ApiError = serde_json::from_str(text).unwrap_or(ApiError { error: "unknown".into(), message: None });
  Err(Error { status, code: e.error, message: e.message })
}

pub async fn get<T: DeserializeOwned>(path: &str) -> Result<T> {
  let (status, text) = raw("GET", path, None).await?;
  let r = parse(status, &text);
  check_session(&r);
  r
}

/// Schreibende Anfrage; loest bei Bedarf das Captcha und wiederholt die Anfrage einmal.
pub async fn send<B: Serialize, T: DeserializeOwned>(method: &str, path: &str, body: &B) -> Result<T> {
  let mut value = serde_json::to_value(body).unwrap_or(Value::Null);
  let (status, text) = raw(method, path, Some(&value)).await?;
  let first = parse::<T>(status, &text);
  let scope = match &first {
    Err(e) if e.code == codes::CAPTCHA_REQUIRED || e.code == codes::CAPTCHA_INVALID => {
      e.message.clone().unwrap_or_else(|| "login".into())
    }
    _ => {
      check_session(&first);
      return first;
    }
  };
  let Some(token) = crate::captcha::solve(&scope).await else {
    return Err(Error { status: 400, code: "captcha_cancelled".into(), message: None });
  };
  if let Value::Object(map) = &mut value {
    map.insert("captcha".into(), Value::String(token));
  }
  let (status, text) = raw(method, path, Some(&value)).await?;
  let r = parse(status, &text);
  check_session(&r);
  r
}

pub async fn post<B: Serialize, T: DeserializeOwned>(path: &str, body: &B) -> Result<T> {
  send("POST", path, body).await
}

pub async fn patch<B: Serialize, T: DeserializeOwned>(path: &str, body: &B) -> Result<T> {
  send("PATCH", path, body).await
}

pub async fn delete<T: DeserializeOwned>(path: &str) -> Result<T> {
  send("DELETE", path, &serde_json::json!({})).await
}

/// Abgelaufene Sitzung: Zustand zuruecksetzen, damit die Oberflaeche "abgemeldet" zeigt.
fn check_session<T>(r: &Result<T>) {
  if let Err(e) = r
    && e.status == 401
    && crate::state::is_logged_in()
  {
    crate::state::refresh_site();
  }
}
