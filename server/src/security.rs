//! Schutzschichten fuer alle Anfragen:
//!
//! - **CSRF**: schreibende API-Anfragen brauchen den Header `x-nrz-pgp` (fremde Seiten koennen
//!   ihn ohne CORS nicht setzen), ein passendes `Origin` und `Sec-Fetch-Site: same-origin`, sofern
//!   der Browser diese Header schickt. Dazu kommt das Sitzungs-Cookie mit `SameSite=Lax`.
//! - **Rate-Limits** je IP und je Konto (gleitendes Fenster im Speicher).
//! - **Sicherheits-Header** auf jeder Antwort (CSP fuer die API, nosniff, kein Framing, …).

use crate::{AppState, error::AppError};
use axum::{
  extract::{ConnectInfo, Request, State},
  http::{HeaderMap, HeaderValue, Method, header},
  middleware::Next,
  response::{IntoResponse, Response},
};
use nrzpgp_shared::CSRF_HEADER;
use std::{
  collections::{HashMap, VecDeque},
  net::{IpAddr, SocketAddr},
  sync::Mutex,
  time::{Duration, Instant},
};

// ---------------------------------------------------------------------------------------------
// Client-IP

/// IP des Clients. Hinter dem eigenen Proxy (`NRZPGP_TRUST_PROXY`) der letzte Eintrag von
/// `X-Forwarded-For` – den hat der Proxy selbst angehaengt, frühere Eintraege sind faelschbar.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
  if trust_proxy {
    let forwarded = headers
      .get("x-forwarded-for")
      .and_then(|v| v.to_str().ok())
      .and_then(|h| h.rsplit(',').map(str::trim).find(|s| !s.is_empty()))
      .and_then(|s| s.parse::<IpAddr>().ok());
    if let Some(ip) = forwarded {
      return ip.to_string();
    }
    if let Some(ip) = headers
      .get("x-real-ip")
      .and_then(|v| v.to_str().ok())
      .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
      return ip.to_string();
    }
  }
  peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into())
}

/// Die IP wird als Request-Extension weitergereicht.
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

// ---------------------------------------------------------------------------------------------
// Rate-Limits

#[derive(Clone, Copy, Debug)]
pub struct Limit {
  pub max: usize,
  pub window: Duration,
}

impl Limit {
  pub const fn per_min(max: usize) -> Self {
    Self { max, window: Duration::from_secs(60) }
  }
  pub const fn per(max: usize, secs: u64) -> Self {
    Self { max, window: Duration::from_secs(secs) }
  }
}

/// Grenzen je Aktion.
pub mod limits {
  use super::Limit;
  /// Alle API-Anfragen je IP.
  pub const API: Limit = Limit::per_min(600);
  /// Login-Versuche je IP.
  pub const LOGIN_IP: Limit = Limit::per(20, 600);
  /// Fehlgeschlagene Logins je Konto, danach Sperre bis das Fenster ablaeuft.
  pub const LOGIN_FAIL_ACCOUNT: Limit = Limit::per(8, 900);
  /// Falsche Passphrasen je Profil (Schutz gegen Durchprobieren), danach 15 min Pause.
  pub const PASSPHRASE_FAIL: Limit = Limit::per(8, 900);
  /// Falsche Konto-Passwoerter bei Bestaetigungen (Loeschen, Tresor, Passwortwechsel).
  pub const PASSWORD_CONFIRM_FAIL: Limit = Limit::per(8, 900);
  /// Schluessel erzeugen/importieren je Konto.
  pub const KEYGEN: Limit = Limit::per(20, 3600);
  /// Tresor-Vorgaenge je Konto.
  pub const VAULT_START: Limit = Limit::per(10, 3600);
  /// Sperre eines Profils nach zu vielen falschen Tresor-Antworten (1 Treffer = gesperrt).
  pub const VAULT_LOCK: Limit = Limit::per(1, 1800);
  /// Krypto-Werkzeuge je Konto (CPU-intensiv).
  pub const TOOLS: Limit = Limit::per(120, 600);
  pub const CAP_CHALLENGE: Limit = Limit::per(40, 600);
  pub const CAP_REDEEM: Limit = Limit::per(40, 600);
  pub const SETTINGS: Limit = Limit::per(20, 600);
}

#[derive(Default)]
pub struct RateLimiter {
  hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
  /// Zaehlt einen Treffer; `false` wenn die Grenze erreicht ist (dann wird nicht gezaehlt).
  pub fn hit(&self, key: &str, limit: Limit) -> bool {
    self.check(key, limit, true)
  }

  /// Nur pruefen, ohne zu zaehlen.
  pub fn peek(&self, key: &str, limit: Limit) -> bool {
    self.check(key, limit, false)
  }

  fn check(&self, key: &str, limit: Limit, count: bool) -> bool {
    let now = Instant::now();
    let mut map = self.hits.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() > 100_000 {
      map.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < Duration::from_secs(86_400)));
    }
    let q = map.entry(key.to_string()).or_default();
    while q.front().is_some_and(|t| now.duration_since(*t) >= limit.window) {
      q.pop_front();
    }
    if q.len() >= limit.max {
      return false;
    }
    if count {
      q.push_back(now);
    }
    true
  }

  pub fn reset(&self, key: &str) {
    self.hits.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
  }

  /// Regelmaessig leere Eintraege entfernen.
  pub fn prune(&self) {
    let now = Instant::now();
    let mut map = self.hits.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < Duration::from_secs(86_400)));
  }
}

impl AppState {
  /// Rate-Limit pruefen und zaehlen, sonst `429`.
  pub fn limit(&self, key: impl AsRef<str>, limit: Limit) -> Result<(), AppError> {
    if self.limiter.hit(key.as_ref(), limit) { Ok(()) } else { Err(AppError::rate_limited()) }
  }
}

// ---------------------------------------------------------------------------------------------
// Middleware

/// IP ermitteln, globales Limit, CSRF-Pruefung fuer schreibende API-Anfragen.
pub async fn guard(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
  let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
  let ip = client_ip(req.headers(), peer, state.config.trust_proxy);
  let path = req.uri().path().to_string();

  if path.starts_with("/api/") {
    if !state.limiter.hit(&format!("api:{ip}"), limits::API) {
      return AppError::rate_limited().into_response();
    }
    let writes = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if writes {
      // Das Cap-Widget sendet keine eigenen Header; seine Endpunkte aendern keine Daten.
      let needs_header = !path.starts_with("/api/cap/");
      if let Err(e) = check_csrf(req.headers(), needs_header, state.config.trust_proxy) {
        return e.into_response();
      }
    }
  }

  req.extensions_mut().insert(ClientIp(ip));
  let mut res = next.run(req).await;
  apply_headers(res.headers_mut(), &path, state.config.secure_cookies);
  res
}

fn check_csrf(headers: &HeaderMap, needs_header: bool, trust_proxy: bool) -> Result<(), AppError> {
  if needs_header && headers.get(CSRF_HEADER).is_none() {
    return Err(AppError::forbidden().msg("csrf"));
  }
  if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
    && site != "same-origin" && site != "none" {
      return Err(AppError::forbidden().msg("csrf"));
    }
  if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    // Hinter dem eigenen Proxy (z. B. umbrelOS app_proxy) kann Host umgeschrieben sein; dann
    // zaehlt der vom Proxy gesetzte X-Forwarded-Host (erster Eintrag).
    let fwd_host = trust_proxy
      .then(|| headers.get("x-forwarded-host").and_then(|v| v.to_str().ok()))
      .flatten()
      .map(|v| v.split(',').next().unwrap_or("").trim());
    let origin_host = origin.split_once("://").map(|(_, h)| h).unwrap_or("");
    let matches = |h: &str| !h.is_empty() && origin_host.eq_ignore_ascii_case(h);
    if origin == "null" || origin_host.is_empty() || !(matches(host) || fwd_host.is_some_and(matches)) {
      return Err(AppError::forbidden().msg("csrf"));
    }
  }
  Ok(())
}

fn set(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
  if !headers.contains_key(name) {
    headers.insert(name, HeaderValue::from_static(value));
  }
}

fn apply_headers(h: &mut HeaderMap, path: &str, secure: bool) {
  set(h, "x-content-type-options", "nosniff");
  set(h, "x-frame-options", "DENY");
  set(h, "referrer-policy", "same-origin");
  set(h, "cross-origin-opener-policy", "same-origin");
  set(h, "cross-origin-resource-policy", "same-origin");
  set(
    h,
    "permissions-policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  );
  if secure {
    set(h, "strict-transport-security", "max-age=31536000; includeSubDomains");
  }
  if path.starts_with("/api/") {
    set(h, "content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    set(h, "cache-control", "no-store");
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
      h.insert(*k, HeaderValue::from_static(v));
    }
    h
  }

  #[test]
  fn csrf_rules() {
    assert!(check_csrf(&hm(&[]), true, false).is_err());
    assert!(check_csrf(&hm(&[(CSRF_HEADER, "1")]), true, false).is_ok());
    assert!(check_csrf(&hm(&[(CSRF_HEADER, "1"), ("sec-fetch-site", "cross-site")]), true, false).is_err());
    assert!(
      check_csrf(&hm(&[(CSRF_HEADER, "1"), ("origin", "https://evil.example"), ("host", "pgp.local")]), true, false)
        .is_err()
    );
    assert!(
      check_csrf(&hm(&[(CSRF_HEADER, "1"), ("origin", "http://pgp.local:8546"), ("host", "pgp.local:8546")]), true, false)
        .is_ok()
    );
    assert!(check_csrf(&hm(&[("origin", "null"), ("host", "x")]), false, false).is_err());
    // X-Forwarded-Host nur hinter vertrauenswuerdigem Proxy.
    let proxied = hm(&[(CSRF_HEADER, "1"), ("origin", "http://umbrel.local:8520"), ("host", "web:8536"), ("x-forwarded-host", "umbrel.local:8520")]);
    assert!(check_csrf(&proxied, true, true).is_ok());
    assert!(check_csrf(&proxied, true, false).is_err());
  }

  #[test]
  fn proxy_ip_uses_last_entry() {
    let h = hm(&[("x-forwarded-for", "6.6.6.6, 10.0.0.2")]);
    assert_eq!(client_ip(&h, None, true), "10.0.0.2");
    let peer: SocketAddr = "127.0.0.1:5".parse().unwrap();
    assert_eq!(client_ip(&h, Some(peer), false), "127.0.0.1");
  }

  #[test]
  fn limiter_window() {
    let l = RateLimiter::default();
    let lim = Limit::per(2, 60);
    assert!(l.hit("a", lim));
    assert!(l.hit("a", lim));
    assert!(!l.hit("a", lim));
    assert!(l.hit("b", lim));
  }
}
