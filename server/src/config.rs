//! Konfiguration ausschliesslich ueber Umgebungsvariablen (siehe README).

use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
  pub bind: SocketAddr,
  pub database: PathBuf,
  pub web_dir: Option<PathBuf>,
  pub admin_name: String,
  /// Passwort fuer das Konto beim ersten Start (oder mit `NRZPGP_ADMIN_PASSWORD_RESET`).
  pub admin_password: Option<String>,
  pub admin_password_reset: bool,
  /// Hauptschluessel fuer die zweite Schutzschicht der privaten Schluessel (min. 32 Zeichen).
  pub master_key: Option<String>,
  /// Sitzungsdauer in Stunden (fest, nicht gleitend).
  pub session_hours: i64,
  /// Cookie nur ueber HTTPS senden (+ HSTS). Hinter TLS-Proxy einschalten.
  pub secure_cookies: bool,
  /// Client-IP aus dem letzten `X-Forwarded-For`-Eintrag lesen (nur hinter eigenem Proxy).
  pub trust_proxy: bool,
  /// Cap-Dienst (`cap/server.mjs`), z. B. `http://127.0.0.1:3000`. Ohne: Captcha aus.
  pub cap_url: Option<String>,
  pub cap_seed: Option<String>,
  /// Ohne funktionierende Cap-Konfiguration nicht starten (Produktion).
  pub cap_required: bool,
}

fn var(name: &str) -> Option<String> {
  std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn flag(name: &str, default: bool) -> bool {
  match var(name).as_deref() {
    Some("1" | "true" | "yes" | "on") => true,
    Some("0" | "false" | "no" | "off") => false,
    _ => default,
  }
}

impl Config {
  pub fn from_env() -> Self {
    let bind = var("NRZPGP_BIND")
      .and_then(|b| b.parse().ok())
      .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8546)));
    let web_dir = var("NRZPGP_WEB_DIR").map(PathBuf::from).or_else(|| {
      ["web/dist", "target/dx/nrzpgp_web/release/web/public", "web/target/dx/nrzpgp_web/release/web/public"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.join("index.html").is_file())
    });
    Self {
      bind,
      database: var("NRZPGP_DATABASE").map_or_else(|| PathBuf::from("data/pgp.db"), PathBuf::from),
      web_dir,
      admin_name: var("NRZPGP_ADMIN_NAME").unwrap_or_else(|| "nrz".into()),
      admin_password: var("NRZPGP_ADMIN_PASSWORD"),
      admin_password_reset: flag("NRZPGP_ADMIN_PASSWORD_RESET", false),
      master_key: var("NRZPGP_MASTER_KEY"),
      session_hours: var("NRZPGP_SESSION_HOURS").and_then(|h| h.parse().ok()).filter(|h| (1..=720).contains(h)).unwrap_or(12),
      secure_cookies: flag("NRZPGP_SECURE_COOKIES", false),
      trust_proxy: flag("NRZPGP_TRUST_PROXY", false),
      cap_url: var("NRZPGP_CAP_URL").map(|u| u.trim_end_matches('/').to_string()),
      cap_seed: var("NRZPGP_CAP_SEED"),
      cap_required: flag("NRZPGP_CAP_REQUIRED", false),
    }
  }
}
