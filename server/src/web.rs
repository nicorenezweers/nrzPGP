//! Liefert die Weboberflaeche (Dioxus/WASM) aus.
//!
//! Existierende Dateien kommen direkt, alle anderen GET-Pfade bekommen `index.html`
//! (Single-Page-App). `index.html` traegt eine strenge Content-Security-Policy: Inline-Skripte der
//! Seite werden per SHA-256-Hash freigegeben, sonst nur Skripte der eigenen Seite. Pro Aufruf gibt
//! es zusaetzlich einen Nonce (`<meta name="nrz-nonce">`): Cap laedt seine Browser-Pruefung als
//! Inline-Skript in ein `srcdoc`-Iframe und braucht dafuer `window.CAP_SCRIPT_NONCE`.

use axum::{
  body::Body,
  http::{HeaderValue, Method, StatusCode, Uri, header},
  response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
  path::{Component, Path, PathBuf},
  sync::Arc,
};

pub struct WebUi {
  root: PathBuf,
  index: String,
  csp: String,
}

const NONCE_PLACEHOLDER: &str = "__NRZ_NONCE__";

impl WebUi {
  pub fn load(dir: &Path) -> Option<Arc<Self>> {
    let root = dir.canonicalize().ok()?;
    let mut index = std::fs::read_to_string(root.join("index.html")).ok()?;
    // Icon schon im HTML, sonst fragt der Browser vor dem Start der App /favicon.ico ab (404).
    if root.join("favicon.svg").is_file() && !index.contains("rel=\"icon\"") {
      index = index.replacen("</head>", "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\"></head>", 1);
    }
    let csp = build_csp(&index);
    tracing::info!("Weboberflaeche aus {}", root.display());
    Some(Arc::new(Self { root, index, csp }))
  }

  /// Sicherer Pfad unterhalb von `root`: keine `..`, keine versteckten Dateien, keine Symlinks
  /// nach aussen.
  fn file_for(&self, url_path: &str) -> Option<PathBuf> {
    let rel = Path::new(url_path.trim_start_matches('/'));
    let mut out = self.root.clone();
    for c in rel.components() {
      match c {
        Component::Normal(part) => {
          if part.to_string_lossy().starts_with('.') {
            return None;
          }
          out.push(part);
        }
        Component::CurDir => {}
        _ => return None,
      }
    }
    if out == self.root || !out.is_file() {
      return None;
    }
    let real = out.canonicalize().ok()?;
    real.starts_with(&self.root).then_some(real)
  }

  pub async fn serve(self: Arc<Self>, method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || !matches!(method, Method::GET | Method::HEAD) {
      return crate::error::AppError::not_found().into_response();
    }
    if let Some(file) = self.file_for(path)
      && let Ok(bytes) = tokio::fs::read(&file).await {
        let mime = mime_guess::from_path(&file).first_or_octet_stream();
        // Dioxus haengt Hashes an Asset-Namen; die koennen dauerhaft gecacht werden.
        let immutable = path.starts_with("/assets/") || path.starts_with("/wasm/");
        let cache = if immutable { "public, max-age=31536000, immutable" } else { "public, max-age=3600" };
        return Response::builder()
          .header(header::CONTENT_TYPE, mime.as_ref())
          .header(header::CACHE_CONTROL, cache)
          .body(Body::from(bytes))
          .unwrap_or_default();
      }
    // Unbekannte Datei mit Endung (z. B. /favicon.png): 404 statt index.html.
    if path.rsplit('/').next().is_some_and(|last| last.contains('.')) {
      return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let nonce = new_nonce();
    let csp = self.csp.replace(NONCE_PLACEHOLDER, &nonce);
    let mut res = Response::new(Body::from(with_nonce_meta(&self.index, &nonce)));
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache, no-store"));
    if let Ok(v) = HeaderValue::from_str(&csp) {
      h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    res
  }
}

/// Inline-`<script>`-Bloecke (ohne `src`) hashen.
fn inline_script_hashes(html: &str) -> Vec<String> {
  let mut hashes = Vec::new();
  let mut rest = html;
  while let Some(start) = rest.find("<script") {
    let after = &rest[start..];
    let Some(tag_end) = after.find('>') else { break };
    let tag = &after[..tag_end];
    let body_start = tag_end + 1;
    let Some(close) = after[body_start..].find("</script>") else { break };
    let body = &after[body_start..body_start + close];
    if !tag.contains(" src=") && !body.trim().is_empty() {
      hashes.push(format!("'sha256-{}'", STANDARD.encode(Sha256::digest(body.as_bytes()))));
    }
    rest = &after[body_start + close + "</script>".len()..];
  }
  hashes
}

fn build_csp(index: &str) -> String {
  let hashes = inline_script_hashes(index).join(" ");
  format!(
    "default-src 'self'; \
     script-src 'self' 'wasm-unsafe-eval' 'nonce-{NONCE_PLACEHOLDER}' {hashes}; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: blob:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     frame-src 'self'; \
     worker-src 'self' blob:; \
     manifest-src 'self'; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'"
  )
}

fn new_nonce() -> String {
  let mut b = [0u8; 18];
  rand::rngs::OsRng.fill_bytes(&mut b);
  STANDARD.encode(b)
}

/// `<meta name="nrz-nonce">` direkt nach `<head>` einfuegen.
fn with_nonce_meta(index: &str, nonce: &str) -> String {
  let meta = format!(r#"<meta name="nrz-nonce" content="{nonce}">"#);
  match index.find("<head>") {
    Some(i) => {
      let at = i + "<head>".len();
      format!("{}{meta}{}", &index[..at], &index[at..])
    }
    None => format!("{meta}{index}"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hashes_only_inline_scripts() {
    let h = inline_script_hashes(r#"<script src="/a.js"></script><script type="module">init()</script>"#);
    assert_eq!(h.len(), 1);
    assert!(h[0].starts_with("'sha256-"));
  }

  #[test]
  fn nonce_meta() {
    assert_ne!(new_nonce(), new_nonce());
    assert_eq!(
      with_nonce_meta("<html><head><title>x</title>", "abc"),
      r#"<html><head><meta name="nrz-nonce" content="abc"><title>x</title>"#
    );
    assert!(build_csp("").contains("'nonce-__NRZ_NONCE__'"));
  }

  #[test]
  fn rejects_traversal() {
    let ui = WebUi { root: std::env::temp_dir().canonicalize().unwrap(), index: String::new(), csp: String::new() };
    assert!(ui.file_for("/../etc/passwd").is_none());
    assert!(ui.file_for("/.env").is_none());
  }
}
