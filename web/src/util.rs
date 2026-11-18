//! Kleine Helfer: Zeitangaben, Titel, Bestaetigung, Zwischenablage, Downloads.

use wasm_bindgen::{JsCast, JsValue};

pub fn now() -> i64 {
  (js_sys::Date::now() / 1000.0) as i64
}

/// "vor 5 Min.", "vor 3 Std.", "vor 2 T." …
pub fn time_ago(ts: i64) -> String {
  let secs = (now() - ts).max(0);
  match secs {
    0..=59 => "gerade eben".into(),
    60..=3599 => format!("vor {} Min.", secs / 60),
    3600..=86_399 => format!("vor {} Std.", secs / 3600),
    86_400..=2_591_999 => format!("vor {} T.", secs / 86_400),
    2_592_000..=31_535_999 => format!("vor {} Mon.", secs / 2_592_000),
    _ => format!("vor {} J.", secs / 31_536_000),
  }
}

/// Datum in Ortszeit ("13.11.2026 14:05").
pub fn full_date(ts: i64) -> String {
  let d = js_sys::Date::new(&JsValue::from_f64(ts as f64 * 1000.0));
  format!(
    "{:02}.{:02}.{} {:02}:{:02}",
    d.get_date(),
    d.get_month() + 1,
    d.get_full_year(),
    d.get_hours(),
    d.get_minutes()
  )
}

/// Nur Datum ("13.11.2026").
pub fn date(ts: i64) -> String {
  let d = js_sys::Date::new(&JsValue::from_f64(ts as f64 * 1000.0));
  format!("{:02}.{:02}.{}", d.get_date(), d.get_month() + 1, d.get_full_year())
}

pub fn set_title(title: &str) {
  if let Some(d) = web_sys::window().and_then(|w| w.document()) {
    d.set_title(&format!("{title} · nrzPGP"));
  }
}

pub fn confirm(text: &str) -> bool {
  web_sys::window().and_then(|w| w.confirm_with_message(text).ok()).unwrap_or(false)
}

pub fn copy_to_clipboard(text: &str) {
  if let Some(w) = web_sys::window() {
    let _ = w.navigator().clipboard().write_text(text);
  }
}

/// Text als Datei herunterladen (Blob + Objekt-URL, kein Inline-JS).
pub fn download(file_name: &str, text: &str, mime: &str) {
  let Some(window) = web_sys::window() else { return };
  let Some(document) = window.document() else { return };
  let parts = js_sys::Array::of1(&JsValue::from_str(text));
  let opts = web_sys::BlobPropertyBag::new();
  opts.set_type(mime);
  let Ok(blob) = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts) else { return };
  let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else { return };
  if let Ok(a) = document.create_element("a")
    && let Ok(a) = a.dyn_into::<web_sys::HtmlAnchorElement>()
  {
    a.set_href(&url);
    a.set_download(file_name);
    if let Some(body) = document.body() {
      let _ = body.append_child(&a);
      a.click();
      let _ = body.remove_child(&a);
    }
  }
  let _ = web_sys::Url::revoke_object_url(&url);
}

/// Dateiname aus einem Profil-/Kontaktnamen ("Max Muster" -> "max-muster").
pub fn slug(s: &str) -> String {
  let mut out = String::new();
  for c in s.to_lowercase().chars() {
    if c.is_ascii_alphanumeric() {
      out.push(c);
    } else if !out.ends_with('-') && !out.is_empty() {
      out.push('-');
    }
  }
  let out = out.trim_end_matches('-').to_string();
  if out.is_empty() { "schluessel".into() } else { out }
}

/// Grobe Staerke einer Passphrase (0–4) mit kurzem Text.
pub fn strength(p: &str) -> (u8, &'static str) {
  let len = p.chars().count();
  if len == 0 {
    return (0, "");
  }
  let classes = [
    p.chars().any(|c| c.is_lowercase()),
    p.chars().any(|c| c.is_uppercase()),
    p.chars().any(|c| c.is_ascii_digit()),
    p.chars().any(|c| !c.is_alphanumeric()),
  ]
  .iter()
  .filter(|b| **b)
  .count();
  let words = p.split_whitespace().count();
  let score = match len {
    0..=11 => 0,
    12..=15 => 1,
    16..=23 => 2,
    _ => 3,
  } + u8::from(classes >= 3 || words >= 4);
  let score = score.min(4);
  let text = match score {
    0 => "zu kurz",
    1 => "schwach",
    2 => "mittel",
    3 => "gut",
    _ => "sehr gut",
  };
  (score, text)
}
