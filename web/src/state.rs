//! Globaler Zustand: Seiteninfos inkl. Sitzung, Meldungen (Toasts), UI-Schalter.
//!
//! Private Schluessel, Passphrasen und entschluesselte Inhalte liegen hier bewusst NIE – nur im
//! Zustand der jeweiligen Seite, damit sie beim Verlassen verworfen werden.

use dioxus::prelude::*;
use nrzpgp_shared::{Me, SiteInfo};

/// Seiteninfo vom Server (`None` = noch nicht geladen).
pub static SITE: GlobalSignal<Option<SiteInfo>> = Signal::global(|| None);
/// Mobile Seitenleiste offen?
pub static SIDEBAR_OPEN: GlobalSignal<bool> = Signal::global(|| false);
/// Kurzmeldungen unten rechts.
pub static TOASTS: GlobalSignal<Vec<Toast>> = Signal::global(Vec::new);

#[derive(Clone, PartialEq)]
pub struct Toast {
  pub id: u32,
  pub text: String,
  pub error: bool,
}

pub fn me() -> Option<Me> {
  SITE.read().as_ref().and_then(|s| s.me.clone())
}

pub fn is_logged_in() -> bool {
  SITE.peek().as_ref().is_some_and(|s| s.me.is_some())
}

pub async fn load_site() {
  match crate::api::get::<SiteInfo>("/api/v1/site").await {
    Ok(s) => *SITE.write() = Some(s),
    Err(e) => {
      if SITE.peek().is_none() {
        toast_error(e.text());
      }
    }
  }
}

pub fn refresh_site() {
  spawn(async move { load_site().await });
}

fn push(text: String, error: bool) {
  let id = TOASTS.peek().iter().map(|t| t.id).max().unwrap_or(0) + 1;
  TOASTS.write().push(Toast { id, text, error });
  spawn(async move {
    gloo_timers::future::TimeoutFuture::new(if error { 5000 } else { 3000 }).await;
    TOASTS.write().retain(|t| t.id != id);
  });
}

pub fn toast(text: impl Into<String>) {
  push(text.into(), false);
}

pub fn toast_error(text: impl Into<String>) {
  push(text.into(), true);
}
