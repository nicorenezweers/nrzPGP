//! Cap-Captcha (https://trycap.dev).
//!
//! Der Server antwortet mit `captcha_required` (Anmeldung und Herausgabe des privaten Schluessels). `api::send` ruft dann [`solve`] auf: das zeigt einen Dialog mit
//! dem Cap-Widget und liefert den Token, mit dem die Anfrage wiederholt wird.
//!
//! Widget, WASM und pako liegen lokal unter `/cap/` (keine Anfragen an fremde Server). Die
//! Browser-Pruefung von Cap laeuft als Inline-Skript in einem Iframe; dafuer bekommt das Widget den
//! CSP-Nonce der Seite (`<meta name="nrz-nonce">`).

use dioxus::prelude::*;
use futures::channel::oneshot;
use std::cell::RefCell;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};

const WIDGET_JS: &str = "/cap/cap-0.1.63.min.js";
const WASM_URL: &str = "/cap/cap_wasm-0.0.8.wasm";
const HASHWX_URL: &str = "/cap/hashwx-0.0.8.wasm";
const PAKO_URL: &str = "/cap/pako_inflate-2.1.0.min.js";
const SLOT_ID: &str = "nrz-cap-slot";

/// Offene Anfrage: Bereich (`login`, `vault`).
static SCOPE: GlobalSignal<Option<String>> = Signal::global(|| None);

thread_local! {
  static PENDING: RefCell<Option<oneshot::Sender<Option<String>>>> = const { RefCell::new(None) };
  static LISTENER: RefCell<Option<Closure<dyn FnMut(JsValue)>>> = const { RefCell::new(None) };
}

/// Zeigt das Captcha fuer `scope` und wartet auf den Token (`None` = abgebrochen).
pub async fn solve(scope: &str) -> Option<String> {
  let (tx, rx) = oneshot::channel();
  // Eine evtl. noch offene Anfrage gilt als abgebrochen.
  PENDING.with(|p| {
    if let Some(old) = p.borrow_mut().replace(tx) {
      let _ = old.send(None);
    }
  });
  *SCOPE.write() = Some(scope.to_string());
  let token = rx.await.ok().flatten();
  // Aufraeumen hier (Dioxus-Task) – `finish` laeuft auch aus dem JS-Ereignis des Widgets, dort
  // duerfen keine Signale geschrieben werden.
  if PENDING.with(|p| p.borrow().is_none()) {
    LISTENER.with(|l| l.borrow_mut().take());
    *SCOPE.write() = None;
  }
  token
}

fn finish(token: Option<String>) {
  PENDING.with(|p| {
    if let Some(tx) = p.borrow_mut().take() {
      let _ = tx.send(token);
    }
  });
}

fn set_global(window: &web_sys::Window, key: &str, value: &str) {
  let _ = js_sys::Reflect::set(window, &JsValue::from_str(key), &JsValue::from_str(value));
}

/// Widget-Skript einmal laden und konfigurieren.
fn ensure_script(window: &web_sys::Window, document: &web_sys::Document) {
  if document.get_element_by_id("nrz-cap-js").is_some() {
    return;
  }
  set_global(window, "CAP_CUSTOM_WASM_URL", WASM_URL);
  set_global(window, "CAP_CUSTOM_HASHWX_URL", HASHWX_URL);
  set_global(window, "CAP_PAKO_URL", PAKO_URL);
  if let Some(nonce) = document
    .query_selector("meta[name=nrz-nonce]")
    .ok()
    .flatten()
    .and_then(|m| m.get_attribute("content"))
  {
    set_global(window, "CAP_SCRIPT_NONCE", &nonce);
  }
  if let Ok(script) = document.create_element("script") {
    let _ = script.set_attribute("id", "nrz-cap-js");
    let _ = script.set_attribute("src", WIDGET_JS);
    if let Some(head) = document.head() {
      let _ = head.append_child(&script);
    }
  }
}

/// `<cap-widget>` in den Platzhalter setzen (Dioxus kennt das Custom Element nicht).
fn mount_widget(scope: &str) {
  let Some(window) = web_sys::window() else { return };
  let Some(document) = window.document() else { return };
  ensure_script(&window, &document);
  let Some(slot) = document.get_element_by_id(SLOT_ID) else { return };
  slot.set_inner_html("");
  let Ok(widget) = document.create_element("cap-widget") else { return };
  let _ = widget.set_attribute("data-cap-api-endpoint", &format!("/api/cap/{scope}/"));
  let _ = widget.set_attribute("data-cap-lang", "de");
  let _ = widget.set_attribute("data-cap-hidden-field-name", "cap-token");
  let on_solve = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
    let token = js_sys::Reflect::get(&ev, &JsValue::from_str("detail"))
      .and_then(|d| js_sys::Reflect::get(&d, &JsValue::from_str("token")))
      .ok()
      .and_then(|t| t.as_string())
      .filter(|t| !t.is_empty());
    if token.is_some() {
      finish(token);
    }
  });
  let _ = widget.add_event_listener_with_callback("solve", on_solve.as_ref().unchecked_ref());
  LISTENER.with(|l| *l.borrow_mut() = Some(on_solve));
  let _ = slot.append_child(&widget);
}

/// Einmal im App-Rahmen einbinden.
#[component]
pub fn CaptchaHost() -> Element {
  let Some(scope) = SCOPE() else {
    return rsx! {};
  };
  let text = if scope == "vault" {
    "Letzte Hürde vor der Herausgabe deines privaten Schlüssels: Bitte bestätige, dass du ein Mensch bist."
  } else {
    "Bitte bestätige kurz, dass du ein Mensch bist. Das schützt dein Konto vor automatisierten Angriffen."
  };
  let mount_scope = scope.clone();
  rsx! {
    div {
      class: "fixed inset-0 z-[70] flex items-end justify-center bg-black/60 p-0 backdrop-blur-sm sm:items-center sm:p-4",
      div {
        class: "fade-in w-full rounded-t-2xl border bg-popover p-5 shadow-2xl sm:max-w-md sm:rounded-2xl",
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "nrz-cap-title",
        onkeydown: move |e: KeyboardEvent| {
            if e.key() == Key::Escape {
                finish(None);
            }
        },
        div { class: "mb-3 flex items-start gap-3",
          span { class: "grid size-9 shrink-0 place-items-center rounded-xl bg-primary/15 text-primary",
            icons::ShieldCheck { class: "size-5" }
          }
          div { class: "flex-1",
            h2 { id: "nrz-cap-title", class: "text-lg font-semibold", "Kurze Bestätigung" }
            p { class: "mt-1 text-sm text-muted-foreground", "{text}" }
          }
        }
        div {
          id: SLOT_ID,
          class: "flex min-h-16 justify-center py-2",
          onmounted: move |_| mount_widget(&mount_scope),
        }
        div { class: "mt-3 flex justify-end",
          button {
            r#type: "button",
            class: "rounded-lg px-3 py-1.5 text-sm text-muted-foreground hover:bg-accent hover:text-foreground",
            onclick: move |_| finish(None),
            "Abbrechen"
          }
        }
      }
    }
  }
}
