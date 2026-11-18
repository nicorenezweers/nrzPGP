//! nrzPGP – Weboberflaeche.
//!
//! Dioxus 0.7 (WASM), Komponenten aus nrzUI, dunkles nrz-Thema. Spricht die eigene JSON-API mit den
//! gemeinsamen Typen aus `nrzpgp_shared`. Alle PGP-Operationen mit privaten Schluesseln laufen auf
//! dem Server; die Oberflaeche sieht nur Ergebnisse.

mod api;
mod captcha;
mod components;
mod pages;
mod route;
mod state;
mod util;

use dioxus::prelude::*;
use route::Route;

const TAILWIND: Asset = asset!("/assets/tailwind.css");
const FAVICON: Asset = asset!("/assets/favicon.svg");

fn main() {
  dioxus::launch(App);
}

#[component]
fn App() -> Element {
  use_future(|| async { state::load_site().await });
  let ready = state::SITE.read().is_some();
  let logged_in = state::SITE.read().as_ref().is_some_and(|s| s.me.is_some());

  rsx! {
    document::Link { rel: "icon", href: FAVICON }
    document::Link { rel: "stylesheet", href: TAILWIND }
    document::Meta { name: "viewport", content: "width=device-width, initial-scale=1, viewport-fit=cover" }
    document::Meta { name: "theme-color", content: "#19191d" }
    document::Meta { name: "referrer", content: "no-referrer" }
    document::Meta { name: "robots", content: "noindex, nofollow" }
    captcha::CaptchaHost {}
    components::common::Toasts {}
    if !ready {
      div { class: "grid min-h-dvh place-items-center bg-background",
        div { class: "flex flex-col items-center gap-3 text-muted-foreground",
          components::common::Logo { class: "size-12" }
          icons::LoaderCircle { class: "size-5 animate-spin" }
        }
      }
    } else if logged_in {
      Router::<Route> {}
    } else {
      pages::auth::LoginScreen {}
    }
  }
}
