//! Anmeldung (Cap-Captcha wird automatisch gezeigt, wenn der Server es verlangt).

use crate::api;
use crate::components::common::{ErrorBox, Logo};
use crate::components::ui::button::Button;
use crate::components::ui::input::{Input, InputType};
use crate::components::ui::label::Label;
use crate::route::Route;
use crate::state::{self, SITE};
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{LoginRequest, Me};

/// Anmeldeseite (ohne Router, solange niemand angemeldet ist).
#[component]
pub fn LoginScreen() -> Element {
  let mut name = use_signal(String::new);
  let mut password = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  use_effect(|| util::set_title("Anmelden"));
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    busy.set(true);
    error.set(None);
    let req = LoginRequest { name: name().trim().to_string(), password: password(), captcha: None };
    spawn(async move {
      match api::post::<_, Me>("/api/v1/auth/login", &req).await {
        Ok(me) => {
          password.set(String::new());
          if let Some(s) = SITE.write().as_mut() {
            s.me = Some(me.clone());
          }
          state::toast(format!("Willkommen, {}!", me.name));
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    div { class: "grid min-h-dvh place-items-center bg-background px-4 py-10",
      div { class: "w-full max-w-md",
        div { class: "rounded-2xl border bg-card p-6 shadow-sm sm:p-8",
          div { class: "mb-6 flex flex-col items-center gap-3 text-center",
            Logo { class: "size-12" }
            div {
              h1 { class: "text-xl font-bold", "nrzPGP" }
              p { class: "mt-1 text-sm text-muted-foreground", "Deine PGP-Schlüssel, sicher auf deinem eigenen Server." }
            }
          }
          form { class: "flex flex-col gap-4", onsubmit: submit,
            if let Some(e) = error() { ErrorBox { text: e } }
            div { class: "flex flex-col gap-1.5",
              Label { html_for: "name", "Benutzername" }
              Input { id: "name", class: "h-10 rounded-xl", autocomplete: "username", required: true, autofocus: true, maxlength: 64, value: name(), oninput: move |e: FormEvent| name.set(e.value()) }
            }
            div { class: "flex flex-col gap-1.5",
              Label { html_for: "password", "Passwort" }
              Input { id: "password", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "current-password", required: true, maxlength: 1024, value: password(), oninput: move |e: FormEvent| password.set(e.value()) }
            }
            Button { button_type: "submit", class: "h-10 w-full rounded-full", disabled: busy(),
              if busy() { icons::LoaderCircle { class: "animate-spin" } }
              "Anmelden"
            }
          }
        }
        p { class: "mt-4 flex items-center justify-center gap-1.5 text-xs text-muted-foreground",
          icons::ShieldCheck { class: "size-3.5" }
          "Geschützt durch "
          a { href: "https://trycap.dev", target: "_blank", rel: "noopener noreferrer", class: "underline", "Cap" }
          " – ohne Bilderrätsel, ohne Tracking."
        }
      }
    }
  }
}

/// `/login` nach erfolgreicher Anmeldung: zur Uebersicht.
#[component]
pub fn LoginDone() -> Element {
  let nav = navigator();
  use_effect(move || {
    nav.replace(Route::Home {});
  });
  rsx! {}
}
