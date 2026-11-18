//! Tresor: Den privaten Schluessel bekommt man erst nach mehreren Raetseln (vom Server erzeugt und
//! geprueft), der Cap-Pruefung und dem Konto-Passwort. Erst dann schickt der Server den Schluessel –
//! er steht nie im HTML und liegt hier nur im Zustand dieser Seite (beim Verlassen verworfen).

use crate::api;
use crate::components::common::{ArmorBox, ErrorBox, Field, InfoBox, PageHeader, Section};
use crate::components::ui::button::{Button, ButtonVariant};
use crate::components::ui::input::{Input, InputType};
use crate::route::Route;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{
  Ok as OkResp, ProfileDetail, VaultAnswer, VaultCancel, VaultFinish, VaultSecret, VaultStart, VaultState, codes,
};

#[derive(Clone, PartialEq)]
enum Phase {
  Intro,
  Running(VaultState),
  Done(VaultSecret),
}

fn cancel_vault(vault_id: String) {
  wasm_bindgen_futures::spawn_local(async move {
    let _ = api::post::<_, OkResp>("/api/v1/vault/cancel", &VaultCancel { vault_id }).await;
  });
}

#[component]
pub fn VaultPage(id: i64) -> Element {
  use_effect(|| util::set_title("Privaten Schlüssel holen"));
  let profile = use_resource(use_reactive!(|id| async move { api::get::<ProfileDetail>(&format!("/api/v1/profiles/{id}")).await }));
  let mut phase = use_signal(|| Phase::Intro);
  let mut error = use_signal(|| None::<(String, String)>);
  let mut busy = use_signal(|| false);
  let mut answer = use_signal(String::new);
  let mut password = use_signal(String::new);
  let mut tick = use_signal(util::now);
  use_future(move || async move {
    loop {
      gloo_timers::future::TimeoutFuture::new(1000).await;
      tick.set(util::now());
    }
  });
  // Seite verlassen: offenen Vorgang abbrechen, Geheimnisse verwerfen.
  use_drop(move || {
    if let Phase::Running(s) = &*phase.peek() {
      cancel_vault(s.vault_id.clone());
    }
  });

  let label = match &*profile.read_unchecked() {
    Some(Ok(p)) => p.summary.label.clone(),
    _ => String::new(),
  };

  let start = move |_| {
    if busy() {
      return;
    }
    busy.set(true);
    error.set(None);
    spawn(async move {
      match api::post::<_, VaultState>("/api/v1/vault/start", &VaultStart { profile_id: id }).await {
        Ok(s) => phase.set(Phase::Running(s)),
        Err(e) => error.set(Some((e.code.clone(), e.text()))),
      }
      busy.set(false);
    });
  };

  let mut on_error = move |e: api::Error| {
    if e.code == codes::VAULT_EXPIRED || e.code == codes::VAULT_LOCKED {
      phase.set(Phase::Intro);
    }
    error.set(Some((e.code.clone(), e.text())));
  };

  let submit_answer = move |e: FormEvent| {
    e.prevent_default();
    let Phase::Running(s) = phase() else { return };
    if busy() || answer().trim().is_empty() {
      return;
    }
    busy.set(true);
    error.set(None);
    let req = VaultAnswer { vault_id: s.vault_id.clone(), answer: answer().trim().to_string() };
    spawn(async move {
      match api::post::<_, VaultState>("/api/v1/vault/answer", &req).await {
        Ok(next) => {
          answer.set(String::new());
          phase.set(Phase::Running(next));
        }
        Err(e) => on_error(e),
      }
      busy.set(false);
    });
  };

  let finish = move |e: FormEvent| {
    e.prevent_default();
    let Phase::Running(s) = phase() else { return };
    if busy() || password().is_empty() {
      return;
    }
    busy.set(true);
    error.set(None);
    let req = VaultFinish { vault_id: s.vault_id.clone(), password: password(), captcha: None };
    spawn(async move {
      match api::post::<_, VaultSecret>("/api/v1/vault/finish", &req).await {
        Ok(secret) => {
          password.set(String::new());
          phase.set(Phase::Done(secret));
          state::toast("Privater Schlüssel freigegeben.");
        }
        Err(e) => {
          if e.code != codes::WRONG_PASSWORD {
            password.set(String::new());
          }
          on_error(e)
        }
      }
      busy.set(false);
    });
  };

  let cancel = move |_| {
    if let Phase::Running(s) = phase() {
      cancel_vault(s.vault_id.clone());
    }
    answer.set(String::new());
    password.set(String::new());
    phase.set(Phase::Intro);
  };

  let body = match phase() {
    Phase::Intro => rsx! {
      Section { title: "So funktioniert der Tresor",
        ol { class: "flex flex-col gap-3 text-sm",
          Step { n: 1, title: "Mehrere Rätsel lösen", text: "Der Server stellt dir zufällige Rätsel (Rechnen, Zahlenfolgen, Wortsalat, Caesar-Verschlüsselung) und zum Schluss dein persönliches Rätsel. Die Lösungen kennt nur der Server." }
          Step { n: 2, title: "Cap-Prüfung", text: "Eine kurze Bot-Prüfung ohne Bilderrätsel." }
          Step { n: 3, title: "Konto-Passwort", text: "Erst dann schickt der Server den privaten Schlüssel – weiterhin mit deiner Passphrase geschützt – zusammen mit dem Widerrufszertifikat." }
        }
        InfoBox { warning: true,
          p { "Zu viele falsche Antworten sperren den Tresor für dieses Profil vorübergehend. Jeder Versuch wird im Protokoll vermerkt." }
        }
        div { class: "mt-5 flex flex-wrap justify-end gap-2",
          Button { variant: ButtonVariant::Ghost, class: "rounded-full", href: Route::ProfilePage { id }.to_string(), "Zurück" }
          Button { class: "rounded-full", disabled: busy(), onclick: start,
            if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::LockKeyhole {} }
            "Tresor öffnen"
          }
        }
      }
    },
    Phase::Running(s) => {
      let left = (s.expires_at - tick()).max(0);
      let steps = s.total + 1;
      rsx! {
        Section {
          div { class: "mb-5 flex flex-wrap items-center gap-3",
            div { class: "flex items-center gap-1.5", "aria-label": "Fortschritt",
              for i in 0..steps {
                span {
                  key: "{i}",
                  class: if i < s.solved { "h-2 w-8 rounded-full bg-success" } else if i == s.solved { "h-2 w-8 rounded-full bg-foreground" } else { "h-2 w-8 rounded-full bg-accent" },
                }
              }
            }
            span { class: "text-sm text-muted-foreground",
              if s.puzzle.is_some() { "Rätsel {s.solved + 1} von {s.total}" } else { "Letzter Schritt" }
            }
            span { class: "ml-auto flex items-center gap-1.5 text-xs text-muted-foreground",
              icons::Clock { class: "size-3.5" }
              "{left / 60}:{left % 60:02}"
            }
          }
          if let Some(pz) = s.puzzle.clone() {
            form { class: "flex flex-col gap-4", onsubmit: submit_answer,
              if s.last_wrong {
                ErrorBox { text: "Falsche Antwort – hier ist ein neues Rätsel. Noch {s.attempts_left} Fehlversuch(e) erlaubt." }
              }
              div { class: "rounded-2xl border bg-background/50 p-5",
                div { class: "mb-2 flex items-center gap-2 text-sm font-semibold",
                  icons::Puzzle { class: "size-4" }
                  "{pz.title}"
                }
                p { class: "whitespace-pre-wrap font-mono text-lg leading-relaxed", "{pz.prompt}" }
                if !pz.hint.is_empty() {
                  p { class: "mt-2 text-sm text-muted-foreground", "{pz.hint}" }
                }
              }
              Field { label: "Deine Antwort", html_for: "answer",
                Input {
                  id: "answer",
                  class: "h-11 rounded-xl text-base",
                  r#type: if pz.kind == "personal" { InputType::Password } else { InputType::Text },
                  autocomplete: "off",
                  autofocus: true,
                  maxlength: nrzpgp_shared::rules::ANSWER_MAX as i64,
                  value: answer(),
                  oninput: move |e: FormEvent| answer.set(e.value()),
                }
              }
              div { class: "flex flex-wrap items-center justify-between gap-2",
                span { class: "text-xs text-muted-foreground", "Fehlversuche übrig: {s.attempts_left}" }
                div { class: "flex gap-2",
                  Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: cancel, "Abbrechen" }
                  Button { button_type: "submit", class: "rounded-full", disabled: busy(),
                    if busy() { icons::LoaderCircle { class: "animate-spin" } }
                    "Antworten"
                  }
                }
              }
            }
          } else {
            form { class: "flex flex-col gap-4", onsubmit: finish,
              div { class: "flex items-center gap-3 rounded-2xl border border-success/40 bg-success/10 p-4 text-sm",
                icons::CircleCheck { class: "size-5 shrink-0 text-success" }
                span { "Alle {s.total} Rätsel gelöst. Jetzt noch Cap-Prüfung und dein Konto-Passwort." }
              }
              Field { label: "Konto-Passwort", html_for: "vpw",
                Input { id: "vpw", r#type: InputType::Password, class: "h-11 rounded-xl", autocomplete: "current-password", autofocus: true, maxlength: 1024, value: password(), oninput: move |e: FormEvent| password.set(e.value()) }
              }
              div { class: "flex justify-end gap-2",
                Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: cancel, "Abbrechen" }
                Button { button_type: "submit", class: "rounded-full", disabled: busy(),
                  if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::LockOpen {} }
                  "Schlüssel freigeben"
                }
              }
            }
          }
        }
      }
    }
    Phase::Done(secret) => {
      let slug = util::slug(&label);
      rsx! {
        div { class: "flex flex-col gap-4",
          InfoBox { warning: true,
            p { class: "font-semibold", "Behandle diesen Schlüssel wie ein Passwort." }
            p { "Er ist weiterhin mit deiner Passphrase geschützt. Speichere ihn nur an einem sicheren Ort (z. B. offline) und gib ihn niemandem. Mit dem Widerrufszertifikat kannst du den Schlüssel für ungültig erklären, falls er verloren geht." }
          }
          Section { title: "Privater Schlüssel",
            ArmorBox { text: secret.secret_key.clone(), file_name: format!("{slug}-secret.asc"), rows: 12, sensitive: true }
          }
          Section { title: "Widerrufszertifikat",
            ArmorBox { text: secret.revocation_certificate.clone(), file_name: format!("{slug}-revocation.asc"), rows: 8, sensitive: true }
          }
          div { class: "flex justify-end",
            Button {
              class: "rounded-full",
              onclick: move |_| {
                  phase.set(Phase::Intro);
                  state::toast("Ausgeblendet.");
              },
              icons::EyeOff {}
              "Ausblenden"
            }
          }
        }
      }
    }
  };

  rsx! {
    PageHeader {
      title: "Privaten Schlüssel holen",
      subtitle: if label.is_empty() { "Tresor".to_string() } else { format!("Profil „{label}“") },
      icon: rsx! { icons::LockKeyhole {} },
      actions: rsx! {
        Button { variant: ButtonVariant::Ghost, class: "rounded-full", href: Route::ProfilePage { id }.to_string(), icons::ArrowLeft {} "Zum Profil" }
      },
    }
    div { class: "flex flex-col gap-4",
      if let Some((code, text)) = error() {
        if code == codes::VAULT_LOCKED {
          div { class: "flex items-start gap-3 rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive",
            icons::LockKeyhole { class: "mt-0.5 size-4 shrink-0" }
            div {
              p { class: "font-semibold", "Tresor gesperrt" }
              p { "{text}" }
            }
          }
        } else {
          ErrorBox { text }
        }
      }
      {body}
    }
  }
}

#[component]
fn Step(n: u32, title: String, text: String) -> Element {
  rsx! {
    li { class: "flex gap-3",
      span { class: "grid size-7 shrink-0 place-items-center rounded-full bg-accent text-xs font-bold", "{n}" }
      div {
        div { class: "font-medium", "{title}" }
        div { class: "text-muted-foreground", "{text}" }
      }
    }
  }
}
