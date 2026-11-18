//! Protokoll, Einstellungen, 404.

use crate::api;
use crate::components::common::{EmptyState, ErrorBox, Field, Loading, PageHeader, Section};
use crate::components::layout::logout;
use crate::components::ui::badge::{Badge, BadgeSize, BadgeVariant};
use crate::components::ui::button::{Button, ButtonVariant};
use crate::components::ui::input::{Input, InputType};
use crate::route::Route;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{AuditEntry, ChangePassword, Ok as OkResp, rules};

fn action_info(action: &str) -> (&'static str, BadgeVariant) {
  match action {
    "login" => ("Anmeldung", BadgeVariant::Secondary),
    "login_failed" => ("Anmeldung fehlgeschlagen", BadgeVariant::Destructive),
    "logout" => ("Abmeldung", BadgeVariant::Muted),
    "password_changed" => ("Passwort geändert", BadgeVariant::Warning),
    "logout_all" => ("Alle abgemeldet", BadgeVariant::Warning),
    "profile_created" => ("Profil erstellt", BadgeVariant::Success),
    "profile_imported" => ("Profil importiert", BadgeVariant::Success),
    "profile_updated" => ("Profil bearbeitet", BadgeVariant::Secondary),
    "profile_deleted" => ("Profil gelöscht", BadgeVariant::Destructive),
    "passphrase_changed" => ("Passphrase geändert", BadgeVariant::Warning),
    "passphrase_failed" => ("Falsche Passphrase", BadgeVariant::Destructive),
    "riddle_changed" => ("Rätsel geändert", BadgeVariant::Warning),
    "decrypt" => ("Entschlüsselt", BadgeVariant::Info),
    "sign" => ("Signiert", BadgeVariant::Info),
    "encrypt" => ("Verschlüsselt", BadgeVariant::Info),
    "vault_start" => ("Tresor geöffnet", BadgeVariant::Secondary),
    "vault_export" => ("Privater Schlüssel herausgegeben", BadgeVariant::Warning),
    "vault_failed" => ("Tresor: Fehlversuch", BadgeVariant::Destructive),
    "vault_locked" => ("Tresor gesperrt", BadgeVariant::Destructive),
    "contact_added" => ("Kontakt hinzugefügt", BadgeVariant::Success),
    "contact_deleted" => ("Kontakt gelöscht", BadgeVariant::Muted),
    _ => ("Ereignis", BadgeVariant::Outline),
  }
}

#[component]
pub fn ActionBadge(action: String) -> Element {
  let (label, variant) = action_info(&action);
  let label = if label == "Ereignis" { action.clone() } else { label.to_string() };
  rsx! { Badge { variant, size: BadgeSize::Sm, class: "whitespace-nowrap", "{label}" } }
}

#[component]
pub fn Log() -> Element {
  use_effect(|| util::set_title("Protokoll"));
  let audit = use_resource(|| async { api::get::<Vec<AuditEntry>>("/api/v1/audit").await });
  rsx! {
    PageHeader {
      title: "Protokoll",
      subtitle: "Sicherheitsrelevante Ereignisse: Anmeldungen, Schlüsselnutzung und Tresor-Zugriffe. Inhalte von Nachrichten oder Schlüssel werden nie protokolliert.",
      icon: rsx! { icons::ScrollText {} },
    }
    match &*audit.read_unchecked() {
        None => rsx! { Loading {} },
        Some(Err(e)) => rsx! { ErrorBox { text: e.text() } },
        Some(Ok(list)) if list.is_empty() => rsx! { EmptyState { title: "Noch keine Ereignisse" } },
        Some(Ok(list)) => rsx! {
          div { class: "overflow-hidden rounded-2xl border bg-card",
            ul { class: "divide-y divide-border",
              for a in list.iter() {
                li { key: "{a.id}", class: "flex flex-col gap-1 px-4 py-3 text-sm sm:flex-row sm:items-center sm:gap-4",
                  span { class: "w-36 shrink-0 font-mono text-xs text-muted-foreground", "{util::full_date(a.at)}" }
                  div { class: "w-56 shrink-0", ActionBadge { action: a.action.clone() } }
                  span { class: "min-w-0 flex-1 break-words", "{a.detail}" }
                  span { class: "shrink-0 font-mono text-xs text-muted-foreground", "{a.ip}" }
                }
              }
            }
          }
        },
    }
  }
}

#[component]
pub fn Settings() -> Element {
  use_effect(|| util::set_title("Einstellungen"));
  let me = state::me();
  let mut current = use_signal(String::new);
  let mut new = use_signal(String::new);
  let mut repeat = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);

  let change = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    let check = rules::password(&new())
      .and_then(|_| if new() == repeat() { Ok(()) } else { Err("Die neuen Passwörter stimmen nicht überein.") });
    if let Err(m) = check {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = ChangePassword { current: current(), new: new() };
    spawn(async move {
      match api::post::<_, OkResp>("/api/v1/account/password", &req).await {
        Ok(_) => {
          current.set(String::new());
          new.set(String::new());
          repeat.set(String::new());
          state::toast("Passwort geändert. Andere Geräte wurden abgemeldet.");
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  let logout_all = move |_| {
    if !util::confirm("Alle Sitzungen beenden (auch diese)?") {
      return;
    }
    spawn(async move {
      match api::post::<_, OkResp>("/api/v1/account/logout-all", &serde_json::json!({})).await {
        Ok(_) => {
          state::toast("Alle Geräte abgemeldet.");
          state::load_site().await;
        }
        Err(e) => state::toast_error(e.text()),
      }
    });
  };

  rsx! {
    PageHeader {
      title: "Einstellungen",
      icon: rsx! { icons::Settings {} },
    }
    div { class: "flex flex-col gap-6",
      Section { title: "Konto",
        div { class: "flex flex-wrap items-center gap-3 text-sm",
          span { class: "text-muted-foreground", "Angemeldet als" }
          span { class: "font-semibold", "{me.as_ref().map(|m| m.name.clone()).unwrap_or_default()}" }
          if let Some(m) = &me {
            span { class: "text-muted-foreground", "· Sitzung gültig bis {util::full_date(m.session_expires_at)}" }
          }
        }
        div { class: "mt-4 flex flex-wrap gap-2",
          Button { variant: ButtonVariant::Outline, class: "rounded-full", onclick: move |_| logout(), icons::LogOut {} "Abmelden" }
          Button { variant: ButtonVariant::Outline, class: "rounded-full", onclick: logout_all, icons::MonitorSmartphone {} "Alle Geräte abmelden" }
        }
      }
      Section { title: "Passwort ändern", description: "Das Konto-Passwort brauchst du zum Anmelden und für die Herausgabe privater Schlüssel.",
        form { class: "flex flex-col gap-4", onsubmit: change,
          if let Some(e) = error() { ErrorBox { text: e } }
          Field { label: "Aktuelles Passwort", html_for: "cpw",
            Input { id: "cpw", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "current-password", maxlength: 1024, value: current(), oninput: move |e: FormEvent| current.set(e.value()) }
          }
          div { class: "grid gap-4 sm:grid-cols-2",
            Field { label: "Neues Passwort", html_for: "npw", hint: "Mindestens 10 Zeichen.",
              Input { id: "npw", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "new-password", maxlength: 1024, value: new(), oninput: move |e: FormEvent| new.set(e.value()) }
            }
            Field { label: "Wiederholen", html_for: "rpw",
              Input { id: "rpw", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "new-password", maxlength: 1024, value: repeat(), oninput: move |e: FormEvent| repeat.set(e.value()) }
            }
          }
          div { class: "flex justify-end",
            Button { button_type: "submit", class: "rounded-full", disabled: busy(),
              if busy() { icons::LoaderCircle { class: "animate-spin" } }
              "Passwort ändern"
            }
          }
        }
      }
      Section { title: "So schützt nrzPGP deine Schlüssel",
        ul { class: "flex flex-col gap-3 text-sm",
          SecurityPoint { title: "Nie im Klartext gespeichert", text: "Jeder private Schlüssel ist mit deiner Passphrase geschützt (OpenPGP) und liegt zusätzlich mit dem Hauptschlüssel des Servers verschlüsselt (XChaCha20-Poly1305) in der Datenbank. Der Hauptschlüssel steht nicht in der Datenbank." }
          SecurityPoint { title: "Passphrase bleibt bei dir", text: "Die Passphrase wird nirgends gespeichert. Der Server entsperrt den Schlüssel nur kurz im Arbeitsspeicher, wenn du entschlüsselst oder signierst." }
          SecurityPoint { title: "Tresor mit Rätseln und Cap", text: "Den privaten Schlüssel bekommst du nur nach mehreren vom Server gestellten Rätseln, deinem persönlichen Rätsel (als Argon2-Hash gespeichert), der Cap-Prüfung und deinem Konto-Passwort. Er steht nie im HTML der Seite." }
          SecurityPoint { title: "Protokoll", text: "Anmeldungen, Entschlüsselungen und Tresor-Zugriffe werden ohne Inhalte protokolliert." }
        }
      }
    }
  }
}

#[component]
fn SecurityPoint(title: String, text: String) -> Element {
  rsx! {
    li { class: "flex gap-3",
      icons::ShieldCheck { class: "mt-0.5 size-4 shrink-0 text-success" }
      div {
        div { class: "font-medium", "{title}" }
        div { class: "text-muted-foreground", "{text}" }
      }
    }
  }
}

#[component]
pub fn NotFound(segments: Vec<String>) -> Element {
  let _ = segments;
  use_effect(|| util::set_title("Nicht gefunden"));
  rsx! {
    EmptyState { title: "Seite nicht gefunden", text: "Diese Adresse gibt es nicht.",
      Button { class: "mt-3 rounded-full", href: Route::Home {}.to_string(), "Zur Übersicht" }
    }
  }
}
