//! Uebersicht: eigene Profile (Schluesselpaare), Schnellzugriff auf Werkzeuge, letzte Ereignisse.

use crate::api;
use crate::components::common::{EmptyState, ErrorBox, FingerprintText, Loading, PageHeader, Section};
use crate::components::ui::badge::{Badge, BadgeSize, BadgeVariant};
use crate::components::ui::button::{Button, ButtonVariant};
use crate::route::Route;
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{AuditEntry, ProfileSummary};

#[component]
pub fn Home() -> Element {
  use_effect(|| util::set_title("Übersicht"));
  let profiles = use_resource(|| async { api::get::<Vec<ProfileSummary>>("/api/v1/profiles").await });
  let audit = use_resource(|| async { api::get::<Vec<AuditEntry>>("/api/v1/audit").await });

  rsx! {
    PageHeader {
      title: "Übersicht",
      subtitle: "Deine Profile mit je einem eigenen Schlüsselpaar – z. B. für verschiedene E-Mail-Adressen oder Zwecke.",
      icon: rsx! { icons::KeyRound {} },
      actions: rsx! {
        Button { variant: ButtonVariant::Outline, class: "rounded-full", href: Route::ImportProfilePage {}.to_string(),
          icons::Upload {}
          "Importieren"
        }
        Button { class: "rounded-full", href: Route::NewProfile {}.to_string(),
          icons::Plus {}
          "Neues Profil"
        }
      },
    }
    div { class: "flex flex-col gap-6",
      match &*profiles.read_unchecked() {
          None => rsx! { Loading {} },
          Some(Err(e)) => rsx! { ErrorBox { text: e.text() } },
          Some(Ok(list)) if list.is_empty() => rsx! {
            EmptyState {
              title: "Noch kein Profil",
              text: "Lege ein Profil an, um ein neues Schlüsselpaar zu erzeugen, oder importiere einen vorhandenen privaten Schlüssel.",
              div { class: "mt-3 flex flex-wrap justify-center gap-2",
                Button { class: "rounded-full", href: Route::NewProfile {}.to_string(), icons::Plus {} "Neues Profil" }
                Button { variant: ButtonVariant::Outline, class: "rounded-full", href: Route::ImportProfilePage {}.to_string(), icons::Upload {} "Importieren" }
              }
            }
          },
          Some(Ok(list)) => rsx! {
            div { class: "grid gap-3 md:grid-cols-2",
              for p in list.iter() {
                ProfileCard { key: "{p.id}", profile: p.clone() }
              }
            }
          },
      }
      Section { title: "Werkzeuge",
        div { class: "grid gap-2 sm:grid-cols-2 lg:grid-cols-4",
          ToolLink { to: Route::Encrypt {}, title: "Verschlüsseln", text: "Nachricht an Kontakte oder dich selbst", icon: rsx! { icons::Lock {} } }
          ToolLink { to: Route::Decrypt {}, title: "Entschlüsseln", text: "Auf dem Server, nur das Ergebnis kommt zurück", icon: rsx! { icons::LockOpen {} } }
          ToolLink { to: Route::Sign {}, title: "Signieren", text: "Klartext, abgetrennt oder eingebettet", icon: rsx! { icons::PenLine {} } }
          ToolLink { to: Route::Verify {}, title: "PGP-Prüfer", text: "Signaturen, Schlüssel und Nachrichten prüfen", icon: rsx! { icons::ShieldCheck {} } }
        }
      }
      Section {
        title: "Letzte Ereignisse",
        actions: rsx! {
          Button { variant: ButtonVariant::Ghost, class: "rounded-full", href: Route::Log {}.to_string(), "Alle anzeigen" icons::ChevronRight {} }
        },
        match &*audit.read_unchecked() {
            None => rsx! { Loading {} },
            Some(Err(e)) => rsx! { ErrorBox { text: e.text() } },
            Some(Ok(list)) if list.is_empty() => rsx! { p { class: "text-sm text-muted-foreground", "Noch keine Ereignisse." } },
            Some(Ok(list)) => rsx! {
              ul { class: "divide-y divide-border",
                for a in list.iter().take(5) {
                  li { key: "{a.id}", class: "flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm",
                    span { class: "w-36 shrink-0 text-xs text-muted-foreground", title: "{util::full_date(a.at)}", "{util::time_ago(a.at)}" }
                    crate::pages::misc::ActionBadge { action: a.action.clone() }
                    span { class: "min-w-0 flex-1 truncate", "{a.detail}" }
                  }
                }
              }
            },
        }
      }
    }
  }
}

#[component]
fn ProfileCard(profile: ProfileSummary) -> Element {
  let p = profile;
  rsx! {
    Link {
      to: Route::ProfilePage { id: p.id },
      class: "group flex flex-col gap-3 rounded-2xl border bg-card p-5 transition-colors hover:border-ring/60",
      div { class: "flex items-start gap-3",
        span { class: "grid size-10 shrink-0 place-items-center rounded-xl bg-accent", icons::KeyRound { class: "size-5" } }
        div { class: "min-w-0 flex-1",
          div { class: "flex flex-wrap items-center gap-2",
            h2 { class: "truncate font-semibold", "{p.label}" }
            Badge { variant: BadgeVariant::Secondary, size: BadgeSize::Sm, "{p.algorithm}" }
          }
          p { class: "truncate text-sm text-muted-foreground", "{p.user_id}" }
        }
        icons::ChevronRight { class: "size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" }
      }
      if !p.purpose.is_empty() {
        p { class: "line-clamp-2 text-sm", "{p.purpose}" }
      }
      FingerprintText { fp: p.fingerprint.clone(), class: "text-muted-foreground" }
      div { class: "flex flex-wrap gap-x-4 text-xs text-muted-foreground",
        span { "Erstellt {util::date(p.created_at)}" }
        if let Some(u) = p.last_used_at {
          span { "Zuletzt benutzt {util::time_ago(u)}" }
        }
      }
    }
  }
}

#[component]
fn ToolLink(to: Route, title: String, text: String, icon: Element) -> Element {
  rsx! {
    Link { to, class: "flex items-start gap-3 rounded-xl border bg-background/40 p-3 transition-colors hover:bg-accent",
      span { class: "grid size-9 shrink-0 place-items-center rounded-lg bg-accent [&_svg]:size-4", {icon} }
      div { class: "min-w-0",
        div { class: "text-sm font-medium", "{title}" }
        div { class: "text-xs text-muted-foreground", "{text}" }
      }
    }
  }
}
