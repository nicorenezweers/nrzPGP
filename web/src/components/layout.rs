//! App-Rahmen: Kopfzeile mit Name und Abmelden, links die Navigation (auf Mobilgeraeten als
//! Schubfach), mittig der Inhalt.

use crate::components::common::Logo;
use crate::components::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::route::Route;
use crate::state::{self, SIDEBAR_OPEN, SITE};
use dioxus::prelude::*;
use nrzpgp_shared::Ok as OkResp;

pub fn logout() {
  spawn(async move {
    let _ = crate::api::post::<_, OkResp>("/api/v1/auth/logout", &serde_json::json!({})).await;
    state::load_site().await;
    state::toast("Abgemeldet.");
  });
}

#[component]
pub fn Shell() -> Element {
  let route = use_route::<Route>();
  use_effect(use_reactive!(|route| {
    let _ = &route;
    *SIDEBAR_OPEN.write() = false;
  }));
  rsx! {
    a { href: "#inhalt", class: "sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[90] focus:rounded-lg focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground", "Zum Inhalt springen" }
    Header {}
    div { class: "mx-auto flex w-full max-w-[1400px]",
      Sidebar {}
      main { id: "inhalt", class: "min-w-0 flex-1 px-3 pt-5 pb-16 sm:px-6 lg:px-8 lg:pt-8",
        div { class: "mx-auto max-w-5xl", Outlet::<Route> {} }
      }
    }
  }
}

#[component]
fn Header() -> Element {
  let me = state::me();
  let site_name = SITE.read().as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "nrzPGP".into());
  rsx! {
    header { class: "sticky top-0 z-30 border-b bg-background/80 backdrop-blur-xl",
      div { class: "mx-auto flex h-14 max-w-[1400px] items-center gap-2 px-3 sm:gap-3 sm:px-5",
        Button {
          variant: ButtonVariant::Ghost,
          size: ButtonSize::Icon,
          class: "rounded-full lg:hidden",
          aria_label: "Menü",
          onclick: move |_| SIDEBAR_OPEN.with_mut(|o| *o = !*o),
          icons::Menu {}
        }
        Link { to: Route::Home {}, class: "flex items-center gap-2.5 rounded-xl pr-2",
          Logo {}
          span { class: "text-lg font-bold tracking-tight", "{site_name}" }
        }
        div { class: "ml-auto flex items-center gap-1 sm:gap-2",
          if let Some(me) = me {
            span { class: "hidden items-center gap-2 rounded-full border bg-card px-3 py-1 text-sm text-muted-foreground sm:flex",
              icons::CircleUser { class: "size-4" }
              span { class: "font-medium text-foreground", "{me.name}" }
            }
            Button {
              variant: ButtonVariant::Ghost,
              class: "rounded-full",
              aria_label: "Abmelden",
              onclick: move |_| logout(),
              icons::LogOut {}
              span { class: "hidden sm:inline", "Abmelden" }
            }
          }
        }
      }
    }
  }
}

#[component]
fn NavItem(to: Route, label: String, active: bool, icon: Element) -> Element {
  rsx! {
    Link {
      to,
      class: if active { "nav-item bg-sidenav-accent text-foreground" } else { "nav-item" },
      "aria-current": if active { "page" } else { "false" },
      {icon}
      span { class: "truncate", "{label}" }
    }
  }
}

#[component]
fn Sidebar() -> Element {
  let route = use_route::<Route>();
  let open = SIDEBAR_OPEN();
  let version = SITE.read().as_ref().map(|s| s.version.clone()).unwrap_or_default();
  let profiles_active = matches!(
    route,
    Route::Home {} | Route::NewProfile {} | Route::ImportProfilePage {} | Route::ProfilePage { .. } | Route::VaultPage { .. }
  );
  let panel = rsx! {
    nav { class: "flex h-full flex-col gap-1 overflow-y-auto px-3 py-4", "aria-label": "Hauptnavigation",
      NavItem { to: Route::Home {}, label: "Übersicht", active: profiles_active, icon: rsx! { icons::KeyRound { class: "size-[18px]" } } }
      div { class: "px-3 pt-4 pb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground", "Werkzeuge" }
      NavItem { to: Route::Encrypt {}, label: "Verschlüsseln", active: matches!(route, Route::Encrypt {}), icon: rsx! { icons::Lock { class: "size-[18px]" } } }
      NavItem { to: Route::Decrypt {}, label: "Entschlüsseln", active: matches!(route, Route::Decrypt {}), icon: rsx! { icons::LockOpen { class: "size-[18px]" } } }
      NavItem { to: Route::Sign {}, label: "Signieren", active: matches!(route, Route::Sign {}), icon: rsx! { icons::PenLine { class: "size-[18px]" } } }
      NavItem { to: Route::Verify {}, label: "PGP-Prüfer", active: matches!(route, Route::Verify {}), icon: rsx! { icons::ShieldCheck { class: "size-[18px]" } } }
      div { class: "px-3 pt-4 pb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground", "Verwaltung" }
      NavItem { to: Route::Contacts {}, label: "Kontakte", active: matches!(route, Route::Contacts {} | Route::ContactPage { .. }), icon: rsx! { icons::Users { class: "size-[18px]" } } }
      NavItem { to: Route::Log {}, label: "Protokoll", active: matches!(route, Route::Log {}), icon: rsx! { icons::ScrollText { class: "size-[18px]" } } }
      NavItem { to: Route::Settings {}, label: "Einstellungen", active: matches!(route, Route::Settings {}), icon: rsx! { icons::Settings { class: "size-[18px]" } } }
      div { class: "mt-auto flex flex-col gap-1 px-3 pt-6 text-xs text-muted-foreground",
        span { class: "flex items-center gap-1.5",
          icons::ShieldCheck { class: "size-3.5" }
          "Geschützt mit "
          a { href: "https://trycap.dev", target: "_blank", rel: "noopener noreferrer", class: "underline hover:text-foreground", "Cap" }
        }
        if !version.is_empty() {
          span { "nrzPGP {version}" }
        }
      }
    }
  };
  rsx! {
    aside { class: "sticky top-14 hidden h-[calc(100dvh-3.5rem)] w-60 shrink-0 border-r border-sidenav-border lg:block", {panel.clone()} }
    if open {
      div { class: "fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden", onclick: move |_| *SIDEBAR_OPEN.write() = false }
      aside { class: "fade-in fixed top-14 bottom-0 left-0 z-50 w-72 border-r bg-background lg:hidden", {panel} }
    }
  }
}
