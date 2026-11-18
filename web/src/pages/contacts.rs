//! Kontakte: oeffentliche Schluessel anderer (Schluesselbund).

use crate::api;
use crate::components::common::{
  ArmorBox, EmptyState, ErrorBox, Field, FingerprintText, InfoBox, Loading, MonoInput, PageHeader, Section,
};
use crate::components::pgp::KeyInfoView;
use crate::components::ui::badge::{Badge, BadgeSize, BadgeVariant};
use crate::components::ui::button::{Button, ButtonVariant};
use crate::components::ui::checkbox::Checkbox;
use crate::components::ui::input::Input;
use crate::components::ui::textarea::Textarea;
use crate::route::Route;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{Contact, ContactDetail, ImportContact, Ok as OkResp, UpdateContact, rules};

#[component]
pub fn Contacts() -> Element {
  use_effect(|| util::set_title("Kontakte"));
  let mut reload = use_signal(|| 0u32);
  let contacts = use_resource(move || async move {
    let _ = reload();
    api::get::<Vec<Contact>>("/api/v1/contacts").await
  });
  let mut armored = use_signal(String::new);
  let mut note = use_signal(String::new);
  let mut show_import = use_signal(|| false);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let mut filter = use_signal(String::new);

  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    if let Err(m) = rules::message(&armored()).and_then(|_| rules::note(&note())) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = ImportContact { armored: armored(), note: note().trim().into() };
    spawn(async move {
      match api::post::<_, Vec<Contact>>("/api/v1/contacts", &req).await {
        Ok(list) => {
          if list.is_empty() {
            state::toast("Keine neuen Schlüssel – schon vorhanden.");
          } else {
            state::toast(format!("{} Kontakt(e) importiert.", list.len()));
          }
          armored.set(String::new());
          note.set(String::new());
          show_import.set(false);
          reload += 1;
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  let q = filter().to_lowercase();
  rsx! {
    PageHeader {
      title: "Kontakte",
      subtitle: "Öffentliche Schlüssel anderer Personen – zum Verschlüsseln an sie und zum Prüfen ihrer Signaturen.",
      icon: rsx! { icons::Users {} },
      actions: rsx! {
        Button { class: "rounded-full", onclick: move |_| show_import.toggle(),
          icons::UserPlus {}
          "Schlüssel importieren"
        }
      },
    }
    div { class: "flex flex-col gap-6",
      if show_import() {
        Section { title: "Öffentlichen Schlüssel importieren",
          form { class: "flex flex-col gap-4", onsubmit: submit,
            if let Some(e) = error() { ErrorBox { text: e } }
            MonoInput { rows: 8, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----", value: armored(), oninput: move |v| armored.set(v) }
            Field { label: "Notiz (optional)", html_for: "cn",
              Input { id: "cn", class: "h-10 rounded-xl", maxlength: rules::NOTE_MAX as i64, value: note(), oninput: move |e: FormEvent| note.set(e.value()) }
            }
            div { class: "flex justify-end gap-2",
              Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: move |_| show_import.set(false), "Abbrechen" }
              Button { button_type: "submit", class: "rounded-full", disabled: busy(),
                if busy() { icons::LoaderCircle { class: "animate-spin" } }
                "Importieren"
              }
            }
          }
        }
      }
      match &*contacts.read_unchecked() {
          None => rsx! { Loading {} },
          Some(Err(e)) => rsx! { ErrorBox { text: e.text() } },
          Some(Ok(list)) if list.is_empty() => rsx! {
            EmptyState { title: "Noch keine Kontakte", text: "Importiere den öffentlichen Schlüssel einer Person, um ihr verschlüsselt zu schreiben." }
          },
          Some(Ok(list)) => {
              let shown: Vec<Contact> = list
                  .iter()
                  .filter(|c| {
                      q.is_empty() || c.label.to_lowercase().contains(&q)
                          || c.fingerprint.to_lowercase().contains(&q)
                          || c.user_ids.iter().any(|u| u.to_lowercase().contains(&q))
                  })
                  .cloned()
                  .collect();
              rsx! {
                Input { class: "h-10 rounded-xl", placeholder: "Suchen nach Name, E-Mail oder Fingerabdruck …", value: filter(), oninput: move |e: FormEvent| filter.set(e.value()) }
                div { class: "flex flex-col gap-2",
                  for c in shown {
                    ContactRow { key: "{c.id}", contact: c }
                  }
                }
              }
          }
      }
    }
  }
}

#[component]
fn ContactRow(contact: Contact) -> Element {
  let c = contact;
  rsx! {
    Link { to: Route::ContactPage { id: c.id }, class: "group flex items-start gap-3 rounded-2xl border bg-card p-4 transition-colors hover:border-ring/60",
      span { class: "grid size-10 shrink-0 place-items-center rounded-xl bg-accent", icons::CircleUser { class: "size-5" } }
      div { class: "min-w-0 flex-1",
        div { class: "flex flex-wrap items-center gap-2",
          span { class: "truncate font-semibold", "{c.label}" }
          if c.verified {
            Badge { variant: BadgeVariant::Success, size: BadgeSize::Sm, "geprüft" }
          }
          if !c.can_encrypt {
            Badge { variant: BadgeVariant::Destructive, size: BadgeSize::Sm, "nicht verwendbar" }
          }
          Badge { variant: BadgeVariant::Secondary, size: BadgeSize::Sm, "{c.algorithm}" }
        }
        for (i, u) in c.user_ids.iter().enumerate().take(3) {
          p { key: "{i}", class: "truncate text-sm text-muted-foreground", "{u}" }
        }
        FingerprintText { fp: c.fingerprint.clone(), class: "text-muted-foreground" }
      }
      icons::ChevronRight { class: "mt-2 size-4 text-muted-foreground" }
    }
  }
}

#[component]
pub fn ContactPage(id: i64) -> Element {
  let mut reload = use_signal(|| 0u32);
  let detail = use_resource(use_reactive!(|id| async move {
    let _ = reload();
    api::get::<ContactDetail>(&format!("/api/v1/contacts/{id}")).await
  }));
  let read = detail.read_unchecked();
  let d = match &*read {
    None => return rsx! { Loading {} },
    Some(Err(e)) => return rsx! { ErrorBox { text: e.text() } },
    Some(Ok(d)) => d.clone(),
  };
  drop(read);
  util::set_title(&d.contact.label);
  let c = d.contact.clone();
  rsx! {
    PageHeader {
      title: "{c.label}",
      subtitle: c.user_ids.first().cloned().unwrap_or_default(),
      icon: rsx! { icons::CircleUser {} },
      actions: rsx! {
        Button { variant: ButtonVariant::Ghost, class: "rounded-full", href: Route::Contacts {}.to_string(), icons::ArrowLeft {} "Alle Kontakte" }
      },
    }
    div { class: "flex flex-col gap-6",
      ContactEdit { key: "{reload}", contact: c.clone(), on_saved: move |_| reload += 1 }
      Section { title: "Öffentlicher Schlüssel",
        ArmorBox { text: d.public_key.clone(), file_name: format!("{}-public.asc", util::slug(&c.label)), rows: 8 }
      }
      Section { title: "Schlüssel-Details",
        KeyInfoView { key_info: d.key.clone() }
      }
    }
  }
}

#[component]
fn ContactEdit(contact: Contact, on_saved: EventHandler<()>) -> Element {
  let id = contact.id;
  let fp = contact.fingerprint.clone();
  let mut label = use_signal(|| contact.label.clone());
  let mut note = use_signal(|| contact.note.clone());
  let mut verified = use_signal(|| contact.verified);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let nav = navigator();
  let save = move |e: FormEvent| {
    e.prevent_default();
    if let Err(m) = rules::label(&label()).and_then(|_| rules::note(&note())) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = UpdateContact { label: label().trim().into(), note: note().trim().into(), verified: verified() };
    spawn(async move {
      match api::patch::<_, ContactDetail>(&format!("/api/v1/contacts/{id}"), &req).await {
        Ok(_) => {
          state::toast("Gespeichert.");
          on_saved.call(());
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  let remove = move |_| {
    if !util::confirm("Kontakt mit seinem öffentlichen Schlüssel löschen?") {
      return;
    }
    spawn(async move {
      match api::delete::<OkResp>(&format!("/api/v1/contacts/{id}")).await {
        Ok(_) => {
          state::toast("Kontakt gelöscht.");
          nav.replace(Route::Contacts {});
        }
        Err(e) => state::toast_error(e.text()),
      }
    });
  };
  rsx! {
    Section { title: "Kontakt",
      form { class: "flex flex-col gap-4", onsubmit: save,
        if let Some(e) = error() { ErrorBox { text: e } }
        div { class: "grid gap-4 sm:grid-cols-2",
          Field { label: "Name", html_for: "cl",
            Input { id: "cl", class: "h-10 rounded-xl", maxlength: rules::LABEL_MAX as i64, value: label(), oninput: move |e: FormEvent| label.set(e.value()) }
          }
          Field { label: "Notiz", html_for: "cnote",
            Textarea { id: "cnote", rows: 2, maxlength: rules::NOTE_MAX as i64, value: note(), oninput: move |e: FormEvent| note.set(e.value()) }
          }
        }
        InfoBox {
          p { "Vergleiche den Fingerabdruck persönlich oder über einen zweiten, sicheren Kanal (z. B. Telefon) mit der Person, bevor du ihn als geprüft markierst:" }
          FingerprintText { fp: fp.clone(), class: "text-foreground" }
        }
        label { class: "flex cursor-pointer items-center gap-3 text-sm",
          onclick: move |e: MouseEvent| {
              e.prevent_default();
              verified.toggle();
          },
          Checkbox { checked: verified(), aria_label: "Fingerabdruck geprüft" }
          "Fingerabdruck persönlich geprüft"
        }
        div { class: "flex flex-wrap justify-between gap-2",
          Button { variant: ButtonVariant::Destructive, class: "rounded-full", onclick: remove, icons::Trash2 {} "Löschen" }
          Button { button_type: "submit", class: "rounded-full", disabled: busy(), icons::Save {} "Speichern" }
        }
      }
    }
  }
}
