//! Werkzeuge: Verschluesseln, Entschluesseln, Signieren und der PGP-Pruefer.
//!
//! Alles mit privaten Schluesseln passiert auf dem Server; hier werden nur Eingaben geschickt und
//! Ergebnisse angezeigt. Passphrasen und Klartexte bleiben im Zustand der Seite.

use crate::api;
use crate::components::common::{ArmorBox, ErrorBox, Field, InfoBox, MonoInput, PageHeader, SELECT_CLASS, Section};
use crate::components::pgp::{KeyInfoView, ProfileSelect, SignatureList};
use crate::components::ui::badge::{Badge, BadgeSize, BadgeVariant};
use crate::components::ui::button::{Button, ButtonVariant};
use crate::components::ui::checkbox::Checkbox;
use crate::components::ui::input::{Input, InputType};
use crate::components::ui::textarea::Textarea;
use crate::route::Route;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{
  Contact, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, ImportContact, InspectKeyRequest,
  InspectMessageRequest, KeyInfo, MessageInfo, ProfileSummary, SignRequest, SignResponse, VerifyRequest,
  VerifyResponse, rules, sign_modes,
};

fn use_profiles() -> Resource<api::Result<Vec<ProfileSummary>>> {
  use_resource(|| async { api::get::<Vec<ProfileSummary>>("/api/v1/profiles").await })
}

fn profiles_of(r: &Resource<api::Result<Vec<ProfileSummary>>>) -> Vec<ProfileSummary> {
  match &*r.read_unchecked() {
    Some(Ok(l)) => l.clone(),
    _ => Vec::new(),
  }
}

#[component]
fn PassInput(id: String, value: Signal<String>, #[props(into, default = "Passphrase".to_string())] label: String) -> Element {
  let mut value = value;
  rsx! {
    Field { label: "{label}", html_for: "{id}",
      Input { id: "{id}", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "off", maxlength: 1024, value: value(), oninput: move |e: FormEvent| value.set(e.value()) }
    }
  }
}

#[component]
fn Pick(checked: bool, label: String, sub: String, on_change: EventHandler<bool>) -> Element {
  rsx! {
    label { class: "flex cursor-pointer items-start gap-3 rounded-xl border bg-background/40 p-3 hover:bg-accent/50",
      onclick: move |e: MouseEvent| {
          e.prevent_default();
          on_change.call(!checked);
      },
      div { class: "pt-0.5", Checkbox { checked, aria_label: "{label}" } }
      div { class: "min-w-0",
        div { class: "truncate text-sm font-medium", "{label}" }
        div { class: "truncate text-xs text-muted-foreground", "{sub}" }
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Verschluesseln

#[component]
pub fn Encrypt() -> Element {
  use_effect(|| util::set_title("Verschlüsseln"));
  let profiles = use_profiles();
  let contacts = use_resource(|| async { api::get::<Vec<Contact>>("/api/v1/contacts").await });
  let mut text = use_signal(String::new);
  let mut picked_profiles = use_signal(Vec::<i64>::new);
  let mut picked_contacts = use_signal(Vec::<i64>::new);
  let mut extra = use_signal(String::new);
  let mut password = use_signal(String::new);
  let mut sign = use_signal(|| None::<i64>);
  let passphrase = use_signal(String::new);
  let mut result = use_signal(|| None::<EncryptResponse>);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);

  let plist = profiles_of(&profiles);
  let clist: Vec<Contact> = match &*contacts.read_unchecked() {
    Some(Ok(l)) => l.iter().filter(|c| c.can_encrypt).cloned().collect(),
    _ => Vec::new(),
  };

  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    if let Err(m) = rules::message(&text()) {
      error.set(Some(m.into()));
      return;
    }
    if picked_profiles().is_empty() && picked_contacts().is_empty() && extra().trim().is_empty() && password().is_empty() {
      error.set(Some("Bitte mindestens einen Empfänger oder ein Passwort angeben.".into()));
      return;
    }
    if sign().is_some() && passphrase().is_empty() {
      error.set(Some("Zum Signieren wird die Passphrase des Profils gebraucht.".into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = EncryptRequest {
      text: text(),
      profile_ids: picked_profiles(),
      contact_ids: picked_contacts(),
      extra_keys: extra(),
      password: password(),
      sign_profile: sign(),
      passphrase: passphrase(),
    };
    let mut passphrase = passphrase;
    spawn(async move {
      match api::post::<_, EncryptResponse>("/api/v1/tools/encrypt", &req).await {
        Ok(r) => {
          passphrase.set(String::new());
          result.set(Some(r));
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  rsx! {
    PageHeader {
      title: "Verschlüsseln",
      subtitle: "Verschlüsselt eine Nachricht an öffentliche Schlüssel (eigene Profile, Kontakte oder eingefügte Schlüssel) und/oder mit einem Passwort. Optional signiert.",
      icon: rsx! { icons::Lock {} },
    }
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Nachricht",
        Textarea { class: "min-h-48 rounded-xl", rows: 10, placeholder: "Dein Text …", value: text(), oninput: move |e: FormEvent| text.set(e.value()) }
      }
      Section { title: "Empfänger",
        div { class: "flex flex-col gap-5",
          if !plist.is_empty() {
            div {
              h3 { class: "mb-2 text-sm font-medium", "Eigene Profile" }
              div { class: "grid gap-2 sm:grid-cols-2",
                for p in plist.iter() {
                  Pick {
                    key: "p{p.id}",
                    checked: picked_profiles().contains(&p.id),
                    label: p.label.clone(),
                    sub: p.user_id.clone(),
                    on_change: {
                        let pid = p.id;
                        move |on: bool| picked_profiles.with_mut(|v| if on { v.push(pid) } else { v.retain(|x| *x != pid) })
                    },
                  }
                }
              }
            }
          }
          div {
            div { class: "mb-2 flex items-center justify-between gap-2",
              h3 { class: "text-sm font-medium", "Kontakte" }
              Link { to: Route::Contacts {}, class: "text-xs text-muted-foreground underline hover:text-foreground", "Kontakte verwalten" }
            }
            if clist.is_empty() {
              p { class: "text-sm text-muted-foreground", "Keine Kontakte mit gültigem Verschlüsselungsschlüssel." }
            }
            div { class: "grid gap-2 sm:grid-cols-2",
              for c in clist.iter() {
                Pick {
                  key: "c{c.id}",
                  checked: picked_contacts().contains(&c.id),
                  label: c.label.clone(),
                  sub: c.user_ids.first().cloned().unwrap_or_else(|| c.key_id.clone()),
                  on_change: {
                      let cid = c.id;
                      move |on: bool| picked_contacts.with_mut(|v| if on { v.push(cid) } else { v.retain(|x| *x != cid) })
                  },
                }
              }
            }
          }
          Field { label: "Weitere öffentliche Schlüssel (optional)", html_for: "extra", hint: "Nur für diese Nachricht, wird nicht gespeichert.",
            MonoInput { id: "extra", rows: 4, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----", value: extra(), oninput: move |v| extra.set(v) }
          }
          Field { label: "Zusätzlich mit Passwort verschlüsseln (optional)", html_for: "sympw", hint: "Wer das Passwort kennt, kann die Nachricht ebenfalls entschlüsseln.",
            Input { id: "sympw", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "new-password", maxlength: 1024, value: password(), oninput: move |e: FormEvent| password.set(e.value()) }
          }
        }
      }
      Section { title: "Signieren (optional)",
        div { class: "grid gap-4 sm:grid-cols-2",
          Field { label: "Signieren mit", html_for: "signp",
            ProfileSelect { id: "signp", profiles: plist.clone(), value: sign(), on_change: move |v| sign.set(v), placeholder: "Nicht signieren" }
          }
          if sign().is_some() {
            PassInput { id: "signpp", value: passphrase }
          }
        }
      }
      div { class: "flex justify-end",
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::Lock {} }
          "Verschlüsseln"
        }
      }
      if let Some(r) = result() {
        Section { title: "Verschlüsselte Nachricht",
          div { class: "mb-3 flex flex-wrap gap-1.5",
            for (i, rc) in r.recipients.iter().enumerate() {
              Badge { key: "{i}", variant: BadgeVariant::Secondary, "{rc}" }
            }
            if r.signed {
              Badge { variant: BadgeVariant::Success, "signiert" }
            }
          }
          ArmorBox { text: r.armored.clone(), file_name: "nachricht.asc", rows: 12 }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Entschluesseln

#[component]
pub fn Decrypt() -> Element {
  use_effect(|| util::set_title("Entschlüsseln"));
  let profiles = use_profiles();
  let mut message = use_signal(String::new);
  let mut info = use_signal(|| None::<MessageInfo>);
  let mut profile = use_signal(|| None::<i64>);
  let passphrase = use_signal(String::new);
  let password = use_signal(String::new);
  let mut result = use_signal(|| None::<DecryptResponse>);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let plist = profiles_of(&profiles);

  let analyze = move |_| {
    if busy() {
      return;
    }
    if let Err(m) = rules::message(&message()) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    result.set(None);
    let req = InspectMessageRequest { message: message() };
    spawn(async move {
      match api::post::<_, MessageInfo>("/api/v1/tools/inspect-message", &req).await {
        Ok(i) => {
          if i.suggested_profile.is_some() {
            profile.set(i.suggested_profile);
          }
          info.set(Some(i));
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  let decrypt = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    if profile().is_none() && password().is_empty() {
      error.set(Some("Bitte ein Profil (mit Passphrase) wählen oder das Passwort der Nachricht angeben.".into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = DecryptRequest { message: message(), profile_id: profile(), passphrase: passphrase(), password: password() };
    let mut passphrase = passphrase;
    let mut password = password;
    spawn(async move {
      match api::post::<_, DecryptResponse>("/api/v1/tools/decrypt", &req).await {
        Ok(r) => {
          passphrase.set(String::new());
          password.set(String::new());
          result.set(Some(r));
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  let pw_encrypted = info().is_some_and(|i| i.password_encrypted);
  let has_recipients = info().is_some_and(|i| !i.recipients.is_empty());

  rsx! {
    PageHeader {
      title: "Entschlüsseln",
      subtitle: "Die Entschlüsselung passiert auf dem Server: Deine Nachricht und Passphrase gehen verschlüsselt über die Verbindung, der Server entsperrt den privaten Schlüssel nur kurz im Arbeitsspeicher und schickt allein das Ergebnis zurück.",
      icon: rsx! { icons::LockOpen {} },
    }
    div { class: "flex flex-col gap-6",
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Verschlüsselte Nachricht",
        MonoInput {
          rows: 10,
          placeholder: "-----BEGIN PGP MESSAGE-----",
          value: message(),
          oninput: move |v| {
              message.set(v);
              info.set(None);
              result.set(None);
          },
        }
        div { class: "mt-3 flex justify-end",
          Button { variant: ButtonVariant::Outline, class: "rounded-full", disabled: busy(), onclick: analyze,
            if busy() && info().is_none() { icons::LoaderCircle { class: "animate-spin" } } else { icons::Search {} }
            "Analysieren"
          }
        }
      }
      if let Some(i) = info() {
        Section { title: "Empfänger der Nachricht",
          MessageInfoView { info: i.clone() }
          form { class: "mt-5 flex flex-col gap-4 border-t pt-5", onsubmit: decrypt,
            div { class: "grid gap-4 sm:grid-cols-2",
              if has_recipients || !pw_encrypted {
                Field { label: "Entschlüsseln mit Profil", html_for: "dp",
                  ProfileSelect { id: "dp", profiles: plist.clone(), value: profile(), on_change: move |v| profile.set(v) }
                }
                if profile().is_some() {
                  PassInput { id: "dpp", value: passphrase }
                }
              }
              if pw_encrypted {
                PassInput { id: "dpw", value: password, label: "Passwort der Nachricht" }
              }
            }
            div { class: "flex justify-end",
              Button { button_type: "submit", class: "rounded-full", disabled: busy(),
                if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::LockOpen {} }
                "Entschlüsseln"
              }
            }
          }
        }
      }
      if let Some(r) = result() {
        Section {
          title: "Inhalt",
          actions: rsx! {
            Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: move |_| result.set(None), icons::EyeOff {} "Ausblenden" }
          },
          div { class: "flex flex-col gap-4",
            SignatureList { signatures: r.signatures.clone() }
            if r.binary {
              InfoBox {
                p { "Der Inhalt ist keine Textnachricht (Datei{file_label(&r.file_name)})." }
                Button {
                  variant: ButtonVariant::Outline,
                  class: "mt-2 rounded-full",
                  onclick: {
                      let r = r.clone();
                      move |_| {
                          let name = if r.file_name.is_empty() { "inhalt.bin.b64".to_string() } else { format!("{}.b64", r.file_name) };
                          util::download(&name, &r.text, "text/plain");
                      }
                  },
                  icons::Download {}
                  "Als Base64 herunterladen"
                }
              }
            } else {
              ArmorBox { text: r.text.clone(), rows: 12 }
            }
          }
        }
      }
    }
  }
}

fn file_label(name: &str) -> String {
  if name.is_empty() { String::new() } else { format!(" „{name}“") }
}

fn kind_label(kind: &str) -> &str {
  match kind {
    "encrypted" => "Verschlüsselte Nachricht",
    "signed" => "Signierte Nachricht",
    "cleartext_signed" => "Klartext-Signatur",
    "signature" => "Abgetrennte Signatur",
    "literal" => "Unverschlüsselte Daten",
    "compressed" => "Komprimierte Daten",
    "public_key" => "Öffentlicher Schlüssel",
    "secret_key" => "Privater Schlüssel",
    other => other,
  }
}

/// Anzeige einer analysierten Nachricht.
#[component]
fn MessageInfoView(info: MessageInfo) -> Element {
  rsx! {
    div { class: "flex flex-col gap-4",
      div { class: "flex flex-wrap gap-1.5",
        Badge { variant: BadgeVariant::Outline, "{kind_label(&info.kind)}" }
        if info.password_encrypted {
          Badge { variant: BadgeVariant::Info, "mit Passwort verschlüsselt" }
        }
      }
      if !info.recipients.is_empty() {
        div { class: "flex flex-col gap-2",
          for (i, r) in info.recipients.iter().enumerate() {
            div { key: "{i}", class: "flex flex-wrap items-center gap-2 rounded-xl border bg-background/40 px-3 py-2 text-sm",
              icons::KeyRound { class: "size-4 text-muted-foreground" }
              code { class: "font-mono text-xs", "{r.key_id}" }
              span { class: "text-xs text-muted-foreground", "{r.algorithm}" }
              if let Some(l) = &r.profile_label {
                Badge { variant: BadgeVariant::Success, size: BadgeSize::Sm, "Profil: {l}" }
              }
              if let Some(l) = &r.contact_label {
                Badge { variant: BadgeVariant::Secondary, size: BadgeSize::Sm, "Kontakt: {l}" }
              }
              if r.profile_label.is_none() && r.contact_label.is_none() {
                Badge { variant: BadgeVariant::Muted, size: BadgeSize::Sm,
                  if r.key_id.chars().all(|c| c == '0') { "anonymer Empfänger" } else { "unbekannt" }
                }
              }
            }
          }
        }
      }
      if !info.signer_key_ids.is_empty() {
        p { class: "text-sm text-muted-foreground",
          "Signiert von Key-ID: "
          for (i, k) in info.signer_key_ids.iter().enumerate() {
            code { key: "{i}", class: "mr-2 font-mono text-xs text-foreground", "{k}" }
          }
        }
      }
      if !info.details.is_empty() {
        ul { class: "list-disc pl-5 text-sm text-muted-foreground",
          for (i, d) in info.details.iter().enumerate() {
            li { key: "{i}", "{d}" }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Signieren

#[component]
pub fn Sign() -> Element {
  use_effect(|| util::set_title("Signieren"));
  let profiles = use_profiles();
  let mut text = use_signal(String::new);
  let mut profile = use_signal(|| None::<i64>);
  let passphrase = use_signal(String::new);
  let mut mode = use_signal(|| sign_modes::CLEARTEXT.to_string());
  let mut result = use_signal(|| None::<String>);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let plist = profiles_of(&profiles);

  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    let Some(pid) = profile() else {
      error.set(Some("Bitte ein Profil wählen.".into()));
      return;
    };
    if let Err(m) = rules::message(&text()) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = SignRequest { text: text(), profile_id: pid, passphrase: passphrase(), mode: mode() };
    let mut passphrase = passphrase;
    spawn(async move {
      match api::post::<_, SignResponse>("/api/v1/tools/sign", &req).await {
        Ok(r) => {
          passphrase.set(String::new());
          result.set(Some(r.armored));
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  let file = if mode() == sign_modes::DETACHED { "signatur.asc" } else { "signiert.asc" };

  rsx! {
    PageHeader {
      title: "Signieren",
      subtitle: "Beweist, dass ein Text von dir stammt und unverändert ist. Signiert wird auf dem Server mit dem privaten Schlüssel des gewählten Profils.",
      icon: rsx! { icons::PenLine {} },
    }
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Text",
        Textarea { class: "min-h-48 rounded-xl", rows: 10, value: text(), oninput: move |e: FormEvent| text.set(e.value()) }
      }
      Section { title: "Signatur",
        div { class: "grid gap-4 sm:grid-cols-2",
          Field { label: "Profil", html_for: "sp",
            ProfileSelect { id: "sp", profiles: plist.clone(), value: profile(), on_change: move |v| profile.set(v) }
          }
          Field { label: "Art", html_for: "sm",
            select { id: "sm", class: SELECT_CLASS, value: "{mode}", onchange: move |e| mode.set(e.value()),
              option { value: sign_modes::CLEARTEXT, selected: mode() == sign_modes::CLEARTEXT, "Klartext-Signatur (lesbar)" }
              option { value: sign_modes::DETACHED, selected: mode() == sign_modes::DETACHED, "Abgetrennte Signatur" }
              option { value: sign_modes::INLINE, selected: mode() == sign_modes::INLINE, "Signierte Nachricht (eingebettet)" }
            }
          }
          PassInput { id: "spp", value: passphrase }
        }
      }
      div { class: "flex justify-end",
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::PenLine {} }
          "Signieren"
        }
      }
      if let Some(r) = result() {
        Section { title: "Ergebnis",
          ArmorBox { text: r, file_name: file, rows: 12 }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// PGP-Pruefer

#[derive(Clone, Copy, PartialEq)]
enum VerifyTab {
  Signature,
  Key,
  Message,
}

#[component]
pub fn Verify() -> Element {
  use_effect(|| util::set_title("PGP-Prüfer"));
  let mut tab = use_signal(|| VerifyTab::Signature);
  let tab_btn = |active: bool| {
    if active {
      "flex h-8 items-center gap-1.5 whitespace-nowrap rounded-full bg-primary px-3 text-sm font-medium text-primary-foreground"
    } else {
      "flex h-8 items-center gap-1.5 whitespace-nowrap rounded-full px-3 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-foreground"
    }
  };
  rsx! {
    PageHeader {
      title: "PGP-Prüfer",
      subtitle: "Signaturen prüfen, Schlüssel untersuchen und verschlüsselte Nachrichten analysieren – ohne private Schlüssel.",
      icon: rsx! { icons::ShieldCheck {} },
    }
    div { class: "no__scrollbar mb-6 flex w-fit max-w-full gap-1 overflow-x-auto rounded-full border bg-card p-1", role: "tablist",
      button { r#type: "button", role: "tab", class: tab_btn(tab() == VerifyTab::Signature), onclick: move |_| tab.set(VerifyTab::Signature), icons::BadgeCheck { class: "size-4" } "Signatur prüfen" }
      button { r#type: "button", role: "tab", class: tab_btn(tab() == VerifyTab::Key), onclick: move |_| tab.set(VerifyTab::Key), icons::KeyRound { class: "size-4" } "Schlüssel prüfen" }
      button { r#type: "button", role: "tab", class: tab_btn(tab() == VerifyTab::Message), onclick: move |_| tab.set(VerifyTab::Message), icons::FileSearch { class: "size-4" } "Nachricht analysieren" }
    }
    match tab() {
        VerifyTab::Signature => rsx! { VerifySignature {} },
        VerifyTab::Key => rsx! { VerifyKey {} },
        VerifyTab::Message => rsx! { VerifyMessage {} },
    }
  }
}

#[component]
fn VerifySignature() -> Element {
  let mut message = use_signal(String::new);
  let mut data = use_signal(String::new);
  let mut extra = use_signal(String::new);
  let mut result = use_signal(|| None::<VerifyResponse>);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let detached = message().contains("BEGIN PGP SIGNATURE") && !message().contains("BEGIN PGP SIGNED MESSAGE");
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    if let Err(m) = rules::message(&message()) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = VerifyRequest { message: message(), data: data(), extra_key: extra() };
    spawn(async move {
      match api::post::<_, VerifyResponse>("/api/v1/tools/verify", &req).await {
        Ok(r) => result.set(Some(r)),
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Signierte Nachricht oder Signatur", description: "Geprüft wird gegen deine Profile, deine Kontakte und optional einen eingefügten Schlüssel.",
        div { class: "flex flex-col gap-4",
          MonoInput { rows: 10, placeholder: "-----BEGIN PGP SIGNED MESSAGE----- / -----BEGIN PGP SIGNATURE----- / -----BEGIN PGP MESSAGE-----", value: message(), oninput: move |v| { message.set(v); result.set(None); } }
          if detached || !data().is_empty() {
            Field { label: "Signierter Text (bei abgetrennter Signatur)", html_for: "vdata",
              Textarea { id: "vdata", rows: 6, class: "rounded-xl", value: data(), oninput: move |e: FormEvent| data.set(e.value()) }
            }
          }
          Field { label: "Öffentlicher Schlüssel des Absenders (optional)", html_for: "vkey",
            MonoInput { id: "vkey", rows: 4, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----", value: extra(), oninput: move |v| extra.set(v) }
          }
        }
      }
      div { class: "flex justify-end",
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::BadgeCheck {} }
          "Prüfen"
        }
      }
      if let Some(r) = result() {
        Section { title: "Ergebnis",
          div { class: "flex flex-col gap-4",
            SignatureList { signatures: r.signatures.clone() }
            if let Some(t) = r.text.clone() {
              ArmorBox { text: t, label: "Signierter Text", rows: 8 }
            }
          }
        }
      }
    }
  }
}

#[component]
fn VerifyKey() -> Element {
  let mut armored = use_signal(String::new);
  let mut result = use_signal(|| None::<Vec<KeyInfo>>);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let mut saving = use_signal(|| false);
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    if let Err(m) = rules::message(&armored()) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = InspectKeyRequest { armored: armored() };
    spawn(async move {
      match api::post::<_, Vec<KeyInfo>>("/api/v1/tools/inspect-key", &req).await {
        Ok(r) => result.set(Some(r)),
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  let save_contact = move |_| {
    if saving() {
      return;
    }
    saving.set(true);
    let req = ImportContact { armored: armored(), note: String::new() };
    spawn(async move {
      match api::post::<_, Vec<Contact>>("/api/v1/contacts", &req).await {
        Ok(list) if list.is_empty() => state::toast("Schlüssel ist schon in den Kontakten."),
        Ok(list) => state::toast(format!("{} Kontakt(e) gespeichert.", list.len())),
        Err(e) => state::toast_error(e.text()),
      }
      saving.set(false);
    });
  };
  let has_public = result().is_some_and(|l| l.iter().any(|k| !k.is_secret));
  rsx! {
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Schlüssel", description: "Öffentlich oder privat (privates Material wird nur untersucht, nie gespeichert). Mehrere Schlüssel hintereinander sind möglich.",
        MonoInput { rows: 10, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----", value: armored(), oninput: move |v| { armored.set(v); result.set(None); } }
      }
      div { class: "flex justify-end",
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::Search {} }
          "Untersuchen"
        }
      }
      if let Some(list) = result() {
        if list.is_empty() {
          InfoBox { p { "Kein Schlüssel gefunden." } }
        }
        for k in list.iter() {
          Section {
            key: "{k.fingerprint}",
            title: k.user_ids.first().cloned().unwrap_or_else(|| k.key_id.clone()),
            KeyInfoView { key_info: k.clone() }
          }
        }
        if has_public {
          div { class: "flex justify-end",
            Button { variant: ButtonVariant::Outline, class: "rounded-full", disabled: saving(), onclick: save_contact,
              icons::UserPlus {}
              "Als Kontakt speichern"
            }
          }
        }
      }
    }
  }
}

#[component]
fn VerifyMessage() -> Element {
  let mut message = use_signal(String::new);
  let mut result = use_signal(|| None::<MessageInfo>);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    if let Err(m) = rules::message(&message()) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    error.set(None);
    let req = InspectMessageRequest { message: message() };
    spawn(async move {
      match api::post::<_, MessageInfo>("/api/v1/tools/inspect-message", &req).await {
        Ok(r) => result.set(Some(r)),
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "PGP-Block", description: "Zeigt, an wen eine Nachricht verschlüsselt ist, wer sie signiert hat und wie sie aufgebaut ist – ohne sie zu entschlüsseln.",
        MonoInput { rows: 10, placeholder: "-----BEGIN PGP MESSAGE-----", value: message(), oninput: move |v| { message.set(v); result.set(None); } }
      }
      div { class: "flex justify-end",
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::FileSearch {} }
          "Analysieren"
        }
      }
      if let Some(i) = result() {
        Section { title: "Analyse", MessageInfoView { info: i } }
      }
    }
  }
}
