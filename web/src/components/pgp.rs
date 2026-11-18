//! PGP-spezifische Anzeigen: Schluessel-Details, Signatur-Ergebnisse, Profil-Auswahl.

use crate::components::common::{FingerprintText, SELECT_CLASS};
use crate::components::ui::badge::{Badge, BadgeSize, BadgeVariant};
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{KeyInfo, ProfileSummary, SignatureCheck};

pub fn flag_label(f: &str) -> &str {
  match f {
    "certify" => "Zertifizieren",
    "sign" => "Signieren",
    "encrypt" => "Verschlüsseln",
    "authenticate" => "Authentifizieren",
    other => other,
  }
}

fn algo_text(algorithm: &str, bits: Option<u32>) -> String {
  match bits {
    Some(b) => format!("{algorithm} ({b} Bit)"),
    None => algorithm.to_string(),
  }
}

#[component]
fn Row(label: String, children: Element) -> Element {
  rsx! {
    div { class: "grid gap-1 py-2.5 sm:grid-cols-[11rem_1fr] sm:gap-4",
      dt { class: "text-sm text-muted-foreground", "{label}" }
      dd { class: "min-w-0 text-sm", {children} }
    }
  }
}

#[component]
fn Flags(flags: Vec<String>) -> Element {
  rsx! {
    div { class: "flex flex-wrap gap-1",
      if flags.is_empty() {
        span { class: "text-muted-foreground", "–" }
      }
      for f in flags {
        Badge { key: "{f}", variant: BadgeVariant::Secondary, size: BadgeSize::Sm, "{flag_label(&f)}" }
      }
    }
  }
}

/// Vollstaendige Ansicht eines Schluessels (Pruefer, Profil, Kontakt).
#[component]
pub fn KeyInfoView(key_info: KeyInfo) -> Element {
  let k = key_info;
  let now = util::now();
  let expired = k.expires_at.is_some_and(|e| e < now);
  rsx! {
    div { class: "flex flex-col gap-4",
      div { class: "flex flex-wrap gap-1.5",
        Badge { variant: BadgeVariant::Outline, "OpenPGP v{k.version}" }
        if k.is_secret {
          Badge { variant: BadgeVariant::Warning, "Privater Schlüssel" }
          if k.secret_protected == Some(true) {
            Badge { variant: BadgeVariant::Success, "mit Passphrase geschützt" }
          } else if k.secret_protected == Some(false) {
            Badge { variant: BadgeVariant::Destructive, "ungeschützt!" }
          }
        } else {
          Badge { variant: BadgeVariant::Secondary, "Öffentlicher Schlüssel" }
        }
        if k.revoked {
          Badge { variant: BadgeVariant::Destructive, "Widerrufen" }
        }
        if expired {
          Badge { variant: BadgeVariant::Destructive, "Abgelaufen" }
        }
        if k.bindings_valid {
          Badge { variant: BadgeVariant::Success, "Selbstsignaturen gültig" }
        } else {
          Badge { variant: BadgeVariant::Destructive, "Selbstsignaturen ungültig" }
        }
        if k.can_encrypt {
          Badge { variant: BadgeVariant::Info, "kann verschlüsseln" }
        }
        if k.can_sign {
          Badge { variant: BadgeVariant::Info, "kann signieren" }
        }
      }
      if !k.warnings.is_empty() {
        ul { class: "flex flex-col gap-1.5 rounded-xl border border-warning/30 bg-warning/10 p-3 text-sm text-warning-dark",
          for (i, w) in k.warnings.iter().enumerate() {
            li { key: "{i}", class: "flex items-start gap-2",
              icons::TriangleAlert { class: "mt-0.5 size-4 shrink-0" }
              span { "{w}" }
            }
          }
        }
      }
      dl { class: "divide-y divide-border",
        Row { label: "Fingerabdruck", FingerprintText { fp: k.fingerprint.clone(), class: "text-sm" } }
        Row { label: "Key-ID", code { class: "font-mono text-xs", "{k.key_id}" } }
        Row { label: "Algorithmus", "{algo_text(&k.algorithm, k.bits)}" }
        Row { label: "Erstellt", "{util::full_date(k.created_at)}" }
        Row { label: "Läuft ab",
          match k.expires_at {
              Some(e) => rsx! { span { class: if expired { "text-destructive" } else { "" }, "{util::full_date(e)}" } },
              None => rsx! { span { class: "text-muted-foreground", "nie" } },
          }
        }
        Row { label: "User-IDs",
          div { class: "flex flex-col gap-0.5",
            if k.user_ids.is_empty() {
              span { class: "text-muted-foreground", "–" }
            }
            for (i, u) in k.user_ids.iter().enumerate() {
              span { key: "{i}", class: "break-all", "{u}" }
            }
          }
        }
        Row { label: "Fähigkeiten", Flags { flags: k.flags.clone() } }
      }
      if !k.subkeys.is_empty() {
        div {
          h3 { class: "mb-2 text-sm font-semibold", "Teilschlüssel ({k.subkeys.len()})" }
          div { class: "flex flex-col gap-2",
            for s in k.subkeys.iter() {
              div { key: "{s.fingerprint}", class: "rounded-xl border bg-background/40 p-3 text-sm",
                div { class: "flex flex-wrap items-center gap-2",
                  code { class: "font-mono text-xs", "{s.key_id}" }
                  span { class: "text-muted-foreground", "{algo_text(&s.algorithm, s.bits)}" }
                  Flags { flags: s.flags.clone() }
                  if s.revoked {
                    Badge { variant: BadgeVariant::Destructive, size: BadgeSize::Sm, "widerrufen" }
                  }
                  if s.expires_at.is_some_and(|e| e < now) {
                    Badge { variant: BadgeVariant::Destructive, size: BadgeSize::Sm, "abgelaufen" }
                  }
                }
                div { class: "mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted-foreground",
                  span { "Erstellt {util::date(s.created_at)}" }
                  if let Some(e) = s.expires_at {
                    span { "Läuft ab {util::date(e)}" }
                  }
                }
                div { class: "mt-1", FingerprintText { fp: s.fingerprint.clone(), class: "text-muted-foreground" } }
              }
            }
          }
        }
      }
    }
  }
}

/// Ergebnisse einer Signaturpruefung.
#[component]
pub fn SignatureList(signatures: Vec<SignatureCheck>) -> Element {
  if signatures.is_empty() {
    return rsx! {
      div { class: "flex items-center gap-2 rounded-xl border bg-accent/30 p-3 text-sm text-muted-foreground",
        icons::Info { class: "size-4 shrink-0" }
        "Keine Signatur enthalten."
      }
    };
  }
  rsx! {
    div { class: "flex flex-col gap-2",
      for (i, s) in signatures.into_iter().enumerate() {
        SignatureItem { key: "{i}", sig: s }
      }
    }
  }
}

#[component]
fn SignatureItem(sig: SignatureCheck) -> Element {
  let unknown = sig.source == "unknown";
  let (box_cls, title) = if sig.valid {
    ("border-success/40 bg-success/10", "Gültige Signatur")
  } else if unknown {
    ("border-border bg-accent/30", "Unbekannter Absender")
  } else {
    ("border-destructive/40 bg-destructive/10", "Ungültige Signatur")
  };
  let source = match sig.source.as_str() {
    "profile" => "eigenes Profil",
    "contact" => "Kontakt",
    "extra" => "angegebener Schlüssel",
    _ => "nicht im Schlüsselbund",
  };
  rsx! {
    div { class: "flex items-start gap-3 rounded-xl border p-3 text-sm {box_cls}",
      if sig.valid {
        icons::CircleCheck { class: "mt-0.5 size-5 shrink-0 text-success" }
      } else if unknown {
        icons::CircleHelp { class: "mt-0.5 size-5 shrink-0 text-muted-foreground" }
      } else {
        icons::CircleX { class: "mt-0.5 size-5 shrink-0 text-destructive" }
      }
      div { class: "min-w-0 flex-1",
        div { class: "flex flex-wrap items-center gap-2",
          span { class: "font-semibold", "{title}" }
          Badge { variant: BadgeVariant::Outline, size: BadgeSize::Sm, "{source}" }
        }
        if let Some(name) = &sig.signer {
          p { class: "mt-0.5 break-all", "{name}" }
        }
        div { class: "mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted-foreground",
          span { "Key-ID " code { class: "font-mono", "{sig.key_id}" } }
          if let Some(t) = sig.created_at {
            span { "signiert {util::full_date(t)}" }
          }
        }
        if let Some(fp) = &sig.fingerprint {
          div { class: "mt-1", FingerprintText { fp: fp.clone(), class: "text-muted-foreground" } }
        }
        if !sig.message.is_empty() {
          p { class: "mt-1 text-xs text-muted-foreground", "{sig.message}" }
        }
      }
    }
  }
}

/// Auswahl eines eigenen Profils (`None` = nichts gewaehlt).
#[component]
pub fn ProfileSelect(
  profiles: Vec<ProfileSummary>,
  value: Option<i64>,
  on_change: EventHandler<Option<i64>>,
  #[props(into, optional)] id: Option<String>,
  #[props(into, default = "Profil wählen …".to_string())] placeholder: String,
) -> Element {
  let current = value.map(|v| v.to_string()).unwrap_or_default();
  rsx! {
    select {
      id: id.clone().unwrap_or_default(),
      class: SELECT_CLASS,
      value: "{current}",
      onchange: move |e| on_change.call(e.value().parse::<i64>().ok()),
      option { value: "", selected: value.is_none(), "{placeholder}" }
      for p in profiles {
        option { key: "{p.id}", value: "{p.id}", selected: value == Some(p.id), "{p.label} – {p.user_id}" }
      }
    }
  }
}
