//! Gemeinsame Bausteine: Logo, Seitenkopf, Abschnitte, Formularfelder, ASCII-Armor-Box,
//! Ladezustaende, Meldungen, Dialog.

use crate::components::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::state::{self, TOASTS};
use crate::util;
use dioxus::prelude::*;

/// Klassen fuer native `<select>`-Felder im Stil von nrzUI.
pub const SELECT_CLASS: &str = "h-10 w-full rounded-xl border border-input bg-transparent px-3 text-sm text-foreground shadow-xs outline-none dark:bg-input/30 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/50 [&>option]:bg-popover";

#[component]
pub fn Logo(#[props(into, optional)] class: Option<String>) -> Element {
  rsx! {
    span { class: "grid shrink-0 place-items-center rounded-xl bg-primary text-primary-foreground {class.clone().unwrap_or_else(|| \"size-8\".into())}",
      icons::KeyRound { class: "size-[55%]" }
    }
  }
}

/// Seitenkopf mit Titel, Untertitel und optionalen Aktionen rechts.
#[component]
pub fn PageHeader(
  title: String,
  #[props(into, optional)] subtitle: Option<String>,
  #[props(optional)] icon: Option<Element>,
  #[props(optional)] actions: Option<Element>,
) -> Element {
  rsx! {
    div { class: "mb-6 flex flex-wrap items-start gap-4",
      if let Some(i) = icon {
        span { class: "grid size-11 shrink-0 place-items-center rounded-2xl bg-accent text-foreground [&_svg]:size-5", {i} }
      }
      // Auf dem Handy volle Breite fuer den Titel, die Aktionen rutschen darunter.
      div { class: "min-w-0 flex-1 basis-[calc(100%-4rem)] sm:basis-0",
        h1 { class: "text-2xl font-bold tracking-tight break-words", "{title}" }
        if let Some(s) = subtitle {
          p { class: "mt-1 max-w-3xl text-sm text-muted-foreground", "{s}" }
        }
      }
      if let Some(a) = actions {
        div { class: "flex w-full flex-wrap items-center gap-2 sm:w-auto", {a} }
      }
    }
  }
}

/// Karte mit Ueberschrift.
#[component]
pub fn Section(
  #[props(into, optional)] title: Option<String>,
  #[props(into, optional)] description: Option<String>,
  #[props(into, optional)] class: Option<String>,
  #[props(optional)] actions: Option<Element>,
  children: Element,
) -> Element {
  rsx! {
    section { class: "rounded-2xl border bg-card p-5 sm:p-6 {class.clone().unwrap_or_default()}",
      if title.is_some() || actions.is_some() {
        div { class: "mb-4 flex flex-wrap items-start justify-between gap-3",
          div { class: "min-w-0",
            if let Some(t) = title {
              h2 { class: "text-base font-semibold", "{t}" }
            }
            if let Some(d) = description {
              p { class: "mt-1 text-sm text-muted-foreground", "{d}" }
            }
          }
          if let Some(a) = actions {
            div { class: "flex flex-wrap items-center gap-2", {a} }
          }
        }
      }
      {children}
    }
  }
}

/// Formularfeld: Beschriftung, Inhalt, optionaler Hinweis.
#[component]
pub fn Field(
  label: String,
  #[props(into, optional)] html_for: Option<String>,
  #[props(into, optional)] hint: Option<String>,
  #[props(into, optional)] class: Option<String>,
  children: Element,
) -> Element {
  rsx! {
    div { class: "flex flex-col gap-1.5 {class.clone().unwrap_or_default()}",
      label { class: "text-sm font-medium", r#for: html_for.clone().unwrap_or_default(), "{label}" }
      {children}
      if let Some(h) = hint {
        p { class: "text-xs text-muted-foreground", "{h}" }
      }
    }
  }
}

/// Schreibgeschuetzte Box fuer ASCII-Armor (Schluessel, Nachrichten) mit Kopieren/Herunterladen.
#[component]
pub fn ArmorBox(
  text: String,
  #[props(into, optional)] file_name: Option<String>,
  #[props(into, optional)] label: Option<String>,
  #[props(default = 10)] rows: i64,
  #[props(default)] sensitive: bool,
) -> Element {
  let copy_text = text.clone();
  let dl_text = text.clone();
  let border = if sensitive { "border-destructive/40" } else { "" };
  rsx! {
    div { class: "flex flex-col gap-2",
      if let Some(l) = &label {
        span { class: "text-sm font-medium", "{l}" }
      }
      textarea {
        class: "w-full resize-y rounded-xl border bg-background px-3 py-2 font-mono text-xs leading-relaxed text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring/50 {border}",
        readonly: true,
        spellcheck: false,
        rows,
        "aria-label": "{label.clone().unwrap_or_else(|| \"Ausgabe\".into())}",
        value: "{text}",
      }
      div { class: "flex flex-wrap gap-2",
        Button {
          variant: ButtonVariant::Outline,
          size: ButtonSize::Sm,
          class: "rounded-full",
          onclick: move |_| {
              util::copy_to_clipboard(&copy_text);
              state::toast("In die Zwischenablage kopiert.");
          },
          icons::Copy {}
          "Kopieren"
        }
        if let Some(f) = file_name {
          Button {
            variant: ButtonVariant::Outline,
            size: ButtonSize::Sm,
            class: "rounded-full",
            onclick: move |_| util::download(&f, &dl_text, "application/pgp-keys"),
            icons::Download {}
            "Herunterladen"
          }
        }
      }
    }
  }
}

/// Grosses Monospace-Eingabefeld (Nachrichten, Schluessel).
#[component]
pub fn MonoInput(
  value: String,
  oninput: EventHandler<String>,
  #[props(into, optional)] id: Option<String>,
  #[props(into, optional)] placeholder: Option<String>,
  #[props(default = 8)] rows: i64,
) -> Element {
  rsx! {
    textarea {
      id: id.clone().unwrap_or_default(),
      class: "w-full resize-y rounded-xl border border-input bg-transparent px-3 py-2 font-mono text-xs leading-relaxed text-foreground shadow-xs outline-none placeholder:text-muted-foreground dark:bg-input/30 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/50",
      rows,
      spellcheck: false,
      autocomplete: "off",
      placeholder: placeholder.clone().unwrap_or_default(),
      value: "{value}",
      oninput: move |e| oninput.call(e.value()),
    }
  }
}

/// Fingerabdruck in Vierergruppen, Monospace.
#[component]
pub fn FingerprintText(fp: String, #[props(into, optional)] class: Option<String>) -> Element {
  let grouped = nrzpgp_shared::rules::group_fingerprint(&fp);
  rsx! {
    code { class: "break-all font-mono text-xs tracking-wide {class.clone().unwrap_or_default()}", "{grouped}" }
  }
}

#[component]
pub fn Loading() -> Element {
  rsx! {
    div { class: "flex justify-center py-10 text-muted-foreground",
      icons::LoaderCircle { class: "size-6 animate-spin" }
    }
  }
}

#[component]
pub fn ErrorBox(text: String) -> Element {
  rsx! {
    div { class: "flex items-start gap-3 rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive", role: "alert",
      icons::CircleAlert { class: "mt-0.5 size-4 shrink-0" }
      span { "{text}" }
    }
  }
}

#[component]
pub fn InfoBox(#[props(default)] warning: bool, children: Element) -> Element {
  let cls = if warning {
    "flex items-start gap-3 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm text-warning-dark"
  } else {
    "flex items-start gap-3 rounded-2xl border bg-accent/40 p-4 text-sm text-muted-foreground"
  };
  rsx! {
    div { class: cls,
      if warning {
        icons::TriangleAlert { class: "mt-0.5 size-4 shrink-0" }
      } else {
        icons::Info { class: "mt-0.5 size-4 shrink-0" }
      }
      div { class: "min-w-0 flex-1 space-y-1", {children} }
    }
  }
}

#[component]
pub fn EmptyState(title: String, #[props(optional)] text: Option<String>, #[props(default = VNode::empty())] children: Element) -> Element {
  rsx! {
    div { class: "flex flex-col items-center gap-2 rounded-2xl border border-dashed px-6 py-12 text-center",
      span { class: "mb-1 grid size-12 place-items-center rounded-2xl bg-accent text-muted-foreground",
        icons::KeyRound { class: "size-6" }
      }
      h3 { class: "font-semibold", "{title}" }
      if let Some(t) = text {
        p { class: "max-w-sm text-sm text-muted-foreground", "{t}" }
      }
      {children}
    }
  }
}

/// Modaler Dialog (unten als Sheet auf Mobilgeraeten).
#[component]
pub fn Modal(title: String, on_close: EventHandler<()>, children: Element) -> Element {
  rsx! {
    div {
      class: "fixed inset-0 z-[60] flex items-end justify-center bg-black/60 backdrop-blur-sm sm:items-center sm:p-4",
      onclick: move |_| on_close.call(()),
      div {
        class: "fade-in max-h-[90dvh] w-full max-w-lg overflow-y-auto rounded-t-2xl border bg-popover p-5 shadow-2xl sm:rounded-2xl",
        role: "dialog",
        "aria-modal": "true",
        onclick: move |e: MouseEvent| e.stop_propagation(),
        onkeydown: move |e: KeyboardEvent| {
            if e.key() == Key::Escape {
                on_close.call(());
            }
        },
        div { class: "mb-4 flex items-center justify-between gap-3",
          h2 { class: "text-lg font-semibold", "{title}" }
          Button {
            variant: ButtonVariant::Ghost,
            size: ButtonSize::IconSm,
            class: "rounded-full",
            aria_label: "Schliessen",
            onclick: move |_| on_close.call(()),
            icons::X {}
          }
        }
        {children}
      }
    }
  }
}

/// Kurzmeldungen (unten rechts, Mobil unten mittig).
#[component]
pub fn Toasts() -> Element {
  let toasts = TOASTS.read().clone();
  rsx! {
    div { class: "pointer-events-none fixed inset-x-0 bottom-6 z-[80] flex flex-col items-center gap-2 px-4 sm:items-end sm:px-6",
      "aria-live": "polite",
      for t in toasts {
        div {
          key: "{t.id}",
          class: if t.error { "fade-in pointer-events-auto flex max-w-sm items-center gap-2.5 rounded-xl border border-destructive/40 bg-popover px-4 py-3 text-sm shadow-xl" } else { "fade-in pointer-events-auto flex max-w-sm items-center gap-2.5 rounded-xl border bg-popover px-4 py-3 text-sm shadow-xl" },
          if t.error {
            icons::CircleAlert { class: "size-4 shrink-0 text-destructive" }
          } else {
            icons::CircleCheck { class: "size-4 shrink-0 text-success" }
          }
          span { "{t.text}" }
        }
      }
    }
  }
}

/// Anzeige der Passphrasen-Staerke (Balken + Text).
#[component]
pub fn StrengthMeter(value: String) -> Element {
  let (score, text) = util::strength(&value);
  if value.is_empty() {
    return rsx! {};
  }
  let color = match score {
    0 | 1 => "bg-destructive",
    2 => "bg-warning",
    _ => "bg-success",
  };
  rsx! {
    div { class: "flex items-center gap-2",
      div { class: "flex flex-1 gap-1",
        for i in 0..4u8 {
          div { key: "{i}", class: if i < score { "h-1.5 flex-1 rounded-full {color}" } else { "h-1.5 flex-1 rounded-full bg-accent" } }
        }
      }
      span { class: "w-16 text-right text-xs text-muted-foreground", "{text}" }
    }
  }
}
