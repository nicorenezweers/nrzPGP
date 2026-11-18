//! Profile: neues Schluesselpaar erzeugen, vorhandenen Schluessel importieren, Details verwalten.

use crate::api;
use crate::components::common::{
  ArmorBox, ErrorBox, Field, InfoBox, Loading, Modal, MonoInput, PageHeader, SELECT_CLASS, Section, StrengthMeter,
};
use crate::components::pgp::KeyInfoView;
use crate::components::ui::button::{Button, ButtonVariant};
use crate::components::ui::input::{Input, InputType};
use crate::components::ui::textarea::Textarea;
use crate::route::Route;
use crate::state;
use crate::util;
use dioxus::prelude::*;
use nrzpgp_shared::{
  ChangePassphrase, ChangeRiddle, CreateProfile, DeleteProfile, ImportProfile, Ok as OkResp, ProfileDetail,
  UpdateProfile, algorithms, rules,
};

/// Passphrase mit Wiederholung und Staerkeanzeige.
#[component]
fn PassphraseFields(value: Signal<String>, repeat: Signal<String>, #[props(into, default = "Passphrase".to_string())] label: String) -> Element {
  let mut value = value;
  let mut repeat = repeat;
  let mismatch = !repeat().is_empty() && repeat() != value();
  rsx! {
    div { class: "grid gap-4 sm:grid-cols-2",
      Field { label: "{label}", html_for: "pp1", hint: "Mindestens 12 Zeichen. Am besten ein Satz aus mehreren Wörtern.",
        Input { id: "pp1", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "new-password", maxlength: 1024, value: value(), oninput: move |e: FormEvent| value.set(e.value()) }
        StrengthMeter { value: value() }
      }
      Field { label: "Wiederholen", html_for: "pp2",
        Input { id: "pp2", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "new-password", maxlength: 1024, value: repeat(), oninput: move |e: FormEvent| repeat.set(e.value()) }
        if mismatch {
          p { class: "text-xs text-destructive", "Stimmt nicht überein." }
        }
      }
    }
  }
}

/// Persoenliches Raetsel (Frage + Antwort).
#[component]
fn RiddleFields(question: Signal<String>, answer: Signal<String>) -> Element {
  let mut question = question;
  let mut answer = answer;
  rsx! {
    div { class: "grid gap-4 sm:grid-cols-2",
      Field { label: "Rätselfrage", html_for: "rq", hint: "Nur du kennst die Antwort, z. B. eine Frage zu einer Erinnerung.",
        Input { id: "rq", class: "h-10 rounded-xl", maxlength: rules::RIDDLE_QUESTION_MAX as i64, placeholder: "Wie hiess mein erstes Fahrrad?", value: question(), oninput: move |e: FormEvent| question.set(e.value()) }
      }
      Field { label: "Antwort", html_for: "ra", hint: "Gross-/Kleinschreibung und Umlaute sind egal. Wird nur als Argon2-Hash gespeichert.",
        Input { id: "ra", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "off", maxlength: rules::RIDDLE_ANSWER_MAX as i64, value: answer(), oninput: move |e: FormEvent| answer.set(e.value()) }
      }
    }
  }
}

#[component]
pub fn NewProfile() -> Element {
  use_effect(|| util::set_title("Neues Profil"));
  let mut label = use_signal(String::new);
  let mut purpose = use_signal(String::new);
  let mut name = use_signal(String::new);
  let mut email = use_signal(String::new);
  let mut comment = use_signal(String::new);
  let mut algorithm = use_signal(|| algorithms::ED25519.to_string());
  let passphrase = use_signal(String::new);
  let repeat = use_signal(String::new);
  let question = use_signal(String::new);
  let answer = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let nav = navigator();

  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    let check = rules::label(&label())
      .and_then(|_| rules::purpose(&purpose()))
      .and_then(|_| rules::uid_name(&name()))
      .and_then(|_| rules::email(&email()))
      .and_then(|_| rules::comment(&comment()))
      .and_then(|_| rules::passphrase(&passphrase()))
      .and_then(|_| if passphrase() == repeat() { Ok(()) } else { Err("Die Passphrasen stimmen nicht überein.") })
      .and_then(|_| rules::riddle(&question(), &answer()));
    if let Err(msg) = check {
      error.set(Some(msg.into()));
      return;
    }
    error.set(None);
    busy.set(true);
    let req = CreateProfile {
      label: label().trim().into(),
      purpose: purpose().trim().into(),
      name: name().trim().into(),
      email: email().trim().into(),
      comment: comment().trim().into(),
      algorithm: algorithm(),
      passphrase: passphrase(),
      riddle_question: question().trim().into(),
      riddle_answer: answer(),
    };
    let mut passphrase = passphrase;
    let mut repeat = repeat;
    let mut answer = answer;
    spawn(async move {
      match api::post::<_, ProfileDetail>("/api/v1/profiles", &req).await {
        Ok(p) => {
          passphrase.set(String::new());
          repeat.set(String::new());
          answer.set(String::new());
          state::toast("Schlüsselpaar erzeugt.");
          nav.replace(Route::ProfilePage { id: p.summary.id });
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  rsx! {
    PageHeader {
      title: "Neues Profil",
      subtitle: "Erzeugt ein neues PGP-Schlüsselpaar auf dem Server. Der private Schlüssel wird nie im Klartext gespeichert: Er ist mit deiner Passphrase geschützt und zusätzlich mit dem Hauptschlüssel des Servers verschlüsselt.",
      icon: rsx! { icons::Plus {} },
    }
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Profil", description: "Wie du dieses Schlüsselpaar in nrzPGP wiedererkennst.",
        div { class: "grid gap-4 sm:grid-cols-2",
          Field { label: "Profilname", html_for: "label",
            Input { id: "label", class: "h-10 rounded-xl", required: true, maxlength: rules::LABEL_MAX as i64, placeholder: "z. B. Arbeit", value: label(), oninput: move |e: FormEvent| label.set(e.value()) }
          }
          Field { label: "Schlüsselart", html_for: "algo",
            select { id: "algo", class: SELECT_CLASS, value: "{algorithm}", onchange: move |e| algorithm.set(e.value()),
              for (v, l) in algorithms::ALL {
                option { key: "{v}", value: v, selected: algorithm() == v, "{l}" }
              }
            }
          }
          Field { label: "Zweck", html_for: "purpose", class: "sm:col-span-2",
            Textarea { id: "purpose", rows: 2, maxlength: rules::PURPOSE_MAX as i64, placeholder: "Wofür ist dieser Schlüssel? (optional)", value: purpose(), oninput: move |e: FormEvent| purpose.set(e.value()) }
          }
        }
      }
      Section { title: "Identität (User-ID)", description: "Steht öffentlich im Schlüssel, z. B. „Max Muster <max@example.com>“.",
        div { class: "grid gap-4 sm:grid-cols-2",
          Field { label: "Name", html_for: "name",
            Input { id: "name", class: "h-10 rounded-xl", required: true, maxlength: rules::NAME_MAX as i64, autocomplete: "name", value: name(), oninput: move |e: FormEvent| name.set(e.value()) }
          }
          Field { label: "E-Mail", html_for: "email",
            Input { id: "email", r#type: InputType::Email, class: "h-10 rounded-xl", required: true, maxlength: rules::EMAIL_MAX as i64, autocomplete: "email", value: email(), oninput: move |e: FormEvent| email.set(e.value()) }
          }
          Field { label: "Kommentar (optional)", html_for: "comment", class: "sm:col-span-2",
            Input { id: "comment", class: "h-10 rounded-xl", maxlength: rules::COMMENT_MAX as i64, value: comment(), oninput: move |e: FormEvent| comment.set(e.value()) }
          }
        }
      }
      Section { title: "Passphrase", description: "Schützt den privaten Schlüssel. Du brauchst sie zum Entschlüsseln und Signieren. Sie wird nirgends gespeichert – vergisst du sie, ist der Schlüssel unbrauchbar.",
        PassphraseFields { value: passphrase, repeat }
      }
      Section { title: "Persönliches Rätsel", description: "Um den privaten Schlüssel später herauszubekommen, musst du mehrere Rätsel lösen – das letzte ist dieses hier. Danach folgen Cap-Prüfung und dein Konto-Passwort.",
        RiddleFields { question, answer }
      }
      div { class: "flex flex-wrap items-center justify-end gap-2",
        if busy() && algorithm() == algorithms::RSA4096 {
          span { class: "text-sm text-muted-foreground", "RSA-Schlüssel werden erzeugt, das kann einige Sekunden dauern …" }
        }
        Button { variant: ButtonVariant::Ghost, class: "rounded-full", href: Route::Home {}.to_string(), "Abbrechen" }
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::KeyRound {} }
          "Schlüsselpaar erzeugen"
        }
      }
    }
  }
}

#[component]
pub fn ImportProfilePage() -> Element {
  use_effect(|| util::set_title("Profil importieren"));
  let mut label = use_signal(String::new);
  let mut purpose = use_signal(String::new);
  let mut secret = use_signal(String::new);
  let mut passphrase = use_signal(String::new);
  let question = use_signal(String::new);
  let answer = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let nav = navigator();

  let submit = move |e: FormEvent| {
    e.prevent_default();
    if busy() {
      return;
    }
    let check = rules::label(&label())
      .and_then(|_| rules::purpose(&purpose()))
      .and_then(|_| rules::message(&secret()))
      .and_then(|_| if passphrase().is_empty() { Err("Bitte die Passphrase des Schlüssels angeben.") } else { Ok(()) })
      .and_then(|_| rules::riddle(&question(), &answer()));
    if let Err(msg) = check {
      error.set(Some(msg.into()));
      return;
    }
    error.set(None);
    busy.set(true);
    let req = ImportProfile {
      label: label().trim().into(),
      purpose: purpose().trim().into(),
      secret_key: secret(),
      passphrase: passphrase(),
      riddle_question: question().trim().into(),
      riddle_answer: answer(),
    };
    let mut answer = answer;
    spawn(async move {
      match api::post::<_, ProfileDetail>("/api/v1/profiles/import", &req).await {
        Ok(p) => {
          secret.set(String::new());
          passphrase.set(String::new());
          answer.set(String::new());
          state::toast("Schlüssel importiert.");
          nav.replace(Route::ProfilePage { id: p.summary.id });
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };

  rsx! {
    PageHeader {
      title: "Profil importieren",
      subtitle: "Übernimmt einen vorhandenen privaten Schlüssel (z. B. aus GnuPG: gpg --armor --export-secret-keys). Der Schlüssel muss mit einer Passphrase geschützt sein; der Server prüft sie und speichert den Schlüssel nur verschlüsselt.",
      icon: rsx! { icons::Upload {} },
    }
    form { class: "flex flex-col gap-6", onsubmit: submit,
      if let Some(e) = error() { ErrorBox { text: e } }
      Section { title: "Profil",
        div { class: "grid gap-4 sm:grid-cols-2",
          Field { label: "Profilname", html_for: "label",
            Input { id: "label", class: "h-10 rounded-xl", required: true, maxlength: rules::LABEL_MAX as i64, value: label(), oninput: move |e: FormEvent| label.set(e.value()) }
          }
          Field { label: "Zweck", html_for: "purpose",
            Input { id: "purpose", class: "h-10 rounded-xl", maxlength: rules::PURPOSE_MAX as i64, value: purpose(), oninput: move |e: FormEvent| purpose.set(e.value()) }
          }
        }
      }
      Section { title: "Privater Schlüssel",
        div { class: "flex flex-col gap-4",
          Field { label: "Schlüssel (ASCII-Armor)", html_for: "sk",
            MonoInput { id: "sk", rows: 10, placeholder: "-----BEGIN PGP PRIVATE KEY BLOCK-----", value: secret(), oninput: move |v| secret.set(v) }
          }
          Field { label: "Passphrase des Schlüssels", html_for: "pp",
            Input { id: "pp", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "off", maxlength: 1024, value: passphrase(), oninput: move |e: FormEvent| passphrase.set(e.value()) }
          }
        }
      }
      Section { title: "Persönliches Rätsel", description: "Wird später verlangt, bevor der private Schlüssel wieder herausgegeben wird.",
        RiddleFields { question, answer }
      }
      div { class: "flex justify-end gap-2",
        Button { variant: ButtonVariant::Ghost, class: "rounded-full", href: Route::Home {}.to_string(), "Abbrechen" }
        Button { button_type: "submit", class: "rounded-full", disabled: busy(),
          if busy() { icons::LoaderCircle { class: "animate-spin" } } else { icons::Upload {} }
          "Importieren"
        }
      }
    }
  }
}

#[derive(Clone, Copy, PartialEq)]
enum Dialog {
  Edit,
  Passphrase,
  Riddle,
  Delete,
}

#[component]
pub fn ProfilePage(id: i64) -> Element {
  let mut reload = use_signal(|| 0u32);
  let detail = use_resource(use_reactive!(|id| async move {
    let _ = reload();
    api::get::<ProfileDetail>(&format!("/api/v1/profiles/{id}")).await
  }));
  let mut dialog = use_signal(|| None::<Dialog>);

  let read = detail.read_unchecked();
  let p = match &*read {
    None => return rsx! { Loading {} },
    Some(Err(e)) => return rsx! { ErrorBox { text: e.text() } },
    Some(Ok(p)) => p.clone(),
  };
  drop(read);
  util::set_title(&p.summary.label);
  let s = p.summary.clone();
  let file = format!("{}-public.asc", util::slug(&s.label));
  let on_done = move |_| {
    dialog.set(None);
    reload += 1;
  };

  rsx! {
    PageHeader {
      title: "{s.label}",
      subtitle: "{s.user_id}",
      icon: rsx! { icons::KeyRound {} },
      actions: rsx! {
        Button { variant: ButtonVariant::Outline, class: "rounded-full", onclick: move |_| dialog.set(Some(Dialog::Edit)),
          icons::Pencil {}
          "Bearbeiten"
        }
        Button { class: "rounded-full", href: Route::VaultPage { id }.to_string(),
          icons::LockKeyhole {}
          "Privaten Schlüssel holen"
        }
      },
    }
    div { class: "flex flex-col gap-6",
      if !s.purpose.is_empty() {
        InfoBox { p { class: "whitespace-pre-line text-foreground", "{s.purpose}" } }
      }
      div { class: "grid gap-3 sm:grid-cols-3",
        Stat { label: "Erstellt", value: util::date(s.created_at) }
        Stat { label: "Zuletzt benutzt", value: s.last_used_at.map(util::time_ago).unwrap_or_else(|| "noch nie".into()) }
        Stat { label: "Privat herausgegeben", value: format!("{}×", p.exports) }
      }
      Section { title: "Öffentlicher Schlüssel", description: "Diesen Schlüssel kannst du weitergeben, damit andere dir verschlüsselt schreiben oder deine Signaturen prüfen können.",
        ArmorBox { text: p.public_key.clone(), file_name: file, rows: 8 }
        div { class: "mt-4 flex flex-wrap gap-2",
          Button { variant: ButtonVariant::Outline, class: "rounded-full", href: Route::Encrypt {}.to_string(), icons::Lock {} "Verschlüsseln" }
          Button { variant: ButtonVariant::Outline, class: "rounded-full", href: Route::Decrypt {}.to_string(), icons::LockOpen {} "Entschlüsseln" }
          Button { variant: ButtonVariant::Outline, class: "rounded-full", href: Route::Sign {}.to_string(), icons::PenLine {} "Signieren" }
        }
      }
      Section { title: "Schlüssel-Details",
        KeyInfoView { key_info: p.key.clone() }
      }
      Section { title: "Sicherheit",
        div { class: "flex flex-col divide-y divide-border",
          SecurityRow {
            title: "Passphrase ändern",
            text: "Der private Schlüssel wird mit der neuen Passphrase neu geschützt.",
            button: rsx! { Button { variant: ButtonVariant::Outline, class: "rounded-full", onclick: move |_| dialog.set(Some(Dialog::Passphrase)), icons::KeyRound {} "Ändern" } },
          }
          SecurityRow {
            title: "Persönliches Rätsel",
            text: "Aktuelle Frage: „{p.riddle_question}“",
            button: rsx! { Button { variant: ButtonVariant::Outline, class: "rounded-full", onclick: move |_| dialog.set(Some(Dialog::Riddle)), icons::Puzzle {} "Ändern" } },
          }
          SecurityRow {
            title: "Profil löschen",
            text: "Löscht das Schlüsselpaar endgültig. Hol dir vorher den privaten Schlüssel, wenn du ihn noch brauchst.",
            button: rsx! { Button { variant: ButtonVariant::Destructive, class: "rounded-full", onclick: move |_| dialog.set(Some(Dialog::Delete)), icons::Trash2 {} "Löschen" } },
          }
        }
      }
    }
    match dialog() {
        Some(Dialog::Edit) => rsx! { EditDialog { id, label: s.label.clone(), purpose: s.purpose.clone(), on_close: move |_| dialog.set(None), on_done } },
        Some(Dialog::Passphrase) => rsx! { PassphraseDialog { id, on_close: move |_| dialog.set(None), on_done } },
        Some(Dialog::Riddle) => rsx! { RiddleDialog { id, on_close: move |_| dialog.set(None), on_done } },
        Some(Dialog::Delete) => rsx! { DeleteDialog { id, label: s.label.clone(), on_close: move |_| dialog.set(None) } },
        None => rsx! {},
    }
  }
}

#[component]
fn Stat(label: String, value: String) -> Element {
  rsx! {
    div { class: "rounded-2xl border bg-card px-4 py-3",
      div { class: "text-xs text-muted-foreground", "{label}" }
      div { class: "mt-0.5 font-semibold", "{value}" }
    }
  }
}

#[component]
fn SecurityRow(title: String, text: String, button: Element) -> Element {
  rsx! {
    div { class: "flex flex-wrap items-center gap-3 py-3 first:pt-0 last:pb-0",
      div { class: "min-w-0 flex-1",
        div { class: "text-sm font-medium", "{title}" }
        div { class: "text-sm text-muted-foreground", "{text}" }
      }
      {button}
    }
  }
}

#[component]
fn EditDialog(id: i64, label: String, purpose: String, on_close: EventHandler<()>, on_done: EventHandler<()>) -> Element {
  let mut label = use_signal(|| label);
  let mut purpose = use_signal(|| purpose);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if let Err(m) = rules::label(&label()).and_then(|_| rules::purpose(&purpose())) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    let req = UpdateProfile { label: label().trim().into(), purpose: purpose().trim().into() };
    spawn(async move {
      match api::patch::<_, ProfileDetail>(&format!("/api/v1/profiles/{id}"), &req).await {
        Ok(_) => {
          state::toast("Gespeichert.");
          on_done.call(());
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    Modal { title: "Profil bearbeiten", on_close,
      form { class: "flex flex-col gap-4", onsubmit: submit,
        if let Some(e) = error() { ErrorBox { text: e } }
        Field { label: "Profilname", html_for: "el",
          Input { id: "el", class: "h-10 rounded-xl", maxlength: rules::LABEL_MAX as i64, value: label(), oninput: move |e: FormEvent| label.set(e.value()) }
        }
        Field { label: "Zweck", html_for: "ep",
          Textarea { id: "ep", rows: 3, maxlength: rules::PURPOSE_MAX as i64, value: purpose(), oninput: move |e: FormEvent| purpose.set(e.value()) }
        }
        p { class: "text-xs text-muted-foreground", "Name und E-Mail im Schlüssel (User-ID) bleiben unverändert." }
        div { class: "flex justify-end gap-2",
          Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: move |_| on_close.call(()), "Abbrechen" }
          Button { button_type: "submit", class: "rounded-full", disabled: busy(), "Speichern" }
        }
      }
    }
  }
}

#[component]
fn PassphraseDialog(id: i64, on_close: EventHandler<()>, on_done: EventHandler<()>) -> Element {
  let mut current = use_signal(String::new);
  let new = use_signal(String::new);
  let repeat = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let submit = move |e: FormEvent| {
    e.prevent_default();
    let check = rules::passphrase(&new())
      .and_then(|_| if new() == repeat() { Ok(()) } else { Err("Die neuen Passphrasen stimmen nicht überein.") });
    if let Err(m) = check {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    let req = ChangePassphrase { current: current(), new: new() };
    spawn(async move {
      match api::post::<_, OkResp>(&format!("/api/v1/profiles/{id}/passphrase"), &req).await {
        Ok(_) => {
          state::toast("Passphrase geändert.");
          on_done.call(());
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    Modal { title: "Passphrase ändern", on_close,
      form { class: "flex flex-col gap-4", onsubmit: submit,
        if let Some(e) = error() { ErrorBox { text: e } }
        Field { label: "Aktuelle Passphrase", html_for: "cp",
          Input { id: "cp", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "off", maxlength: 1024, value: current(), oninput: move |e: FormEvent| current.set(e.value()) }
        }
        PassphraseFields { value: new, repeat, label: "Neue Passphrase" }
        div { class: "flex justify-end gap-2",
          Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: move |_| on_close.call(()), "Abbrechen" }
          Button { button_type: "submit", class: "rounded-full", disabled: busy(),
            if busy() { icons::LoaderCircle { class: "animate-spin" } }
            "Ändern"
          }
        }
      }
    }
  }
}

#[component]
fn RiddleDialog(id: i64, on_close: EventHandler<()>, on_done: EventHandler<()>) -> Element {
  let mut password = use_signal(String::new);
  let question = use_signal(String::new);
  let answer = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if let Err(m) = rules::riddle(&question(), &answer()) {
      error.set(Some(m.into()));
      return;
    }
    busy.set(true);
    let req = ChangeRiddle { password: password(), question: question().trim().into(), answer: answer() };
    spawn(async move {
      match api::post::<_, OkResp>(&format!("/api/v1/profiles/{id}/riddle"), &req).await {
        Ok(_) => {
          state::toast("Rätsel geändert.");
          on_done.call(());
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    Modal { title: "Persönliches Rätsel ändern", on_close,
      form { class: "flex flex-col gap-4", onsubmit: submit,
        if let Some(e) = error() { ErrorBox { text: e } }
        RiddleFields { question, answer }
        Field { label: "Konto-Passwort zur Bestätigung", html_for: "rpw",
          Input { id: "rpw", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "current-password", maxlength: 1024, value: password(), oninput: move |e: FormEvent| password.set(e.value()) }
        }
        div { class: "flex justify-end gap-2",
          Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: move |_| on_close.call(()), "Abbrechen" }
          Button { button_type: "submit", class: "rounded-full", disabled: busy(), "Speichern" }
        }
      }
    }
  }
}

#[component]
fn DeleteDialog(id: i64, label: String, on_close: EventHandler<()>) -> Element {
  let mut password = use_signal(String::new);
  let mut error = use_signal(|| None::<String>);
  let mut busy = use_signal(|| false);
  let nav = navigator();
  let confirm_label = label.clone();
  let submit = move |e: FormEvent| {
    e.prevent_default();
    if !util::confirm(&format!("Profil „{confirm_label}“ mit Schlüsselpaar wirklich endgültig löschen?")) {
      return;
    }
    busy.set(true);
    let req = DeleteProfile { password: password() };
    spawn(async move {
      match api::post::<_, OkResp>(&format!("/api/v1/profiles/{id}/delete"), &req).await {
        Ok(_) => {
          state::toast("Profil gelöscht.");
          nav.replace(Route::Home {});
        }
        Err(e) => error.set(Some(e.text())),
      }
      busy.set(false);
    });
  };
  rsx! {
    Modal { title: "Profil löschen", on_close,
      form { class: "flex flex-col gap-4", onsubmit: submit,
        if let Some(e) = error() { ErrorBox { text: e } }
        InfoBox { warning: true,
          p { "Das Profil „{label}“ und sein privater Schlüssel werden endgültig gelöscht. Nachrichten an diesen Schlüssel kannst du danach nicht mehr entschlüsseln." }
        }
        Field { label: "Konto-Passwort", html_for: "dpw",
          Input { id: "dpw", r#type: InputType::Password, class: "h-10 rounded-xl", autocomplete: "current-password", maxlength: 1024, value: password(), oninput: move |e: FormEvent| password.set(e.value()) }
        }
        div { class: "flex justify-end gap-2",
          Button { variant: ButtonVariant::Ghost, class: "rounded-full", onclick: move |_| on_close.call(()), "Abbrechen" }
          Button { variant: ButtonVariant::Destructive, button_type: "submit", class: "rounded-full", disabled: busy(), icons::Trash2 {} "Endgültig löschen" }
        }
      }
    }
  }
}
