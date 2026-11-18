//! Eingaberegeln, gleich fuer Server (verbindlich) und Oberflaeche (Vorpruefung).

pub const LABEL_MAX: usize = 60;
pub const PURPOSE_MAX: usize = 300;
pub const NAME_MAX: usize = 100;
pub const EMAIL_MAX: usize = 254;
pub const COMMENT_MAX: usize = 100;
pub const PASSWORD_MIN: usize = 10;
pub const PASSWORD_MAX: usize = 1024;
/// Mindestlaenge der Schluessel-Passphrase.
pub const PASSPHRASE_MIN: usize = 12;
pub const PASSPHRASE_MAX: usize = 1024;
pub const RIDDLE_QUESTION_MAX: usize = 300;
pub const RIDDLE_ANSWER_MIN: usize = 3;
pub const RIDDLE_ANSWER_MAX: usize = 200;
pub const NOTE_MAX: usize = 1000;
/// Groesste Nachricht/Schluessel als Text (Body-Limit des Servers ist etwas groesser).
pub const MESSAGE_MAX: usize = 1_500_000;
pub const ANSWER_MAX: usize = 200;

fn has_control(s: &str) -> bool {
  s.chars().any(|c| c.is_control())
}

fn chars(s: &str) -> usize {
  s.chars().count()
}

pub fn label(s: &str) -> Result<(), &'static str> {
  let n = chars(s.trim());
  if n == 0 {
    return Err("Bitte einen Namen für das Profil angeben.");
  }
  if n > LABEL_MAX || has_control(s) {
    return Err("Der Profilname ist zu lang oder enthält ungültige Zeichen.");
  }
  Ok(())
}

pub fn purpose(s: &str) -> Result<(), &'static str> {
  if chars(s) > PURPOSE_MAX || s.chars().any(|c| c.is_control() && c != '\n') {
    return Err("Der Zweck ist zu lang.");
  }
  Ok(())
}

/// Name fuer die User-ID: keine spitzen Klammern (sonst kaputte User-ID).
pub fn uid_name(s: &str) -> Result<(), &'static str> {
  let n = chars(s.trim());
  if n == 0 {
    return Err("Bitte einen Namen angeben.");
  }
  if n > NAME_MAX || has_control(s) || s.contains(['<', '>', '(', ')']) {
    return Err("Der Name ist zu lang oder enthält < > ( ).");
  }
  Ok(())
}

pub fn comment(s: &str) -> Result<(), &'static str> {
  if chars(s) > COMMENT_MAX || has_control(s) || s.contains(['<', '>', '(', ')']) {
    return Err("Der Kommentar ist zu lang oder enthält < > ( ).");
  }
  Ok(())
}

/// Einfache, strenge Pruefung einer E-Mail-Adresse (ein @, Domain mit Punkt, keine Leerzeichen).
pub fn email(s: &str) -> Result<(), &'static str> {
  let s = s.trim();
  let bad = || Err("Bitte eine gültige E-Mail-Adresse angeben.");
  if s.is_empty() || s.len() > EMAIL_MAX || has_control(s) || s.contains([' ', '<', '>', '(', ')', ',', ';']) {
    return bad();
  }
  let Some((local, domain)) = s.split_once('@') else { return bad() };
  if local.is_empty() || domain.contains('@') || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
    return bad();
  }
  Ok(())
}

pub fn password(s: &str) -> Result<(), &'static str> {
  let n = chars(s);
  if n < PASSWORD_MIN {
    return Err("Das Passwort braucht mindestens 10 Zeichen.");
  }
  if n > PASSWORD_MAX {
    return Err("Das Passwort ist zu lang.");
  }
  Ok(())
}

pub fn passphrase(s: &str) -> Result<(), &'static str> {
  let n = chars(s);
  if n < PASSPHRASE_MIN {
    return Err("Die Passphrase braucht mindestens 12 Zeichen.");
  }
  if n > PASSPHRASE_MAX {
    return Err("Die Passphrase ist zu lang.");
  }
  if s.trim() != s {
    return Err("Die Passphrase darf nicht mit Leerzeichen beginnen oder enden.");
  }
  Ok(())
}

pub fn riddle(question: &str, answer: &str) -> Result<(), &'static str> {
  let q = chars(question.trim());
  if !(5..=RIDDLE_QUESTION_MAX).contains(&q) || has_control(question) {
    return Err("Bitte eine Rätselfrage mit 5 bis 300 Zeichen angeben.");
  }
  let a = chars(&normalize_answer(answer));
  if !(RIDDLE_ANSWER_MIN..=RIDDLE_ANSWER_MAX).contains(&a) {
    return Err("Die Antwort auf das Rätsel braucht 3 bis 200 Zeichen.");
  }
  Ok(())
}

pub fn note(s: &str) -> Result<(), &'static str> {
  if chars(s) > NOTE_MAX {
    return Err("Die Notiz ist zu lang.");
  }
  Ok(())
}

pub fn message(s: &str) -> Result<(), &'static str> {
  if s.trim().is_empty() {
    return Err("Bitte Text eingeben.");
  }
  if s.len() > MESSAGE_MAX {
    return Err("Der Text ist zu lang (max. 1,5 MB).");
  }
  Ok(())
}

/// Antworten vergleichbar machen: Kleinbuchstaben, Umlaute ausgeschrieben, Leerraum zusammengefasst.
pub fn normalize_answer(s: &str) -> String {
  let lower = s.trim().to_lowercase();
  let mut out = String::with_capacity(lower.len());
  for c in lower.chars() {
    match c {
      'ä' => out.push_str("ae"),
      'ö' => out.push_str("oe"),
      'ü' => out.push_str("ue"),
      'ß' => out.push_str("ss"),
      c if c.is_whitespace() => {
        if !out.ends_with(' ') {
          out.push(' ');
        }
      }
      c => out.push(c),
    }
  }
  out.trim().to_string()
}

/// Fingerabdruck in Vierergruppen ("ABCD 1234 …").
pub fn group_fingerprint(fp: &str) -> String {
  let clean: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
  let groups: Vec<String> = clean.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
  let half = groups.len() / 2;
  if groups.len() == 10 {
    format!("{}  {}", groups[..half].join(" "), groups[half..].join(" "))
  } else {
    groups.join(" ")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn emails() {
    assert!(email("max@example.com").is_ok());
    assert!(email("max@localhost").is_err());
    assert!(email("a b@example.com").is_err());
    assert!(email("<x>@e.com").is_err());
  }

  #[test]
  fn answers() {
    assert_eq!(normalize_answer("  Grüne   Äpfel "), "gruene aepfel");
    assert!(riddle("Wie hiess mein erstes Haustier?", "Bello").is_ok());
    assert!(riddle("kurz", "Bello").is_err());
  }

  #[test]
  fn fingerprint_groups() {
    assert_eq!(
      group_fingerprint("0123456789abcdef0123456789ABCDEF01234567"),
      "0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567"
    );
  }
}
