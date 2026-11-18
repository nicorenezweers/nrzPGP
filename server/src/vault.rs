//! Tresor: der private Schluessel eines Profils wird erst herausgegeben, wenn nacheinander mehrere
//! Raetsel geloest sind, danach Cap-Captcha und Konto-Passwort stimmen.
//!
//! - Raetsel und Loesungen entstehen nur hier auf dem Server (Zufall aus dem Betriebssystem); die
//!   Oberflaeche bekommt nur die Aufgabe, nie die Loesung.
//! - Ablauf: drei zufaellige Raetsel (Rechnen, Zahlenfolge, Wortsalat, Caesar-Chiffre) in zufaelliger
//!   Reihenfolge, zuletzt das persoenliche Raetsel des Profils (Antwort nur als Argon2-Hash gespeichert).
//! - Jeder Vorgang gehoert zu genau einer Sitzung, laeuft nach 10 Minuten ab und erlaubt insgesamt
//!   3 Fehlversuche. Danach ist der Tresor fuer das Profil 30 Minuten gesperrt.

use nrzpgp_shared::{Puzzle, rules::normalize_answer};
use rand::{Rng, rngs::OsRng, seq::SliceRandom};
use std::{
  collections::HashMap,
  sync::Mutex,
  time::{Duration, Instant},
};

pub const VAULT_TTL: Duration = Duration::from_secs(600);
pub const MAX_ATTEMPTS: u32 = 3;
/// Nach dem Loesen aller Raetsel bleibt so viel Zeit fuer Captcha und Passwort.
pub const RANDOM_PUZZLES: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
  Math,
  Sequence,
  Anagram,
  Caesar,
  Personal,
}

impl Kind {
  fn code(self) -> &'static str {
    match self {
      Kind::Math => "math",
      Kind::Sequence => "sequence",
      Kind::Anagram => "anagram",
      Kind::Caesar => "caesar",
      Kind::Personal => "personal",
    }
  }
}

/// Aufgabe + erwartete Antwort (normalisiert). Beim persoenlichen Raetsel prueft der Aufrufer gegen
/// den Argon2-Hash, `answer` ist dann leer.
#[derive(Clone, Debug)]
pub struct Generated {
  pub puzzle: Puzzle,
  pub answer: String,
}

const WORDS: [&str; 48] = [
  "SCHLUESSEL", "SIGNATUR", "TRESOR", "PASSWORT", "GEHEIMNIS", "FESTUNG", "LEUCHTTURM", "KOMPASS",
  "SCHMETTERLING", "BERGSTEIGER", "ZAUBERER", "GEWITTER", "BIBLIOTHEK", "FAHRRAD", "KASTANIE", "REGENBOGEN",
  "SCHNEEFLOCKE", "WALDWEG", "SONNENBLUME", "EICHHOERNCHEN", "PINGUIN", "KRISTALL", "VULKAN", "GALAXIE",
  "LABYRINTH", "TELESKOP", "ANKER", "BRUECKE", "DRACHE", "FEUERWERK", "GLETSCHER", "HORIZONT",
  "INSELN", "JONGLEUR", "KAPITAEN", "LAWINE", "MOSAIK", "NORDLICHT", "ORCHESTER", "PYRAMIDE",
  "QUELLE", "RAKETE", "SEGELBOOT", "TROMPETE", "UHRWERK", "VERSTECK", "WINDMUEHLE", "ZITRONE",
];

fn rng() -> OsRng {
  OsRng
}

pub fn generate(kind: Kind) -> Generated {
  let mut r = rng();
  match kind {
    Kind::Math => {
      let a = r.gen_range(12..=39);
      let b = r.gen_range(3..=9);
      let c = r.gen_range(10..=99);
      let d = r.gen_range(2..=40);
      let result = a * b + c - d;
      Generated {
        puzzle: Puzzle {
          kind: kind.code().into(),
          title: "Rechenrätsel".into(),
          prompt: format!("Wie viel ist {a} × {b} + {c} − {d}?"),
          hint: "Punkt vor Strich. Nur die Zahl eingeben.".into(),
        },
        answer: result.to_string(),
      }
    }
    Kind::Sequence => {
      let (terms, next, hint): (Vec<i64>, i64, &str) = match r.gen_range(0..4) {
        0 => {
          let start = r.gen_range(2..=30);
          let step = r.gen_range(3..=17);
          let t: Vec<i64> = (0..5).map(|i| start + i * step).collect();
          (t, start + 5 * step, "Immer gleich viel dazu.")
        }
        1 => {
          let start = r.gen_range(2..=6);
          let f: i64 = r.gen_range(2..=3);
          let t: Vec<i64> = (0..5).map(|i| start * f.pow(i as u32)).collect();
          (t, start * f.pow(5), "Immer mit derselben Zahl malnehmen.")
        }
        2 => {
          let off = r.gen_range(1..=9);
          let s = r.gen_range(1..=4);
          let t: Vec<i64> = (s..s + 5).map(|n| n * n + off).collect();
          (t, (s + 5) * (s + 5) + off, "Quadratzahlen spielen eine Rolle.")
        }
        _ => {
          let mut a = r.gen_range(1..=5);
          let mut b = r.gen_range(2..=8);
          let mut t = vec![a, b];
          for _ in 0..3 {
            let c = a + b;
            t.push(c);
            a = b;
            b = c;
          }
          (t, a + b, "Jede Zahl ergibt sich aus den beiden davor.")
        }
      };
      let shown: Vec<String> = terms.iter().map(i64::to_string).collect();
      Generated {
        puzzle: Puzzle {
          kind: kind.code().into(),
          title: "Zahlenfolge".into(),
          prompt: format!("Welche Zahl kommt als Nächstes?  {}, …", shown.join(", ")),
          hint: hint.into(),
        },
        answer: next.to_string(),
      }
    }
    Kind::Anagram => {
      let word = *WORDS.choose(&mut r).unwrap_or(&"SCHLUESSEL");
      let mut letters: Vec<char> = word.chars().collect();
      // So lange mischen, bis es nicht mehr das Wort ist.
      for _ in 0..10 {
        letters.shuffle(&mut r);
        if letters.iter().collect::<String>() != word {
          break;
        }
      }
      let shown: Vec<String> = letters.iter().map(char::to_string).collect();
      Generated {
        puzzle: Puzzle {
          kind: kind.code().into(),
          title: "Wortsalat".into(),
          prompt: format!("Bilde aus diesen Buchstaben ein deutsches Wort:  {}", shown.join(" ")),
          hint: format!("{} Buchstaben, Umlaute sind ausgeschrieben (AE, OE, UE).", word.chars().count()),
        },
        answer: normalize_answer(word),
      }
    }
    Kind::Caesar => {
      let word = *WORDS.choose(&mut r).unwrap_or(&"TRESOR");
      let shift: u8 = r.gen_range(3..=11);
      let enc: String = word.chars().map(|c| (((c as u8 - b'A' + shift) % 26) + b'A') as char).collect();
      Generated {
        puzzle: Puzzle {
          kind: kind.code().into(),
          title: "Caesar-Chiffre".into(),
          prompt: format!("Entschlüssle:  {enc}"),
          hint: format!("Jeder Buchstabe wurde um {shift} Stellen im Alphabet nach hinten verschoben."),
        },
        answer: normalize_answer(word),
      }
    }
    Kind::Personal => Generated {
      puzzle: Puzzle {
        kind: kind.code().into(),
        title: "Persönliches Rätsel".into(),
        prompt: String::new(),
        hint: "Die Antwort hast du beim Anlegen des Profils festgelegt (Groß-/Kleinschreibung egal).".into(),
      },
      answer: String::new(),
    },
  }
}

/// Reihenfolge eines neuen Vorgangs: drei verschiedene Zufallsraetsel, dann das persoenliche.
pub fn plan() -> Vec<Kind> {
  let mut pool = vec![Kind::Math, Kind::Sequence, Kind::Anagram, Kind::Caesar];
  pool.shuffle(&mut rng());
  pool.truncate(RANDOM_PUZZLES);
  pool.push(Kind::Personal);
  pool
}

/// Antwort vergleichen (normalisiert, Zahlen auch mit Leerzeichen/Punkt).
pub fn matches(expected: &str, given: &str) -> bool {
  let g = normalize_answer(given);
  let g = if expected.chars().all(|c| c.is_ascii_digit() || c == '-') {
    g.chars().filter(|c| !matches!(c, ' ' | '.' | '\'' | '’')).collect::<String>()
  } else {
    g
  };
  // Laengenunabhaengiger Vergleich ist hier nicht noetig (Loesung ist nie geheim gegenueber dem Loesenden),
  // aber schadet nicht.
  constant_eq(expected.as_bytes(), g.as_bytes())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------------------------
// Laufende Vorgaenge (nur im Speicher)

pub struct Session {
  pub session_hash: String,
  pub profile_id: i64,
  pub profile_label: String,
  pub riddle_question: String,
  pub plan: Vec<Kind>,
  pub step: usize,
  pub current: Generated,
  pub attempts_left: u32,
  pub last_wrong: bool,
  pub started: Instant,
  pub started_unix: i64,
}

impl Session {
  pub fn done(&self) -> bool {
    self.step >= self.plan.len()
  }

  pub fn expired(&self) -> bool {
    self.started.elapsed() > VAULT_TTL
  }

  pub fn kind(&self) -> Option<Kind> {
    self.plan.get(self.step).copied()
  }

  /// Aufgabe fuer den aktuellen Schritt erzeugen.
  pub fn roll(&mut self) {
    if let Some(kind) = self.kind() {
      let mut g = generate(kind);
      if kind == Kind::Personal {
        g.puzzle.prompt = self.riddle_question.clone();
      }
      self.current = g;
    }
  }

  pub fn state(&self, id: &str) -> nrzpgp_shared::VaultState {
    nrzpgp_shared::VaultState {
      vault_id: id.to_string(),
      profile_label: self.profile_label.clone(),
      solved: self.step.min(self.plan.len()) as u32,
      total: self.plan.len() as u32,
      puzzle: (!self.done()).then(|| self.current.puzzle.clone()),
      attempts_left: self.attempts_left,
      last_wrong: self.last_wrong,
      expires_at: self.started_unix + VAULT_TTL.as_secs() as i64,
    }
  }
}

#[derive(Default)]
pub struct Vaults {
  map: Mutex<HashMap<String, Session>>,
}

impl Vaults {
  pub fn with<T>(&self, f: impl FnOnce(&mut HashMap<String, Session>) -> T) -> T {
    let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, s| !s.expired());
    f(&mut map)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn puzzles_are_solvable() {
    for _ in 0..200 {
      for kind in [Kind::Math, Kind::Sequence, Kind::Anagram, Kind::Caesar] {
        let g = generate(kind);
        assert!(!g.answer.is_empty());
        assert!(!g.puzzle.prompt.contains(&g.answer.to_uppercase()) || kind == Kind::Sequence || kind == Kind::Math);
        assert!(matches(&g.answer, &g.answer.to_uppercase()));
        assert!(!matches(&g.answer, "falsch"));
      }
    }
  }

  #[test]
  fn caesar_decodes() {
    let g = generate(Kind::Caesar);
    let enc = g.puzzle.prompt.rsplit(' ').next().unwrap().to_string();
    let shift: u8 = g.puzzle.hint.split_whitespace().find_map(|w| w.parse().ok()).unwrap();
    let dec: String = enc.chars().map(|c| (((c as u8 - b'A' + 26 - shift) % 26) + b'A') as char).collect();
    assert!(matches(&g.answer, &dec));
  }

  #[test]
  fn plan_ends_personal() {
    let p = plan();
    assert_eq!(p.len(), RANDOM_PUZZLES + 1);
    assert_eq!(*p.last().unwrap(), Kind::Personal);
    assert!(matches("1234", " 1 234 "));
  }
}
