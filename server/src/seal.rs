//! Zweite Schutzschicht fuer private Schluessel in der Datenbank.
//!
//! Jeder private Schluessel ist schon mit der Passphrase des Profils geschuetzt (OpenPGP-S2K). Bevor
//! er in SQLite landet, wird er zusaetzlich mit XChaCha20-Poly1305 versiegelt. Der Schluessel dafuer
//! wird je Profil per HKDF-SHA256 aus dem Hauptschluessel (`NRZPGP_MASTER_KEY`, nur in der
//! Umgebung, nie in der Datenbank) abgeleitet; die zufaellige Profil-Kennung ist zusaetzlich als
//! AAD gebunden, damit sich versiegelte Werte nicht zwischen Profilen oder Feldern tauschen lassen.
//!
//! Wer nur die Datenbank hat, sieht also nichts. Wer Datenbank *und* Hauptschluessel hat, hat immer
//! noch einen passphrase-geschuetzten Schluessel.

use chacha20poly1305::{
  XChaCha20Poly1305, XNonce,
  aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroizing;

const VERSION: u8 = 1;

pub struct Sealer {
  master: Zeroizing<Vec<u8>>,
}

impl Sealer {
  pub fn new(master: &str) -> Self {
    // Hauptschluessel einmal mit HKDF-Extract normalisieren (beliebige Laenge erlaubt, min. 32 Zeichen
    // werden in der Konfiguration erzwungen).
    let hk = Hkdf::<Sha256>::new(Some(b"nrzpgp-master-v1"), master.as_bytes());
    let mut prk = Zeroizing::new(vec![0u8; 32]);
    hk.expand(b"nrzpgp-seal-root", &mut prk).expect("hkdf");
    Self { master: prk }
  }

  fn key_for(&self, context: &str) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::from_prk(&self.master).expect("prk");
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(format!("nrzpgp-seal:{context}").as_bytes(), out.as_mut()).expect("hkdf");
    out
  }

  /// Versiegelt `plain` fuer `context` (z. B. `profile:<uid>:secret`). Ergebnis: Version, Nonce, Chiffrat.
  pub fn seal(&self, context: &str, plain: &[u8]) -> Vec<u8> {
    let key = self.key_for(context);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
      .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: context.as_bytes() })
      .expect("seal");
    let mut out = Vec::with_capacity(1 + 24 + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
  }

  /// Oeffnet einen versiegelten Wert; `None` bei falschem Kontext, Hauptschluessel oder Manipulation.
  pub fn open(&self, context: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < 1 + 24 + 16 || sealed[0] != VERSION {
      return None;
    }
    let key = self.key_for(context);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
      .decrypt(XNonce::from_slice(&sealed[1..25]), Payload { msg: &sealed[25..], aad: context.as_bytes() })
      .ok()
      .map(Zeroizing::new)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn roundtrip_and_binding() {
    let s = Sealer::new("ein-sehr-langer-hauptschlüssel-fuer-tests-123");
    let sealed = s.seal("profile:abc:secret", b"geheim");
    assert_ne!(&sealed[25..], b"geheim");
    assert_eq!(s.open("profile:abc:secret", &sealed).unwrap().as_slice(), b"geheim");
    // Anderer Kontext, anderer Hauptschluessel, manipuliert: alles abgelehnt.
    assert!(s.open("profile:xyz:secret", &sealed).is_none());
    assert!(Sealer::new("ein-anderer-hauptschlüssel-fuer-tests-456").open("profile:abc:secret", &sealed).is_none());
    let mut bad = sealed.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(s.open("profile:abc:secret", &bad).is_none());
    // Zwei Siegel desselben Inhalts unterscheiden sich (zufaellige Nonce).
    assert_ne!(sealed, s.seal("profile:abc:secret", b"geheim"));
  }
}
