#!/usr/bin/env bash
# Prueft nrzPGP gegen GnuPG (in Docker): Schluessel importieren, Nachrichten von nrzPGP
# entschluesseln und pruefen, Antwort/Signatur/Passwort-Nachricht von GnuPG zurueck,
# Widerrufszertifikat importieren.
#   scripts/gpg-interop.sh             (Ed25519)
#   INTEROP_ALG=rsa4096 scripts/gpg-interop.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target; DIR="$(mktemp -d "$PWD/target/interop.XXXXXX")"
export INTEROP_DIR="$DIR"
cargo test -q -p nrzpgp interop -- --ignored >/dev/null
# Dateien per tar ueber stdin/stdout (ohne Bind-Mount, funktioniert auch mit colima/Remote-Docker).
COPYFILE_DISABLE=1 tar --no-xattrs -C "$DIR" -cf - . | docker run -i --rm debian:trixie-slim sh -euc '
  exec 3>&1 1>&2
  mkdir /w && tar -C /w -xf -
  apt-get update -qq >/dev/null && apt-get install -y -qq gnupg >/dev/null 2>&1
  export GNUPGHOME=$(mktemp -d)
  P="--batch --yes --pinentry-mode loopback --passphrase interop-passphrase-123"
  gpg $P --import /w/sec.asc 2>&1 | grep -E "imported|secret key" | head -3
  echo "--- nrzPGP -> GnuPG: entschluesseln + Signatur"
  gpg $P --decrypt /w/from_rpgp.asc 2>/w/dec.err; grep -E "Good signature|Korrekte" /w/dec.err
  echo; echo "--- Klartext-Signatur"
  gpg --batch --verify /w/clear.asc 2>&1 | grep -E "Good signature"
  echo "--- Passwort-Nachricht"
  gpg --batch --pinentry-mode loopback --passphrase pw-123 --decrypt /w/pw.asc 2>/dev/null; echo
  echo "--- GnuPG -> nrzPGP"
  echo "Antwort von GnuPG" | gpg $P --trust-model always --armor --encrypt --sign -r interop@example.com > /w/from_gpg.asc
  echo "Klartext von GnuPG" | gpg $P --armor --clearsign > /w/gpg_clear.asc
  echo "GnuPG Passwort" | gpg --batch --yes --pinentry-mode loopback --passphrase gpg-pw-456 --armor --symmetric > /w/gpg_pw.asc
  echo "--- Widerrufszertifikat"
  gpg --batch --import /w/revocation.asc 2>&1 | grep -iE "revocation|widerruf" | head -2
  gpg --list-keys interop@example.com 2>&1 | grep -E "revoked" | head -1
  tar -C /w -cf - from_gpg.asc gpg_clear.asc gpg_pw.asc >&3
' | tar -C "$DIR" -xf -
cargo test -q -p nrzpgp interop -- --ignored 2>&1 | grep -E "test result|panicked"
echo "Ordner: $DIR"
