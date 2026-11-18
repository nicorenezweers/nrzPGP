#!/usr/bin/env bash
# nrzPGP lokal bauen und starten: Cap-Dienst (Node) + Server (Rust) mit Weboberflaeche.
#   scripts/run.sh            Release-Build, http://127.0.0.1:8546
#   SKIP_BUILD=1 scripts/run.sh
# Geheimnisse liegen in data/dev.env (wird beim ersten Start erzeugt, nicht im Git).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data

if [ ! -f data/dev.env ]; then
  umask 077
  printf 'NRZPGP_CAP_SEED=%s\nNRZPGP_MASTER_KEY=%s\nNRZPGP_ADMIN_PASSWORD=%s\n' \
    "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" "nrz-$(openssl rand -hex 8)" > data/dev.env
  echo "data/dev.env angelegt (Konto nrz, Passwort dort)."
fi
set -a; . data/dev.env; set +a

# dioxus-cli finden (`dx` im PATH kann auch Denos dx sein).
DX="${DX:-}"
for c in "${DX}" "$(command -v dx || true)" "${HOME}/.cargo/bin/dx"; do
  if [ -n "${c}" ] && "${c}" --version 2>/dev/null | grep -qi dioxus; then DX="${c}"; break; fi
  DX=""
done

if [ -z "${SKIP_BUILD:-}" ]; then
  [ -n "${DX}" ] || { echo "dioxus-cli (dx) nicht gefunden - cargo binstall dioxus-cli" >&2; exit 1; }
  cargo build --release -p nrzpgp
  (cd web && CARGO_TARGET_DIR="$PWD/../target" "${DX}" build --release --platform web)
fi

CAP_PORT="${CAP_PORT:-3918}"
CAP_SEED="$NRZPGP_CAP_SEED" CAP_PORT="$CAP_PORT" node cap/server.mjs &
CAP_PID=$!
trap 'kill $CAP_PID 2>/dev/null || true' EXIT

NRZPGP_CAP_URL="http://127.0.0.1:${CAP_PORT}" \
NRZPGP_WEB_DIR="target/dx/nrzpgp_web/release/web/public" \
NRZPGP_DATABASE="${NRZPGP_DATABASE:-data/pgp.db}" \
  ./target/release/nrzpgp
