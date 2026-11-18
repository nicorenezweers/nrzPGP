#!/usr/bin/env bash
# Baut nrzPGP fuer umbrelOS (Linux amd64 + arm64), legt die fertigen Dateien auf den Zweig
# `umbrel` und pusht den Tag `umbrel-<version>`. nrzGit traegt die Version dann per nrzStore.json
# selbst im nrzStore ein (RELEASE in hooks/pre-start, version, releaseNotes, Store-Version).
#
#   ./scripts/umbrel-release.sh 1.0.1 "Kurze Beschreibung"
#
# Voraussetzungen: dioxus-cli 0.7 (dx), zig + cargo-zigbuild, Rust-Targets
# x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu und wasm32-unknown-unknown.
set -euo pipefail

VERSION="${1:?Version fehlt, z.B. 1.0.1}"
NOTES="${2:-nrzPGP ${VERSION}}"
TAG="umbrel-${VERSION}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [ -n "$(git status --porcelain)" ]; then
  echo "Arbeitsverzeichnis nicht sauber - erst committen." >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "Tag ${TAG} gibt es schon." >&2
  exit 1
fi

# dioxus-cli finden (`dx` im PATH kann auch Denos dx sein).
DX="${DX:-}"
for c in "${DX}" "$(command -v dx || true)" "${HOME}/.cargo/bin/dx"; do
  if [ -n "${c}" ] && "${c}" --version 2>/dev/null | grep -qi dioxus; then DX="${c}"; break; fi
  DX=""
done
[ -n "${DX}" ] || { echo "dioxus-cli (dx) nicht gefunden - cargo binstall dioxus-cli" >&2; exit 1; }
cargo zigbuild --help >/dev/null 2>&1 || { echo "cargo-zigbuild fehlt" >&2; exit 1; }

# Pfade ohne Leerzeichen (zig-Wrapper und C-Builds wie SQLite vertragen keine).
BUILD="${NRZPGP_BUILD_DIR:-/tmp/nrzpgp-build}"
export CARGO_ZIGBUILD_CACHE_DIR="${BUILD}/zigcache"
OUT="$(mktemp -d)"
trap 'rm -rf "${OUT}"' EXIT
# C-Bibliotheken (SQLite) werden mit `ar` gepackt; Apples ar kann keine ELF-Objekte und
# erzeugt dann ein leeres Archiv. Deshalb ar/ranlib von zig verwenden.
mkdir -p "${BUILD}/bin"
printf '#!/bin/sh\nexec zig ar "$@"\n' > "${BUILD}/bin/zig-ar"
printf '#!/bin/sh\nexec zig ranlib "$@"\n' > "${BUILD}/bin/zig-ranlib"
chmod +x "${BUILD}/bin/zig-ar" "${BUILD}/bin/zig-ranlib"
export AR="${BUILD}/bin/zig-ar" RANLIB="${BUILD}/bin/zig-ranlib"

echo "==> Oberflaeche (Dioxus/WASM)"
# Alte Assets frueherer Builds nicht mitliefern.
rm -rf "${BUILD}/webdist" "${BUILD}/wasm/dx/nrzpgp_web/release/web/public"
(cd web && CARGO_TARGET_DIR="${BUILD}/wasm" "${DX}" bundle --platform web --release --out-dir "${BUILD}/webdist")
test -f "${BUILD}/webdist/public/index.html"
# Cap-Widget, WASM und pako (lokal statt CDN), falls dx public/ nicht mitkopiert hat.
mkdir -p "${BUILD}/webdist/public/cap"
cp web/public/cap/* "${BUILD}/webdist/public/cap/"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "${OUT}/web.tar.gz" -C "${BUILD}/webdist/public" .

build() { # <rust-target> <arch>
  echo "==> Server ${2} (${1})"
  CARGO_TARGET_DIR="${BUILD}/linux" cargo zigbuild --release -p nrzpgp --target "${1}.2.31"
  gzip -9 -c "${BUILD}/linux/${1}/release/nrzpgp" > "${OUT}/nrzpgp-${2}.gz"
}
build x86_64-unknown-linux-gnu amd64
build aarch64-unknown-linux-gnu arm64
echo "==> Captcha-Dienst (cap/)"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "${OUT}/cap.tar.gz" -C cap server.mjs vendor
(cd "${OUT}" && shasum -a 256 nrzpgp-amd64.gz nrzpgp-arm64.gz web.tar.gz cap.tar.gz > SHA256SUMS)

# Zweig `umbrel` in einem eigenen Worktree aktualisieren (nur fertige Dateien).
WT="$(mktemp -d)"
git fetch origin umbrel 2>/dev/null || true
if git rev-parse -q --verify origin/umbrel >/dev/null; then
  git worktree add -q "${WT}" -B umbrel origin/umbrel
else
  git worktree add -q --detach "${WT}"
  (cd "${WT}" && git checkout -q --orphan umbrel && git rm -rqf .)
fi
cp "${OUT}"/* "${WT}/"
git show HEAD:scripts/umbrel-README.md > "${WT}/README.md"
(
  cd "${WT}"
  git add -A
  git commit -qm "nrzPGP ${VERSION}: Umbrel-Paket"
  git tag -a "${TAG}" -m "${NOTES}"
  git push -q origin umbrel
  git push -q origin "${TAG}"
)
git worktree remove --force "${WT}"
echo "==> ${TAG} veroeffentlicht. nrzGit aktualisiert den nrzStore."
