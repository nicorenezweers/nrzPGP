# nrzPGP – Umbrel-Paket

Dieser Zweig enthaelt nur fertige Dateien fuer die App `nrz-pgp` im nrzStore:

| Datei | Inhalt |
|-------|--------|
| `nrzpgp-amd64.gz`, `nrzpgp-arm64.gz` | Server (Rust, axum + SQLite + rPGP) fuer Linux |
| `web.tar.gz` | Weboberflaeche (Dioxus/WASM, nrzUI) |
| `cap.tar.gz` | Captcha-Dienst (Cap, `cap/server.mjs` + capjs-core, laeuft im Container `cap`) |
| `SHA256SUMS` | Pruefsummen, `hooks/pre-start` prueft sie vor dem Entpacken |

Gebaut mit `scripts/umbrel-release.sh` auf dem Zweig `main`. Quellcode (AGPL-3.0): Zweig `main`.
