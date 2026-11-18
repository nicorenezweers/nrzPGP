# nrzPGP – Captcha-Dienst (Cap Core)

Interner Dienst fuer das [Cap](https://trycap.dev)-Captcha. Der Rust-Server (`server/src/cap.rs`)
reicht die Widget-Anfragen (`/api/cap/{scope}/challenge|redeem`) hierher weiter und prueft Tokens
ueber `/siteverify` (einmal gueltig, fail closed).

- `server.mjs`: kleiner HTTP-Server ohne npm-Abhaengigkeiten (Node 22+), Bereiche `login` (Anmeldung)
  und `vault` (Herausgabe eines privaten Schluessels). Aktiv: Proof of Work (HashWX),
  Browser-Instrumentierung mit Sperre fuer Headless-/Automations-Browser, Verhaltensanalyse, Sperre
  erkannter KI-Agenten.
- `vendor/capjs-core/`: [capjs-core](https://www.npmjs.com/package/capjs-core) **0.1.16**, unveraendert
  (Apache-2.0, siehe `vendor/capjs-core/LICENSE`).
- Im Browser: Widget `@cap.js/widget` **0.1.63**, `@cap.js/wasm` **0.0.8** und pako 2.1.0 lokal in
  `web/public/cap/` (keine Anfragen an fremde Server).

| Variable | Zweck |
|----------|-------|
| `CAP_SEED` | Gemeinsames Geheimnis mit dem Server (`NRZPGP_CAP_SEED`, min. 16 Zeichen) |
| `CAP_PORT` | Port (Standard 3000), nur intern erreichbar machen |
| `CAP_TEST_ALLOW_AUTOMATION=1` | **Nur fuer E2E-Tests**: Bot-Erkennung blockiert nicht. Nie in Produktion. |
