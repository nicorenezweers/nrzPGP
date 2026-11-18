// nrzPGP-Captcha-Dienst: Cap (https://trycap.dev, Apache-2.0) mit capjs-core, ohne Abhaengigkeiten.
//
// Nur intern erreichbar. Der nrzPGP-Server reicht Challenge und Einloesen vom Browser hierher
// weiter und prueft vor dem Login und vor der Herausgabe eines privaten Schluessels (Tresor) den
// Token ueber /siteverify. Jede Anfrage braucht den Header x-cap-internal (aus CAP_SEED).
//
//   POST /challenge  {scope, wasm}                 -> Challenge fuer das Widget
//   POST /redeem     {scope, body, headers}        -> {success, token, expires} | {success:false, reason}
//   POST /siteverify {scope, token}                -> {success}   (Token nur einmal gueltig)
//   GET  /health
//
// Zustand (verbrauchte Challenges, ausgegebene Tokens) liegt im Speicher: nach einem Neustart muss
// man das Captcha hoechstens noch einmal loesen.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { generateChallenge, validateChallenge } from "./vendor/capjs-core/src/index.js";

const SEED = process.env.CAP_SEED || "";
if (SEED.length < 16) {
  console.error("nrzpgp-cap: CAP_SEED fehlt oder ist zu kurz");
  process.exit(1);
}
const SECRET = createHmac("sha256", SEED).update("nrzpgp-cap-secret").digest();
// Der Rust-Server berechnet denselben Wert: sha256("nrzpgp-cap-internal:" + seed), hex.
const INTERNAL_KEY = Buffer.from(
  createHash("sha256").update(`nrzpgp-cap-internal:${SEED}`).digest("hex"),
);
const PORT = Number(process.env.CAP_PORT || 3000);
// Nur fuer automatisierte Tests (Playwright): Headless-/Bot-Erkennung laeuft weiter, blockiert
// aber nicht. Niemals in Produktion setzen.
const TEST_MODE = process.env.CAP_TEST_ALLOW_AUTOMATION === "1";
if (TEST_MODE) console.warn("nrzpgp-cap: TESTMODUS – automatisierte Browser werden NICHT blockiert!");

export const SCOPES = new Set(["login", "vault"]);
const MAX_BODY = 256 * 1024;
const MAX_ENTRIES = 200_000;
const TOKEN_TTL_MS = 10 * 60 * 1000;
// Header, die capjs-core fuer die Erkennung von KI-Agenten auswertet.
const AGENT_HEADERS = [
  "user-agent",
  "signature-agent",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "accept-language",
];

/** Map mit Ablaufzeit und Obergrenze (gegen Speicher-Ueberlauf). */
export class TtlStore {
  constructor(max = MAX_ENTRIES) {
    this.max = max;
    this.map = new Map();
  }
  prune(now = Date.now()) {
    for (const [k, v] of this.map) if (v.exp <= now) this.map.delete(k);
  }
  /** Setzt nur, wenn der Schluessel fehlt oder abgelaufen ist. */
  claim(key, ttlMs, value = true) {
    const now = Date.now();
    const cur = this.map.get(key);
    if (cur && cur.exp > now) return false;
    if (this.map.size >= this.max) this.prune(now);
    if (this.map.size >= this.max) return false;
    this.map.set(key, { exp: now + ttlMs, value });
    return true;
  }
  take(key) {
    const cur = this.map.get(key);
    this.map.delete(key);
    return cur && cur.exp > Date.now() ? cur.value : undefined;
  }
}

const nonces = new TtlStore();
const tokens = new TtlStore();
const behaviorDigests = new TtlStore();
setInterval(() => {
  const now = Date.now();
  nonces.prune(now);
  tokens.prune(now);
  behaviorDigests.prune(now);
}, 60_000).unref();

const sha256 = (s) => createHash("sha256").update(s).digest("hex");

export function challengeOptions(scope, wasm) {
  return {
    scope,
    ...(wasm ? {} : { protocols: ["sha256-pow"] }),
    // Browser-Pruefung im Iframe: blockiert Headless-/Automations-Browser.
    instrumentation: { blockAutomatedBrowsers: !TEST_MODE, ...(wasm ? {} : { noWasm: true }) },
    // Verhaltensanalyse: eindeutig automatisierte Eingaben und erkannte KI-Agenten scheitern.
    // Fehlende Maus-/Touch-Interaktion allein blockiert nicht (Tastatur, Screenreader).
    behavior: { block: !TEST_MODE, requireInteraction: false, blockAgents: TEST_MODE ? false : "identified" },
  };
}

export async function redeem(scope, body, headers) {
  const result = await validateChallenge(SECRET, body, {
    scope,
    tokenTtlMs: TOKEN_TTL_MS,
    request: { headers: headers ?? {} },
    consumeNonce: async (sig, ttlMs) => nonces.claim(sig, ttlMs),
    behaviorReplayCheck: async (digest, ttlMs) => !behaviorDigests.claim(digest, ttlMs),
  });
  if (!result.success) return { success: false, reason: result.reason ?? "invalid" };
  if (!tokens.claim(result.tokenKey, TOKEN_TTL_MS, scope)) {
    return { success: false, reason: "busy" };
  }
  return { success: true, token: result.token, expires: result.expires };
}

export function siteverify(scope, token) {
  if (typeof token !== "string" || token.length > 200) return { success: false };
  const i = token.indexOf(":");
  if (i <= 0) return { success: false };
  const key = `${token.slice(0, i)}:${sha256(token.slice(i + 1))}`;
  // take(): Token wird auch bei falschem Scope verbraucht.
  return { success: tokens.take(key) === scope };
}

function authorized(req) {
  const got = Buffer.from(String(req.headers["x-cap-internal"] || ""));
  return got.length === INTERNAL_KEY.length && timingSafeEqual(got, INTERNAL_KEY);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("too_large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(new Error("invalid_json"));
      }
    });
    req.on("error", reject);
  });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}

function pickHeaders(h) {
  const out = {};
  if (h && typeof h === "object") {
    for (const k of AGENT_HEADERS) if (typeof h[k] === "string") out[k] = h[k].slice(0, 1024);
  }
  return out;
}

async function handle(req, res) {
  const url = new URL(req.url, "http://cap");
  if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true });
  if (req.method !== "POST") return send(res, 404, { error: "not_found" });
  if (!authorized(req)) return send(res, 403, { error: "forbidden" });
  let body;
  try {
    body = await readJson(req);
  } catch (e) {
    return send(res, 400, { error: e.message });
  }
  const scope = body?.scope;
  if (!SCOPES.has(scope)) return send(res, 400, { error: "invalid_scope" });

  switch (url.pathname) {
    case "/challenge":
      return send(res, 200, await generateChallenge(SECRET, challengeOptions(scope, body.wasm !== false)));
    case "/redeem": {
      const r = await redeem(scope, body.body, pickHeaders(body.headers));
      return send(res, r.success ? 200 : 400, r);
    }
    case "/siteverify":
      return send(res, 200, siteverify(scope, body.token));
    default:
      return send(res, 404, { error: "not_found" });
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  createServer((req, res) => {
    handle(req, res).catch((e) => {
      console.error("nrzpgp-cap:", e?.message || e);
      if (!res.headersSent) send(res, 500, { error: "internal" });
    });
  })
    .listen(PORT, "0.0.0.0", () => console.log(`nrzpgp-cap: Port ${PORT}`));
  for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => process.exit(0));
}
