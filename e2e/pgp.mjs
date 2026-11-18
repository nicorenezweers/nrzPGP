// E2E gegen eine laufende Instanz (Server + Cap-Dienst):
//   BASE=http://127.0.0.1:8546 PASSWORD=... node pgp.mjs        (HEADED=1 fuer sichtbaren Browser)
//
// Prueft im echten Browser: Anmeldung mit Cap-Widget, Profil, Entschluesseln im GUI (Server macht
// die Arbeit), Tresor mit allen Raetseln + Cap + Passwort; dazu die Cap-Pflichtpruefungen (ohne Token,
// gefaelschter Token, Token zweimal), dass der private Schluessel vor der Freigabe nirgends im HTML
// steht, und dass keine CSP-/Konsolenfehler auftreten. Screenshots in shots/.
import { chromium } from "playwright-core";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";

const BASE = process.env.BASE ?? "http://127.0.0.1:8546";
const PASSWORD = process.env.PASSWORD;
if (!PASSWORD) throw new Error("PASSWORD (Konto nrz) fehlt");
mkdirSync("shots", { recursive: true });

const browser = await chromium.launch({
  executablePath:
    process.env.CHROME ||
    `${homedir()}/Library/Caches/ms-playwright/chromium-1254/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`,
  headless: !process.env.HEADED,
});
const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 }, locale: "de-CH" });
const page = await ctx.newPage();
const logs = [];
const redeemed = [];
page.on("console", (m) => ["error", "warning"].includes(m.type()) && logs.push(`${m.type()}: ${m.text()}`));
page.on("pageerror", (e) => logs.push(`pageerror: ${e}`));
page.on("response", (r) => r.status() === 404 && logs.push(`404 ${r.url()}`));
page.on("response", async (r) => {
  if (r.url().includes("/api/cap/") && r.url().endsWith("/redeem")) {
    const j = await r.json().catch(() => ({}));
    if (j.token) redeemed.push(j.token);
    else console.log("     redeem:", r.status(), JSON.stringify(j).slice(0, 200));
  }
});

let failed = 0;
async function step(name, fn) {
  const t0 = Date.now();
  try {
    const info = await fn();
    console.log(`OK   ${name} (${Date.now() - t0} ms)${info ? " – " + info : ""}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}: ${String(e.message).split("\n")[0]}`);
    await page.screenshot({ path: `shots/fail-${name.replace(/\W+/g, "_")}.png` }).catch(() => {});
  }
}

const dialog = () => page.getByRole("dialog").filter({ hasText: "Kurze Bestätigung" });
async function solveCaptcha() {
  await dialog().waitFor({ timeout: 15000 });
  const trigger = page.locator('cap-widget [role="button"]');
  await trigger.waitFor({ timeout: 15000 });
  await page.screenshot({ path: "shots/captcha.png" });
  const box = await trigger.boundingBox();
  await page.mouse.move(box.x + 4, box.y + 4, { steps: 9 });
  await page.waitForTimeout(250);
  await page.mouse.move(box.x + box.width / 4, box.y + box.height / 2, { steps: 13 });
  await page.waitForTimeout(180);
  await trigger.click();
  await dialog().waitFor({ state: "detached", timeout: 30000 });
}

async function api(path, method, body) {
  return page.evaluate(
    async ([path, method, body]) => {
      const r = await fetch(path, {
        method,
        headers: { "content-type": "application/json", "x-nrz-pgp": "1" },
        body: body ? JSON.stringify(body) : undefined,
      });
      return { status: r.status, json: await r.json().catch(() => null) };
    },
    [path, method, body],
  );
}

// Gleiche Wortliste wie server/src/vault.rs (fuer den Wortsalat).
const WORDS = "SCHLUESSEL SIGNATUR TRESOR PASSWORT GEHEIMNIS FESTUNG LEUCHTTURM KOMPASS SCHMETTERLING BERGSTEIGER ZAUBERER GEWITTER BIBLIOTHEK FAHRRAD KASTANIE REGENBOGEN SCHNEEFLOCKE WALDWEG SONNENBLUME EICHHOERNCHEN PINGUIN KRISTALL VULKAN GALAXIE LABYRINTH TELESKOP ANKER BRUECKE DRACHE FEUERWERK GLETSCHER HORIZONT INSELN JONGLEUR KAPITAEN LAWINE MOSAIK NORDLICHT ORCHESTER PYRAMIDE QUELLE RAKETE SEGELBOOT TROMPETE UHRWERK VERSTECK WINDMUEHLE ZITRONE".split(" ");
const RIDDLE = "Wie hiess mein erstes Haustier?";
const RIDDLE_ANSWER = "Bello";
const PASS = "e2e-passphrase-sehr-lang";

function solvePuzzle(title, prompt, hint) {
  if (title.startsWith("Rechen")) {
    const [a, b, c, d] = prompt.match(/\d+/g).map(Number);
    return String(a * b + c - d);
  }
  if (title.startsWith("Zahlenfolge")) {
    const t = prompt.match(/\d+/g).map(Number);
    const d1 = t.slice(1).map((x, i) => x - t[i]);
    if (d1.every((x) => x === d1[0])) return String(t[4] + d1[0]);
    if (t[1] % t[0] === 0 && t.slice(1).every((x, i) => x === t[i] * (t[1] / t[0]))) return String(t[4] * (t[1] / t[0]));
    if (t.slice(2).every((x, i) => x === t[i] + t[i + 1])) return String(t[3] + t[4]);
    // n^2 + k: Differenzen steigen um 2
    return String(t[4] + d1[3] + 2);
  }
  if (title.startsWith("Wortsalat")) {
    const letters = prompt.split(":").pop().replace(/\s+/g, "").split("").sort().join("");
    return WORDS.find((w) => w.split("").sort().join("") === letters);
  }
  if (title.startsWith("Caesar")) {
    const enc = prompt.trim().split(/\s+/).pop();
    const shift = Number(hint.match(/\d+/)[0]);
    return enc.replace(/[A-Z]/g, (ch) => String.fromCharCode(((ch.charCodeAt(0) - 65 + 26 - shift) % 26) + 65));
  }
  if (title.startsWith("Pers")) return RIDDLE_ANSWER;
  throw new Error("Unbekanntes Raetsel " + title);
}

let profileId;

await step("Anmeldeseite laedt", async () => {
  await page.goto(BASE);
  await page.getByRole("button", { name: "Anmelden" }).waitFor({ timeout: 20000 });
  await page.screenshot({ path: "shots/login.png" });
});

await step("Login ohne/mit gefaelschtem Cap-Token wird abgelehnt", async () => {
  const r = await api("/api/v1/auth/login", "POST", { name: "nrz", password: PASSWORD });
  if (r.json?.error !== "captcha_required") throw new Error(JSON.stringify(r));
  const f = await api("/api/v1/auth/login", "POST", { name: "nrz", password: PASSWORD, captcha: "abcd1234:deadbeef" });
  if (f.json?.error !== "captcha_invalid") throw new Error("gefaelscht: " + JSON.stringify(f));
  return `${r.status} captcha_required, gefaelscht ${f.status} captcha_invalid`;
});

await step("Anmelden mit Cap-Widget", async () => {
  await page.locator("#name").fill("nrz");
  await page.locator("#password").fill(PASSWORD);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await solveCaptcha();
  await page.getByText("Willkommen, nrz").waitFor({ timeout: 15000 });
  await page.screenshot({ path: "shots/home.png" });
});

await step("Cap-Token ist nur einmal gueltig", async () => {
  const token = redeemed.at(-1);
  if (!token) throw new Error("kein Token mitgeschnitten");
  const r = await api("/api/v1/auth/login", "POST", { name: "nrz", password: PASSWORD, captcha: token });
  if (r.json?.error !== "captcha_invalid") throw new Error(JSON.stringify(r));
  return "zweite Verwendung: captcha_invalid";
});

await step("Profil anlegen (Schluessel erzeugen)", async () => {
  const r = await api("/api/v1/profiles", "POST", {
    label: `E2E ${Date.now().toString(36)}`, purpose: "Browser-Test", name: "E2E Test", email: "e2e@example.com",
    comment: "", algorithm: "ed25519", passphrase: PASS, riddle_question: RIDDLE, riddle_answer: RIDDLE_ANSWER,
  });
  if (r.status !== 200) throw new Error(JSON.stringify(r));
  profileId = r.json.summary.id;
  await page.goto(`${BASE}/profiles/${profileId}`);
  await page.getByText(r.json.summary.user_id).first().waitFor({ timeout: 15000 });
  await page.screenshot({ path: "shots/profile.png", fullPage: true });
  return r.json.summary.fingerprint;
});

await step("Entschluesseln im GUI (Server entschluesselt)", async () => {
  const enc = await api("/api/v1/tools/encrypt", "POST", { text: "Geheimes Treffen um 8 Uhr", profile_ids: [profileId], sign_profile: profileId, passphrase: PASS });
  if (enc.status !== 200) throw new Error(JSON.stringify(enc));
  await page.goto(`${BASE}/decrypt`);
  await page.locator('textarea[placeholder="-----BEGIN PGP MESSAGE-----"]').fill(enc.json.armored);
  await page.getByRole("button", { name: "Analysieren" }).click();
  await page.locator("#dpp").waitFor({ timeout: 10000 });
  await page.locator("#dpp").fill(PASS);
  await page.getByRole("button", { name: "Entschlüsseln", exact: true }).click();
  await page.waitForFunction(
    () => [...document.querySelectorAll("textarea[readonly]")].some((t) => t.value.includes("Geheimes Treffen um 8 Uhr")),
    null,
    { timeout: 15000 },
  );
  await page.getByText("Gültige Signatur").first().waitFor({ timeout: 5000 }).catch(() => page.getByText("Gueltige Signatur").first().waitFor({ timeout: 5000 }));
  await page.screenshot({ path: "shots/decrypt.png", fullPage: true });
});

await step("Tresor: Raetsel, Cap und Passwort geben den privaten Schluessel frei", async () => {
  await page.goto(`${BASE}/profiles/${profileId}/vault`);
  await page.getByRole("button", { name: "Tresor öffnen" }).click();
  for (let i = 0; i < 4; i++) {
    const box = page.locator("p.font-mono").first();
    await box.waitFor({ timeout: 10000 });
    const card = box.locator("xpath=..");
    const title = (await card.locator("div").first().innerText()).trim();
    const prompt = (await box.innerText()).trim();
    const hint = (await card.locator("p.text-muted-foreground").innerText().catch(() => "")).trim();
    const html = await page.content();
    if (html.includes("PRIVATE KEY")) throw new Error("privater Schluessel vor der Freigabe im HTML!");
    const answer = solvePuzzle(title, prompt, hint);
    if (i === 0) await page.screenshot({ path: "shots/vault-puzzle.png" });
    await page.locator("#answer").fill(answer);
    await page.getByRole("button", { name: "Antworten" }).click();
    await page.waitForFunction((p) => !document.body.innerText.includes(p), prompt, { timeout: 10000 });
  }
  await page.locator("#vpw").fill(PASSWORD);
  if ((await page.content()).includes("PRIVATE KEY")) throw new Error("zu frueh im HTML");
  await page.getByRole("button", { name: "Schlüssel freigeben" }).click();
  await solveCaptcha();
  await page.getByText("Behandle diesen Schlüssel wie ein Passwort").waitFor({ timeout: 15000 });
  const value = await page.locator("textarea[readonly]").first().inputValue();
  if (!value.includes("BEGIN PGP PRIVATE KEY BLOCK")) throw new Error("kein privater Schluessel sichtbar");
  await page.screenshot({ path: "shots/vault-done.png", fullPage: true });
  await page.getByRole("button", { name: "Ausblenden" }).click();
  if ((await page.content()).includes("PRIVATE KEY")) throw new Error("nach Ausblenden noch im DOM");
});

await step("Protokoll zeigt Vorgaenge", async () => {
  await page.goto(`${BASE}/log`);
  await page.getByText("herausgegeben").first().waitFor({ timeout: 10000 });
  await page.screenshot({ path: "shots/log.png" });
});

await step("Mobile Ansicht", async () => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE}/`);
  await page.waitForTimeout(800);
  await page.screenshot({ path: "shots/mobile.png" });
});

await step("Keine Konsolen-/CSP-Fehler", async () => {
  const bad = logs.filter((l) => !l.includes("allow-scripts and allow-same-origin") && !/status of 4\d\d/.test(l));
  if (bad.length) throw new Error(bad.slice(0, 5).join(" | "));
});

await browser.close();
console.log(failed ? `${failed} Schritt(e) fehlgeschlagen` : "Alle Schritte OK");
process.exit(failed ? 1 : 0);
