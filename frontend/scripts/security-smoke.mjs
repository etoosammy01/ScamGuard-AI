// Runs against disposable, already-started API/frontend servers and a separate headless Chrome.
// Uses Node 24's WebSocket support, so no browser-testing dependency is required.
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { assertLocalTargets } from "./local-targets.mjs";
import { randomUUID } from "node:crypto";
const app = process.env.SMOKE_APP_URL ?? "http://localhost:3000";
const api = process.env.SMOKE_API_URL ?? "http://localhost:8080";
const debug = process.env.CHROME_DEBUG_URL ?? "http://127.0.0.1:9224";
assertLocalTargets([app, api, debug]);
const target = await (
  await fetch(`${debug}/json/new?about:blank`, { method: "PUT" })
).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  ws.addEventListener("open", resolve, { once: true });
  ws.addEventListener("error", reject, { once: true });
});
let nextID = 0;
const pending = new Map();
const exceptions = [],
  mutations = [];
ws.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data);
  if (message.id) {
    const callback = pending.get(message.id);
    if (!callback) return;
    pending.delete(message.id);
    clearTimeout(callback.timeout);
    if (message.error) callback.reject(message.error);
    else callback.resolve(message.result);
  }
  if (message.method === "Runtime.exceptionThrown")
    exceptions.push(message.params.exceptionDetails.text);
  if (
    message.method === "Network.requestWillBeSent" &&
    ["POST", "PATCH"].includes(message.params.request.method)
  )
    mutations.push(message.params.request.url);
});
function call(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++nextID;
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`CDP timeout: ${method}`));
    }, 15000);
    pending.set(id, { resolve, reject, timeout });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const result = await call("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails)
    throw new Error(
      result.exceptionDetails.exception?.description ??
        result.exceptionDetails.text,
    );
  return result.result.value;
}
async function waitFor(expression, label) {
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      if (await evaluate(expression)) return;
    } catch {
      /* navigation can replace the execution context */
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  const state = await evaluate(
    `({path:location.pathname, text:document.body.innerText.slice(0,1200)})`,
  ).catch(() => null);
  throw new Error(`Timed out: ${label}; state=${JSON.stringify(state)}`);
}
async function navigate(path) {
  await call("Page.navigate", { url: `${app}${path}` });
}
const email = `phase7-${randomUUID()}@example.invalid`,
  other = `phase7-other-${randomUUID()}@example.invalid`,
  password = "Synthetic security passphrase 2026";
const downloads = await mkdtemp(join(tmpdir(), "scamguard-private-downloads-"));
async function apiFetch(path, method = "GET", body) {
  return evaluate(
    `(async()=>{const r=await fetch(${JSON.stringify(api)}+${JSON.stringify(path)},{method:${JSON.stringify(method)},credentials:"include",headers:{"Content-Type":"application/json"},body:${body === undefined ? "undefined" : JSON.stringify(JSON.stringify(body))}});return {status:r.status,data:r.status!==204&&r.headers.get('content-type')?.includes('json')?await r.json():null};})()`,
  );
}
async function click(text) {
  await evaluate(
    `(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)});if(!b)throw new Error('Missing button');b.click();})()`,
  );
}
async function downloaded(name) {
  for (let i = 0; i < 80; i++) {
    try {
      const data = await readFile(join(downloads, name));
      if (
        data.length &&
        (!name.endsWith(".pdf") ||
          (data.subarray(0, 5).toString() === "%PDF-" &&
            data.subarray(-100).toString().includes("%%EOF")))
      )
        return data;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("Download did not complete: " + name);
}
try {
  await call("Runtime.enable");
  await call("Page.enable");
  await call("Network.enable");
  await call("Network.clearBrowserCookies");
  await call("Browser.setDownloadBehavior", {
    behavior: "allow",
    downloadPath: downloads,
  });
  await navigate("/login");
  await waitFor(`!!document.querySelector('#password')`, "login");
  for (const account of [email, other])
    assert.equal(
      (
        await apiFetch("/api/v1/auth/register", "POST", {
          full_name: "Security Browser Fixture",
          email: account,
          password,
          confirm_password: password,
        })
      ).status,
      202,
    );
  assert.equal(
    (await apiFetch("/api/v1/auth/login", "POST", { email, password })).status,
    200,
  );
  const message = await apiFetch("/api/v1/scans/message", "POST", {
    content: "URGENT bank account suspended. Send your OTP now.",
  });
  assert.equal(message.status, 201);
  const id = message.data.result.scan_id;
  assert.equal(
    (
      await apiFetch("/api/v1/scans/url", "POST", {
        url: "https://paypal-login.invalid/",
      })
    ).status,
    201,
  );
  await navigate("/history");
  await waitFor(
    `document.body.innerText.includes('Scan history')&&!!document.querySelector('tbody tr')`,
    "history",
  );
  await click("Export CSV");
  const csv = await downloaded("scamguard-scans.csv");
  assert(csv.toString().startsWith("Scan ID,"));
  assert(!csv.toString().includes("Send your OTP"));
  await navigate("/history/" + id);
  await waitFor(
    `document.body.innerText.includes('Download Security Report')`,
    "details",
  );
  await click("Download Security Report");
  const pdf = await downloaded("scamguard-security-report.pdf");
  assert(pdf.subarray(0, 5).toString() === "%PDF-");
  assert(pdf.length < 2 * 1024 * 1024);
  const profile = await apiFetch("/api/v1/users/me", "PATCH", {
    full_name: "<img src=x onerror=window.__xss=true>",
  });
  assert.equal(profile.status, 200);
  await navigate("/dashboard");
  await waitFor(
    `document.body.innerText.includes('<img src=x')`,
    "escaped name",
  );
  assert.equal(
    await evaluate(
      `window.__xss===true||!!document.querySelector('img[onerror]')`,
    ),
    false,
  );
  assert.equal(
    (await apiFetch("/api/v1/auth/login", "POST", { email: other, password }))
      .status,
    200,
  );
  for (const path of ["/api/v1/scans/" + id, "/api/v1/scans/" + id + "/report"])
    assert.equal((await apiFetch(path)).status, 404);
  assert.equal((await apiFetch("/api/v1/scans/" + id, "DELETE")).status, 404);
  assert.equal((await apiFetch("/api/v1/admin/overview")).status, 403);
  assert.equal((await apiFetch("/api/v1/auth/logout", "POST")).status, 204);
  assert.equal((await apiFetch("/api/v1/scans")).status, 401);
  await navigate("/history");
  await waitFor(`location.pathname==='/login'`, "logout protection");
  assert.deepEqual(exceptions, []);
  console.log(
    "Phase 7 browser security journey passed: register/login, scans, history/details, real private PDF/CSV downloads, escaped profile text, cross-user read/report/delete denial, admin denial and logout protection.",
  );
} finally {
  await call("Page.close").catch(() => {});
  ws.close();
  await rm(downloads, { recursive: true, force: true });
}
