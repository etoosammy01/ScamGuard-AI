// Runs against disposable, already-started API/frontend servers and a separate headless Chrome.
// Uses Node 24's WebSocket support, so no browser-testing dependency is required.
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
const app = process.env.SMOKE_APP_URL ?? "http://localhost:3000";
const api = process.env.SMOKE_API_URL ?? "http://localhost:8080";
const debug = process.env.CHROME_DEBUG_URL ?? "http://127.0.0.1:9224";
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
const email = `phase6-${randomUUID()}@example.invalid`,
  password = "Synthetic security passphrase 2026";
const adminBinary = process.env.SMOKE_ADMIN_BINARY;
if (!adminBinary)
  throw new Error(
    "Set SMOKE_ADMIN_BINARY to the compiled backend/cmd/admin operator command. Use disposable servers and database only.",
  );
async function apiFetch(path, method = "GET", body) {
  return evaluate(
    `(async()=>{const response=await fetch(${JSON.stringify(api)}+${JSON.stringify(path)},{method:${JSON.stringify(method)},credentials:"include",headers:{"Content-Type":"application/json"},body:${body === undefined ? "undefined" : JSON.stringify(JSON.stringify(body))}});return {status:response.status,data:response.headers.get("content-type")?.includes("json")?await response.json():null};})()`,
  );
}
async function click(text) {
  await evaluate(
    `(()=>{const button=[...document.querySelectorAll("button")].find(b=>b.textContent===${JSON.stringify(text)});if(!button)throw new Error("Missing button");button.click();})()`,
  );
}
try {
  await call("Runtime.enable");
  await call("Page.enable");
  await call("Network.enable");
  await call("Network.clearBrowserCookies");
  await navigate("/login");
  await waitFor(`!!document.querySelector('#password')`, "login page");
  assert.equal(
    (
      await apiFetch("/api/v1/auth/register", "POST", {
        full_name: "Phase Six Operator",
        email,
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
  await navigate("/admin");
  await waitFor(
    `document.body.innerText.includes('Administrator access required')`,
    "regular user admin rejection",
  );
  for (let i = 0; i < 22; i++)
    assert.equal((await apiFetch("/api/v1/admin/overview")).status, 403);
  const created = await apiFetch("/api/v1/scans/message", "POST", {
    content:
      "URGENT! Your bank account is suspended. Verify your password at https://bank-login.invalid now.",
  });
  assert.equal(created.status, 201);
  const scan = created.data.result;
  await navigate(`/history/${scan.scan_id}`);
  await waitFor(
    `document.body.innerText.includes('Download Security Report')`,
    "report button",
  );
  await call("Browser.setDownloadBehavior", { behavior: "deny" });
  await click("Download Security Report");
  await waitFor(
    `!![...document.querySelectorAll('button')].find(b=>b.textContent==='Download Security Report'&&!b.disabled)`,
    "completed report request",
  );
  assert(
    !(await evaluate(
      `document.body.innerText.includes('could not be downloaded')`,
    )),
  );
  // Failure must leave a visible error; the report button never reports false success.
  await evaluate(
    `window.__originalFetch=window.fetch;window.fetch=(url,options)=>String(url).endsWith('/report')?Promise.resolve(new Response('unavailable',{status:503})):window.__originalFetch(url,options)`,
  );
  await click("Download Security Report");
  await waitFor(
    `document.body.innerText.includes('could not be downloaded')`,
    "report error",
  );
  await evaluate(`window.fetch=window.__originalFetch`);
  execFileSync(adminBinary, [email, "phase6-disposable-browser-test"], {
    env: process.env,
    stdio: "pipe",
  });
  await navigate("/admin");
  await waitFor(
    `document.body.innerText.includes('Operational monitoring')`,
    "admin overview",
  );
  assert(await evaluate(`!!document.querySelector('a[href="/admin"]')`));
  await navigate("/admin/users");
  await waitFor(`!!document.querySelector('tbody tr')`, "user management");
  const selfDisabled = await evaluate(
    `(()=>{const row=[...document.querySelectorAll('tbody tr')].find(r=>r.textContent.includes(${JSON.stringify(email)}));return row?.querySelector('button')?.disabled;})()`,
  );
  assert.equal(selfDisabled, true);
  if (process.env.SMOKE_EXPECT_PAGINATION === "1") {
    await click("Next");
    await waitFor(
      `document.querySelector('caption')?.textContent.includes('page 2')`,
      "user list pagination",
    );
    await click("Previous");
    await waitFor(
      `document.querySelector('caption')?.textContent.includes('page 1')`,
      "previous user page",
    );
  }
  await evaluate(
    `(()=>{const b=[...document.querySelectorAll('tbody button')].find(b=>!b.disabled&&b.textContent==='Suspend');if(!b)throw new Error('Need disposable fixture user');b.click();})()`,
  );
  await waitFor(
    `!!document.querySelector('[role="dialog"]')`,
    "suspension confirmation",
  );
  assert(
    await evaluate(
      `document.querySelector('[role="dialog"]').textContent.includes('Active sessions will be revoked')`,
    ),
  );
  await click("Cancel");
  await waitFor(
    `!document.querySelector('[role="dialog"]')`,
    "cancel confirmation",
  );
  await evaluate(
    `[...document.querySelectorAll('tbody button')].find(b=>!b.disabled&&b.textContent==='Suspend').click()`,
  );
  await waitFor(
    `!!document.querySelector('[role="dialog"]')`,
    "confirmation ready",
  );
  await click("Confirm status change");
  await waitFor(
    `!document.querySelector('[role="dialog"]')&&!![...document.querySelectorAll('tbody button')].find(b=>b.textContent==='Reactivate')`,
    "suspension result",
  );
  await evaluate(
    `[...document.querySelectorAll('tbody button')].find(b=>b.textContent==='Reactivate').click()`,
  );
  await click("Confirm status change");
  await waitFor(
    `!document.querySelector('[role="dialog"]')&&!document.body.innerText.includes('Saving')`,
    "reactivation",
  );
  await navigate("/admin/analytics");
  await waitFor(`!!document.querySelector('meter')`, "aggregate charts");
  await navigate("/admin/audit-logs");
  await waitFor(`!!document.querySelector('tbody tr')`, "audit records");
  await click("Next");
  await waitFor(
    `document.querySelector('caption')?.textContent.includes('page 2')`,
    "audit pagination",
  );
  await call("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  for (const path of [
    "/admin",
    "/admin/users",
    "/admin/analytics",
    "/admin/audit-logs",
    "/admin/settings",
  ]) {
    await navigate(path);
    await waitFor(
      `!!document.querySelector('.admin-page')&&!document.body.innerText.includes('Loading ')`,
      "mobile " + path,
    );
    assert(
      await evaluate(`document.documentElement.scrollWidth<=window.innerWidth`),
      "page overflow: " + path,
    );
  }
  assert.deepEqual(exceptions, []);
  console.log(
    "Phase 6 browser checks passed: role rejection, report download/error, overview, users pagination/confirmation/status, analytics, audit pagination, mobile layouts.",
  );
} finally {
  await call("Page.close").catch(() => {});
  ws.close();
}
