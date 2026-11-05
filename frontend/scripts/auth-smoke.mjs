// Runs against disposable, already-started API/frontend servers and a separate headless Chrome.
// Uses Node 24's WebSocket support, so no browser-testing dependency is required.
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
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
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
  const state = await evaluate(`({path:location.pathname, text:document.body.innerText.slice(0,1200)})`).catch(() => null);
  throw new Error(`Timed out: ${label}; state=${JSON.stringify(state)}`);
}
async function navigate(path) {
  await call("Page.navigate", { url: `${app}${path}` });
}
async function fill(values) {
  await evaluate(
    `(() => { for (const [name,value] of Object.entries(${JSON.stringify(values)})) { const input=document.querySelector('[name="'+name+'"]'); if(!input) throw new Error('Missing field '+name); input.value=value; } })()`,
  );
}
async function submit() {
  await evaluate('document.querySelector("form").requestSubmit()');
}
async function fillScanner(value) {
  await evaluate(`(() => { const field=document.querySelector('#scan-input'); const prototype=field.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype,'value').set.call(field,${JSON.stringify(value)}); field.dispatchEvent(new Event('input',{bubbles:true})); })()`);
}
const email = `browser-${randomUUID()}@example.invalid`,
  password = "Synthetic secure passphrase 2026";
try {
  await call("Runtime.enable");
  await call("Page.enable");
  await call("Network.enable");
  await call("Network.clearBrowserCookies");
  await navigate("/dashboard");
  await waitFor(
    `location.pathname==='/login' && !!document.querySelector('#password')`,
    "protected dashboard redirect",
  );
  await evaluate(
    `document.querySelector('[aria-label="Show password"]').click()`,
  );
  assert(await evaluate(`document.querySelector('#password').type==='text'`));
  await fill({ email, password });
  await submit();
  await waitFor(
    `document.body.innerText.includes('Email or password is incorrect')`,
    "generic login failure",
  );
  console.log(
    "Unauthenticated redirects, password visibility, and login errors passed",
  );
  await navigate("/register");
  await waitFor(`!!document.querySelector('#full_name')`, "registration form");
  await fill({
    full_name: "Browser Test User",
    email,
    password: "short",
    confirm_password: "short",
  });
  assert(await evaluate(`document.querySelector('#password').minLength===12`));
  await submit();
  await waitFor(
    `document.body.innerText.includes('Use at least 12 characters')`,
    "password validation",
  );
  await fill({ password, confirm_password: "different long passphrase" });
  await submit();
  await waitFor(
    `document.body.innerText.includes('passwords do not match')`,
    "confirmation validation",
  );
  await fill({ confirm_password: password });
  await submit();
  await waitFor(
    `document.body.innerText.includes('Check your next step.')`,
    "generic registration response",
  );
  await evaluate(`document.querySelector('.registration-complete a').click()`);
  await waitFor(
    `location.pathname==='/login' && !!document.querySelector('#password')`,
    "login after registration",
  );
  await fill({ email, password });
  await submit();
  await waitFor(
    `location.pathname==='/dashboard' && document.body.innerText.includes('Welcome, Browser Test User.')`,
    "authenticated dashboard",
  );
  await navigate("/scan/message");
  await waitFor(`!!document.querySelector('#scan-input')`, "message scanner");
  await fillScanner("URGENT: Your bank account has been suspended. Verify your password at https://secure-login.invalid/verify");
  await submit();
  await waitFor(`!!document.querySelector('.result-card') && document.querySelectorAll('.indicator-list li').length > 0`, "message scan result and indicators");
  await navigate("/scan/url");
  await waitFor(`!!document.querySelector('#scan-input')`, "URL scanner");
  await fillScanner("https://paypal-example.com/login");
  await submit();
  await waitFor(`!!document.querySelector('.result-card')`, "URL scan result");
  console.log("Authenticated message and URL scans returned real rule-based results");
  await navigate("/dashboard");
  await waitFor(`document.body.innerText.includes('Total scans') && document.body.innerText.includes('Recent scans')`, "authenticated dashboard history and analytics");
  assert(await evaluate(`document.body.innerText.includes('2') && document.body.innerText.includes('View Scan History')`), "real saved scan data appears on dashboard");
  await navigate("/history");
  await waitFor(`!!document.querySelector('.history-count') && document.querySelectorAll('.history-table tbody tr').length===2`, "owner scan history");
  await evaluate(`document.querySelector('.history-table tbody a').click()`);
  await waitFor(`!!document.querySelector('.scan-detail-card') && document.body.innerText.includes('unavailable; original content is not stored')`, "retained scan details and privacy disclosure");
  await navigate("/dashboard");
  await waitFor(`document.body.innerText.includes('Total scans')`, "dashboard after details navigation");
  const { cookies } = await call("Storage.getCookies");
  const session = cookies.find(
    (cookie) =>
      cookie.name === "scamguard_session" ||
      cookie.name === "__Host-scamguard_session",
  );
  assert(
    session?.httpOnly &&
      session.sameSite === "Lax" &&
      session.value.length === 43,
    "safe opaque cookie",
  );
  assert(
    await evaluate("localStorage.length===0 && sessionStorage.length===0"),
    "no browser-stored authentication tokens",
  );
  await call("Page.reload");
  await waitFor(
    `document.body.innerText.includes('Welcome, Browser Test User.')`,
    "session survives refresh",
  );
  await navigate("/login");
  await waitFor(
    `location.pathname==='/dashboard'`,
    "authenticated guest-page redirect",
  );
  for (const width of [1440, 768, 390, 320]) {
    await call("Emulation.setDeviceMetricsOverride", {
      width,
      height: 900,
      deviceScaleFactor: 1,
      mobile: width < 500,
    });
    assert(
      await evaluate("document.documentElement.scrollWidth<=innerWidth"),
      `dashboard horizontal overflow at ${width}`,
    );
  }
  console.log(
    "Authenticated dashboard, cookie flags, refresh persistence, guest redirect, and responsive layouts passed",
  );
  await navigate("/profile");
  await waitFor(
    `!!document.querySelector('#profile_name')`,
    "profile retrieval",
  );
  assert(await evaluate(`document.querySelector('#profile_email').readOnly`));
  await fill({
    full_name: "Updated Browser User",
    bio: "Synthetic profile used only in automated testing.",
  });
  await submit();
  await waitFor(
    `document.body.innerText.includes('Your profile has been updated.')`,
    "profile save",
  );
  await call("Page.reload");
  await waitFor(
    `document.querySelector('#profile_name')?.value==='Updated Browser User'`,
    "persisted profile",
  );
  await evaluate(
    `[...document.querySelectorAll('button')].find(button=>button.textContent.includes('Sign out')).click()`,
  );
  await waitFor(
    `location.pathname==='/login' && !!document.querySelector('#password')`,
    "logout redirect",
  );
  const replay = await fetch(`${api}/api/v1/auth/me`, {
    headers: { Cookie: `${session.name}=${session.value}` },
  });
  assert.equal(replay.status, 401, "logout revokes original token");
  await fill({ email, password });
  await submit();
  await waitFor(`location.pathname==='/dashboard'`, "fresh login");
  const again = (await call("Storage.getCookies")).cookies.find(
    (cookie) => cookie.name === session.name,
  );
  assert(again && again.value !== session.value, "fresh session token");
  const revoke = await fetch(`${api}/api/v1/auth/logout`, {
    method: "POST",
    headers: { Origin: app, Cookie: `${again.name}=${again.value}` },
  });
  assert.equal(revoke.status, 204);
  await call("Page.reload");
  await waitFor(
    `location.pathname==='/login'`,
    "server-invalidated session redirects",
  );
  assert.equal(
    exceptions.length,
    0,
    `Browser exceptions: ${exceptions.join(", ")}`,
  );
  assert(
    mutations.every((url) =>
      /\/api\/v1\/(auth\/(login|register|logout)|users\/me|scans\/(message|url))$/.test(url),
    ),
    "no scanner submission or unexpected mutation",
  );
  console.log(
    "Profile update persistence, logout revocation, fresh sessions, and invalidated-session redirects passed",
  );
  console.log("Complete authentication browser smoke test passed");
} finally {
  await call("Page.close").catch(() => {});
  ws.close();
}
