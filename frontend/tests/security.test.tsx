import React from "react";
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ErrorState } from "../src/components/ui";
import { authRequest, UNAUTHORIZED_EVENT } from "../src/lib/auth-api";
import { assertLocalTargets } from "../scripts/local-targets.mjs";
test("untrusted response text is escaped by shared UI", () => {
  const html = renderToStaticMarkup(
    <ErrorState>{'<img src=x onerror="alert(1)">'}</ErrorState>,
  );
  assert(!html.includes("<img"));
  assert(html.includes("&lt;img"));
});
test("browser testing rejects nonlocal infrastructure", () => {
  assertLocalTargets([
    "http://localhost:3000",
    "http://127.0.0.1:8080",
    "http://[::1]:9224",
  ]);
  for (const url of [
    "https://example.com",
    "http://localhost.evil.invalid",
    "http://user:pass@localhost",
  ])
    assert.throws(() => assertLocalTargets([url]), /loopback/);
});
test("expired session API response dispatches authentication invalidation", async () => {
  const previousFetch = globalThis.fetch,
    previousBase = process.env.NEXT_PUBLIC_API_URL,
    previousWindow = globalThis.window;
  const target = new EventTarget();
  let revoked = false;
  target.addEventListener(UNAUTHORIZED_EVENT, () => {
    revoked = true;
  });
  try {
    Object.defineProperty(globalThis, "window", {
      value: target,
      writable: true,
      configurable: true,
    });
    process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080";
    globalThis.fetch = async () => new Response(null, { status: 401 });
    await assert.rejects(authRequest("/api/v1/scans"));
    assert.equal(revoked, true);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousBase === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = previousBase;
    Object.defineProperty(globalThis, "window", {
      value: previousWindow,
      writable: true,
      configurable: true,
    });
  }
});
