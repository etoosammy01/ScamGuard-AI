import React from "react";
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  validateRegistration,
  authDestination,
} from "../src/lib/auth-validation";
import { authRequest, APIError, signOut } from "../src/lib/auth-api";
import { SessionLoading } from "../src/components/auth-guard";
const valid = {
  full_name: "Test User",
  email: "test@example.invalid",
  password: "a long synthetic passphrase",
  confirm_password: "a long synthetic passphrase",
};
test("registration validates name, email, password bytes, and confirmation", () => {
  assert.equal(validateRegistration(valid), null);
  for (const change of [
    { full_name: " " },
    { full_name: "x".repeat(201) },
    { email: "bad" },
    { password: "short" },
    { confirm_password: "different" },
    { password: "🔒".repeat(300) },
  ])
    assert.equal(
      typeof validateRegistration({ ...valid, ...change }),
      "string",
    );
  const long = "a good long passphrase ".repeat(30);
  assert.equal(
    validateRegistration({ ...valid, password: long, confirm_password: long }),
    null,
  );
});
test("protected and guest routes use distinct loading/session destinations", () => {
  assert.equal(authDestination("unauthenticated", false), "/login");
  assert.equal(authDestination("authenticated", true), "/dashboard");
  for (const status of ["loading", "error"])
    assert.equal(authDestination(status, false), null);
  assert.equal(authDestination("authenticated", false), null);
});
test("session loading state is accessible", () => {
  const html = renderToStaticMarkup(<SessionLoading />);
  assert.match(html, /Checking your secure session/);
  assert.match(html, /role="status"/);
});
test("login errors stay generic and logout sends cookies without persisting tokens", async () => {
  const previousFetch = globalThis.fetch,
    previousURL = process.env.NEXT_PUBLIC_API_URL;
  process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080";
  try {
    globalThis.fetch = async () =>
      Response.json(
        { error: { message: "sensitive backend details" } },
        { status: 401 },
      );
    await assert.rejects(
      authRequest("/api/v1/auth/login", { method: "POST" }, false),
      (error: unknown) =>
        error instanceof APIError &&
        error.status === 401 &&
        !error.message.includes("sensitive"),
    );
    globalThis.fetch = async (url, options) => {
      assert.equal(url, "http://localhost:8080/api/v1/auth/logout");
      assert.equal(options?.method, "POST");
      assert.equal(options?.credentials, "include");
      assert.equal(options?.body, undefined);
      return new Response(null, { status: 204 });
    };
    await signOut();
  } finally {
    globalThis.fetch = previousFetch;
    if (previousURL === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = previousURL;
  }
});
