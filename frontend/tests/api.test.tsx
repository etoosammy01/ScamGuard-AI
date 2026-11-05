import { test } from "node:test";
import assert from "node:assert/strict";
import { getHealth } from "../src/lib/api";

test("health client validates responses and handles backend errors", async () => {
  const previousURL = process.env.NEXT_PUBLIC_API_URL;
  const previousFetch = globalThis.fetch;
  process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080/";
  try {
    globalThis.fetch = async (url) => {
      assert.equal(url, "http://localhost:8080/api/v1/health");
      return Response.json({
        status: "ok",
        service: "scamguard-api",
        version: "1.0.0",
      });
    };
    assert.equal((await getHealth()).status, "ok");
    globalThis.fetch = async () =>
      Response.json({ status: "ok", service: "another-service" });
    await assert.rejects(getHealth(), /Invalid health response/);
    globalThis.fetch = async () => new Response(null, { status: 503 });
    await assert.rejects(getHealth(), /API unavailable/);
    globalThis.fetch = async () => {
      throw new TypeError("Network failure");
    };
    await assert.rejects(getHealth(), /Network failure/);
    delete process.env.NEXT_PUBLIC_API_URL;
    await assert.rejects(getHealth(), /not configured/);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousURL === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = previousURL;
  }
});
