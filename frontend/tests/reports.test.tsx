import { test } from "node:test";
import assert from "node:assert/strict";
import { downloadSecurityReport } from "../src/lib/history-api";
test("security report uses cookies, fixed API path and validates PDF or errors", async () => {
  const original = globalThis.fetch,
    base = process.env.NEXT_PUBLIC_API_URL;
  process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080";
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(
        String(url),
        "http://localhost:8080/api/v1/scans/scan-id/report",
      );
      assert.equal(init?.credentials, "include");
      assert.equal(init?.cache, "no-store");
      return new Response("%PDF-1.7\nfixture", {
        headers: { "Content-Type": "application/pdf" },
      });
    };
    assert.equal(
      (await downloadSecurityReport("scan-id")).type,
      "application/pdf",
    );
    for (const status of [401, 403, 404, 429, 503]) {
      globalThis.fetch = async () => new Response("error", { status });
      await assert.rejects(
        downloadSecurityReport("scan-id"),
        /could not be downloaded/,
      );
    }
    globalThis.fetch = async () =>
      Response.json({ url: "https://untrusted.invalid" });
    await assert.rejects(
      downloadSecurityReport("scan-id"),
      /did not return a PDF/,
    );
    globalThis.fetch = async () =>
      new Response("not a pdf", {
        headers: { "Content-Type": "application/pdf" },
      });
    await assert.rejects(downloadSecurityReport("scan-id"), /invalid/);
  } finally {
    globalThis.fetch = original;
    if (base === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = base;
  }
});
