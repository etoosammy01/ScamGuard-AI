import { test } from "node:test";
import assert from "node:assert/strict";
import { submitScan, validateScanInput } from "../src/lib/scan-api";

test("scan form source keeps output escaped and submissions type-specific", async () => {
 const fs = await import("node:fs");
 const source = fs.readFileSync(new URL("../src/components/scan-form.tsx", import.meta.url), "utf8");
 assert.match(source, /submitScan\(type, input\)/);
 assert.match(source, /aria-live="polite"/);
 assert.match(source, /false positives or miss threats/);
 assert.match(source, /Analyzing…/);
 assert.doesNotMatch(source, /dangerouslySetInnerHTML/);
});
test("scan API sends credentialed message and URL requests and validates responses", async () => {
 const oldFetch = globalThis.fetch, oldURL = process.env.NEXT_PUBLIC_API_URL;
 process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080";
 try {
  globalThis.fetch = async (url, options) => {
   assert.equal(options?.credentials, "include");
   assert.equal(options?.method, "POST");
   const type = String(url).endsWith("/message") ? "message" : "url";
   assert.equal(JSON.parse(String(options?.body))[type === "message" ? "content" : "url"], type === "message" ? "Synthetic suspicious text" : "https://example.com/path");
   return Response.json({ result: { scan_id: "id", scan_type: type, risk_score: 0, risk_level: "low", category: "unknown", indicators: [], recommendations: ["Stay cautious."], analysis_mode: "rules", created_at: "2026-11-05T00:00:00Z" } }, { status: 201 });
  };
  assert.equal((await submitScan("message", "Synthetic suspicious text")).scan_type, "message");
  assert.equal((await submitScan("url", "https://example.com/path")).scan_type, "url");
  globalThis.fetch = async () => Response.json({ result: { scan_type: "url", risk_score: 101, risk_level: "critical", indicators: [], recommendations: [], analysis_mode: "rules" } }, { status: 201 });
  await assert.rejects(submitScan("message", "text"), /invalid result/);
  globalThis.fetch = async () => { throw new Error("network detail"); };
  await assert.rejects(submitScan("url", "https://example.com"), /Unable to reach ScamGuard/);
 } finally { globalThis.fetch = oldFetch; if (oldURL === undefined) delete process.env.NEXT_PUBLIC_API_URL; else process.env.NEXT_PUBLIC_API_URL = oldURL; }
});
test("scanner validates empty, oversized, and unsupported URL input", () => {
 assert.match(validateScanInput("message", "  ") ?? "", /Enter a message/);
 assert.match(validateScanInput("message", "é".repeat(5001)) ?? "", /10,000 bytes/);
 assert.match(validateScanInput("url", "javascript:alert(1)") ?? "", /HTTP or HTTPS/);
 assert.equal(validateScanInput("url", "https://example.com/path"), null);
});
