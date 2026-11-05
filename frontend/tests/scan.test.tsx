import { test } from "node:test";
import assert from "node:assert/strict";
import { submitScan, validateScanInput } from "../src/lib/scan-api";

test("scan form source keeps output escaped and submissions type-specific", async () => {
 const fs = await import("node:fs");
 const source = fs.readFileSync(new URL("../src/components/scan-form.tsx", import.meta.url), "utf8");
 assert.match(source, /submitScan\(type, input, useAI \? "hybrid" : "rules"\)/);
 assert.match(source, /aria-live="polite"/);
 assert.match(source, /false positives or miss threats/);
 assert.match(source, /Analyzing with rules and AI…/);
 assert.match(source, /sends the submitted content to the configured OpenAI service/);
 assert.match(source, /AI assistance/);
 assert.match(source, /Rules \+ AI/);
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
   const body = JSON.parse(String(options?.body));
   assert.equal(body[type === "message" ? "content" : "url"], type === "message" ? "Synthetic suspicious text" : "https://example.com/path");
   assert.equal(body.analysis_mode, "rules");
   return Response.json({ result: { scan_id: "id", scan_type: type, risk_score: 0, rule_score: 0, final_score: 0, risk_level: "low", category: "unknown", indicators: [], recommendations: ["Stay cautious."], analysis_mode: "rules", ai_status: "not_requested", created_at: "2026-11-05T00:00:00Z" } }, { status: 201 });
  };
  assert.equal((await submitScan("message", "Synthetic suspicious text")).scan_type, "message");
  assert.equal((await submitScan("url", "https://example.com/path")).scan_type, "url");
  globalThis.fetch = async () => Response.json({ result: { scan_type: "url", risk_score: 101, rule_score: 0, final_score: 101, risk_level: "critical", indicators: [], recommendations: [], analysis_mode: "rules", ai_status: "not_requested" } }, { status: 201 });
  await assert.rejects(submitScan("message", "text"), /invalid result/);
  globalThis.fetch = async () => { throw new Error("network detail"); };
  await assert.rejects(submitScan("url", "https://example.com"), /Unable to reach ScamGuard/);
 } finally { globalThis.fetch = oldFetch; if (oldURL === undefined) delete process.env.NEXT_PUBLIC_API_URL; else process.env.NEXT_PUBLIC_API_URL = oldURL; }
});
test("scan API exposes hybrid completion and rules-only provider fallback", async () => {
 const original=globalThis.fetch, old=process.env.NEXT_PUBLIC_API_URL; process.env.NEXT_PUBLIC_API_URL="http://localhost:8080";
 const response={scan_id:"id",scan_type:"message",risk_score:40,rule_score:30,final_score:40,risk_level:"moderate",category:"phishing",indicators:[],recommendations:[],analysis_mode:"hybrid",ai_status:"completed",ai_assessment:{category:"phishing",risk_score:70,confidence:"medium",indicators:[{type:"urgency",reason:"Pressure to act."}],explanation:"Possible impersonation.",recommendations:[]},created_at:"2026-11-05T00:00:00Z"};
 try { globalThis.fetch=async (_url,opts)=>{assert.equal(JSON.parse(String(opts?.body)).analysis_mode,"hybrid"); return Response.json({result:response});}; assert.equal((await submitScan("message","suspicious","hybrid")).ai_status,"completed");
  globalThis.fetch=async()=>Response.json({result:{...response,analysis_mode:"rules",ai_status:"unavailable",ai_assessment:undefined,final_score:30,risk_score:30,risk_level:"moderate"}}); assert.equal((await submitScan("message","suspicious","hybrid")).ai_status,"unavailable");
 } finally {globalThis.fetch=original;if(old===undefined)delete process.env.NEXT_PUBLIC_API_URL;else process.env.NEXT_PUBLIC_API_URL=old;}
});
test("scanner validates empty, oversized, and unsupported URL input", () => {
 assert.match(validateScanInput("message", "  ") ?? "", /Enter a message/);
 assert.match(validateScanInput("message", "é".repeat(5001)) ?? "", /10,000 bytes/);
 assert.match(validateScanInput("url", "javascript:alert(1)") ?? "", /HTTP or HTTPS/);
 assert.equal(validateScanInput("url", "https://example.com/path"), null);
});
