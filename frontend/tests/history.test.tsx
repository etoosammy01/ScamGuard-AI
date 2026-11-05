import { test } from "node:test";
import assert from "node:assert/strict";
import { deleteAllScans, downloadScanCSV, getDashboardStats, listScans } from "../src/lib/history-api";

const scan = {
  scan_id: "00000000-0000-0000-0000-000000000001", scan_type: "message", risk_score: 60,
  risk_level: "high", category: "phishing", indicators: [], recommendations: [],
  analysis_mode: "rules", ai_status: "not_requested", rule_score: 60, final_score: 60,
  explanation: "One retained indicator.", original_content_available: false, created_at: "2026-06-01T12:00:00Z",
};
const stats = {
  total_scans: 1, message_scans: 1, url_scans: 0, low_risk_scans: 0, moderate_risk_scans: 0,
  high_risk_scans: 1, critical_risk_scans: 0, scans_last_7_days: 1, scans_last_30_days: 1,
  ai_assisted_scans: 0, rules_only_scans: 1, categories: [{ category: "phishing", count: 1 }],
  activity: [{ date: "2026-06-01", count: 1 }],
};
test("history client sends typed filters and validates real dashboard data", async () => {
  const previousURL = process.env.NEXT_PUBLIC_API_URL;
  const previousFetch = globalThis.fetch;
  process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080";
  const calls: { url: string; init?: RequestInit }[] = [];
  try {
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return String(url).includes("dashboard/stats")
        ? Response.json(stats)
        : Response.json({ items: [scan], page: 2, page_size: 20, total: 21 });
    };
    const page = await listScans({ page: 2, page_size: 20, risk_level: "high", search: "phishing" });
    assert.equal(page.items[0].scan_id, scan.scan_id);
    assert.match(calls[0].url, /page=2.*risk_level=high/);
    assert.equal(calls[0].init?.credentials, "include");
    const dashboard = await getDashboardStats();
    assert.equal(dashboard.high_risk_scans, 1);
    globalThis.fetch = async () => Response.json({ ...stats, critical_risk_scans: -1 });
    await assert.rejects(getDashboardStats(), /invalid response/i);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousURL === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = previousURL;
  }
});
test("history deletion and CSV export use authenticated API and validate downloads", async () => {
  const previousURL = process.env.NEXT_PUBLIC_API_URL;
  const previousFetch = globalThis.fetch;
  process.env.NEXT_PUBLIC_API_URL = "http://localhost:8080";
  const calls: { url: string; init?: RequestInit }[] = [];
  try {
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (init?.method === "DELETE") return Response.json({ deleted: 4 });
      return new Response("Scan ID,Risk score\n", { headers: { "Content-Type": "text/csv; charset=utf-8" } });
    };
    assert.equal(await deleteAllScans(), 4);
    const blob = await downloadScanCSV({ risk_level: "critical" });
    assert.equal(blob.type.replace(";charset", "; charset"), "text/csv; charset=utf-8");
    assert.equal(calls[0].init?.credentials, "include");
    assert.match(calls[1].url, /risk_level=critical/);
    globalThis.fetch = async () => new Response("bad", { status: 413 });
    await assert.rejects(downloadScanCSV({}), /Narrow the filters/);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousURL === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = previousURL;
  }
});
