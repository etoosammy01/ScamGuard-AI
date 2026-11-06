import { APIError, authRequest, UNAUTHORIZED_EVENT } from "@/lib/auth-api";
import type { DashboardStats, ScanFilters, ScanPage } from "@/types/history";
import type { ScanResult } from "@/types/scan";

const base = () => process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "");
function record(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function validScan(value: unknown): value is ScanResult {
  if (!record(value)) return false;
  return typeof value.scan_id === "string" && ["message", "url"].includes(String(value.scan_type)) &&
    Number.isInteger(value.risk_score) && Number(value.risk_score) >= 0 && Number(value.risk_score) <= 100 &&
    ["low", "moderate", "high", "critical"].includes(String(value.risk_level)) &&
    typeof value.category === "string" && typeof value.analysis_mode === "string" && typeof value.ai_status === "string" &&
    Array.isArray(value.indicators) && Array.isArray(value.recommendations) && typeof value.explanation === "string" &&
    typeof value.created_at === "string" && value.original_content_available === false;
}
export async function listScans(filters: ScanFilters = {}): Promise<ScanPage> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value !== undefined && value !== "") query.set(key, String(value));
  const data: unknown = await authRequest(`/api/v1/scans${query.size ? `?${query}` : ""}`);
  if (!record(data) || !Array.isArray(data.items) || !data.items.every(validScan) || !Number.isInteger(data.page) || !Number.isInteger(data.page_size) || !Number.isInteger(data.total)) throw new APIError(0, "invalid_response", "Scan history returned an invalid response.");
  return data as unknown as ScanPage;
}
export async function getScan(id: string): Promise<ScanResult> {
  const data: unknown = await authRequest(`/api/v1/scans/${encodeURIComponent(id)}`);
  if (!record(data) || !validScan(data.scan)) throw new APIError(0, "invalid_response", "Scan details returned an invalid response.");
  return data.scan;
}
export async function getDashboardStats(): Promise<DashboardStats> {
  const data: unknown = await authRequest("/api/v1/dashboard/stats");
  if (!record(data)) throw new APIError(0, "invalid_response", "Dashboard statistics returned an invalid response.");
  const numeric = ["total_scans", "message_scans", "url_scans", "low_risk_scans", "moderate_risk_scans", "high_risk_scans", "critical_risk_scans", "scans_last_7_days", "scans_last_30_days", "ai_assisted_scans", "rules_only_scans"];
  if (numeric.some((key) => !Number.isInteger(data[key]) || Number(data[key]) < 0) || !Array.isArray(data.categories) || !Array.isArray(data.activity)) throw new APIError(0, "invalid_response", "Dashboard statistics returned an invalid response.");
  return data as unknown as DashboardStats;
}
export async function deleteScan(id: string): Promise<void> {
  await authRequest(`/api/v1/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
}
export async function deleteAllScans(): Promise<number> {
  const data: unknown = await authRequest("/api/v1/scans", { method: "DELETE" });
  if (!record(data) || !Number.isInteger(data.deleted) || Number(data.deleted) < 0) throw new APIError(0, "invalid_response", "The deletion response was invalid.");
  return Number(data.deleted);
}
export async function downloadScanCSV(filters: ScanFilters): Promise<Blob> {
  const api = base();
  if (!api) throw new APIError(0, "unavailable", "Unable to reach ScamGuard. Please try again.");
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value !== undefined && value !== "") query.set(key, String(value));
  let response: Response;
  try { response = await fetch(`${api}/api/v1/scans/export${query.size ? `?${query}` : ""}`, { credentials: "include", cache: "no-store", signal: AbortSignal.timeout(15000) }); }
  catch { throw new APIError(0, "unavailable", "Unable to download scan history. Please try again."); }
  if (!response.ok) {
    if (response.status === 401 && typeof window !== "undefined") window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    throw new APIError(response.status, "export_failed", response.status === 413 ? "Narrow the filters to export fewer scans." : "Scan history could not be exported.");
  }
  if (!response.headers.get("content-type")?.includes("text/csv")) throw new APIError(0, "invalid_response", "The export response was not a CSV file.");
  return response.blob();
}

export async function downloadSecurityReport(id: string): Promise<Blob> {
  const api = base();
  if (!api) throw new Error("API URL is not configured.");
  const response = await fetch(`${api}/api/v1/scans/${encodeURIComponent(id)}/report`, {
    credentials: "include", cache: "no-store", signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    if (response.status === 401 && typeof window !== "undefined") window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    throw new Error("Security report could not be downloaded. Please try again.");
  }
  if (!response.headers.get("content-type")?.includes("application/pdf")) throw new Error("The server did not return a PDF report.");
  const blob = await response.blob();
  if (!blob.size || blob.size > 2 * 1024 * 1024 || !((await blob.slice(0, 5).text()) === "%PDF-")) throw new Error("The PDF report was invalid.");
  return blob;
}
