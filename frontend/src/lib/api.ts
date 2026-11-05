import type { Health } from "@/types/api";
export async function getHealth(signal?: AbortSignal): Promise<Health> {
  const base = process.env.NEXT_PUBLIC_API_URL;
  if (!base) throw new Error("API URL is not configured");
  const timeout = AbortSignal.timeout(5000);
  const response = await fetch(`${base.replace(/\/$/, "")}/api/v1/health`, {
    cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
  });
  if (!response.ok) throw new Error("API unavailable");
  const data: unknown = await response.json();
  if (
    !data ||
    typeof data !== "object" ||
    !("status" in data) ||
    data.status !== "ok" ||
    !("service" in data) ||
    data.service !== "scamguard-api" ||
    !("version" in data) ||
    typeof data.version !== "string"
  )
    throw new Error("Invalid health response");
  return data as Health;
}
