import type { Registration, User } from "@/types/auth";
export const UNAUTHORIZED_EVENT = "scamguard:unauthorized";
export class APIError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "APIError";
  }
}
export async function authRequest(
  path: string,
  options: RequestInit = {},
  notify = true,
): Promise<unknown> {
  const base = process.env.NEXT_PUBLIC_API_URL;
  if (!base)
    throw new APIError(
      0,
      "unavailable",
      "Unable to reach ScamGuard. Please try again.",
    );
  let response: Response;
  try {
    response = await fetch(`${base.replace(/\/$/, "")}${path}`, {
      ...options,
      credentials: "include",
      cache: "no-store",
      headers: options.body
        ? { "Content-Type": "application/json" }
        : undefined,
      signal: options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(5000)])
        : AbortSignal.timeout(5000),
    });
  } catch {
    throw new APIError(
      0,
      "unavailable",
      "Unable to reach ScamGuard. Please try again.",
    );
  }
  if (!response.ok) {
    if (response.status === 401 && notify && typeof window !== "undefined")
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    const messages: Record<number, string> = {
      400: "Please check the submitted fields.",
      401: "Email or password is incorrect, or your session has expired.",
      403: "This request was blocked. Check the configured frontend origin.",
      429: "Too many attempts. Please wait before trying again.",
    };
    throw new APIError(
      response.status,
      "request_failed",
      messages[response.status] ??
        "ScamGuard is temporarily unavailable. Please try again.",
    );
  }
  return response.status === 204 ? null : response.json();
}
function parseUser(data: unknown): User {
  if (!data || typeof data !== "object" || !("user" in data))
    throw new APIError(0, "invalid_response", "Unexpected account response.");
  const u = data.user;
  if (
    !u ||
    typeof u !== "object" ||
    !("id" in u) ||
    typeof u.id !== "string" ||
    !("full_name" in u) ||
    typeof u.full_name !== "string" ||
    !("email" in u) ||
    typeof u.email !== "string" ||
    !("bio" in u) ||
    typeof u.bio !== "string" ||
    !("role" in u) ||
    !["user", "admin"].includes(String(u.role)) ||
    !("created_at" in u) ||
    typeof u.created_at !== "string"
  )
    throw new APIError(0, "invalid_response", "Unexpected account response.");
  return u as User;
}
export async function currentUser(signal?: AbortSignal): Promise<User> {
  return parseUser(await authRequest("/api/v1/auth/me", { signal }, false));
}
export async function signIn(email: string, password: string): Promise<User> {
  return parseUser(
    await authRequest(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }) },
      false,
    ),
  );
}
export async function registerAccount(input: Registration): Promise<void> {
  await authRequest(
    "/api/v1/auth/register",
    { method: "POST", body: JSON.stringify(input) },
    false,
  );
}
export async function signOut(): Promise<void> {
  await authRequest("/api/v1/auth/logout", { method: "POST" });
}
export async function updateProfile(
  full_name: string,
  bio: string,
): Promise<User> {
  return parseUser(
    await authRequest("/api/v1/users/me", {
      method: "PATCH",
      body: JSON.stringify({ full_name, bio }),
    }),
  );
}
export async function getProfile(signal?: AbortSignal): Promise<User> {
  return parseUser(await authRequest("/api/v1/users/me", { signal }));
}
