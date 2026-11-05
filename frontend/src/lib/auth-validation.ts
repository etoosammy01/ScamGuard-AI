import type { Registration } from "@/types/auth";
export function validateRegistration(input: Registration): string | null {
  const name = input.full_name.trim();
  if (
    [...name].length < 1 ||
    [...name].length > 200 ||
    /[\u0000-\u001f\u007f]/u.test(name)
  )
    return "Enter a name between 1 and 200 characters.";
  if (
    input.email.trim().length > 254 ||
    !/^[^\s@]+@[^\s@]+$/.test(input.email.trim())
  )
    return "Enter a valid email address.";
  if ([...input.password].length < 12)
    return "Use at least 12 characters for your password.";
  if (new TextEncoder().encode(input.password).length > 1024)
    return "Keep the password within 1,024 UTF-8 bytes.";
  if (input.password !== input.confirm_password)
    return "The passwords do not match.";
  return null;
}
export function authDestination(
  status: string,
  guestOnly: boolean,
): string | null {
  if (guestOnly && status === "authenticated") return "/dashboard";
  if (!guestOnly && status === "unauthenticated") return "/login";
  return null;
}
