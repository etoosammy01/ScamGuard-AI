"use client";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import {
  Eye,
  EyeOff,
  ShieldCheck,
  ArrowRight,
  LockKeyhole,
} from "lucide-react";
import { registerAccount } from "@/lib/auth-api";
import { validateRegistration } from "@/lib/auth-validation";
import { useAuth } from "./auth-provider";
import { AuthGuard } from "./auth-guard";
import { Button, Card, ErrorState, LoadingState } from "./ui";
export function AuthForm({ mode }: { mode: "login" | "register" }) {
  const registration = mode === "register";
  const { login } = useAuth();
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [submitted, setSubmitted] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const data = new FormData(form);
    const input = {
      full_name: String(data.get("full_name") ?? ""),
      email: String(data.get("email") ?? "").trim(),
      password: String(data.get("password") ?? ""),
      confirm_password: String(data.get("confirm_password") ?? ""),
    };
    if (registration) {
      const invalid = validateRegistration(input);
      if (invalid) {
        setError(invalid);
        return;
      }
    }
    setBusy(true);
    try {
      if (registration) {
        await registerAccount(input);
        form.reset();
        setSubmitted(true);
      } else await login(input.email, input.password);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to continue. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <AuthGuard guestOnly>
      <main id="main" className="auth-page">
        <Link className="brand" href="/">
          <ShieldCheck className="blue" size={26} />
          ScamGuard<span className="brand-ai">AI</span>
        </Link>
        <Card className="auth-card">
          <span className="auth-emblem">
            <LockKeyhole size={25} />
          </span>
          <p className="eyebrow">YOUR SECURITY STARTS HERE</p>
          <h1>
            {registration
              ? "A safer digital life starts here."
              : "Welcome back."}
          </h1>
          <p>
            {registration
              ? "Create your ScamGuard account. Stay aware, stay in control."
              : "Sign in to your secure ScamGuard workspace."}
          </p>
          {submitted ? (
            <div className="registration-complete" role="status">
              <ShieldCheck size={28} />
              <h2>Check your next step.</h2>
              <p>
                If this address is eligible, your account has been created. You
                can now try signing in.
              </p>
              <Link className="button" href="/login">
                Continue to sign in <ArrowRight size={16} />
              </Link>
            </div>
          ) : (
            <form onSubmit={submit} className="account-form">
              {registration && (
                <div>
                  <label htmlFor="full_name">Full name</label>
                  <input
                    id="full_name"
                    name="full_name"
                    autoComplete="name"
                    required
                    maxLength={200}
                    placeholder="Your full name"
                    disabled={busy}
                  />
                </div>
              )}
              <div>
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  maxLength={254}
                  placeholder="you@example.com"
                  disabled={busy}
                />
              </div>
              <div>
                <label htmlFor="password">Password</label>
                <div className="password-field">
                  <input
                    id="password"
                    name="password"
                    type={visible ? "text" : "password"}
                    autoComplete={
                      registration ? "new-password" : "current-password"
                    }
                    required
                    minLength={registration ? 12 : undefined}
                    maxLength={1024}
                    aria-describedby={
                      registration ? "password-help" : undefined
                    }
                    disabled={busy}
                  />
                  <button
                    type="button"
                    onClick={() => setVisible(!visible)}
                    aria-label={visible ? "Hide password" : "Show password"}
                    aria-pressed={visible}
                  >
                    {visible ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
                {registration && (
                  <p id="password-help" className="field-help">
                    At least 12 characters. Long passphrases are welcome (up to
                    1,024 UTF-8 bytes).
                  </p>
                )}
              </div>
              {registration && (
                <div>
                  <label htmlFor="confirm_password">Confirm password</label>
                  <input
                    id="confirm_password"
                    name="confirm_password"
                    type={visible ? "text" : "password"}
                    autoComplete="new-password"
                    required
                    maxLength={1024}
                    disabled={busy}
                  />
                </div>
              )}
              {error && (
                <div className="form-error">
                  <ErrorState>{error}</ErrorState>
                </div>
              )}
              <Button type="submit" disabled={busy}>
                {busy ? (
                  <LoadingState>
                    {registration ? "Creating account…" : "Signing in…"}
                  </LoadingState>
                ) : (
                  <>
                    {registration ? "Create account" : "Sign in"}
                    <ArrowRight size={16} />
                  </>
                )}
              </Button>
            </form>
          )}
          <p className="auth-switch">
            {registration ? "Already have an account?" : "New to ScamGuard?"}{" "}
            <Link href={registration ? "/login" : "/register"}>
              {registration ? "Sign in" : "Create an account"}
            </Link>
          </p>
        </Card>
        <p className="auth-footnote">
          <LockKeyhole size={13} /> Your session stays in a secure, HTTP-only
          cookie.
        </p>
        <p className="auth-footnote">Scanning becomes available in Phase 3.</p>
      </main>
    </AuthGuard>
  );
}
