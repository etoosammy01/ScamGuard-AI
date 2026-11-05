"use client";
import Link from "next/link";
import { useState } from "react";
import { LogOut, ShieldCheck } from "lucide-react";
import { useAuth } from "./auth-provider";
import { Button, ErrorState } from "./ui";
export function AccountNav() {
  const { state, logout } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function handleLogout() {
    setBusy(true);
    setError("");
    try {
      await logout();
    } catch {
      setError("Unable to sign out. Please try again.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <header className="nav-wrap">
      <nav
        className="container navbar account-navbar"
        aria-label="Account navigation"
      >
        <Link className="brand" href="/">
          <ShieldCheck className="blue" size={24} />
          ScamGuard<span className="brand-ai">AI</span>
        </Link>
        <div className="account-links">
          <Link href="/dashboard">Dashboard</Link>
          <Link href="/profile">Profile</Link>
          {state.status === "authenticated" && (
            <Button
              className="secondary small"
              onClick={() => void handleLogout()}
              disabled={busy}
            >
              <LogOut size={14} />
              {busy ? "Signing out…" : "Sign out"}
            </Button>
          )}
        </div>
      </nav>
      {error && (
        <div className="container logout-error">
          <ErrorState>{error}</ErrorState>
        </div>
      )}
    </header>
  );
}
