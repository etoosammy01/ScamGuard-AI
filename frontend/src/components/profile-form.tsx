"use client";
import { useEffect, useState, type FormEvent } from "react";
import { getProfile, updateProfile } from "@/lib/auth-api";
import { useAuth } from "./auth-provider";
import { Button, Card, ErrorState, LoadingState } from "./ui";
export function ProfileForm() {
  const { state, setUser } = useAuth();
  const [profile, setProfile] = useState(state.user);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    getProfile(controller.signal)
      .then((user) => {
        if (!controller.signal.aborted) setProfile(user);
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setLoadError("Unable to load your profile. Reload to try again.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, []);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get("full_name") ?? "").trim();
    const bio = String(data.get("bio") ?? "");
    setError("");
    setSaved(false);
    if (
      [...name].length < 1 ||
      [...name].length > 200 ||
      [...bio].length > 500
    ) {
      setError(
        "Enter a name of 1–200 characters and a bio of up to 500 characters.",
      );
      return;
    }
    setBusy(true);
    try {
      const user = await updateProfile(name, bio);
      setProfile(user);
      setUser(user);
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to save profile.");
    } finally {
      setBusy(false);
    }
  }
  if (loading)
    return (
      <Card className="workspace-card">
        <LoadingState>Loading your profile…</LoadingState>
      </Card>
    );
  if (loadError || !profile)
    return (
      <Card className="workspace-card">
        <ErrorState>{loadError || "Profile unavailable."}</ErrorState>
      </Card>
    );
  return (
    <>
      <div className="workspace-heading">
        <div>
          <p className="eyebrow">ACCOUNT SETTINGS</p>
          <h1>Your profile.</h1>
          <p>Manage the basics of your ScamGuard account.</p>
        </div>
      </div>
      <Card className="workspace-card profile-card">
        <form className="account-form" onSubmit={submit}>
          <div>
            <label htmlFor="profile_name">Full name</label>
            <input
              id="profile_name"
              name="full_name"
              autoComplete="name"
              defaultValue={profile.full_name}
              maxLength={200}
              required
              disabled={busy}
            />
          </div>
          <div>
            <label htmlFor="profile_email">Email address</label>
            <input
              id="profile_email"
              value={profile.email}
              readOnly
              aria-describedby="email-help"
            />
            <p className="field-help" id="email-help">
              Email changes require a verified flow and are not available yet.
            </p>
          </div>
          <div>
            <label htmlFor="bio">
              About you <span className="optional">(optional)</span>
            </label>
            <textarea
              id="bio"
              name="bio"
              rows={4}
              defaultValue={profile.bio}
              maxLength={500}
              disabled={busy}
              placeholder="A short introduction. Avoid sensitive personal information."
            />
            <p className="field-help">Up to 500 characters.</p>
          </div>
          <div className="profile-meta">
            <span>Member since</span>
            <time dateTime={profile.created_at}>
              {new Date(profile.created_at).toLocaleDateString("en-US", {
                year: "numeric",
                month: "long",
                day: "numeric",
                timeZone: "UTC",
              })}
            </time>
          </div>
          {error && <ErrorState>{error}</ErrorState>}
          {saved && (
            <p className="saved-message" role="status">
              Your profile has been updated.
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save profile"}
          </Button>
        </form>
      </Card>
    </>
  );
}
