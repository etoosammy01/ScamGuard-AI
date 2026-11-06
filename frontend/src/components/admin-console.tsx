"use client";
import Link from "next/link";
import { useEffect, useState, useRef, useEffectEvent } from "react";
import { useAuth } from "./auth-provider";
import { AuthGuard } from "./auth-guard";
import { AccountNav } from "./account-nav";
import { Button, Card, ErrorState, LoadingState } from "./ui";
import { authRequest } from "@/lib/auth-api";

type AdminUser = {
  id: string;
  full_name: string;
  email: string;
  role: string;
  status: string;
  created_at: string;
};
type Audit = {
  id: string;
  actor_user_id: string | null;
  action: string;
  target_id: string;
  created_at: string;
  outcome: string;
};
type Bucket = { label: string; count: number };
type Data = {
  items?: (AdminUser | Audit)[];
  total?: number;
  metrics?: Record<string, number>;
  monitoring?: Record<string, string | number | boolean>;
  [key: string]: unknown;
};
const sections = [
  ["overview", "Overview", "/admin"],
  ["users", "Users", "/admin/users"],
  ["analytics", "Analytics", "/admin/analytics"],
  ["audit-logs", "Audit logs", "/admin/audit-logs"],
  ["settings", "Settings", "/admin/settings"],
];
export function AdminConsole({ section }: { section: string }) {
  return (
    <AuthGuard>
      <AdminAccess section={section} />
    </AuthGuard>
  );
}
function AdminAccess({ section }: { section: string }) {
  const { state } = useAuth();
  if (state.status !== "authenticated" || state.user.role !== "admin")
    return (
      <main id="main" className="container workspace">
        <Card>
          <ErrorState>Administrator access required.</ErrorState>
          <Link href="/dashboard">Return to dashboard</Link>
        </Card>
      </main>
    );
  return <AdminContent section={section} actor={state.user.id} />;
}
function AdminContent({ section, actor }: { section: string; actor: string }) {
  const [data, setData] = useState<Data | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(true);
  const [page, setPage] = useState(1),
    [search, setSearch] = useState(""),
    [query, setQuery] = useState(""),
    [days, setDays] = useState(30),
    [revision, setRevision] = useState(0);
  const [pending, setPending] = useState<AdminUser | null>(null),
    [saving, setSaving] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setBusy(true);
      setError("");
      setData(null);
      const params =
        section === "users"
          ? `?page=${page}&search=${encodeURIComponent(query)}`
          : section === "audit-logs"
            ? `?page=${page}`
            : section === "analytics"
              ? `?days=${days}`
              : "";
      try {
        const response = await authRequest(
          `/api/v1/admin/${section}${params}`,
          { signal: controller.signal },
        );
        if (!controller.signal.aborted) setData(response as Data);
      } catch (e) {
        if (!controller.signal.aborted)
          setError(
            e instanceof Error ? e.message : "Unable to load administration.",
          );
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    }, 0);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [section, page, query, days, revision]);
  async function changeStatus() {
    if (!pending) return;
    setSaving(true);
    setError("");
    try {
      await authRequest(
        `/api/v1/admin/users/${encodeURIComponent(pending.id)}/status`,
        {
          method: "PATCH",
          body: JSON.stringify({
            status: pending.status === "active" ? "suspended" : "active",
          }),
        },
      );
      setPending(null);
      setRevision((v) => v + 1);
    } catch {
      setError(
        "Account status could not be changed. Self-suspension and suspension of the last active administrator are blocked.",
      );
    } finally {
      setSaving(false);
    }
  }
  const title = sections.find((s) => s[0] === section)?.[1] ?? "Administration";
  return (
    <>
      <AccountNav />
      <main id="main" className="container workspace admin-page">
        <p className="eyebrow">PLATFORM ADMINISTRATION</p>
        <h1>{title}</h1>
        <p>Restricted operational data. Account actions are audited.</p>
        <nav className="admin-nav" aria-label="Administration">
          {sections.map(([key, text, href]) => (
            <Link
              key={key}
              href={href}
              aria-current={key === section ? "page" : undefined}
            >
              {text}
            </Link>
          ))}
        </nav>
        {section === "users" && (
          <form
            className="admin-controls"
            onSubmit={(e) => {
              e.preventDefault();
              setPage(1);
              setQuery(search);
            }}
          >
            <label>
              Search name or email{" "}
              <input
                value={search}
                maxLength={100}
                onChange={(e) => setSearch(e.target.value)}
              />
            </label>
            <Button type="submit">Search</Button>
          </form>
        )}
        {section === "analytics" && (
          <label>
            UTC date range{" "}
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            >
              {[7, 30, 90].map((n) => (
                <option key={n} value={n}>
                  Last {n} days
                </option>
              ))}
            </select>
          </label>
        )}
        {error && <ErrorState>{error}</ErrorState>}
        {busy ? (
          <LoadingState>Loading {title.toLowerCase()}…</LoadingState>
        ) : !data ? (
          <Button onClick={() => setRevision((v) => v + 1)}>Retry</Button>
        ) : (
          <>
            {section === "overview" && (
              <>
                <div className="admin-metrics">
                  {Object.entries(data.metrics ?? {}).map(([key, value]) => (
                    <Card key={key}>
                      <h2>{label(key)}</h2>
                      <strong>{value.toLocaleString()}</strong>
                    </Card>
                  ))}
                </div>
                <Card>
                  <h2>Operational monitoring</h2>
                  <dl className="admin-definitions">
                    {Object.entries(data.monitoring ?? {}).map(
                      ([key, value]) => (
                        <div key={key}>
                          <dt>{label(key)}</dt>
                          <dd>{String(value)}</dd>
                        </div>
                      ),
                    )}
                  </dl>
                </Card>
              </>
            )}
            {section === "users" && (
              <div className="admin-table-scroll">
                <table>
                  <caption>Registered accounts — page {page}</caption>
                  <thead>
                    <tr>
                      {["Account", "Role", "Status", "Created", "Action"].map(
                        (x) => (
                          <th key={x} scope="col">
                            {x}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {(data.items as AdminUser[]).map((u) => (
                      <tr key={u.id}>
                        <td>
                          {u.full_name}
                          <br />
                          <span>{u.email}</span>
                        </td>
                        <td>{u.role}</td>
                        <td>{u.status}</td>
                        <td>
                          <time dateTime={u.created_at}>
                            {new Date(u.created_at).toLocaleDateString()}
                          </time>
                        </td>
                        <td>
                          <Button
                            className={
                              u.status === "active"
                                ? "danger-button"
                                : "secondary"
                            }
                            disabled={u.id === actor}
                            onClick={() => setPending(u)}
                          >
                            {u.status === "active" ? "Suspend" : "Reactivate"}
                          </Button>
                          {u.id === actor && <span> Your account</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!data.items?.length && <p>No matching accounts.</p>}
              </div>
            )}
            {section === "audit-logs" && (
              <div className="admin-table-scroll">
                <table>
                  <caption>Security audit events — page {page}</caption>
                  <thead>
                    <tr>
                      {[
                        "Timestamp",
                        "Action",
                        "Actor",
                        "Target",
                        "Outcome",
                      ].map((x) => (
                        <th key={x} scope="col">
                          {x}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(data.items as Audit[]).map((a) => (
                      <tr key={a.id}>
                        <td>{new Date(a.created_at).toLocaleString()}</td>
                        <td>{label(a.action)}</td>
                        <td>{a.actor_user_id ?? "Operator"}</td>
                        <td>{a.target_id || "—"}</td>
                        <td>{a.outcome}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!data.items?.length && <p>No audit events recorded.</p>}
              </div>
            )}
            {["users", "audit-logs"].includes(section) && (
              <nav className="admin-controls" aria-label="Pagination">
                <Button
                  disabled={page <= 1}
                  onClick={() => {
                    setBusy(true);
                    setPage((p) => p - 1);
                  }}
                >
                  Previous
                </Button>
                <span>
                  Page {page} · {data.total ?? 0} records
                </span>
                <Button
                  disabled={page * 20 >= (data.total ?? 0)}
                  onClick={() => {
                    setBusy(true);
                    setPage((p) => p + 1);
                  }}
                >
                  Next
                </Button>
              </nav>
            )}
            {section === "analytics" && (
              <>
                <p>
                  Counts reflect retained records within the selected UTC range.
                  Empty dates have zero records. Weekly buckets start on Monday.
                </p>
                <div className="admin-metrics">
                  {[
                    "daily_scans",
                    "weekly_scans",
                    "risk_levels",
                    "categories",
                    "scan_types",
                    "analysis_modes",
                    "ai_statuses",
                    "registrations",
                  ].map((key) => (
                    <Card key={key}>
                      <h2>{label(key)}</h2>
                      <BucketChart rows={data[key] as Bucket[]} />
                    </Card>
                  ))}
                </div>
                <AIFallbackSummary rows={data.ai_statuses as Bucket[]} />
                <p>
                  AI status counts include persisted fallback outcomes; disabled
                  or unrequested AI is not a provider failure. A provider error
                  rate is not instrumented.
                </p>
              </>
            )}
            {section === "settings" && (
              <Card>
                <p>
                  Read-only deployment settings. Editable controls are deferred
                  to preserve security policy validation.
                </p>
                <dl className="admin-definitions">
                  {Object.entries(data).map(([key, value]) => (
                    <div key={key}>
                      <dt>{label(key)}</dt>
                      <dd>{String(value)}</dd>
                    </div>
                  ))}
                </dl>
              </Card>
            )}
          </>
        )}
        {pending && (
          <StatusDialog
            user={pending}
            saving={saving}
            error={error}
            onCancel={() => setPending(null)}
            onConfirm={() => void changeStatus()}
          />
        )}
      </main>
    </>
  );
}
export function StatusDialog({
  user,
  saving,
  onCancel,
  onConfirm,
  error,
}: {
  user: AdminUser;
  saving: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  error?: string;
}) {
  const ref = useDialogFocus(onCancel, saving);
  return (
    <div className="admin-modal-backdrop">
      <section
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby="status-title"
        className="admin-modal"
      >
        <h2 id="status-title">
          {user.status === "active"
            ? "Suspend account?"
            : "Reactivate account?"}
        </h2>
        <p>{user.email}</p>
        <p>
          {user.status === "active"
            ? "Active sessions will be revoked. Authenticated access will stop on the next request."
            : "The user will need to sign in again. Revoked sessions remain invalid."}
        </p>
        {error && <ErrorState>{error}</ErrorState>}
        <Button disabled={saving} onClick={onCancel}>
          Cancel
        </Button>
        <Button className="danger-button" disabled={saving} onClick={onConfirm}>
          {saving ? "Saving…" : "Confirm status change"}
        </Button>
      </section>
    </div>
  );
}
function label(value: string) {
  return value.replaceAll("_", " ");
}
export function BucketChart({ rows }: { rows: Bucket[] }) {
  if (!rows.length) return <p>No activity in this range.</p>;
  const total = rows.reduce((s, r) => s + r.count, 0),
    max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul className="admin-chart">
      {rows.map((r) => (
        <li key={r.label}>
          <span>{label(r.label)}</span>
          <meter
            min={0}
            max={max}
            value={r.count}
            aria-label={`${r.label}: ${r.count}`}
          />
          <span>
            {r.count} ({total ? ((r.count / total) * 100).toFixed(1) : "0"}%)
          </span>
        </li>
      ))}
    </ul>
  );
}

function useDialogFocus(onCancel: () => void, saving: boolean) {
  const ref = useRef<HTMLElement>(null);
  const cancelDialog = useEffectEvent(() => {
    if (!saving) onCancel();
  });
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const dialog = ref.current;
    dialog?.querySelector<HTMLButtonElement>("button")?.focus();
    function key(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        cancelDialog();
      }
      if (e.key === "Tab") {
        const buttons = dialog?.querySelectorAll<HTMLButtonElement>(
          "button:not(:disabled)",
        );
        if (!buttons?.length) {
          e.preventDefault();
          return;
        }
        const first = buttons[0],
          last = buttons[buttons.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      previous?.focus();
    };
  }, []);
  return ref;
}

export function AIFallbackSummary({ rows }: { rows: Bucket[] }) {
  const requested = rows.filter((r) =>
    [
      "completed",
      "disabled",
      "rate_limited",
      "unavailable",
      "validation_failed",
    ].includes(r.label),
  );
  const total = requested.reduce((sum, r) => sum + r.count, 0);
  const fallback = requested
    .filter((r) => r.label !== "completed")
    .reduce((sum, r) => sum + r.count, 0);
  return (
    <p>
      Hybrid-request fallback rate:{" "}
      {total
        ? `${((fallback / total) * 100).toFixed(1)}% (${fallback} of ${total})`
        : "No retained hybrid requests"}
      . Includes disabled AI, rate limits, unavailable analysis and invalid AI
      output; this is not a provider error rate.
    </p>
  );
}
