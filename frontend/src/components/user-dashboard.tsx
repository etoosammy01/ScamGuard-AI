"use client";
import Link from "next/link";
import {
  History,
  Link2,
  MessageSquareText,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { useAuth } from "./auth-provider";
import { Card, StatusIndicator } from "./ui";
export function UserDashboard() {
  const { state } = useAuth();
  if (state.status !== "authenticated") return null;
  const user = state.user;
  return (
    <>
      <div className="workspace-heading">
        <div>
          <p className="eyebrow">YOUR SECURITY WORKSPACE</p>
          <h1>Welcome, {user.full_name}.</h1>
          <p>A little awareness makes a big difference.</p>
        </div>
        <StatusIndicator tone="ok">Signed in securely</StatusIndicator>
      </div>
      <div className="stats-grid">
        {[
          { label: "Total scans", icon: ScanLine },
          { label: "High-risk detections", icon: ShieldAlert },
          { label: "Recent assessments", icon: ShieldCheck },
        ].map((item) => (
          <Card className="stat" key={item.label}>
            <div className="stat-label">
              {item.label}
              <item.icon className="blue" size={18} />
            </div>
            <strong aria-label="Not available">—</strong>
            <span>Available when scanning launches in Phase 3</span>
          </Card>
        ))}
      </div>
      <div className="workspace-grid">
        <Card className="workspace-card">
          <h2>
            <History size={20} />
            Recent scans
          </h2>
          <div className="empty-scans">
            <ScanLine size={34} />
            <h3>Your scan history will start here.</h3>
            <p>
              No scans have been performed. Live scanning and saved history are
              not available yet.
            </p>
            <Link href="/#scanner" className="text-link">
              Explore the scanner preview
            </Link>
          </div>
        </Card>
        <Card className="workspace-card account-summary">
          <h2>
            <UserRound size={20} />
            Your account
          </h2>
          <dl>
            <dt>Full name</dt>
            <dd>{user.full_name}</dd>
            <dt>Email</dt>
            <dd>{user.email}</dd>
            <dt>Account type</dt>
            <dd>{user.role === "admin" ? "Administrator" : "Standard user"}</dd>
          </dl>
          <Link href="/profile" className="button secondary">
            View profile
          </Link>
        </Card>
      </div>
      <div className="quick-scan-grid">
        <Link href="/#scanner" className="card quick-scan">
          <MessageSquareText size={24} />
          <div>
            <h3>Message scanner preview</h3>
            <p>Get familiar with the interface · Phase 3</p>
          </div>
        </Link>
        <Link href="/#scanner" className="card quick-scan">
          <Link2 size={24} />
          <div>
            <h3>URL scanner preview</h3>
            <p>See the planned link-checking flow · Phase 3</p>
          </div>
        </Link>
      </div>
      <p className="workspace-note">
        Scan statistics are unavailable placeholders, not simulated results.
      </p>
    </>
  );
}
