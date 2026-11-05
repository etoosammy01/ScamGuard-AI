import {
  Activity,
  ArrowUpRight,
  CircleCheck,
  Link2,
  MessageSquareText,
  ShieldAlert,
  ShieldCheck,
  ScanLine,
} from "lucide-react";
import { Card, StatusIndicator } from "./ui";
const activities = [
  {
    title: "Account verification message",
    type: "Message",
    time: "Today, 10:42 AM",
    risk: "High risk",
    style: "high",
    icon: MessageSquareText,
  },
  {
    title: "Delivery tracking link",
    type: "Link",
    time: "Today, 9:18 AM",
    risk: "Medium risk",
    style: "medium",
    icon: Link2,
  },
  {
    title: "Team meeting reminder",
    type: "Message",
    time: "Yesterday",
    risk: "Low risk",
    style: "low",
    icon: MessageSquareText,
  },
];
export function Dashboard() {
  return (
    <section id="dashboard" className="container section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">CLARITY AT A GLANCE</p>
          <h2>Your security, in perspective.</h2>
          <p>A preview of the insights you’ll have at your fingertips.</p>
        </div>
        <span className="demo-label">DEMO DATA · ILLUSTRATIVE ONLY</span>
      </div>
      <div className="dashboard-shell">
        <div className="dashboard-top">
          <div>
            <span className="dashboard-icon">
              <Activity size={18} />
            </span>
            <strong>Security overview</strong>
          </div>
          <StatusIndicator tone="neutral">Demo workspace</StatusIndicator>
        </div>
        <div className="stats-grid">
          {[
            {
              icon: ScanLine,
              label: "Total scans",
              value: "128",
              note: "Illustrative scan count",
              color: "blue",
            },
            {
              icon: ShieldAlert,
              label: "High-risk detections",
              value: "24",
              note: "Illustrative threats flagged",
              color: "red",
            },
            {
              icon: ShieldCheck,
              label: "Low-risk assessments",
              value: "86",
              note: "Illustrative low-risk results",
              color: "green",
            },
          ].map((s) => (
            <Card className="stat" key={s.label}>
              <div className="stat-label">
                {s.label}
                <s.icon size={18} className={s.color} />
              </div>
              <strong>{s.value}</strong>
              <span>{s.note}</span>
            </Card>
          ))}
        </div>
        <div className="dashboard-content">
          <Card className="activity-card">
            <div className="card-heading">
              <h3>Recent activity</h3>
              <span className="muted">Sample history</span>
            </div>
            {activities.map((a) => (
              <div className="activity-row" key={a.title}>
                <span className="activity-icon">
                  <a.icon size={17} />
                </span>
                <div className="activity-detail">
                  <strong>{a.title}</strong>
                  <span>
                    {a.type} · {a.time}
                  </span>
                </div>
                <span className={`risk ${a.style}`}>{a.risk}</span>
              </div>
            ))}
          </Card>
          <Card className="distribution">
            <h3>Threat distribution</h3>
            <div className="chart-row">
              <div
                className="donut"
                role="img"
                aria-label="Demo distribution: 24 high, 18 medium, 86 low risk scans"
              >
                <div>
                  <strong>128</strong>
                  <span>demo scans</span>
                </div>
              </div>
              <div className="legend">
                <span>
                  <i className="dot high" />
                  High <b>24</b>
                </span>
                <span>
                  <i className="dot medium" />
                  Medium <b>18</b>
                </span>
                <span>
                  <i className="dot low" />
                  Low <b>86</b>
                </span>
              </div>
            </div>
          </Card>
        </div>
        <div className="quick-actions">
          <span>
            <CircleCheck size={16} /> Make checking a habit.
          </span>
          <a href="#scanner">
            Preview message scanner <ArrowUpRight size={14} />
          </a>
          <a href="#scanner">
            Preview link checker <ArrowUpRight size={14} />
          </a>
        </div>
      </div>
      <p className="demo-disclaimer">
        All figures and activity above are fictional examples. No scans have
        been performed.
      </p>
    </section>
  );
}
