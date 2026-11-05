"use client";
import { useState } from "react";
import {
  Link2,
  MessageSquareText,
  LockKeyhole,
  ArrowRight,
} from "lucide-react";
import { Button, Card } from "./ui";
export function Scanner() {
  const [tab, setTab] = useState<"message" | "url">("message");
  return (
    <section id="scanner" className="container section scanner-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">YOUR NEXT LINE OF DEFENSE</p>
          <h2>A little caution goes a long way.</h2>
          <p>Get familiar with your future security companion.</p>
        </div>
        <span className="demo-label">PREVIEW · PHASE 3</span>
      </div>
      <Card className="scanner-card">
        <div className="scanner-form">
          <div
            className="tabs"
            role="tablist"
            aria-label="Scan type"
            onKeyDown={(event) => {
              if (
                ["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
              ) {
                event.preventDefault();
                const next =
                  event.key === "Home"
                    ? "message"
                    : event.key === "End"
                      ? "url"
                      : tab === "message"
                        ? "url"
                        : "message";
                setTab(next);
                document.getElementById(`${next}-tab`)?.focus();
              }
            }}
          >
            <button
              id="message-tab"
              role="tab"
              tabIndex={tab === "message" ? 0 : -1}
              aria-selected={tab === "message"}
              aria-controls="scan-panel"
              onClick={() => setTab("message")}
            >
              <MessageSquareText size={17} />
              Message
            </button>
            <button
              id="url-tab"
              role="tab"
              tabIndex={tab === "url" ? 0 : -1}
              aria-selected={tab === "url"}
              aria-controls="scan-panel"
              onClick={() => setTab("url")}
            >
              <Link2 size={17} />
              Link
            </button>
          </div>
          <div
            id="scan-panel"
            role="tabpanel"
            aria-labelledby={`${tab}-tab`}
            tabIndex={0}
          >
            <label htmlFor={tab}>
              {tab === "message" ? "Suspicious message" : "Suspicious URL"}
            </label>
            {tab === "message" ? (
              <textarea
                id="message"
                maxLength={10000}
                rows={4}
                placeholder="Paste a suspicious message here to explore the interface…"
                aria-describedby="preview-notice"
              />
            ) : (
              <input
                id="url"
                type="url"
                maxLength={2048}
                placeholder="https://example.com/suspicious-link"
                aria-describedby="preview-notice"
              />
            )}
          </div>
          <div className="form-bottom">
            <span>
              <LockKeyhole size={13} /> Inputs stay in your browser
            </span>
            <Button disabled>
              Scanning available in Phase 3 <ArrowRight size={15} />
            </Button>
          </div>
        </div>
        <aside className="scanner-note">
          <span className="note-icon">
            <ShieldIcon />
          </span>
          <h3>Pause. Check. Protect.</h3>
          <p id="preview-notice">
            This is an interface preview. Inputs are not transmitted or saved,
            and no analysis is performed. Live scanning arrives in Phase 3.
          </p>
          <p>
            Never paste passwords, financial details, or other sensitive
            information.
          </p>
        </aside>
      </Card>
    </section>
  );
}
function ShieldIcon() {
  return <LockKeyhole size={25} />;
}
