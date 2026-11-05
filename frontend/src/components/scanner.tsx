import Link from "next/link";
import { Link2, MessageSquareText, ShieldCheck } from "lucide-react";
import { Card } from "./ui";
export function Scanner() {
  return (
    <section id="scanner" className="container section scanner-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">YOUR NEXT LINE OF DEFENSE</p>
          <h2>A little caution goes a long way.</h2>
          <p>Use transparent, rule-based checks to review suspicious content.</p>
        </div>
        <span className="demo-label">RULE-BASED SCANNING · PHASE 3</span>
      </div>
      <Card className="scanner-card">
        <div className="scanner-form">
          <p>Sign in to analyze submitted messages or HTTP/HTTPS links. Your submitted content is analyzed in memory and only the result is stored.</p>
          <div className="hero-actions">
            <Link className="button" href="/scan/message"><MessageSquareText size={17}/> Scan a message</Link>
            <Link className="button secondary" href="/scan/url"><Link2 size={17}/> Check a link</Link>
          </div>
        </div>
        <aside className="scanner-note">
          <span className="note-icon">
            <ShieldCheck size={25} />
          </span>
          <h3>Advisory rule-based checks</h3>
          <p id="preview-notice">
            Results can include false positives or miss threats. A low score is not a guarantee of safety.
          </p>
          <p>
            Never paste passwords, OTPs, payment information, or other secrets.
          </p>
        </aside>
      </Card>
    </section>
  );
}
