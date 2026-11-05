import { ShieldCheck } from "lucide-react";
import { Brand } from "./navbar";
export function Footer() {
  return (
    <footer className="container footer">
      <div>
        <Brand />
        <p>More awareness. Better decisions. A safer digital life.</p>
      </div>
      <div className="footer-note">
        <span>
          <ShieldCheck size={15} /> Built with security in mind
        </span>
        <p>© {new Date().getFullYear()} ScamGuard AI · Rule-based scanning</p>
      </div>
    </footer>
  );
}
