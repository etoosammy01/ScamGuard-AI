import Link from "next/link";
import { ShieldCheck, ArrowUpRight } from "lucide-react";
export function Brand() {
  return (
    <Link className="brand" href="/#home" aria-label="ScamGuard AI home">
      <span className="brand-mark">
        <ShieldCheck size={23} />
      </span>
      ScamGuard<span className="brand-ai">AI</span>
    </Link>
  );
}
export function Navbar() {
  return (
    <header className="nav-wrap">
      <nav className="container navbar" aria-label="Main navigation">
        <Brand />
        <div className="nav-links">
          <a href="#features">Features</a>
          <a href="#how-it-works">How it works</a>
          <Link href="/dashboard">Dashboard</Link>
        </div>
        <Link className="button small" href="/scan/message">
          Scan a message <ArrowUpRight size={15} />
        </Link>
      </nav>
    </header>
  );
}
