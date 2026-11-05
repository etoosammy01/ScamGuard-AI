import { ShieldCheck, ArrowUpRight } from "lucide-react";
export function Brand() {
  return (
    <a className="brand" href="#home" aria-label="ScamGuard AI home">
      <span className="brand-mark">
        <ShieldCheck size={23} />
      </span>
      ScamGuard<span className="brand-ai">AI</span>
    </a>
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
          <a href="#dashboard">Dashboard</a>
        </div>
        <a className="button small" href="#scanner">
          Explore scanner <ArrowUpRight size={15} />
        </a>
      </nav>
    </header>
  );
}
