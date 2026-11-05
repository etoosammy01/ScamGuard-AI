import {
  ArrowRight,
  ArrowUpRight,
  BrainCircuit,
  ChartNoAxesCombined,
  Fingerprint,
  GraduationCap,
  History,
  Link2,
  LockKeyhole,
  MessageSquareText,
  Radar,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";
import { Card } from "@/components/ui";
import { Connectivity } from "@/components/connectivity";
import { Dashboard } from "@/components/dashboard";
import { Scanner } from "@/components/scanner";
import Link from "next/link";
const features = [
  {
    icon: BrainCircuit,
    title: "AI-Powered Scam Analysis",
    text: "A future second opinion on messages that don’t feel quite right.",
    tag: "PLANNED · PHASE 4",
  },
  {
    icon: Link2,
    title: "Phishing Link Detection",
    text: "Review suspicious URL syntax without opening or fetching the link.",
    tag: "RULE-BASED · LIVE",
  },
  {
    icon: ChartNoAxesCombined,
    title: "Clear Risk Assessments",
    text: "See a score, triggered indicators, and safer next steps.",
    tag: "RULE-BASED · LIVE",
  },
  {
    icon: History,
    title: "Scan History",
    text: "Revisit past assessments and spot patterns over time.",
    tag: "PLANNED · FUTURE PHASE",
  },
  {
    icon: GraduationCap,
    title: "Security Awareness",
    text: "Build the knowledge to recognize common scam tactics.",
    tag: "PLANNED · FUTURE PHASE",
  },
];
export default function Home() {
  return (
    <>
      <Navbar />
      <main id="main">
        <section id="home" className="container hero">
          <div className="hero-copy">
            <span className="pill">
              <span className="tiny-dot" /> YOUR DIGITAL PEACE OF MIND
            </span>
            <h1>
              Stay One Step
              <br />
              Ahead of <span>Scammers.</span>
            </h1>
            <p className="hero-description">
              Analyze suspicious messages and links with ScamGuard AI.
              Understand potential phishing threats before you trust, click, or
              share.
            </p>
            <div className="hero-actions">
              <Link className="button" href="/scan/message">
                <MessageSquareText size={18} /> Scan a Message{" "}
                <ArrowRight size={16} />
              </Link>
              <Link className="button secondary" href="/scan/url">
                <Link2 size={18} /> Check a Link
              </Link>
            </div>
            <p className="hero-disclaimer">
              <LockKeyhole size={13} /> Advisory rule-based scans · Sign in to use
            </p>
          </div>
          <div
            className="hero-visual"
            aria-label="ScamGuard security illustration"
          >
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="radar-grid" />
            <div className="shield-glow">
              <ShieldCheck strokeWidth={1.2} />
            </div>
            <div className="floating-card float-top">
              <span className="mini-icon">
                <Fingerprint size={20} />
              </span>
              <div>
                <strong>Designed for trust</strong>
                <span>Security at the foundation</span>
              </div>
            </div>
            <div className="floating-card float-bottom">
              <span className="mini-icon green">
                <Radar size={21} />
              </span>
              <div>
                <strong>Think before you click.</strong>
                <span>A safer habit starts here.</span>
              </div>
              <Sparkles size={15} className="blue" />
            </div>
            <span className="visual-caption">
              AWARENESS IS YOUR FIRST DEFENSE
            </span>
          </div>
        </section>
        <div className="trust-band">
          <div className="container trust-content">
            <span>
              <ShieldCheck size={17} /> Built for everyday digital safety
            </span>
            <span>
              <LockKeyhole size={17} /> Privacy-conscious by design
            </span>
            <Connectivity />
          </div>
        </div>
        <section id="features" className="container section">
          <div className="section-heading">
            <div>
              <p className="eyebrow">CONFIDENCE, BUILT IN</p>
              <h2>Smarter checks. Safer choices.</h2>
              <p>
                The tools we’re building to help you navigate a world of digital
                threats.
              </p>
            </div>
            <Link className="text-link" href="#scanner">
              Explore the preview <ArrowUpRight size={16} />
            </Link>
          </div>
          <div className="features-grid">
            {features.map((f) => (
              <Card className="feature" key={f.title}>
                <span className="feature-icon">
                  <f.icon size={23} />
                </span>
                <h3>{f.title}</h3>
                <p>{f.text}</p>
                <span className="feature-tag">{f.tag}</span>
              </Card>
            ))}
          </div>
        </section>
        <section id="how-it-works" className="how-section">
          <div className="container section">
            <div className="center-heading">
              <p className="eyebrow">SIMPLE BY DESIGN</p>
              <h2>From uncertainty to understanding.</h2>
              <p>From a suspicious message or URL to an explainable assessment.</p>
            </div>
            <div className="steps">
              {[
                {
                  title: "Submit something suspicious",
                  text: "Paste a message or link you want to check.",
                },
                {
                  title: "Let ScamGuard analyze",
                  text: "Threat indicators will be assessed for potential risks.",
                },
                {
                  title: "Understand the assessment",
                  text: "Review a clear risk level and helpful explanation.",
                },
                {
                  title: "Take safer action",
                  text: "Use the insights to make a more informed decision.",
                },
              ].map((s, i) => (
                <div className="step" key={s.title}>
                  <span className="step-number">0{i + 1}</span>
                  <h3>{s.title}</h3>
                  <p>{s.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
        <Dashboard />
        <Scanner />
        <section className="container awareness">
          <ShieldCheck size={27} />
          <div>
            <h3>Your best defense starts with a pause.</h3>
            <p>
              Unexpected urgency, requests for money, and pressure to share
              personal details deserve a second look.
            </p>
          </div>
          <a href="#how-it-works">
            Build safer habits <ArrowRight size={16} />
          </a>
        </section>
      </main>
      <Footer />
    </>
  );
}
