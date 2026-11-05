"use client";
import { useState, type FormEvent } from "react";
import Link from "next/link";
import { ArrowLeft, LoaderCircle, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { submitScan, validateScanInput } from "@/lib/scan-api";
import type { ScanResult } from "@/types/scan";
import { AuthGuard } from "@/components/auth-guard";
import { AccountNav } from "@/components/account-nav";
import { Button, Card, ErrorState } from "@/components/ui";
export function ScanForm({ type }: { type: "message" | "url" }) {
 const [input, setInput] = useState("");
 const [result, setResult] = useState<ScanResult | null>(null);
 const [error, setError] = useState("");
 const [busy, setBusy] = useState(false);
 const maximum = type === "message" ? 10000 : 2048;
 async function submit(event: FormEvent<HTMLFormElement>) {
  event.preventDefault(); setError(""); setResult(null);
  const validationError = validateScanInput(type, input);
  if (validationError) { setError(validationError); return; }
  setBusy(true);
  try { setResult(await submitScan(type, input)); }
  catch (e) { setError(e instanceof Error ? e.message : "The scan could not be completed. Try again."); }
  finally { setBusy(false); }
 }
 return <AuthGuard><AccountNav /><main id="main" className="container workspace scan-page"><Link href="/dashboard" className="back-link"><ArrowLeft size={16}/> Back to dashboard</Link><div className="workspace-heading scan-heading"><div><p className="eyebrow">RULE-BASED SECURITY CHECK</p><h1>{type === "message" ? "Analyze a suspicious message" : "Check a suspicious URL"}</h1><p>Results are advisory and may include false positives or miss threats. A low score cannot guarantee safety.</p></div></div><div className="scan-layout"><Card className="workspace-card"><form className="scan-form" onSubmit={submit}><label htmlFor="scan-input">{type === "message" ? "Message or email text" : "Full HTTP or HTTPS URL"}</label>{type === "message" ? <textarea id="scan-input" rows={8} maxLength={maximum} value={input} onChange={e => setInput(e.target.value)} placeholder="Paste the suspicious message here…" disabled={busy} aria-describedby="scan-privacy"/> : <input id="scan-input" type="url" maxLength={maximum} value={input} onChange={e => setInput(e.target.value)} placeholder="https://example.com/path" disabled={busy}/>}<p className="field-help">{new TextEncoder().encode(input).length.toLocaleString()} / {maximum.toLocaleString()} bytes · Submitted text is analyzed in memory and never saved.</p>{error && <div className="form-error"><ErrorState>{error}</ErrorState></div>}<Button type="submit" disabled={busy}>{busy ? <><LoaderCircle size={16} className="spin"/> Analyzing…</> : "Analyze with ScamGuard"}</Button></form><p className="scan-privacy" id="scan-privacy"><ShieldCheck size={15}/> Submitted content and extracted links are never opened, fetched, or stored. Only the analysis result is saved to your account.</p></Card><div aria-live="polite" className="scan-results">{result ? <Result result={result}/> : <Card className="scan-empty"><ShieldCheck size={34}/><h2>Your assessment will appear here</h2><p>Enter a message or URL to see transparent, rule-based indicators and safety recommendations.</p></Card>}</div></div></main></AuthGuard>;
}
function Result({ result }: { result: ScanResult }) {
 return <Card className="result-card"><div className="result-title"><div><p className="eyebrow">RULE-BASED ASSESSMENT</p><h2>Risk assessment</h2></div><span className={`risk-badge ${result.risk_level}`}><ShieldAlert size={16}/>{result.risk_level}</span></div><div className={`score-gauge ${result.risk_level}`} role="img" aria-label={`Risk score ${result.risk_score} out of 100, ${result.risk_level}`}><strong>{result.risk_score}</strong><span>/ 100 risk score</span></div><div className="result-meta"><span>Category</span><strong>{result.category.replaceAll("_", " ")}</strong><span>Analysis</span><strong>Deterministic rules</strong></div><section className="result-section"><h3>Indicators ({result.indicators.length})</h3>{result.indicators.length ? <ul className="indicator-list">{result.indicators.map(item => <li key={item.rule_id}><div><strong>{item.description}</strong><span>{item.rule_id.replaceAll("_", " ")}</span></div><b>+{item.score_contribution}</b></li>)}</ul> : <p className="clear-state"><ShieldCheck size={16}/> No configured risk indicators were found. This does not guarantee safety.</p>}</section><section className="result-section"><h3>Safety recommendations</h3><ul className="recommendation-list">{result.recommendations.map(item => <li key={item}><TriangleAlert size={15}/>{item}</li>)}</ul></section><p className="result-disclaimer">Automated rule-based results are advisory. ScamGuard can produce false positives and false negatives.</p></Card>;
}
