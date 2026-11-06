"use client";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Trash2 } from "lucide-react";
import { AuthGuard } from "@/components/auth-guard";
import { AccountNav } from "@/components/account-nav";
import { Button, Card, ErrorState, LoadingState } from "@/components/ui";
import { deleteScan, getScan, downloadSecurityReport } from "@/lib/history-api";
import type { ScanResult } from "@/types/scan";

export function ScanDetail(){
 const params=useParams<{id:string}>();const router=useRouter();const [scan,setScan]=useState<ScanResult|null>(null);const [busy,setBusy]=useState(true);const [downloading,setDownloading]=useState(false);const [deleting,setDeleting]=useState(false);const [error,setError]=useState("");
 const load=useCallback(async()=>{setBusy(true);setError("");try{setScan(await getScan(params.id));}catch(e){setError(e instanceof Error?e.message:"Scan details could not be loaded.");}finally{setBusy(false);}},[params.id]);
 useEffect(()=>{const timer=setTimeout(()=>void load(),0);return()=>clearTimeout(timer);},[load]);
 async function download(){if(!scan)return;setDownloading(true);setError("");try{const blob=await downloadSecurityReport(scan.scan_id);const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="scamguard-security-report.pdf";document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){setError(e instanceof Error?e.message:"Report download failed.");}finally{setDownloading(false);}}
 async function remove(){if(!scan||!window.confirm("Delete this scan record? This cannot be undone."))return;setDeleting(true);setError("");try{await deleteScan(scan.scan_id);router.replace("/history");}catch(e){setError(e instanceof Error?e.message:"Scan could not be deleted.");setDeleting(false);}}
 return <AuthGuard><AccountNav/><main id="main" className="container workspace history-page"><Link className="back-link" href="/history"><ArrowLeft size={16}/> Scan history</Link>{busy?<Card><LoadingState>Loading saved scan details…</LoadingState></Card>:error&&!scan?<Card><ErrorState>{error}</ErrorState><Button className="secondary" onClick={()=>void load()}>Retry</Button></Card>:scan&&<>
  <div className="workspace-heading detail-heading"><div><p className="eyebrow">SAVED SCAN RESULT</p><h1>Scan details</h1><p>Submitted content was not retained with this record.</p></div><Button onClick={()=>void download()} disabled={downloading}>{downloading?"Generating report…":"Download Security Report"}</Button><Button className="danger-button" onClick={()=>void remove()} disabled={deleting}><Trash2 size={16}/>{deleting?"Deleting…":"Delete scan"}</Button></div>
  {error&&<Card><ErrorState>{error}</ErrorState></Card>}
  <Card className="scan-detail-card"><div className="detail-score"><div><p className="eyebrow">FINAL RISK SCORE</p><strong>{scan.final_score}</strong><span>/ 100</span></div><span className={`risk-badge ${scan.risk_level}`}>{scan.risk_level}</span></div><dl className="detail-metadata"><dt>Scan ID</dt><dd className="scan-id">{scan.scan_id}</dd><dt>Scan type</dt><dd>{scan.scan_type==="url"?"URL":"Message"}</dd><dt>Category</dt><dd>{scan.category.replaceAll("_"," ")}</dd><dt>Analysis mode</dt><dd>{scan.analysis_mode==="hybrid"?"Rules + AI":"Rules only"}</dd><dt>AI status</dt><dd>{scan.ai_status.replaceAll("_"," ")}</dd><dt>Rule score</dt><dd>{scan.rule_score} / 100</dd><dt>Created (UTC)</dt><dd><time dateTime={scan.created_at}>{new Date(scan.created_at).toLocaleString(undefined,{timeZone:"UTC"})}</time></dd></dl>
  <section className="detail-section"><h2>Explanation</h2><p>{scan.explanation||"No explanation was retained for this scan."}</p><p className="privacy-note">Original message or URL: {scan.original_content_available?"retained":"unavailable; original content is not stored"}.</p></section>
  <section className="detail-section"><h2>Triggered indicators</h2>{scan.indicators.length?<ul className="indicator-list">{scan.indicators.map(i=><li key={i.rule_id}><div><strong>{i.description}</strong><span>{i.rule_id.replaceAll("_"," ")}</span></div><b>+{i.score_contribution}</b></li>)}</ul>:<p>No configured rule indicators were retained.</p>}</section>
  <section className="detail-section"><h2>Safety recommendations</h2>{scan.recommendations.length?<ul className="recommendation-list">{scan.recommendations.map((r,i)=><li key={`${i}-${r}`}>{r}</li>)}</ul>:<p>No recommendations were retained.</p>}</section>
  </Card>
 </>}</main></AuthGuard>;
}
