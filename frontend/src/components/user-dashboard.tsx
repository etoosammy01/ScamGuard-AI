"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Activity, ArrowRight, Link2, MessageSquareText, ScanLine, ShieldAlert, ShieldCheck } from "lucide-react";
import { useAuth } from "./auth-provider";
import { Card, Button, ErrorState, LoadingState, StatusIndicator } from "./ui";
import { getDashboardStats, listScans } from "@/lib/history-api";
import type { DashboardStats } from "@/types/history";
import type { ScanResult } from "@/types/scan";
import { DashboardCharts } from "./dashboard-charts";

export function UserDashboard() {
 const {state}=useAuth();const [stats,setStats]=useState<DashboardStats|null>(null);const [recent,setRecent]=useState<ScanResult[]>([]);const [busy,setBusy]=useState(true);const [error,setError]=useState("");
 const load=useCallback(async()=>{setBusy(true);setError("");try{const [s,p]=await Promise.all([getDashboardStats(),listScans({page:1,page_size:5})]);setStats(s);setRecent(p.items);}catch(e){setError(e instanceof Error?e.message:"Dashboard data could not be loaded.");}finally{setBusy(false);}},[]);
 useEffect(()=>{if(state.status!=="authenticated")return;const timer=setTimeout(()=>void load(),0);return()=>clearTimeout(timer);},[state.status,load]);
 if(state.status!=="authenticated")return null;
 const user=state.user;
 return <>
  <div className="workspace-heading dashboard-welcome"><div><p className="eyebrow">YOUR SECURITY WORKSPACE</p><h1>Welcome, {user.full_name}.</h1><p>Stay curious. Verify unexpected requests through a channel you trust.</p></div><StatusIndicator tone="ok">Signed in securely</StatusIndicator></div>
  <div className="dashboard-quick-actions"><Link className="card quick-scan" href="/scan/message"><MessageSquareText/><span><strong>Scan Message</strong><small>Check suspicious text</small></span><ArrowRight size={16}/></Link><Link className="card quick-scan" href="/scan/url"><Link2/><span><strong>Scan URL</strong><small>Inspect link structure</small></span><ArrowRight size={16}/></Link><Link className="card quick-scan" href="/history"><Activity/><span><strong>View Scan History</strong><small>Browse and export results</small></span><ArrowRight size={16}/></Link></div>
  {busy&&<Card><LoadingState>Loading your private dashboard data…</LoadingState></Card>}
  {error&&<Card className="dashboard-error"><ErrorState>{error}</ErrorState><Button className="secondary" onClick={()=>void load()}>Retry</Button></Card>}
  {!busy&&!error&&stats&&<>
   <div className="phase5-stats-grid">{[
    {label:"Total scans",value:stats.total_scans,icon:ScanLine,theme:"blue"},
    {label:"High-risk detections",value:stats.high_risk_scans,icon:ShieldAlert,theme:"red"},
    {label:"Critical-risk detections",value:stats.critical_risk_scans,icon:ShieldAlert,theme:"red"},
    {label:"Scans this week",value:stats.scans_last_7_days,icon:ShieldCheck,theme:"green"},
   ].map(x=><Card className="stat" key={x.label}><div className="stat-label">{x.label}<x.icon className={x.theme} size={18}/></div><strong>{x.value.toLocaleString()}</strong></Card>)}</div>
   {stats.total_scans===0?<Card className="history-empty dashboard-empty"><ScanLine size={36}/><h2>Your scan history starts here</h2><p>Scan a message or URL to get an advisory assessment. Original submitted content is not retained.</p><div><Link className="button" href="/scan/message">Scan a message</Link><Link className="button secondary" href="/scan/url">Scan a URL</Link></div></Card>:<>
    <DashboardCharts stats={stats}/>
    <div className="category-breakdown card"><div><h2>Scam category breakdown</h2><p>Categories supported by saved detection indicators.</p></div>{stats.categories.length?stats.categories.map(item=><div className="category-row" key={item.category}><span>{item.category.replaceAll("_"," ")}</span><b>{item.count}</b></div>):<p>No categorized threat indicators yet.</p>}</div>
    <Card className="recent-scans"><div className="recent-heading"><div><h2><Activity size={19}/> Recent scans</h2><p>Five most recent saved assessments.</p></div><Link href="/history" className="text-link">View all history <ArrowRight size={14}/></Link></div>
     {recent.length?<div className="recent-table-wrap"><table className="recent-table"><thead><tr><th>Scan</th><th>Risk</th><th>Category</th><th>Analysis</th><th>Date</th><th></th></tr></thead><tbody>{recent.map(item=><tr key={item.scan_id}><td>{item.scan_type==="url"?"URL":"Message"}</td><td><span className={`risk-badge ${item.risk_level}`}>{item.risk_level}</span></td><td>{item.category.replaceAll("_"," ")}</td><td>{item.ai_status==="completed"?"Rules + AI":item.analysis_mode==="hybrid"?`Rules + AI fallback (${item.ai_status.replaceAll("_"," ")})`:"Rules only"}</td><td>{new Date(item.created_at).toLocaleDateString()}</td><td><Link href={`/history/${encodeURIComponent(item.scan_id)}`} aria-label="View scan details"><ArrowRight size={15}/></Link></td></tr>)}</tbody></table></div>:<p>No recent scans.</p>}
    </Card>
   </>}
   <p className="stats-definition">“Last 7 days” is a rolling 168-hour window. Activity shows UTC calendar days. Statistics include only scans that remain in your history.</p>
  </>}
 </>;
}
