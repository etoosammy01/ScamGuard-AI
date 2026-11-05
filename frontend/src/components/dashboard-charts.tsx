"use client";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DashboardStats } from "@/types/history";

const riskColors={low:"#54c6a2",moderate:"#e1b85e",high:"#ed8190",critical:"#e94e64"};
export function DashboardCharts({stats}:{stats:DashboardStats}){
 const risk=[{name:"Low",value:stats.low_risk_scans,color:riskColors.low},{name:"Moderate",value:stats.moderate_risk_scans,color:riskColors.moderate},{name:"High",value:stats.high_risk_scans,color:riskColors.high},{name:"Critical",value:stats.critical_risk_scans,color:riskColors.critical}];
 return <div className="analytics-grid">
  <section className="card analytics-card"><h2>Risk distribution</h2><p>Saved scan results by risk level.</p><div className="risk-chart" role="img" aria-label={risk.map(x=>`${x.name}: ${x.value}`).join(", ")}><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={risk} dataKey="value" nameKey="name" innerRadius={58} outerRadius={82} paddingAngle={3}>{risk.map(x=><Cell key={x.name} fill={x.color}/>)}</Pie><Tooltip contentStyle={{background:"#101929",border:"1px solid #344765",borderRadius:8}}/></PieChart></ResponsiveContainer></div><div className="chart-legend">{risk.map(x=><span key={x.name}><i style={{background:x.color}}/> {x.name}<b>{x.value}</b></span>)}</div></section>
  <section className="card analytics-card"><h2>Scan activity</h2><p>Daily scans during the last 30 UTC calendar days.</p><div role="img" aria-label="Daily scan activity for the last 30 days"><ResponsiveContainer width="100%" height={250}><BarChart data={stats.activity} margin={{top:12,right:8,bottom:4,left:-18}}><CartesianGrid stroke="#26354a" strokeDasharray="3 3" vertical={false}/><XAxis dataKey="date" tick={{fill:"#a0aec3",fontSize:10}} tickFormatter={value=>value.slice(5)} interval={4}/><YAxis allowDecimals={false} tick={{fill:"#a0aec3",fontSize:10}}/><Tooltip contentStyle={{background:"#101929",border:"1px solid #344765",borderRadius:8}}/><Bar dataKey="count" name="Scans" fill="#5595ff" radius={[4,4,0,0]}/></BarChart></ResponsiveContainer></div></section>
 </div>;
}
