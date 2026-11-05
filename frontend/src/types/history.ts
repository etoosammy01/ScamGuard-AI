import type { ScanResult } from "@/types/scan";

export type ScanFilters = {
  page?: number;
  page_size?: number;
  risk_level?: string;
  scan_type?: string;
  category?: string;
  from?: string;
  to?: string;
  search?: string;
};
export type ScanPage = { items: ScanResult[]; page: number; page_size: number; total: number };
export type DashboardStats = {
  total_scans: number;
  message_scans: number;
  url_scans: number;
  low_risk_scans: number;
  moderate_risk_scans: number;
  high_risk_scans: number;
  critical_risk_scans: number;
  scans_last_7_days: number;
  scans_last_30_days: number;
  ai_assisted_scans: number;
  rules_only_scans: number;
  categories: { category: string; count: number }[];
  activity: { date: string; count: number }[];
};
