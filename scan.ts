export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type ScanType = 'message' | 'url';
export type Language = 'en' | 'kn' | 'hi';
export type ReputationStatus = 'unknown' | 'clean' | 'malicious';

export interface UrlReputation {
  status: ReputationStatus;
  source: string;
  detail: string;
  threats: string[];
}

export interface ScanSummary {
  id: string;
  scan_type: ScanType;
  input_text: string;
  language: Language;
  category: string;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
}

export interface ScanRecord extends ScanSummary {
  detected_scripts: string[];
  confidence: number;
  summary: string;
  explanation: string;
  recommendations: string[];
  url_reputation: UrlReputation | null;
  ai_used: boolean;
}

export interface ScanIndicator {
  id: string;
  scan_id: string;
  code: string;
  title: string;
  severity: RiskLevel;
  points: number;
  explanation: string;
  evidence: string | null;
}

export interface ScanCreatedResponse {
  id: string;
  risk_score: number;
  risk_level: RiskLevel;
}

export interface FeedbackItem {
  id: string;
  comment: string;
  suggested_level: RiskLevel | null;
  created_at: string;
  scan_category: string | null;
  scan_risk_level: RiskLevel | null;
  scan_type: ScanType | null;
}

export interface LevelCount {
  level: RiskLevel;
  count: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface TrendPoint {
  date: string;
  count: number;
}

export interface AdminStats {
  total_scans: number;
  total_users: number;
  high_risk_scans: number;
  level_counts: LevelCount[];
  category_counts: CategoryCount[];
  trend: TrendPoint[];
  feedback: FeedbackItem[];
}
