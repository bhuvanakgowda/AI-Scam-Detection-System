import { supabase } from '@/lib/supabaseClient';
import type { Language, ScanCreatedResponse, ScanIndicator, ScanRecord, ScanSummary, ScanType } from '@/types/scan';

const SUMMARY_COLUMNS = 'id, scan_type, input_text, language, category, risk_score, risk_level, created_at';
const HISTORY_LIMIT = 200;

export interface ScanRequest {
  type: ScanType;
  input: string;
  language: Language;
}

export async function runScan(request: ScanRequest): Promise<ScanCreatedResponse> {
  const { data, error } = await supabase.functions.invoke<ScanCreatedResponse & { error?: string }>('scan', {
    body: request,
  });
  if (error) throw error;
  if (!data || typeof data.id !== 'string' || typeof data.risk_score !== 'number') {
    throw new Error('The scan returned an unexpected response.');
  }
  return data;
}

export async function fetchScan(scanId: string): Promise<ScanRecord | null> {
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', scanId)
    .maybeSingle();
  if (error) throw error;
  return data as ScanRecord | null;
}

export async function fetchScanIndicators(scanId: string): Promise<ScanIndicator[]> {
  const { data, error } = await supabase
    .from('scan_indicators')
    .select('id, scan_id, code, title, severity, points, explanation, evidence')
    .eq('scan_id', scanId)
    .order('points', { ascending: false });
  if (error) throw error;
  return (data ?? []) as ScanIndicator[];
}

export async function fetchRecentScans(limit: number): Promise<ScanSummary[]> {
  const { data, error } = await supabase
    .from('scans')
    .select(SUMMARY_COLUMNS)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return (data ?? []) as ScanSummary[];
}

export async function fetchHistory(): Promise<ScanSummary[]> {
  return fetchRecentScans(HISTORY_LIMIT);
}

export async function fetchRiskCounts(): Promise<Pick<ScanSummary, 'risk_level' | 'created_at'>[]> {
  const { data, error } = await supabase
    .from('scans')
    .select('risk_level, created_at')
    .order('created_at', { ascending: false })
    .limit(5000);
  if (error) throw error;
  return (data ?? []) as Pick<ScanSummary, 'risk_level' | 'created_at'>[];
}

export async function deleteScan(scanId: string): Promise<void> {
  const { error } = await supabase.from('scans').delete().eq('id', scanId);
  if (error) throw error;
}
