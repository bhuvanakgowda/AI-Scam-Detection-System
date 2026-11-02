import { supabase } from '@/lib/supabaseClient';
import type { RiskLevel } from '@/types/scan';

export async function submitFeedback(scanId: string, comment: string, suggestedLevel: RiskLevel | null) {
  const { error } = await supabase.from('feedback').insert({
    scan_id: scanId,
    comment: comment.trim(),
    suggested_level: suggestedLevel,
  });
  if (error) throw error;
}
