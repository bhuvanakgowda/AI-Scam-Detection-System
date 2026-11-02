import { supabase } from '@/lib/supabaseClient';
import type { AdminStats } from '@/types/scan';

export async function fetchAdminStats(): Promise<AdminStats> {
  const { data, error } = await supabase.functions.invoke<AdminStats>('admin-stats', { method: 'GET' });
  if (error) throw error;
  if (!data || typeof data.total_scans !== 'number' || !Array.isArray(data.feedback)) {
    throw new Error('The admin statistics response was incomplete.');
  }
  return data;
}
