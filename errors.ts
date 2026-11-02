import type { AuthError } from '@supabase/supabase-js';

export function getAuthErrorMessage(error: AuthError | Error): string {
  const message = error.message.toLowerCase();
  if (message.includes('invalid login credentials')) return 'The email or password is incorrect.';
  if (message.includes('already registered') || message.includes('already exists')) {
    return 'An account with this email already exists. Try signing in instead.';
  }
  if (message.includes('password should be at least')) return 'Please choose a longer password.';
  if (message.includes('rate limit') || message.includes('too many')) {
    return 'Too many attempts. Please wait a minute and try again.';
  }
  if (message.includes('failed to fetch') || message.includes('network')) {
    return 'We could not reach the server. Check your connection and try again.';
  }
  return 'Something went wrong. Please try again.';
}

export async function getFunctionErrorMessage(error: unknown): Promise<string> {
  const fallback = 'Something went wrong. Please try again.';
  if (!(error instanceof Error)) return fallback;

  const context = (error as Error & { context?: unknown }).context;
  if (context instanceof Response) {
    try {
      const body = (await context.json()) as { error?: unknown };
      if (typeof body.error === 'string' && body.error.length > 0) return body.error;
    } catch {
      return fallback;
    }
  }
  if (error.message.toLowerCase().includes('fetch')) {
    return 'We could not reach the server. Check your connection and try again.';
  }
  return fallback;
}
