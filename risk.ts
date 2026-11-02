import type { RiskLevel } from '@/types/scan';

export interface RiskMeta {
  label: string;
  text: string;
  badge: string;
  bar: string;
  stroke: string;
  glow: string;
}

export const RISK_META: Record<RiskLevel, RiskMeta> = {
  low: {
    label: 'Low risk',
    text: 'text-emerald-300',
    badge: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
    bar: 'bg-emerald-400',
    stroke: '#34d399',
    glow: 'shadow-[0_0_40px_rgba(52,211,153,0.25)]',
  },
  medium: {
    label: 'Medium risk',
    text: 'text-amber-300',
    badge: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
    bar: 'bg-amber-400',
    stroke: '#fbbf24',
    glow: 'shadow-[0_0_40px_rgba(251,191,36,0.25)]',
  },
  high: {
    label: 'High risk',
    text: 'text-orange-300',
    badge: 'border-orange-400/30 bg-orange-400/10 text-orange-300',
    bar: 'bg-orange-400',
    stroke: '#fb923c',
    glow: 'shadow-[0_0_40px_rgba(251,146,60,0.25)]',
  },
  critical: {
    label: 'Critical risk',
    text: 'text-rose-300',
    badge: 'border-rose-400/30 bg-rose-400/10 text-rose-300',
    bar: 'bg-rose-500',
    stroke: '#fb7185',
    glow: 'shadow-[0_0_40px_rgba(251,113,133,0.3)]',
  },
};

export const RISK_LEVELS: RiskLevel[] = ['low', 'medium', 'high', 'critical'];

export const LANGUAGE_OPTIONS = [
  { value: 'en', label: 'English' },
  { value: 'kn', label: 'Kannada' },
  { value: 'hi', label: 'Hindi' },
] as const;
