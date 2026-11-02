export type Severity = "low" | "medium" | "high" | "critical";

export type Finding = {
  code: string;
  title: string;
  severity: Severity;
  points: number;
  category: string;
  explanation: string;
  evidence: string | null;
};
