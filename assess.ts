import type { Finding, Severity } from "./types.ts";
import type { ReputationStatus } from "./url.ts";

export type Assessment = {
  score: number;
  level: Severity;
  confidence: number;
  category: string;
};

const URL_ADVICE =
  "Do not enter passwords, OTPs or payment details on this website, and do not open it on your phone or computer.";

const ADVICE: Record<string, string> = {
  job_fee: "Do not pay any registration, training, kit or processing fee. Genuine companies do not charge candidates to hire them.",
  job_offer: "Check the company on its official website and confirm the offer with your college placement cell.",
  advance_payment: "Do not send money to anyone before you have verified who they are and what the payment is for.",
  guaranteed_earnings: "Be wary of guaranteed or unusually high earnings. Real income always involves some uncertainty.",
  credential_request: "Never share an OTP, UPI PIN, CVV or banking password with anyone, even if they say they are from your bank.",
  kyc_update: "Banks do not ask you to update KYC through message links. Use your bank's official app or visit the branch.",
  upi_collect_trap: "Entering a UPI PIN always sends money out. Decline collect requests you did not expect.",
  lottery_bait: "Prizes for contests you never entered are not real. Do not pay tax or fees to claim a prize.",
  urgency_pressure: "Pause before acting. Scammers create urgency so that you do not stop to check.",
  secrecy_request: "Talk to a trusted family member or friend before doing anything the message asks.",
  impersonation: "Confirm the sender through the official app or website of the organisation, not through the contact in the message.",
  suspicious_link: "Do not open the link or enter any details on it. Type the official website address yourself.",
  reputation_malicious: "Do not open this address. Delete the message and report it.",
};

const REPORT_ADVICE =
  "If you have already shared details or paid, call the 1930 cyber crime helpline immediately and report at cybercrime.gov.in.";

export function severityForScore(score: number): Severity {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function assess(
  findings: Finding[],
  reputation: ReputationStatus | null,
  shortInput: boolean,
): Assessment {
  let score = Math.min(100, findings.reduce((sum, finding) => sum + finding.points, 0));
  if (findings.some((finding) => finding.severity === "critical")) score = Math.max(score, 75);
  if (reputation === "malicious") score = Math.max(score, 90);

  let confidence = findings.length > 0 ? Math.min(95, 50 + findings.length * 8) : 60;
  if (shortInput) confidence -= 15;
  if (reputation === "unknown") confidence = Math.min(confidence, 60);
  if (reputation === "malicious") confidence = 95;

  const strongest = [...findings].sort((a, b) => b.points - a.points)[0];
  return {
    score: Math.round(score),
    level: severityForScore(score),
    confidence: Math.max(20, Math.min(95, Math.round(confidence))),
    category: strongest?.category ?? "No known scam pattern",
  };
}

export function fallbackSummary(assessment: Assessment, findings: Finding[], isUrl: boolean): string {
  if (findings.length === 0) {
    return isUrl
      ? "No suspicious patterns were found in this address. This does not prove it is safe."
      : "No known scam warning signs were found in this message. Stay cautious with any money or personal details.";
  }
  const subject = isUrl ? "This link" : "This message";
  return `${subject} shows ${findings.length} warning sign${findings.length === 1 ? "" : "s"} linked to ${assessment.category.toLowerCase()}.`;
}

export function fallbackExplanation(findings: Finding[]): string {
  if (findings.length === 0) {
    return "The rule-based checks did not match any known scam pattern. Scam messages change often, so a clean result is never a guarantee.";
  }
  return findings.map((finding) => finding.explanation).join(" ");
}

export function recommendationsFor(findings: Finding[], level: Severity): string[] {
  const advice: string[] = [];
  for (const finding of findings) {
    const text = ADVICE[finding.code] ?? (finding.category === "Phishing link" ? URL_ADVICE : null);
    if (text && !advice.includes(text)) advice.push(text);
  }
  if (advice.length === 0) {
    advice.push("No known warning sign was found. Still never share an OTP, PIN or password with anyone.");
  }
  if (level === "high" || level === "critical") advice.push(REPORT_ADVICE);
  return advice.slice(0, 6);
}
