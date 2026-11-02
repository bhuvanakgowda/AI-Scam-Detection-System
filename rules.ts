import type { Finding, Severity } from "./types.ts";

type RuleDef = {
  code: string;
  title: string;
  severity: Severity;
  points: number;
  category: string;
  explanation: string;
  test: (text: string) => string | null;
};

const JOB = /\b(?:jobs?|internships?|interns?|vacancy|vacancies|hiring|hr team|recruit(?:ment|er|ing)?|offer letter|work from home|wfh|part[- ]time|select(?:ed)?|shortlisted|naukri|kelasa)\b|ಕೆಲಸ|ನೌಕರಿ|ಉದ್ಯೋಗ|नौकरी|नोकरी|इंटर्नशिप/i;
const FEE = /\b(?:fee|fees|deposit|registration|processing|shulka|shulk)\b|ಶುಲ್ಕ|शुल्क|फीस/i;
const PAYMENT = /\b(?:pay|paying|payment|send|deposit|transfer|remit|kattu|kattabeku|bhejo|bhejiye|jama)\b|ಕಟ್ಟ|ಪಾವತಿ|ಕಳುಹಿ|ಜಮಾ|भेज|जमा|भुगतान/i;
const MONEY = /₹|\brs\.?\s*\d|\brs\b|\brupees?\b|\brupaye\b|\brupayi\b|\brupaya\b|\binr\b|\d\s*lakhs?\b|रुपये|रुपए|रुपया|ರೂಪಾಯಿ|ರೂ\.?|ಸಾವಿರ|हजार/i;
const CREDENTIAL = /\b(?:otp|one[- ]time password|cvv|upi pin|mpin|atm pin|pin|password|passcode|net ?banking|account number|debit card|card number|aadhaar|aadhar|pan card)\b|ಒಟಿಪಿ|ओटीपी|ಪಿನ್|पिन|ಪಾಸ್‌?ವರ್ಡ್|पासवर्ड/i;
const REQUEST = /\b(?:share|send|enter|provide|tell|give|submit|reply|verify|confirm|bhejo|bhejiye|kodi|kodu|kalisi)\b|ಹಂಚ|ಕಳುಹಿ|ಕೊಡಿ|ನಮೂದಿಸ|भेजें|भेजो|बताएं|बताओ|दीजिए|दें|दो/i;
const KYC = /\bkyc\b|know your customer|re-?kyc|(?:aadhaar|pan) (?:update|link)|link (?:your )?(?:aadhaar|pan)|केवाईसी|ಕೆವೈಸಿ/i;
const UPI = /\bupi\b|collect request|\bqr\b|qr code|google pay|gpay|phonepe|paytm/i;
const UPI_TRAP = /\b(?:refund|cashback|reversal|reversed|credited|receive|received|approve|accept|scan|collect)\b/i;
const LOTTERY = /\b(?:lottery|lucky draw|jackpot|you (?:have )?won|winner|congratulations|prize|reward points|free (?:gift|recharge|data))\b|लॉटरी|ಲಾಟರಿ|इनाम|ಬಹುಮಾನ/i;
const GUARANTEE = /\b(?:guaranteed?|assured|100\s*%\s*(?:safe|genuine)|risk[- ]free|no investment|daily income|weekly income|per day|per hour|earn (?:up to )?(?:rs\.?\s*|₹\s*)?\d[\d,]*|\d[\d,]*\s*(?:per|a|\/)\s*(?:day|hour|week|month))\b|ಗ್ಯಾರಂಟಿ|गारंटी|ಖಾತರಿ/i;
const URGENT = /\b(?:urgent(?:ly)?|immediately|immediate action|within \d+\s*(?:hours?|hrs?|minutes?|mins?)|today only|last chance|expire[sd]?|expiring|suspend(?:ed)?|blocked|deactivate[d]?|frozen|freeze|will be closed|legal action|arrest(?:ed)?|final warning|act now)\b|ತಕ್ಷಣ|तुरंत|तुरन्त|ब्लॉक|ಬ್ಲಾಕ್/i;
const SECRECY = /\b(?:do not tell|don'?t tell|keep (?:it )?(?:a )?secret|confidential|tell no one|don'?t share with (?:anyone|others))\b|ಯಾರಿಗೂ ಹೇಳ|किसी को मत बताना|किसी को न बताएं/i;
const ORG = /\b(?:sbi|hdfc|icici|axis bank|kotak|paytm|phonepe|google pay|amazon|flipkart|income tax|rbi|npci|police|cyber cell|trai|epfo|customs|fedex|dtdc|irctc|bank)\b/i;
const LINK_HINT = /https?:\/\/|www\./i;

function excerpt(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + length + 30);
  return `${start > 0 ? "..." : ""}${text.slice(start, end).trim()}${end < text.length ? "..." : ""}`;
}

function hit(pattern: RegExp, text: string): string | null {
  const match = pattern.exec(text);
  return match ? excerpt(text, match.index, match[0].length) : null;
}

const RULES: RuleDef[] = [
  {
    code: "job_fee",
    title: "Asks you to pay a job or registration fee",
    severity: "high",
    points: 40,
    category: "Fake job or internship offer",
    explanation: "Real employers do not charge candidates for registration, training, kits or processing. Paying a fee to be hired is the most common job scam.",
    test: (text) => {
      if (!JOB.test(text)) return null;
      return hit(FEE, text) ?? (PAYMENT.test(text) ? hit(MONEY, text) : null);
    },
  },
  {
    code: "job_offer",
    title: "Unsolicited job or internship offer",
    severity: "low",
    points: 10,
    category: "Fake job or internship offer",
    explanation: "Job or internship offers that arrive out of nowhere, especially ones saying you are selected without an interview, are a common scam opening.",
    test: (text) => hit(JOB, text),
  },
  {
    code: "advance_payment",
    title: "Asks you to pay money first",
    severity: "high",
    points: 30,
    category: "Advance-fee payment request",
    explanation: "The message asks you to send money before you receive anything. Genuine services do not need an upfront payment to deliver a job, prize or refund.",
    test: (text) => {
      if (JOB.test(text) || !PAYMENT.test(text)) return null;
      return hit(MONEY, text);
    },
  },
  {
    code: "guaranteed_earnings",
    title: "Guaranteed or unrealistic earnings",
    severity: "high",
    points: 20,
    category: "Investment or earnings scam",
    explanation: "Promises of guaranteed or fast income are used to lure people in. Genuine income always carries some uncertainty.",
    test: (text) => hit(GUARANTEE, text),
  },
  {
    code: "credential_request",
    title: "Asks for OTP, PIN or banking details",
    severity: "critical",
    points: 45,
    category: "OTP or credential theft",
    explanation: "Banks, UPI apps and employers never ask for your OTP, PIN, CVV or banking password. Anyone who asks for these is trying to take your money.",
    test: (text) => (REQUEST.test(text) ? hit(CREDENTIAL, text) : null),
  },
  {
    code: "kyc_update",
    title: "Fake KYC or account update request",
    severity: "high",
    points: 25,
    category: "Bank KYC scam",
    explanation: "Scammers pose as banks and claim your KYC or account must be updated to avoid blocking. Banks do not request KYC updates through links in messages.",
    test: (text) => hit(KYC, text),
  },
  {
    code: "upi_collect_trap",
    title: "UPI request that takes money instead of sending it",
    severity: "high",
    points: 20,
    category: "UPI payment scam",
    explanation: "Scammers send UPI collect requests or ask you to scan a QR code or approve a request to 'receive' a refund. Entering a UPI PIN always sends money out.",
    test: (text) => {
      if (!UPI.test(text)) return null;
      return hit(UPI_TRAP, text);
    },
  },
  {
    code: "lottery_bait",
    title: "Prize, lottery or reward bait",
    severity: "medium",
    points: 20,
    category: "Lottery or prize scam",
    explanation: "Winning a prize you never entered, followed by a request for a tax or fee to claim it, is a classic scam.",
    test: (text) => hit(LOTTERY, text),
  },
  {
    code: "urgency_pressure",
    title: "Creates urgency or fear",
    severity: "medium",
    points: 15,
    category: "Urgent threat or pressure tactic",
    explanation: "Messages that threaten blocking, suspension or legal action within a short time push you to act without thinking. Pause and verify through the official channel.",
    test: (text) => hit(URGENT, text),
  },
  {
    code: "secrecy_request",
    title: "Asks you to keep it secret",
    severity: "high",
    points: 15,
    category: "Social engineering",
    explanation: "Being told not to tell family, friends or your bank is a sign of manipulation. Honest organisations do not ask you to hide contact from others.",
    test: (text) => hit(SECRECY, text),
  },
  {
    code: "impersonation",
    title: "Claims to be a bank, government or well-known brand",
    severity: "medium",
    points: 10,
    category: "Impersonation of a trusted organisation",
    explanation: "The message names a bank, government body or popular app and pushes for action or a link. Scammers borrow trusted names to look legitimate.",
    test: (text) => {
      const org = hit(ORG, text);
      if (!org) return null;
      return URGENT.test(text) || CREDENTIAL.test(text) || KYC.test(text) || LINK_HINT.test(text) ? org : null;
    },
  },
];

export function evaluateMessage(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    const evidence = rule.test(text);
    if (evidence === null) continue;
    findings.push({
      code: rule.code,
      title: rule.title,
      severity: rule.severity,
      points: rule.points,
      category: rule.category,
      explanation: rule.explanation,
      evidence,
    });
  }
  return findings;
}

export function detectScripts(text: string): string[] {
  const scripts: string[] = [];
  if (/[A-Za-z]/.test(text)) scripts.push("latin");
  if (/[\u0C80-\u0CFF]/.test(text)) scripts.push("kannada");
  if (/[\u0900-\u097F]/.test(text)) scripts.push("devanagari");
  return scripts;
}
