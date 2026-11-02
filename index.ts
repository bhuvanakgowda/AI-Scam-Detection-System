import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";
import { assess, fallbackExplanation, fallbackSummary, recommendationsFor, severityForScore, type Assessment } from "./assess.ts";
import { explainWithGemini, redactPersonalData, type Language } from "./gemini.ts";
import { detectScripts, evaluateMessage } from "./rules.ts";
import { analyzeUrlStructure, checkReputation, extractLinks, parseUrl, type Reputation } from "./url.ts";
import type { Finding } from "./types.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const LANGUAGES: Language[] = ["en", "kn", "hi"];
const MAX_MESSAGE_LENGTH = 2000;
const MAX_URL_LENGTH = 500;

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type ScanRequest = {
  type: "message" | "url";
  input: string;
  language: Language;
};

type Analysis = {
  findings: Finding[];
  assessment: Assessment;
  reputation: Reputation | null;
  scripts: string[];
  summary: string;
  explanation: string;
  recommendations: string[];
  aiUsed: boolean;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function parseRequest(body: unknown): ScanRequest {
  if (!body || typeof body !== "object") throw new HttpError(400, "Send the message or link to scan.");
  const candidate = body as Record<string, unknown>;

  if (candidate.type !== "message" && candidate.type !== "url") {
    throw new HttpError(400, "Choose whether you are scanning a message or a link.");
  }
  if (typeof candidate.input !== "string") throw new HttpError(400, "Enter something to scan.");

  const cleaned = Array.from(candidate.input)
    .filter((char) => {
      const code = char.codePointAt(0) ?? 0;
      return !(code === 0x7f || (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d));
    })
    .join("")
    .trim();
  const maxLength = candidate.type === "message" ? MAX_MESSAGE_LENGTH : MAX_URL_LENGTH;
  if (cleaned.length === 0) throw new HttpError(400, "Enter something to scan.");
  if (cleaned.length > maxLength) {
    throw new HttpError(400, `Please keep it under ${maxLength} characters.`);
  }

  const language = LANGUAGES.includes(candidate.language as Language) ? (candidate.language as Language) : "en";
  return { type: candidate.type, input: cleaned, language };
}

async function analyseMessage(text: string, language: Language): Promise<Analysis> {
  const findings = evaluateMessage(text);

  for (const link of extractLinks(text)) {
    const parsed = parseUrl(link);
    if (!parsed) continue;
    const linkFindings = analyzeUrlStructure(parsed, link);
    if (linkFindings.length === 0) continue;
    const linkScore = Math.min(100, linkFindings.reduce((sum, finding) => sum + finding.points, 0));
    findings.push({
      code: "suspicious_link",
      title: "Suspicious link in the message",
      severity: severityForScore(linkScore),
      points: Math.min(35, Math.round(linkScore * 0.5)),
      category: "Phishing link",
      explanation: `The link ${link} shows: ${linkFindings.map((finding) => finding.title.toLowerCase()).join("; ")}. The link was not opened.`,
      evidence: link,
    });
  }

  const assessment = assess(findings, null, text.length < 25);
  const ai = await explainWithGemini({
    kind: "message",
    content: redactPersonalData(text),
    language,
    level: assessment.level,
    score: assessment.score,
    category: assessment.category,
    findings: findings.map((finding) => ({ title: finding.title, explanation: finding.explanation })),
  });

  return {
    findings,
    assessment,
    reputation: null,
    scripts: detectScripts(text),
    summary: ai?.summary ?? fallbackSummary(assessment, findings, false),
    explanation: ai?.explanation ?? fallbackExplanation(findings),
    recommendations: ai?.recommendations ?? recommendationsFor(findings, assessment.level),
    aiUsed: ai !== null,
  };
}

async function analyseUrl(input: string, language: Language): Promise<Analysis> {
  const parsed = parseUrl(input);
  if (!parsed) throw new HttpError(400, "Please enter a valid web address, such as example.com/login.");

  const normalized = parsed.toString();
  const findings = analyzeUrlStructure(parsed, input);
  const reputation = await checkReputation(normalized);

  if (reputation.status === "malicious") {
    findings.push({
      code: "reputation_malicious",
      title: "Listed as unsafe by a reputation service",
      severity: "critical",
      points: 60,
      category: "Phishing link",
      explanation: reputation.detail,
      evidence: normalized,
    });
  }

  const assessment = assess(findings, reputation.status, false);
  const ai = await explainWithGemini({
    kind: "url",
    content: `Host: ${parsed.hostname}`,
    language,
    level: assessment.level,
    score: assessment.score,
    category: assessment.category,
    findings: findings.map((finding) => ({ title: finding.title, explanation: finding.explanation })),
  });

  return {
    findings,
    assessment,
    reputation,
    scripts: [],
    summary: ai?.summary ?? fallbackSummary(assessment, findings, true),
    explanation: ai?.explanation ?? fallbackExplanation(findings),
    recommendations: ai?.recommendations ?? recommendationsFor(findings, assessment.level),
    aiUsed: ai !== null,
  };
}

async function saveScan(
  supabase: SupabaseClient,
  request: ScanRequest,
  analysis: Analysis,
): Promise<string> {
  const { data: scan, error: scanError } = await supabase
    .from("scans")
    .insert({
      scan_type: request.type,
      input_text: request.input,
      language: request.language,
      detected_scripts: analysis.scripts,
      category: analysis.assessment.category,
      risk_score: analysis.assessment.score,
      risk_level: analysis.assessment.level,
      confidence: analysis.assessment.confidence,
      summary: analysis.summary,
      explanation: analysis.explanation,
      recommendations: analysis.recommendations,
      url_reputation: analysis.reputation,
      ai_used: analysis.aiUsed,
    })
    .select("id")
    .single();
  if (scanError || !scan) throw scanError ?? new Error("Scan insert returned no row");

  if (analysis.findings.length > 0) {
    const { error: indicatorError } = await supabase.from("scan_indicators").insert(
      analysis.findings.map((finding) => ({
        scan_id: scan.id,
        code: finding.code,
        title: finding.title,
        severity: finding.severity,
        points: finding.points,
        explanation: finding.explanation,
        evidence: finding.evidence,
      })),
    );
    if (indicatorError) {
      await supabase.from("scans").delete().eq("id", scan.id);
      throw indicatorError;
    }
  }

  return scan.id as string;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const token = req.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
    if (!token) throw new HttpError(401, "Please sign in to run a scan.");

    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await supabase.auth.getUser(token);
    if (userError || !userData.user) throw new HttpError(401, "Your session has expired. Please sign in again.");

    const request = parseRequest(await req.json().catch(() => null));
    const analysis = request.type === "message"
      ? await analyseMessage(request.input, request.language)
      : await analyseUrl(request.input, request.language);
    const scanId = await saveScan(supabase, request, analysis);

    return json({
      id: scanId,
      risk_score: analysis.assessment.score,
      risk_level: analysis.assessment.level,
    });
  } catch (err) {
    if (err instanceof HttpError) return json({ error: err.message }, err.status);
    console.error("scan failed", err);
    return json({ error: "The scan could not be completed. Please try again." }, 500);
  }
});
