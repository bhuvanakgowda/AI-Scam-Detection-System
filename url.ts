import type { Finding } from "./types.ts";

export type ReputationStatus = "unknown" | "clean" | "malicious";

export type Reputation = {
  status: ReputationStatus;
  source: string;
  detail: string;
  threats: string[];
};

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd",
  "ow.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly",
]);

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click",
  "buzz", "work", "loan", "icu", "cam", "monster", "rest",
]);

const FREE_HOSTS = [
  ".web.app", ".firebaseapp.com", ".netlify.app", ".github.io", ".pages.dev",
  ".vercel.app", ".weebly.com", ".glitch.me", ".000webhostapp.com",
  ".blogspot.com", ".wixsite.com", ".godaddysites.com", ".framer.app",
];

const BRANDS: Record<string, string[]> = {
  sbi: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"],
  hdfc: ["hdfcbank.com"],
  icici: ["icicibank.com"],
  axis: ["axisbank.com"],
  paytm: ["paytm.com"],
  phonepe: ["phonepe.com"],
  amazon: ["amazon.in", "amazon.com"],
  flipkart: ["flipkart.com"],
  paypal: ["paypal.com"],
  netflix: ["netflix.com"],
  whatsapp: ["whatsapp.com"],
  npci: ["npci.org.in"],
  irctc: ["irctc.co.in"],
  incometax: ["incometax.gov.in"],
};

const LURE_WORDS = [
  "login", "verify", "secure", "account", "update", "kyc", "bank", "upi",
  "refund", "reward", "bonus", "wallet", "signin", "confirm", "claim",
  "unlock", "otp", "gift", "offer",
];

const LINK_PATTERN =
  /\b(?:https?:\/\/[^\s<>"']+|www\.[^\s<>"']+|(?:[a-z0-9-]+\.)+(?:com|in|org|net|co|info|xyz|top|online|site|link|click|me|ly|io|tk|ml|ga|cf|gq|zip|mov|buzz|icu)(?:\/[^\s<>"']*)?)/gi;

export function parseUrl(raw: string): URL | null {
  const trimmed = raw.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (!url.hostname.includes(".")) return null;
  return url;
}

export function extractLinks(text: string): string[] {
  const found = text.match(LINK_PATTERN) ?? [];
  const cleaned = found.map((link) => link.replace(/[.,;:!?)\]]+$/, ""));
  return [...new Set(cleaned)].slice(0, 3);
}

export function analyzeUrlStructure(url: URL, raw: string): Finding[] {
  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const findings: Finding[] = [];
  const add = (
    code: string,
    title: string,
    severity: Finding["severity"],
    points: number,
    explanation: string,
    evidence: string | null,
  ) => {
    findings.push({ code, title, severity, points, category: "Phishing link", explanation, evidence });
  };

  if (url.protocol === "http:") {
    add("url_http", "Unencrypted connection", "medium", 10,
      "The link uses http instead of https, so information sent to it is not protected.", `http://${host}`);
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) {
    add("url_ip_host", "Raw IP address instead of a website name", "high", 30,
      "Banks and shops use domain names. A bare IP address is a common way to hide a scam site.", host);
  }

  if (url.username || url.password) {
    add("url_userinfo", "Hidden destination using @", "high", 30,
      "Text before an @ sign can make an address look trusted while it actually sends you somewhere else.", raw.slice(0, 120));
  }

  if (host.includes("xn--")) {
    add("url_punycode", "Look-alike (punycode) domain", "high", 25,
      "The domain uses encoded characters that can imitate a familiar website name.", host);
  }

  if (SHORTENERS.has(host)) {
    add("url_shortener", "Shortened link hides the real destination", "medium", 15,
      "Short links hide where you will actually land, which is why scammers use them.", host);
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    add("url_tld", "Domain ending often used by scams", "medium", 15,
      `The .${tld} ending is cheap and frequently used for temporary scam sites.`, host);
  }

  if (labels.length >= 5) {
    add("url_deep_subdomain", "Very deep subdomain chain", "medium", 10,
      "Long chains of words before the real domain are used to make a fake address look official.", host);
  }

  if ((host.match(/-/g) ?? []).length >= 3) {
    add("url_hyphens", "Many hyphens in the domain", "low", 8,
      "Long hyphenated domains such as 'secure-bank-login-verify' are often built to imitate real brands.", host);
  }

  const tokens = host.split(/[.-]/);
  for (const [brand, officialDomains] of Object.entries(BRANDS)) {
    const isOfficial = officialDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
    if (tokens.includes(brand) && !isOfficial) {
      add("url_brand", "Brand name used on an unofficial domain", "high", 30,
        `The address mentions "${brand}" but does not belong to its official website.`, host);
      break;
    }
  }

  const lowerAddress = `${host}${url.pathname}${url.search}`.toLowerCase();
  const lures = LURE_WORDS.filter((word) => lowerAddress.includes(word));
  if (lures.length >= 2) {
    const shown = lures.slice(0, 4).map((word) => `"${word}"`).join(", ");
    add("url_lure_words", "Login or payment words in the address", "high", 20,
      `The address contains words such as ${shown}, which are typical of fake login or payment pages.`, shown);
  }

  if (url.port && url.port !== "80" && url.port !== "443") {
    add("url_port", "Unusual port number", "low", 8,
      "Banking and shopping sites normally use the standard web ports.", `:${url.port}`);
  }

  if (FREE_HOSTS.some((suffix) => host.endsWith(suffix))) {
    add("url_free_host", "Free website hosting", "low", 10,
      "Free website builders are easy to set up and are often used for temporary scam pages.", host);
  }

  if (raw.length > 120) {
    add("url_long", "Very long web address", "low", 5,
      "Very long addresses with many parameters are often used to hide the real destination.", null);
  }

  return findings;
}

export async function checkReputation(normalizedUrl: string): Promise<Reputation> {
  const apiKey = Deno.env.get("GOOGLE_SAFE_BROWSING_API_KEY");
  if (!apiKey) {
    return {
      status: "unknown",
      source: "Not connected",
      detail: "No reputation service is connected, so this address has not been checked against known malicious-site lists. Unknown does not mean safe.",
      threats: [],
    };
  }

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "scamsathi", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: normalizedUrl }],
          },
        }),
        signal: AbortSignal.timeout(8000),
      },
    );
    if (!response.ok) throw new Error(`Reputation service responded with ${response.status}`);

    const data = (await response.json()) as { matches?: { threatType: string }[] };
    const threats = (data.matches ?? []).map((match) => match.threatType);
    if (threats.length > 0) {
      return {
        status: "malicious",
        source: "Google Safe Browsing",
        detail: "This address is listed as unsafe by Google Safe Browsing. Do not open it.",
        threats,
      };
    }
    return {
      status: "clean",
      source: "Google Safe Browsing",
      detail: "Not listed as unsafe by Google Safe Browsing when checked. This does not guarantee the site is safe.",
      threats: [],
    };
  } catch (err) {
    console.error("reputation lookup failed", err);
    return {
      status: "unknown",
      source: "Google Safe Browsing",
      detail: "The reputation check could not be completed, so the status is unknown.",
      threats: [],
    };
  }
}
