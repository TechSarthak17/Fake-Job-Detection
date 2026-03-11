const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "proton.me",
  "protonmail.com"
]);

const SCAM_PATTERNS = [
  { pattern: "registration fee", score: 25, label: "Scam keyword detected: registration fee" },
  { pattern: "registration charges", score: 25, label: "Scam keyword detected: registration charges" },
  { pattern: "training fee", score: 25, label: "Scam keyword detected: training fee" },
  { pattern: "training charges", score: 25, label: "Scam keyword detected: training charges" },
  { pattern: "processing fee", score: 25, label: "Scam keyword detected: processing fee" },
  { pattern: "processing charges", score: 25, label: "Scam keyword detected: processing charges" },
  { pattern: "security deposit", score: 25, label: "Scam keyword detected: security deposit" },
  { pattern: "documentation fee", score: 25, label: "Scam keyword detected: documentation fee" },
  { pattern: "documentation charges", score: 25, label: "Scam keyword detected: documentation charges" },
  { pattern: "onboarding fee", score: 25, label: "Scam keyword detected: onboarding fee" },
  { pattern: "onboarding charges", score: 25, label: "Scam keyword detected: onboarding charges" },
  { pattern: "guaranteed job", score: 20, label: "Unrealistic promise detected: guaranteed job" },
  { pattern: "urgent hiring", score: 10, label: "Pressure tactic detected: urgent hiring" },
  { pattern: "work from home with high salary", score: 15, label: "High-pay remote lure detected" },
  { pattern: "no interview", score: 20, label: "Suspicious shortcut detected: no interview" },
  { pattern: "instant joining", score: 15, label: "Pressure tactic detected: instant joining" }
];

const PAYMENT_PATTERNS = [
  /\bpayment\b/i,
  /\bpay\b/i,
  /\btransfer\b/i,
  /\bupi\b/i,
  /\bdeposit\b/i,
  /\brupees\b/i,
  /\brs\.?\b/i,
  /\u20B9/
];

const resultElement = document.getElementById("result");
const formElement = document.getElementById("jobForm");

const companyLookup = {
  byName: new Map(),
  byDomain: new Map()
};

let companyDatabaseLoaded = false;

fetch("data/companies.json")
  .then((response) => response.json())
  .then((data) => {
    buildCompanyLookup(data);
    companyDatabaseLoaded = true;
  })
  .catch(() => {
    renderDatabaseWarning();
  });

formElement.addEventListener("submit", (event) => {
  event.preventDefault();

  const companyName = document.getElementById("companyName").value.trim();
  const email = document.getElementById("email").value.trim();
  const website = document.getElementById("website").value.trim();
  const message = document.getElementById("message").value.trim();

  const analysis = analyzeJob({
    companyName,
    email,
    website,
    message
  });

  renderResult(analysis);
});

function buildCompanyLookup(data) {
  Object.entries(data).forEach(([company, domain]) => {
    const normalizedCompany = normalizeCompanyName(company);
    const normalizedDomain = normalizeDomain(domain);

    if (!normalizedCompany || !normalizedDomain) {
      return;
    }

    companyLookup.byName.set(normalizedCompany, normalizedDomain);
    companyLookup.byDomain.set(normalizedDomain, normalizedCompany);
  });
}

function analyzeJob({ companyName, email, website, message }) {
  const reasons = [];
  let risk = 0;

  const normalizedText = normalizeText(message);
  const emailDomain = getEmailDomain(email);
  const websiteDomain = getWebsiteDomain(website);
  const normalizedCompany = normalizeCompanyName(companyName);

  const findings = [
    ...detectFreeEmailRisk(emailDomain, normalizedCompany),
    ...detectScamKeywords(normalizedText),
    ...detectPaymentRequest(normalizedText),
    ...detectDomainRisk(normalizedCompany, websiteDomain)
  ];

  findings.forEach((finding) => {
    if (!reasons.includes(finding.label)) {
      risk += finding.score;
      reasons.push(finding.label);
    }
  });

  const cappedRisk = Math.min(risk, 100);
  const verdict = getRiskLevel(cappedRisk);

  return {
    risk: cappedRisk,
    verdict,
    reasons: reasons.length ? reasons : ["No major scam indicators detected"],
    summary: buildSummary(cappedRisk, reasons.length)
  };
}

function detectFreeEmailRisk(emailDomain, normalizedCompany) {
  if (!emailDomain || !FREE_EMAIL_DOMAINS.has(emailDomain)) {
    return [];
  }

  const label = normalizedCompany
    ? "Free email domain used instead of a company email"
    : "Free email domain used";

  return [{ score: 20, label }];
}

function detectScamKeywords(text) {
  const findings = [];

  SCAM_PATTERNS.forEach((item) => {
    if (text.includes(item.pattern)) {
      findings.push({ score: item.score, label: item.label });
    }
  });

  return findings;
}

function detectPaymentRequest(text) {
  const matches = PAYMENT_PATTERNS.filter((pattern) => pattern.test(text));

  if (matches.length === 0) {
    return [];
  }

  return [{
    score: matches.length >= 2 ? 20 : 10,
    label: "Possible payment request detected in the message"
  }];
}

function detectDomainRisk(companyName, websiteDomain) {
  if (!companyName || !websiteDomain) {
    return [];
  }

  const officialDomain = companyLookup.byName.get(companyName);

  if (!officialDomain) {
    return [];
  }

  if (websiteDomain === officialDomain || websiteDomain.endsWith(`.${officialDomain}`)) {
    return [];
  }

  const findings = [];

  if (domainContainsCompanyName(websiteDomain, companyName)) {
    findings.push({
      score: 30,
      label: `Possible fake domain pretending to be ${companyName}`
    });
  }

  const similarity = calculateDomainSimilarity(websiteDomain, officialDomain);

  if (similarity >= 0.74) {
    findings.push({
      score: 20,
      label: `Domain is similar to the official domain (${officialDomain})`
    });
  }

  return findings;
}

function getRiskLevel(score) {
  if (score <= 30) {
    return { label: "SAFE", className: "safe" };
  }

  if (score <= 60) {
    return { label: "SUSPICIOUS", className: "suspicious" };
  }

  return { label: "HIGH RISK", className: "high-risk" };
}

function buildSummary(score, reasonCount) {
  if (!companyDatabaseLoaded) {
    return "Analysis completed with email and message checks. Fake-domain verification is unavailable until the company database loads.";
  }

  if (score === 0) {
    return "The offer looks low risk based on the current checks, but manual verification is still recommended.";
  }

  return `Detected ${reasonCount} warning signal${reasonCount === 1 ? "" : "s"} across email, message, and website analysis.`;
}

function renderResult(analysis) {
  resultElement.className = "result-card";
  resultElement.innerHTML = `
    <div class="result-header">
      <div>
        <h2>Risk Assessment</h2>
        <p class="subtitle">${escapeHtml(analysis.summary)}</p>
      </div>
      <div class="risk-badge ${analysis.verdict.className}">${analysis.verdict.label}</div>
    </div>
    <div class="result-grid">
      <div class="metric">
        <span class="metric-label">Risk Score</span>
        <strong class="metric-value">${analysis.risk}/100</strong>
      </div>
      <div class="metric">
        <span class="metric-label">Severity</span>
        <strong class="metric-value">${analysis.verdict.label}</strong>
      </div>
      <div class="metric">
        <span class="metric-label">Signals Found</span>
        <strong class="metric-value">${analysis.reasons.length}</strong>
      </div>
    </div>
    <ul class="reason-list">
      ${analysis.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
    </ul>
  `;
}

function renderDatabaseWarning() {
  resultElement.className = "result-card";
  resultElement.innerHTML = `
    <h2>Risk Assessment</h2>
    <p class="subtitle">The company database could not be loaded. Keyword and email analysis still work, but fake-domain checks are temporarily unavailable.</p>
  `;
}

function normalizeText(text) {
  return text.toLowerCase().replace(/\s+/g, " ").trim();
}

function normalizeCompanyName(name) {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function normalizeDomain(value) {
  return value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]
    .trim();
}

function getEmailDomain(email) {
  const parts = email.toLowerCase().split("@");
  return parts.length === 2 ? parts[1].trim() : "";
}

function getWebsiteDomain(website) {
  if (!website) {
    return "";
  }

  const withProtocol = website.startsWith("http://") || website.startsWith("https://")
    ? website
    : `https://${website}`;

  try {
    const url = new URL(withProtocol);
    return normalizeDomain(url.hostname);
  } catch {
    return normalizeDomain(website);
  }
}

function domainContainsCompanyName(domain, companyName) {
  return domain.replace(/[^a-z0-9]/g, "").includes(companyName);
}

function calculateDomainSimilarity(domainA, domainB) {
  const left = domainA.replace(/[^a-z0-9]/g, "");
  const right = domainB.replace(/[^a-z0-9]/g, "");

  if (!left || !right) {
    return 0;
  }

  const distance = levenshteinDistance(left, right);
  return 1 - distance / Math.max(left.length, right.length);
}

function levenshteinDistance(a, b) {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const matrix = Array.from({ length: rows }, () => new Array(cols).fill(0));

  for (let row = 0; row < rows; row += 1) {
    matrix[row][0] = row;
  }

  for (let col = 0; col < cols; col += 1) {
    matrix[0][col] = col;
  }

  for (let row = 1; row < rows; row += 1) {
    for (let col = 1; col < cols; col += 1) {
      const cost = a[row - 1] === b[col - 1] ? 0 : 1;
      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + cost
      );
    }
  }

  return matrix[rows - 1][cols - 1];
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
