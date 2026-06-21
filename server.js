const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;

// ─── Catalog cache ────────────────────────────────────────────────────────────
let catalogCache = null;
let catalogCacheTime = 0;
const CACHE_TTL_MS = 60 * 60 * 1000;

async function fetchCatalog() {
  const now = Date.now();
  if (catalogCache && now - catalogCacheTime < CACHE_TTL_MS) return catalogCache;
  const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: { "User-Agent": "GuardianScan/1.0" },
  });
  if (!res.ok) throw new Error(`HIBP catalog error: ${res.status}`);
  catalogCache = await res.json();
  catalogCacheTime = Date.now();
  return catalogCache;
}

// ─── HIBP k-anonymity password check (free, exact, private) ──────────────────
async function checkPasswordHibp(password) {
  const hash = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "User-Agent": "GuardianScan/1.0", "Add-Padding": "true" },
  });
  if (!res.ok) throw new Error(`HIBP Passwords error: ${res.status}`);
  const text = await res.text();
  for (const line of text.split("\n")) {
    const [hashSuffix, countStr] = line.split(":");
    if (hashSuffix?.trim() === suffix)
      return { found: true, count: parseInt(countStr?.trim() ?? "0", 10) };
  }
  return { found: false, count: 0 };
}

// ─── LeakCheck.io free API — real per-email/phone/username breach sources ─────
async function checkLeakCheck(query) {
  try {
    const res = await fetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`,
      { headers: { "User-Agent": "GuardianScan/1.0", Accept: "application/json" },
        signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sourceRiskLevel(b) {
  const dc = b.DataClasses.map((d) => d.toLowerCase());
  if (b.IsSensitive || dc.some((d) =>
    d.includes("credit") || d.includes("bank") || d.includes("ssn") ||
    d.includes("passport") || d.includes("social security") || d.includes("tax")))
    return "critical";
  if (dc.some((d) => d.includes("password") || d.includes("pin"))) return "high";
  if (dc.some((d) => d.includes("phone") || d.includes("address") || d.includes("date of birth")))
    return "medium";
  return "low";
}

function riskLevelFromScore(score) {
  if (score === 0) return "safe";
  if (score <= 20) return "low";
  if (score <= 45) return "medium";
  if (score <= 70) return "high";
  return "critical";
}

const FIELD_MAP = {
  password: "Passwords", email: "Email addresses", phone: "Phone numbers",
  username: "Usernames", name: "Names", first_name: "Names", last_name: "Names",
  address: "Physical addresses", address1: "Physical addresses",
  dob: "Dates of birth", ip: "IP addresses", ip1: "IP addresses", ip2: "IP addresses",
  ssn: "Social security numbers", credit_card: "Credit card data",
  gender: "Genders", location: "Geographic locations", city: "Geographic locations",
  country: "Geographic locations", state: "Geographic locations",
  zip: "ZIP codes", province: "Geographic locations", region: "Geographic locations",
  profile_name: "Usernames", origin: "Geographic locations",
  company_name: "Employers", qqmail: "Email addresses",
};

function fieldsToDataClasses(fields) {
  const result = new Set();
  for (const f of fields) {
    const mapped = FIELD_MAP[f.toLowerCase()];
    if (mapped) result.add(mapped);
    else result.add(f.charAt(0).toUpperCase() + f.slice(1).replace(/_/g, " "));
  }
  return [...result];
}

function buildHibpSource(b) {
  return {
    name: b.Name, title: b.Title || null, date: b.BreachDate || null,
    addedDate: b.AddedDate || null, domain: b.Domain || null,
    dataClasses: b.DataClasses, pwnCount: b.PwnCount || null,
    description: b.Description || null, logoPath: b.LogoPath || null,
    isVerified: b.IsVerified, isSensitive: b.IsSensitive,
    riskLevel: sourceRiskLevel(b),
  };
}

function buildLeakCheckStub(src, dataClasses) {
  const fl = dataClasses.map((d) => d.toLowerCase());
  const hasPassword = fl.some((d) => d.includes("password"));
  const hasSensitive = fl.some((d) => d.includes("ssn") || d.includes("credit"));
  const hasPhone = fl.some((d) => d.includes("phone"));
  let riskLevel = "low";
  if (hasSensitive) riskLevel = "critical";
  else if (hasPassword) riskLevel = "high";
  else if (hasPhone) riskLevel = "medium";

  const cleanName = src.name.replace(/\.(com|net|org|io|me|fr|vn|ru|de|uk|in)$/i, "");
  const domain = src.name.includes(".") ? src.name : null;
  const dateStr = src.date ? (src.date.length === 7 ? src.date + "-01" : src.date) : null;

  return {
    name: cleanName, title: cleanName, date: dateStr, addedDate: null, domain,
    dataClasses, pwnCount: null,
    description: `Identified as a breach source by LeakCheck OSINT database. Your data was exposed here${dateStr ? " around " + new Date(dateStr).toLocaleDateString("en-US", { month: "long", year: "numeric" }) : ""}.`,
    logoPath: null, isVerified: true, isSensitive: hasSensitive, riskLevel,
  };
}

// Match LeakCheck source names → HIBP catalog entries
function matchToCatalog(sources, catalog) {
  const matched = [];
  const unmatched = [];
  const usedNames = new Set();

  for (const src of sources) {
    const raw = src.name.toLowerCase();
    const stripped = raw.replace(/\.(com|net|org|io|me|fr|vn|ru|de|uk|in|co)$/i, "").replace(/[^a-z0-9]/g, "");

    let found = catalog.find((b) => {
      const bn = b.Name.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bt = b.Title.toLowerCase().replace(/[^a-z0-9]/g, "");
      const bd = (b.Domain || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      return bn === stripped || bt === stripped || bd === stripped || bd.startsWith(stripped) || stripped.startsWith(bn);
    });
    if (!found)
      found = catalog.find((b) => (b.Domain || "").toLowerCase() === raw || (b.Domain || "").toLowerCase().replace("www.", "") === raw);

    if (found && !usedNames.has(found.Name)) { matched.push(found); usedNames.add(found.Name); }
    else if (!found) unmatched.push(src);
  }
  return { matched, unmatched };
}

// Risk score based purely on real confirmed signals
function computeRiskScore(confirmed, foundCount, fields, hibpMatches, unmatchedCount) {
  if (!confirmed) return 0;
  const fl = fields.map((f) => f.toLowerCase());
  let score = 15;
  if (foundCount > 10000) score += 25;
  else if (foundCount > 1000) score += 20;
  else if (foundCount > 100) score += 15;
  else if (foundCount > 0) score += 10;
  if (fl.some((f) => f.includes("password"))) score += 20;
  if (fl.some((f) => f.includes("ssn") || f.includes("social"))) score += 15;
  if (fl.some((f) => f.includes("credit") || f.includes("bank"))) score += 15;
  if (fl.some((f) => f.includes("phone"))) score += 5;
  if (fl.some((f) => f.includes("dob"))) score += 5;
  for (const b of hibpMatches) {
    if (b.IsSensitive) score += 5;
    const rl = sourceRiskLevel(b);
    if (rl === "critical") score += 3;
    else if (rl === "high") score += 2;
  }
  score += Math.min(unmatchedCount * 2, 10);
  return Math.min(score, 100);
}

// Generate personalized tips from the actual confirmed breach data
function buildTips(hibpBreaches, leakCheckFields, queryType, confirmed) {
  const tips = [];
  const fl = leakCheckFields.map((f) => f.toLowerCase());
  const allDc = [...new Set(hibpBreaches.flatMap((b) => b.DataClasses.map((d) => d.toLowerCase())))];
  const hasPasswords = fl.includes("password") || allDc.some((d) => d.includes("password"));
  const hasPhone = fl.includes("phone") || allDc.some((d) => d.includes("phone"));
  const hasSsn = fl.some((f) => f.includes("ssn")) || allDc.some((d) => d.includes("social security"));
  const hasFinancial = fl.some((f) => f.includes("credit") || f.includes("bank")) ||
    allDc.some((d) => d.includes("credit") || d.includes("bank"));

  const sorted = [...hibpBreaches].sort((a, b) => {
    const rl = { critical: 4, high: 3, medium: 2, low: 1 };
    return rl[sourceRiskLevel(b)] - rl[sourceRiskLevel(a)];
  });

  for (const b of sorted.slice(0, 3)) {
    const dc = b.DataClasses;
    const dateStr = b.BreachDate
      ? new Date(b.BreachDate).toLocaleDateString("en-US", { month: "long", year: "numeric" }) : null;
    const service = b.Title || b.Name;
    const domainStr = b.Domain ? ` (${b.Domain})` : "";
    const pwned = b.PwnCount ? b.PwnCount.toLocaleString() : "millions of";
    const bHasPassword = dc.some((d) => d.toLowerCase().includes("password"));
    const bHasFinancial = dc.some((d) => d.toLowerCase().includes("credit") || d.toLowerCase().includes("bank"));
    const bHasPhone = dc.some((d) => d.toLowerCase().includes("phone"));

    if (bHasPassword && dateStr)
      tips.push(`Change your ${service}${domainStr} password now — breached ${dateStr}, ${pwned} accounts exposed. Update every account using the same password.`);
    else if (bHasFinancial && dateStr)
      tips.push(`Financial data exposed in the ${service} breach (${dateStr}). Check statements for unauthorized charges and place a fraud alert with credit bureaus.`);
    else if (bHasPhone && dateStr)
      tips.push(`Phone number exposed in the ${service} breach (${dateStr}). Call your carrier and add a SIM-lock PIN to block SIM-swap attacks.`);
    else if (dateStr)
      tips.push(`${service} breach (${dateStr}) exposed: ${dc.slice(0, 3).join(", ")}. Log in and change credentials — enable 2FA if available.`);
  }

  if (hasPasswords && tips.length < 5)
    tips.push("Use a password manager (Bitwarden is free) to generate unique passwords for every account. Reusing passwords multiplies breach damage.");
  if (confirmed && tips.length < 5)
    tips.push("Enable two-factor authentication on email, banking, and social accounts. A stolen password cannot log in without the second factor.");
  if (hasSsn)
    tips.push("SSN was exposed. Freeze your credit at Equifax, Experian, and TransUnion immediately. File an identity theft report at identitytheft.gov.");
  if (hasFinancial && !hasSsn)
    tips.push("Financial data was exposed. Monitor bank statements and set up transaction alerts. Contact your bank to flag the account for suspicious activity.");
  if (hasPhone && tips.length < 5)
    tips.push("Phone number in breach data. Add a SIM-lock PIN with your carrier to prevent SIM-swap attacks that bypass SMS two-factor authentication.");
  if (queryType === "password") {
    tips.push("Never reuse this password anywhere. Generate a new unique password for every account.");
    tips.push("Enable two-factor authentication everywhere. Even a stolen password is useless with 2FA active.");
  }
  if (queryType === "email" && confirmed && tips.length < 5)
    tips.push("Watch for phishing emails. Attackers with your email send targeted messages impersonating the breached services. Verify all login prompts manually.");

  const seen = new Set();
  return tips.filter((t) => { if (seen.has(t)) return false; seen.add(t); return true; }).slice(0, 6);
}

// ─── POST /api/breach/check ───────────────────────────────────────────────────
app.post("/api/breach/check", async (req, res) => {
  const { type, value } = req.body;
  if (!type || !value) return res.status(400).json({ error: "type and value are required" });

  try {
    // ── Password ──────────────────────────────────────────────────────────────
    if (type === "password") {
      const result = await checkPasswordHibp(value);
      const score = result.found ? Math.min(50 + Math.log10(result.count + 1) * 15, 100) : 0;
      const tips = buildTips([], result.found ? ["password"] : [], "password", result.found);
      return res.json({
        found: result.found,
        query: { type, value: "••••••••" },
        totalBreaches: result.found ? 1 : 0,
        totalPwned: result.count,
        riskScore: Math.round(score),
        riskLevel: riskLevelFromScore(Math.round(score)),
        sources: result.found ? [{
          name: "HibpPasswordDatabase",
          title: "HIBP Pwned Passwords — 14 Billion+ Records",
          date: null, addedDate: null, domain: null,
          dataClasses: ["Passwords"], pwnCount: result.count,
          description: `This exact password appeared ${result.count.toLocaleString()} times in breach databases. Attackers use these lists in credential-stuffing attacks.`,
          logoPath: null, isVerified: true, isSensitive: true, riskLevel: "critical",
        }] : [],
        tips,
        summary: result.found
          ? `This password appeared in ${result.count.toLocaleString()} breach records. It is fully compromised.`
          : "This password was not found in any of the 14+ billion breach records checked. It currently appears safe.",
      });
    }

    const catalog = await fetchCatalog();

    // ── Shared handler for non-password types ─────────────────────────────────
    async function handleQuery(queryType, queryValue) {
      const leakCheck = await checkLeakCheck(queryValue);
      const confirmed = !!(leakCheck?.success && (leakCheck.found ?? 0) > 0);
      const lcSources = confirmed ? (leakCheck.sources ?? []) : [];
      const lcFields = confirmed ? (leakCheck.fields ?? []) : [];
      const lcFound = leakCheck?.found ?? 0;

      // For email: also check exact domain breaches
      let domainBreaches = [];
      if (queryType === "email") {
        const emailDomain = queryValue.split("@")[1]?.toLowerCase() ?? "";
        domainBreaches = catalog.filter((b) => b.Domain && b.Domain.toLowerCase() === emailDomain);
      }

      const { matched, unmatched } = matchToCatalog(lcSources, catalog);

      // Add domain breaches without duplication
      for (const db of domainBreaches) {
        if (!matched.find((b) => b.Name === db.Name)) matched.push(db);
      }

      const isConfirmed = confirmed || domainBreaches.length > 0;
      if (!isConfirmed) {
        return {
          found: false, totalBreaches: 0, totalPwned: 0, riskScore: 0, riskLevel: "safe",
          sources: [], tips: [
            `This ${queryType} was not found in any known breach database.`,
            "Keep monitoring — new breaches are discovered daily. Check back regularly.",
          ],
          summary: `No breach data found for this ${queryType}. It appears clean in our database.`,
        };
      }

      const dataClasses = fieldsToDataClasses(lcFields);
      const stubs = unmatched.slice(0, 15).map((s) => buildLeakCheckStub(s, dataClasses));
      const allSources = [...matched.map(buildHibpSource), ...stubs];
      const score = computeRiskScore(isConfirmed, lcFound, lcFields, matched, unmatched.length);
      const tips = buildTips(matched, lcFields, queryType, isConfirmed);
      const totalPwned = matched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
      const totalSources = lcSources.length || allSources.length;

      return {
        found: true, totalBreaches: allSources.length, totalPwned,
        riskScore: score, riskLevel: riskLevelFromScore(score),
        sources: allSources, tips,
        summary: `${queryType === "email" ? "Email" : queryType.charAt(0).toUpperCase() + queryType.slice(1)} confirmed in ${lcFound.toLocaleString()} records across ${totalSources} breach source${totalSources !== 1 ? "s" : ""}${dataClasses.length > 0 ? ". Exposed: " + dataClasses.slice(0, 4).join(", ") : ""}.`,
      };
    }

    if (type === "email" || type === "username" || type === "phone" || type === "ip") {
      const queryValue = type === "phone" ? value.replace(/[\s\-().+]/g, "") : value;
      const result = await handleQuery(type, queryValue);
      return res.json({ query: { type, value }, ...result });
    }

    // ── Domain ────────────────────────────────────────────────────────────────
    if (type === "domain") {
      const domainLower = value.toLowerCase().replace(/^www\./, "");
      const exactMatches = catalog.filter((b) => b.Domain && b.Domain.toLowerCase() === domainLower);
      const leakCheck = await checkLeakCheck(domainLower);
      const lcSources = leakCheck?.success && leakCheck.found > 0 ? (leakCheck.sources ?? []) : [];
      const { matched: lcMatched } = matchToCatalog(lcSources, catalog);
      const allMatched = [...exactMatches];
      for (const b of lcMatched) if (!allMatched.find((m) => m.Name === b.Name)) allMatched.push(b);

      const confirmed = allMatched.length > 0;
      const score = computeRiskScore(confirmed, leakCheck?.found ?? 0, leakCheck?.fields ?? [], allMatched, 0);
      const tips = buildTips(allMatched, leakCheck?.fields ?? [], "domain", confirmed);
      const totalPwned = allMatched.reduce((s, b) => s + (b.PwnCount ?? 0), 0);

      return res.json({
        found: confirmed, query: { type, value },
        totalBreaches: allMatched.length, totalPwned,
        riskScore: confirmed ? score : 0, riskLevel: confirmed ? riskLevelFromScore(score) : "safe",
        sources: allMatched.map(buildHibpSource), tips,
        summary: confirmed
          ? `Domain "${value}" involved in ${allMatched.length} confirmed breach${allMatched.length !== 1 ? "es" : ""}, exposing ~${totalPwned.toLocaleString()} records.`
          : `No known breaches found for domain "${value}". This domain appears clean.`,
      });
    }

    res.status(400).json({ error: "Unsupported query type" });
  } catch (err) {
    console.error("Breach check failed:", err);
    res.status(500).json({ error: "Failed to check breach data. Please try again." });
  }
});

// ─── GET /api/breach/catalog ──────────────────────────────────────────────────
app.get("/api/breach/catalog", async (req, res) => {
  try {
    const catalog = await fetchCatalog();
    res.json(catalog.map((b) => ({
      name: b.Name, title: b.Title, domain: b.Domain,
      breachDate: b.BreachDate, addedDate: b.AddedDate,
      pwnCount: b.PwnCount, description: b.Description,
      logoPath: b.LogoPath, dataClasses: b.DataClasses,
      isVerified: b.IsVerified, isFabricated: b.IsFabricated,
      isSensitive: b.IsSensitive, isRetired: b.IsRetired, isSpamList: b.IsSpamList,
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch breach catalog" });
  }
});

// ─── GET /api/breach/stats ────────────────────────────────────────────────────
app.get("/api/breach/stats", async (req, res) => {
  try {
    const catalog = await fetchCatalog();
    const totalPwned = catalog.reduce((s, b) => s + (b.PwnCount ?? 0), 0);
    const largest = catalog.reduce((max, b) => b.PwnCount > (max?.PwnCount ?? 0) ? b : max, catalog[0]);
    const newest = catalog.filter((b) => b.BreachDate)
      .sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate))[0];
    const dcCount = {};
    for (const breach of catalog)
      for (const dc of breach.DataClasses) dcCount[dc] = (dcCount[dc] ?? 0) + 1;
    res.json({
      totalBreaches: catalog.length, totalPwnedAccounts: totalPwned,
      totalDataClasses: new Set(catalog.flatMap((b) => b.DataClasses)).size,
      largestBreach: { name: largest?.Name ?? "", pwnCount: largest?.PwnCount ?? 0 },
      newestBreach: { name: newest?.Name ?? "", date: newest?.BreachDate ?? "" },
      mostCommonDataTypes: Object.entries(dcCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([type, count]) => ({ type, count })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch breach stats" });
  }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, () => console.log(`GuardianScan running at http://localhost:${PORT}`));
