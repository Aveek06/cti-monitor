// Vercel serverless function — proxies CISA KEV + NVD CVE API
// Enriches the 90 most-recently-added KEV entries with NVD CVSS scores.
// CDN-cached for 2 hours; bust with ?bust=1.

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fetchKev() {
  const r = await fetch(KEV_URL, {
    headers: { "User-Agent": "cti-dashboard/1.0" },
  });
  if (!r.ok) throw new Error(`CISA KEV fetch failed: ${r.status}`);
  const d = await r.json();
  const entries = d.vulnerabilities || [];
  return entries.sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded));
}

function parseCvss(vuln) {
  if (!vuln?.metrics) return null;
  const m31 = vuln.metrics.cvssMetricV31?.[0]?.cvssData;
  const m30 = vuln.metrics.cvssMetricV30?.[0]?.cvssData;
  const m2  = vuln.metrics.cvssMetricV2?.[0]?.cvssData;
  const primary = m31 || m30;
  if (primary) {
    return {
      score:    primary.baseScore,
      severity: primary.baseSeverity,
      version:  primary.version,
      vector:   primary.vectorString || null,
    };
  }
  if (m2) {
    const s = m2.baseScore;
    return {
      score:    s,
      severity: s >= 7 ? "HIGH" : s >= 4 ? "MEDIUM" : "LOW",
      version:  "2.0",
      vector:   m2.vectorString || null,
    };
  }
  return null;
}

async function fetchNvdCvss(cveId, apiKey) {
  try {
    const url = `${NVD_URL}?cveId=${encodeURIComponent(cveId)}`;
    const headers = { "User-Agent": "cti-dashboard/1.0" };
    if (apiKey) headers.apiKey = apiKey;
    const r = await fetch(url, { headers });
    if (!r.ok) return null;
    const d = await r.json();
    const vuln = d.vulnerabilities?.[0]?.cve;
    return vuln ? parseCvss(vuln) : null;
  } catch {
    return null;
  }
}

async function buildCvssMap(cveIds, apiKey) {
  const map = {};
  const BATCH = 10;
  // With API key: ~50 req/30s limit → 700ms between batches of 10 is safe
  // Without key:  ~5 req/30s limit  → 6500ms between batches of 10
  const DELAY = apiKey ? 700 : 6500;

  for (let i = 0; i < cveIds.length; i += BATCH) {
    const batch = cveIds.slice(i, i + BATCH);
    const results = await Promise.all(
      batch.map(id => fetchNvdCvss(id, apiKey).then(v => [id, v]))
    );
    results.forEach(([id, v]) => { if (v) map[id] = v; });
    if (i + BATCH < cveIds.length) await sleep(DELAY);
  }
  return map;
}

module.exports = async function handler(req, res) {
  const apiKey = process.env.NVD_API_KEY;

  if (req.query.bust) {
    res.setHeader("Cache-Control", "no-store");
  } else {
    res.setHeader("Cache-Control", "s-maxage=7200, stale-while-revalidate=3600");
  }

  try {
    const kev = await fetchKev();

    // Enrich the 90 most-recently-added entries with NVD CVSS
    const toEnrich = kev.slice(0, 90).map(e => e.cveID);
    const cvssMap  = await buildCvssMap(toEnrich, apiKey);

    return res.json({
      kevEntries:    kev,
      cvssMap,
      totalKev:      kev.length,
      enrichedCount: Object.keys(cvssMap).length,
      updatedAt:     new Date().toISOString(),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
