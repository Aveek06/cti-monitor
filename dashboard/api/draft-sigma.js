// Vercel serverless — POST generates a Sigma rule skeleton for a given TTP + article.
// Requires ANTHROPIC_API_KEY, DATABASE_URL, SESSION_SECRET env vars.

const { Pool } = require("pg");
const { jwtVerify } = require("jose");
const Anthropic = require("@anthropic-ai/sdk");
const yaml = require("js-yaml");

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

// ATT&CK technique → Sigma logsource (category always injected from code, not the model)
const LOGSOURCE_MAP = {
  "T1059":     { category: "process_creation",        product: "windows" },
  "T1059.001": { category: "process_creation",        product: "windows" },
  "T1059.003": { category: "process_creation",        product: "windows" },
  "T1059.005": { category: "process_creation",        product: "windows" },
  "T1003":     { category: "process_access",          product: "windows" },
  "T1003.001": { category: "process_access",          product: "windows" },
  "T1003.002": { category: "file_event",              product: "windows" },
  "T1053":     { category: "process_creation",        product: "windows" },
  "T1053.005": { category: "scheduled_task_creation", product: "windows" },
  "T1547":     { category: "registry_set",            product: "windows" },
  "T1547.001": { category: "registry_set",            product: "windows" },
  "T1566":     { category: "file_event",              product: "windows" },
  "T1566.001": { category: "file_event",              product: "windows" },
  "T1566.002": { category: "network_connection",      product: "windows" },
  "T1078":     { category: "authentication",          product: "windows" },
  "T1021":     { category: "network_connection",      product: "windows" },
  "T1021.001": { category: "network_connection",      product: "windows" },
  "T1021.002": { category: "network_connection",      product: "windows" },
  "T1055":     { category: "process_creation",        product: "windows" },
  "T1055.001": { category: "create_remote_thread",    product: "windows" },
  "T1055.012": { category: "process_creation",        product: "windows" },
  "T1070":     { category: "process_creation",        product: "windows" },
  "T1070.001": { category: "process_creation",        product: "windows" },
  "T1105":     { category: "network_connection",      product: "windows" },
  "T1190":     { category: "web_server",              product: null      },
  "T1486":     { category: "file_event",              product: "windows" },
  "T1496":     { category: "process_creation",        product: "windows" },
  "T1036":     { category: "process_creation",        product: "windows" },
  "T1218":     { category: "process_creation",        product: "windows" },
  "T1112":     { category: "registry_set",            product: "windows" },
};
const DEFAULT_LOGSOURCE = { category: "process_creation", product: "windows" };

function logsourceFor(techniqueId) {
  const parent = (techniqueId || "").split(".")[0];
  return LOGSOURCE_MAP[techniqueId] || LOGSOURCE_MAP[parent] || DEFAULT_LOGSOURCE;
}

function buildPrompt({ techniqueId, techniqueName, tactic, apt, iocs, ls }) {
  const productLine = ls.product ? `- logsource.product: ${ls.product}` : "";
  const techniqueTag = techniqueId.toLowerCase();
  const tacticTag = (tactic || "unknown").toLowerCase();
  return `You are a threat detection engineer. Draft a Sigma rule skeleton.

Technique: ${techniqueId} — ${techniqueName || techniqueId} (tactic: ${tactic || "unknown"})
Attribution: ${apt || "unknown"}
IOCs from this article: ${iocs || "none stated"}

Requirements:
- logsource.category: ${ls.category}
${productLine}
- status: experimental
- level: medium (use high only if the technique has near-zero legitimate use)
- detection: must contain selection_main block + at least one filter_<name> block
- Populate selection fields using ONLY values explicitly stated above — do not invent IOCs
- falsepositives: 2-3 entries (e.g. AV/EDR products, admin scripts, deployment tools)
- tags: ["attack.${tacticTag}", "attack.${techniqueTag}"]
- id: generate a valid UUID v4
- title: short human-readable name for the rule
- Output ONLY the YAML — no markdown fences, no code blocks, no prose`;
}

async function callHaiku(client, prompt) {
  const msg = await client.messages.create({
    model: "claude-haiku-4-5-20251001",
    max_tokens: 600,
    messages: [{ role: "user", content: prompt }],
  });
  let text = msg.content[0].text.trim();
  // Strip accidental markdown fences
  text = text.replace(/^```ya?ml\s*/i, "").replace(/\s*```\s*$/i, "");
  return text;
}

function parseCookie(header) {
  if (!header) return {};
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

async function requireAdmin(req) {
  try {
    const token = parseCookie(req.headers.cookie)["cti_session"];
    if (!token || !process.env.SESSION_SECRET) return false;
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET);
    const { payload } = await jwtVerify(token, secret);
    return payload.is_admin === true;
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!(await requireAdmin(req)))
    return res.status(403).json({ error: "Admin access required" });

  if (!process.env.ANTHROPIC_API_KEY)
    return res.status(500).json({ error: "ANTHROPIC_API_KEY not configured" });
  if (!process.env.DATABASE_URL)
    return res.status(500).json({ error: "DATABASE_URL not configured" });

  const { technique_id, source_article } = req.body || {};
  if (!technique_id || !source_article)
    return res.status(400).json({ error: "technique_id and source_article required" });
  if (typeof technique_id !== "string" || !/^T\d{4}(\.\d{3})?$/.test(technique_id))
    return res.status(400).json({ error: "Invalid technique_id format" });

  try {
    // Fetch TTP details
    const { rows: ttpRows } = await pool().query(
      "SELECT * FROM ttp_observations WHERE technique_id=$1 AND source_article=$2 LIMIT 1",
      [technique_id, source_article]
    );
    const ttp = ttpRows[0] || {};

    // Fetch associated IOCs for this article (up to 15)
    const { rows: iocRows } = await pool().query(
      "SELECT value, type FROM ioc_indicators WHERE source_article=$1 LIMIT 15",
      [source_article]
    );
    const iocs = iocRows.map(r => `${r.value} (${r.type})`).join(", ") || "none";

    const ls = logsourceFor(technique_id);
    const prompt = buildPrompt({
      techniqueId: technique_id,
      techniqueName: ttp.technique_name,
      tactic: ttp.tactic,
      apt: ttp.attributed_apt,
      iocs,
      ls,
    });

    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    let sigmaYaml = await callHaiku(client, prompt);

    // Validate YAML — retry once with correction if it fails to parse
    try {
      yaml.load(sigmaYaml);
    } catch {
      const correctionNote =
        "\n\nNote: your previous output failed YAML parsing. Output strictly valid YAML only — no extra text.";
      sigmaYaml = await callHaiku(client, prompt + correctionNote);
      try {
        yaml.load(sigmaYaml);
      } catch (e) {
        return res.status(422).json({ error: "Generated YAML failed validation after retry", detail: e.message });
      }
    }

    // Store (INSERT … ON CONFLICT DO NOTHING — first draft wins)
    await pool().query(
      `INSERT INTO sigma_rules
         (technique_id, technique_name, tactic, source_article, source_blog, attributed_apt, sigma_yaml)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (technique_id, source_article) DO NOTHING`,
      [
        technique_id,
        ttp.technique_name || null,
        ttp.tactic || null,
        source_article,
        ttp.source_blog || null,
        ttp.attributed_apt || null,
        sigmaYaml,
      ]
    );

    // Fetch the stored row (may be pre-existing if conflict)
    const { rows: stored } = await pool().query(
      "SELECT * FROM sigma_rules WHERE technique_id=$1 AND source_article=$2 LIMIT 1",
      [technique_id, source_article]
    );

    if (!stored[0]) {
      console.error("draft-sigma: SELECT after INSERT returned no row for technique_id=%s source_article=%s", technique_id, source_article);
      return res.status(500).json({ error: "Failed to retrieve saved sigma rule" });
    }
    return res.status(200).json({ sigma_rule: stored[0] });
  } catch (e) {
    console.error("POST /api/draft-sigma error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
};
