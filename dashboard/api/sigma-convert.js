// Vercel serverless — POST converts a Sigma YAML to a target platform query.
// Body: { id?: number, sigma_yaml: string, platform: "splunk"|"sentinel"|"elastic"|"qradar" }
// Auth: any authenticated user (read-only operation).

const { jwtVerify } = require("jose");
const Anthropic = require("@anthropic-ai/sdk");
const { Pool } = require("pg");

let _pool;
function pool() {
  if (!_pool) _pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
  return _pool;
}

// Maps platform key → sigma_rules column name
const PLATFORM_COL = {
  splunk:   "splunk_spl",
  sentinel: "sentinel_kql",
  elastic:  "elastic_eql",
  qradar:   "qradar_aql",
};

const PLATFORMS = {
  splunk: {
    label: "Splunk SPL",
    hint: `Output a Splunk SPL search query.
Rules:
- Start with: index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  (adjust sourcetype based on logsource.category: process_creation→Sysmon EventCode=1,
   network_connection→EventCode=3, registry_set→EventCode=13, file_event→EventCode=11)
- Map Sigma fields: Image→Image, CommandLine→CommandLine, ParentImage→ParentImage,
  TargetObject→TargetObject, DestinationIp→DestinationIp, DestinationPort→DestinationPort
- Use | search or WHERE clauses for filters
- End with | table _time, ComputerName, Image, CommandLine`,
  },
  sentinel: {
    label: "Microsoft Sentinel KQL",
    hint: `Output a Microsoft Sentinel KQL query.
Rules:
- Choose the correct table based on logsource.category:
  process_creation→DeviceProcessEvents, network_connection→DeviceNetworkEvents,
  registry_set→DeviceRegistryEvents, file_event→DeviceFileEvents,
  authentication→SecurityEvent, scheduled_task_creation→DeviceProcessEvents,
  process_access→DeviceEvents
- Map Sigma fields: Image→InitiatingProcessFolderPath+InitiatingProcessFileName,
  CommandLine→ProcessCommandLine, ParentImage→InitiatingProcessParentFileName,
  TargetObject→RegistryKey, DestinationIp→RemoteIP, DestinationPort→RemotePort
- Use | where clauses with contains, startswith, endswith, matches regex
- End with | project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine`,
  },
  elastic: {
    label: "Elastic EQL",
    hint: `Output an Elastic EQL query.
Rules:
- Start with the correct event category based on logsource.category:
  process_creation→process where, network_connection→network where,
  registry_set→registry where, file_event→file where,
  authentication→authentication where
- Map Sigma fields: Image→process.executable, CommandLine→process.command_line,
  ParentImage→process.parent.executable, TargetObject→registry.path,
  DestinationIp→destination.ip, DestinationPort→destination.port
- Use : for wildcard match, == for exact, and/or/not for logic
- Output as a single EQL sequence or event query`,
  },
  qradar: {
    label: "IBM QRadar AQL",
    hint: `Output an IBM QRadar AQL query.
Rules:
- Start with: SELECT UTF8(payload) AS Payload, sourceip, destinationip,
  QIDNAME(qid) AS EventName, LOGSOURCENAME(logsourceid) AS LogSource
  FROM events
- Use WHERE clauses with ILIKE for string matching, = for exact
- Map Sigma fields to QRadar common fields: CommandLine→UTF8(payload),
  Image→Application, DestinationIp→destinationip, DestinationPort→destinationport
- End with: LAST 24 HOURS`,
  },
};

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

async function requireAuth(req) {
  try {
    const token = parseCookie(req.headers.cookie)["cti_session"];
    if (!token || !process.env.SESSION_SECRET) return false;
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET);
    await jwtVerify(token, secret);
    return true;
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!(await requireAuth(req)))
    return res.status(401).json({ error: "Unauthorized" });

  if (!process.env.ANTHROPIC_API_KEY)
    return res.status(500).json({ error: "ANTHROPIC_API_KEY not configured" });

  const { id, sigma_yaml, platform } = req.body || {};
  if (!sigma_yaml) return res.status(400).json({ error: "sigma_yaml required" });
  if (!platform || !PLATFORMS[platform])
    return res.status(400).json({ error: `platform must be one of: ${Object.keys(PLATFORMS).join(", ")}` });

  const p = PLATFORMS[platform];
  const prompt = `You are a threat detection engineer. Convert the following Sigma rule to a ${p.label} query.

${p.hint}

Sigma rule:
${sigma_yaml}

Output ONLY the ${p.label} query — no explanation, no markdown fences, no prose. Just the raw query.`;

  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const msg = await client.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 400,
      messages: [{ role: "user", content: prompt }],
    });
    let query = msg.content[0].text.trim();
    // Strip accidental markdown fences
    query = query.replace(/^```[a-z]*\s*/i, "").replace(/\s*```\s*$/i, "");
    // Persist to DB so future loads skip the Haiku call
    const col = PLATFORM_COL[platform];
    if (col && id && Number.isInteger(+id) && +id > 0 && process.env.DATABASE_URL) {
      try {
        const result = await pool().query(
          `UPDATE sigma_rules SET ${col}=$1 WHERE id=$2`,
          [query, +id]
        );
        console.log(`sigma-convert: saved ${col} for id=${id}, rowCount=${result.rowCount}`);
      } catch (e) {
        console.error(`sigma-convert: DB save failed (${col}, id=${id}):`, e.message);
      }
    } else if (!process.env.DATABASE_URL) {
      console.warn("sigma-convert: DATABASE_URL not set, skipping DB save");
    } else if (!(+id > 0)) {
      console.warn(`sigma-convert: id=${id} is invalid, skipping DB save`);
    }
    return res.json({ query, platform, label: p.label });
  } catch (e) {
    console.error("POST /api/sigma-convert error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
};
