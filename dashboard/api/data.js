// Vercel serverless function — fetches latest workflow artifact from GitHub
// and returns { config, state, lastActive, updatedAt } as JSON.
// Cached at CDN edge for 1 hour so GitHub API is called at most once per hour.

const AdmZip = require("adm-zip");

const OWNER = process.env.GITHUB_OWNER || "Aveek06";
const REPO  = process.env.GITHUB_REPO  || "cti-monitor";
const REF   = process.env.GITHUB_REF   || "main";

async function ghGet(path, token, rawJson = false) {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: {
      Authorization:          `Bearer ${token}`,
      Accept:                 rawJson
        ? "application/vnd.github.raw+json"
        : "application/vnd.github+json",
      "User-Agent":           "cti-dashboard/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    redirect: "follow",
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    const err = new Error(`GitHub ${res.status}: ${txt.slice(0, 240)}`);
    err.status = res.status;
    throw err;
  }
  return res;
}

module.exports = async function handler(req, res) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return res.status(500).json({
      error: "GITHUB_TOKEN env var not configured. Add it in Vercel → Settings → Environment Variables.",
    });
  }

  // If the caller passes ?bust=1, skip the edge cache entirely so fresh
  // artifact data is always returned (used by the manual Refresh button).
  if (req.query.bust) {
    res.setHeader("Cache-Control", "no-store");
  } else {
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=600");
  }

  try {
    // 1. Fetch config.json directly from repo (raw content)
    const cfgRes = await ghGet(
      `/repos/${OWNER}/${REPO}/contents/config.json?ref=${REF}`,
      token,
      true
    );
    const config = await cfgRes.json();

    // 2. Find latest non-expired cti-state artifact
    const listRes = await ghGet(
      `/repos/${OWNER}/${REPO}/actions/artifacts?per_page=30`,
      token
    );
    const { artifacts = [] } = await listRes.json();
    const artifact = artifacts.find(
      (a) => a.name.startsWith("cti-state-") && !a.expired
    );
    if (!artifact) {
      return res.status(404).json({
        error:
          "No recent workflow artifact found. " +
          "Run the cti-monitor GitHub Actions workflow first, then reload.",
      });
    }

    // 3. Download artifact ZIP and extract state files
    const dlRes = await ghGet(
      `/repos/${OWNER}/${REPO}/actions/artifacts/${artifact.id}/zip`,
      token
    );
    const buf = Buffer.from(await dlRes.arrayBuffer());
    const zip = new AdmZip(buf);

    function parseEntry(name) {
      const entry = zip.getEntry(name);
      if (!entry) throw new Error(`${name} not found in artifact ZIP`);
      return JSON.parse(entry.getData().toString("utf8"));
    }

    const state      = parseEntry("state.json");
    const lastActive = parseEntry("last_active.json");
    let   prevRunLinks = [];
    try { prevRunLinks = parseEntry("prev_run_links.json"); } catch (_) {}

    return res.json({ config, state, lastActive, prevRunLinks, updatedAt: artifact.updated_at });
  } catch (err) {
    const status =
      typeof err.status === "number" && err.status >= 400 && err.status < 600
        ? Math.min(err.status, 503)
        : 500;
    return res.status(status).json({ error: err.message });
  }
};
