"""
ATT&CK TTP extraction from article text.

Two-pass approach:
  1. Regex  — free, instant; finds explicitly cited T-IDs (e.g. T1566.001)
  2. Claude — semantic; infers techniques from prose descriptions

Both passes are merged and deduplicated by technique_id.
Claude pass is skipped when ANTHROPIC_API_KEY is absent.
"""

import re
import json

TECHNIQUE_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')

MAX_ARTICLES_PER_RUN = 20   # cost guard: max AI calls per pipeline run
MAX_TEXT_CHARS       = 4000  # truncate article to keep token costs low


def extract_ttps_regex(text: str) -> list[dict]:
    """Return explicitly cited T-IDs found in text."""
    found = sorted(set(TECHNIQUE_RE.findall(text.upper())))
    return [{"technique_id": tid, "technique_name": None, "tactic": None}
            for tid in found]


def extract_ttps_ai(text: str, api_key: str) -> list[dict]:
    """Use Claude Haiku to infer ATT&CK techniques from prose."""
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        snippet = text[:MAX_TEXT_CHARS]
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=600,
            messages=[{
                "role": "user",
                "content": (
                    "You are a MITRE ATT&CK analyst. Extract attack techniques from "
                    "the security article below.\n\n"
                    "Return ONLY a JSON array. Each element must have:\n"
                    "  technique_id   — ATT&CK ID e.g. T1566.001\n"
                    "  technique_name — short name e.g. Spearphishing Attachment\n"
                    "  tactic         — tactic slug e.g. initial-access\n\n"
                    "Rules:\n"
                    "- Only include techniques clearly described or demonstrated.\n"
                    "- Do not hallucinate. If uncertain, omit.\n"
                    "- Return [] if nothing found.\n"
                    "- Output raw JSON, no markdown fences.\n\n"
                    f"Article:\n{snippet}"
                ),
            }],
        )
        raw = msg.content[0].text.strip()
        raw = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw, flags=re.MULTILINE)
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return []
        result = []
        for t in parsed:
            tid = (t.get("technique_id") or "").upper().strip()
            if re.match(r'^T\d{4}(\.\d{3})?$', tid):
                result.append({
                    "technique_id":   tid,
                    "technique_name": (t.get("technique_name") or "").strip() or None,
                    "tactic":         (t.get("tactic") or "").strip().lower() or None,
                })
        return result
    except Exception as e:
        print(f"TTP AI extraction failed: {e}")
        return []


def extract_ttps(text: str, api_key: str = "") -> list[dict]:
    """Merge regex + AI results, deduped by technique_id."""
    regex_hits = extract_ttps_regex(text)

    if not api_key:
        return regex_hits

    ai_hits = extract_ttps_ai(text, api_key)

    # AI results are richer (have names/tactics); regex fills gaps
    merged: dict[str, dict] = {t["technique_id"]: t for t in ai_hits}
    for t in regex_hits:
        if t["technique_id"] not in merged:
            merged[t["technique_id"]] = t

    return list(merged.values())
