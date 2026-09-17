import json
import logging
import anthropic

_PROMPT = """\
You are a cybersecurity intelligence analyst. Extract structured data from the article below.

Return ONLY valid JSON — no markdown fences, no prose — in this exact schema:
{{
  "ttps": [{{"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "initial-access", "confidence": 90, "evidence": "Attackers sent spearphishing emails with malicious Word attachments"}}],
  "iocs": [{{"value": "evil.com", "type": "domain"}}],
  "apt": "APT28"
}}

Rules:
- ttps: MITRE ATT&CK technique IDs the article's narrative prose explicitly describes an attacker PERFORMING in this specific incident — not techniques merely mentioned, referenced in passing, or catalogued in a summary/background section.
  - IGNORE standalone technique tables, "ATT&CK Navigator" mappings, or appendix-style lists that catalog techniques for a malware family or actor in general. Only count a technique if the prose narrates a concrete action taken during this incident.
  - If the article explicitly cites a technique ID inline while describing a specific action in this incident (e.g. "...used PowerShell (T1059.001) to..."), USE THAT EXACT ID — it overrides whatever ID you would otherwise infer semantically — and assign confidence 90-100, since it is the author's own explicit attribution.
  - Otherwise, identify the technique yourself from the described behavior using your own knowledge of MITRE ATT&CK (e.g. recognizing "sent a malicious Word attachment via email" as T1566.001 even though no ID is written), and score confidence per the scale below.
  - Prefer the most specific sub-technique ID (e.g. T1059.001 over T1059) when the text is specific enough to identify one.
  - Empty array if nothing is clearly demonstrated in prose.
  - confidence: integer 0-100. 90-100 = the article explicitly cites this technique's ID inline, or the narrative explicitly shows the attacker performing it with specific technical detail. 60-89 = clearly described but moderate specificity. 40-59 = inferred from context. <40 = uncertain, or the only support is a summary table/list rather than prose. Omit a technique rather than assign confidence below 40.
  - evidence: a short verbatim quote (≤120 chars) from the narrative prose (never a table row or bare technique-ID list) that most clearly demonstrates the technique. Use null if no specific sentence stands out.
- iocs: only values explicitly stated in the text. Do NOT invent or hallucinate.
  Allowed types: domain, url, ipv4-addr, ipv6-addr, sha256, sha1, md5, email-addr
- apt: most specific known threat actor / group name, or null if attribution is unclear.
- If a field has no findings use [] or null.

Source: {site}
Article URL: {link}

{text}"""

_MODEL = "claude-haiku-4-5-20251001"
# Haiku handles 200K context; send full article so the IOC section at the
# bottom of CTI blogs is never truncated. Cap at 150K chars (~37K tokens)
# which is well within Haiku's context window and covers any real blog post.
_MAX_TEXT_CHARS = 150_000


def extract_all(text: str, link: str, api_key: str, site: str = "", rel_score: int = 50) -> dict:
    """Single Haiku call returning ttps, iocs, apt from the full article text."""
    empty: dict = {"ttps": [], "iocs": [], "apt": None}
    if not api_key or not text:
        return empty
    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": _PROMPT.format(
                site=site or link,
                link=link,
                text=text[:_MAX_TEXT_CHARS],
            )}],
        )
        raw = msg.content[0].text.strip()
        # Strip markdown code fences if Claude wraps in them anyway
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw.strip())
        # Normalise TTP entries — ensure confidence/evidence fields are always present
        ttps = []
        for t in (data.get("ttps") or []):
            ttps.append({
                "technique_id":   t.get("technique_id"),
                "technique_name": t.get("technique_name"),
                "tactic":         t.get("tactic"),
                "confidence":     t.get("confidence"),
                "evidence":       (t.get("evidence") or "")[:120] or None,
            })
        return {
            "ttps": ttps,
            "iocs": data.get("iocs") or [],
            "apt":  data.get("apt") or None,
        }
    except Exception as e:
        logging.warning(f"  [ai_extractor] {link[:70]}: {e}")
        return empty
