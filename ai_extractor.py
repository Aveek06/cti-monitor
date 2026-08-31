import json
import anthropic

_PROMPT = """\
You are a cybersecurity intelligence analyst. Extract structured data from the article below.

Return ONLY valid JSON — no markdown fences, no prose — in this exact schema:
{{
  "ttps": [{{"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "initial-access"}}],
  "iocs": [{{"value": "evil.com", "type": "domain"}}],
  "apt": "APT28"
}}

Rules:
- ttps: MITRE ATT&CK technique IDs, names, and tactic slugs. Empty array if none.
- iocs: only values explicitly stated in the text. Do NOT invent or hallucinate.
  Allowed types: domain, url, ipv4-addr, ipv6-addr, sha256, sha1, md5, email-addr
- apt: most specific known threat actor / group name, or null if attribution is unclear.
- If a field has no findings use [] or null.

Article URL: {link}

{text}"""


def extract_all(text: str, link: str, api_key: str) -> dict:
    """Single Haiku call returning ttps, iocs, apt. Returns empty result on failure."""
    empty: dict = {"ttps": [], "iocs": [], "apt": None}
    if not api_key or not text:
        return empty
    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=1000,
            messages=[{"role": "user", "content": _PROMPT.format(
                link=link,
                text=text[:3500],
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
        return {
            "ttps": data.get("ttps") or [],
            "iocs": data.get("iocs") or [],
            "apt":  data.get("apt") or None,
        }
    except Exception as e:
        print(f"  [ai_extractor] {link[:70]}: {e}")
        return empty
