import re
import requests
from bs4 import BeautifulSoup

SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
SHA1_RE   = re.compile(r'\b[0-9a-fA-F]{40}\b')
MD5_RE    = re.compile(r'\b[0-9a-fA-F]{32}\b')
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|top|online|site|tech|app|cloud)\b',
    re.IGNORECASE,
)

_FP_DOMAINS = {
    "example.com", "github.com", "google.com", "microsoft.com", "amazon.com",
    "cloudflare.com", "twitter.com", "linkedin.com", "youtube.com", "facebook.com",
    "virustotal.com", "mitre.org", "w3.org", "schema.org", "jquery.com",
}

APT_ALIASES = {
    "APT10": ["apt10", "apt-10", "menupass", "menu pass", "stone panda", "cloud hopper", "stonepanda"],
    "APT29": ["apt29", "apt-29", "cozy bear", "cozybear", "wellmess", "goldmax", "hammertoss"],
    "APT38": ["apt38", "apt-38", "lazarus", "beagleboyz", "fastcash"],
}


def fetch_article_text(url: str) -> str | None:
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return None
        if "html" not in resp.headers.get("content-type", ""):
            return None
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["nav", "header", "footer", "script", "style", "aside", "form"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return None


def undefang(text: str) -> str:
    text = re.sub(r'\[\.\]', '.', text)
    text = re.sub(r'\(\.\)', '.', text)
    text = re.sub(r'hxxps', 'https', text, flags=re.IGNORECASE)
    text = re.sub(r'hxxp', 'http', text, flags=re.IGNORECASE)
    return text


def extract_iocs(text: str) -> list[dict]:
    clean = undefang(text)
    seen  = set()
    results = []

    for m in SHA256_RE.finditer(clean):
        v = m.group().lower()
        if v not in seen:
            seen.add(v)
            results.append({"value": v, "type": "sha256"})

    for m in SHA1_RE.finditer(clean):
        v = m.group().lower()
        # SHA256 contains runs of 64 chars; a 40-char match inside one is still blocked by \b
        if v not in seen:
            seen.add(v)
            results.append({"value": v, "type": "sha1"})

    for m in MD5_RE.finditer(clean):
        v = m.group().lower()
        if v not in seen:
            seen.add(v)
            results.append({"value": v, "type": "md5"})

    for m in DOMAIN_RE.finditer(clean):
        v = m.group().lower()
        if v not in seen and v not in _FP_DOMAINS:
            seen.add(v)
            results.append({"value": v, "type": "domain"})

    return results


def detect_apt(text: str) -> str | None:
    lower = text.lower()
    for apt, aliases in APT_ALIASES.items():
        for alias in aliases:
            if alias in lower:
                return apt
    return None
