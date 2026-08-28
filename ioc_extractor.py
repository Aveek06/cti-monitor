import re
import requests
from bs4 import BeautifulSoup

SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
SHA1_RE   = re.compile(r'\b[0-9a-fA-F]{40}\b')
MD5_RE    = re.compile(r'\b[0-9a-fA-F]{32}\b')
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|kr|jp|in|au|fr|nl|br|pl|it|es|se|no|ch|fi|'
    r'info|biz|xyz|top|online|site|tech|app|cloud|live|space|store|shop|club|pro|me|cc|tv)\b',
    re.IGNORECASE,
)

_FP_DOMAINS = {
    # Infrastructure / CDN
    "example.com", "cloudflare.com", "amazonaws.com", "akamai.com", "fastly.com",
    "w3.org", "schema.org", "jquery.com", "bootstrapcdn.com", "jsdelivr.net",
    # Major tech platforms
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "microsoft.com", "azure.com", "azurewebsites.net", "live.com", "office.com",
    "amazon.com", "aws.amazon.com",
    "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
    "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "tiktok.com",
    # AI / security vendors (commonly cited in CTI articles)
    "anthropic.com", "claude.com",
    "openai.com", "openai.azure.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "virustotal.com", "shodan.io", "censys.io", "greynoise.io", "alienvault.com",
    # Threat intel / govt / standards bodies
    "mitre.org", "nist.gov", "cisa.gov", "us-cert.gov", "cert.org",
    "nvd.nist.gov", "cve.org",
    "sans.org", "owasp.org",
    # News / research (appear as references, not IOCs)
    "bleepingcomputer.com", "krebsonsecurity.com",
    "therecord.media", "darkreading.com", "securityweek.com",
    "wired.com", "techcrunch.com",
    "arstechnica.com", "thehackernews.com",
}


def _is_fp(domain: str) -> bool:
    """Return True if domain matches any FP entry exactly or as a subdomain."""
    d = domain.lower()
    for fp in _FP_DOMAINS:
        if d == fp or d.endswith("." + fp):
            return True
    return False

APT_ALIASES = {
    # ── Jakusz-scored groups (LTV coefficients in ioc_scorer.py) ──────────────
    "APT10":    ["apt10", "apt-10", "menupass", "menu pass", "stone panda", "cloud hopper", "stonepanda"],
    "APT29":    ["apt29", "apt-29", "cozy bear", "cozybear", "wellmess", "goldmax", "hammertoss",
                 "nobelium", "midnight blizzard", "yttrium"],
    "APT38":    ["apt38", "apt-38", "lazarus", "beagleboyz", "fastcash", "hidden cobra", "bluenoroff"],

    # ── Chinese nation-state (heavy university / life-sciences / research targeting) ─
    "APT40":    ["apt40", "apt-40", "temp.periscope", "bronze mohawk", "gadolinium",
                 "radius typhoon", "kryptonite panda"],
    "APT41":    ["apt41", "apt-41", "winnti", "barium", "double dragon", "bronze atlas",
                 "earth baku", "brass typhoon"],
    "APT18":    ["apt18", "apt-18", "wekby", "tg-0416"],          # historical healthcare targeting
    "Hafnium":  ["hafnium"],                                        # COVID-19 / university research
    "VoltTyphoon": ["volt typhoon", "volttyphoon", "bronze silhouette", "vanguard panda",
                    "dev-0391"],                                    # critical infra / healthcare OT

    # ── Iranian nation-state (medical research, universities, pharma) ─────────
    "APT33":    ["apt33", "apt-33", "elfin", "refined kitten", "magnallium", "holmium"],
    "APT34":    ["apt34", "apt-34", "oilrig", "helix kitten", "crambus", "iridium", "hazel sandstorm"],
    "APT35":    ["apt35", "apt-35", "charming kitten", "charmingkitten", "phosphorus",
                 "mint sandstorm", "newscaster", "ta453", "ballistic bobcat"],  # targets universities, hospitals
    "APT42":    ["apt42", "apt-42", "damselfly", "calanque"],      # IRGC, academia / ngo / healthcare-adjacent
    "MuddyWater": ["muddywater", "muddy water", "static kitten", "seedworm",
                   "mercury", "mango sandstorm", "ta450"],         # health sector campaigns in ME

    # ── Russian nation-state (hospitals, pharma, research) ───────────────────
    "APT28":    ["apt28", "apt-28", "fancy bear", "fancybear", "sofacy", "pawn storm",
                 "sednit", "strontium", "forest blizzard"],
    "Sandworm": ["sandworm", "sand worm", "apt44", "apt-44", "voodoo bear", "seashell blizzard",
                 "iridium", "electrum", "telebots"],               # disrupted hospitals in Ukraine/EU
    "Turla":    ["turla", "snake", "venomous bear", "waterbug", "secret blizzard",
                 "uroboros", "penquin"],                            # academic / research espionage

    # ── North Korean (hospitals, pharma, medical device ransomware) ───────────
    "APT43":    ["apt43", "apt-43", "kimsuky", "thallium", "velvet chollima",
                 "babyshark", "golddragon", "black banshee", "emerald sleet"],
    "Andariel": ["andariel", "silent chollima", "stonefly", "onyx sleet",
                 "apt45", "apt-45", "guardians of peace"],          # ransomware against hospitals, biotech

    # ── Other nation-state ────────────────────────────────────────────────────
    "APT32":    ["apt32", "apt-32", "ocean lotus", "oceanlotus", "cobalt kitty", "canvas cyclone"],
    "SideWinder": ["sidewinder", "rattlesnake", "apt-c-17", "hardcore nationalist"],  # targets health orgs in South Asia

    # ── Financially motivated / ransomware (heavy hospital targeting) ─────────
    "ALPHV":    ["alphv", "blackcat", "black cat", "noberus"],     # Change Healthcare, hospital chains
    "LockBit":  ["lockbit", "lock bit", "abcd ransomware"],        # NHS, hospital systems worldwide
    "Clop":     ["clop", "cl0p", "ta505", "fin11"],                # NHS via MOVEit, pharma
    "Hive":     ["hive ransomware", "hiveransom"],                  # FBI-disrupted; hit 1500+ orgs incl. hospitals
    "Medusa":   ["medusa ransomware", "medusalocker", "medusa blog"],  # active hospital targeting
    "RansomHub": ["ransomhub", "ransom hub"],                       # successors to ALPHV, targeting healthcare
    "BlackBasta": ["black basta", "blackbasta"],                    # Ascension Health, NHS Scotland
    "WizardSpider": ["wizard spider", "wizardspider", "trickbot", "ryuk",
                     "conti", "team9"],                             # hospital ransomware wave 2020-2022
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
        if v not in seen and not _is_fp(v):
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
