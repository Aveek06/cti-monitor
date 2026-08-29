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
    # AI / LLM vendors
    "anthropic.com", "claude.com",
    "openai.com", "openai.azure.com",
    # Dev platforms & source hosting
    "github.com", "githubusercontent.com", "githubassets.com",
    "gitlab.com", "bitbucket.org",
    "npmjs.com", "pypi.org", "rubygems.org", "crates.io", "pkg.go.dev",
    "nuget.org", "maven.org", "mvnrepository.com",
    "stackoverflow.com", "stackexchange.com",
    "golang.org", "python.org", "nodejs.org", "rust-lang.org", "mozilla.org",
    # Container / cloud-native platforms
    "docker.com", "docker.io", "hub.docker.com",
    "kubernetes.io", "k8s.io", "helm.sh",
    "quay.io", "gcr.io", "registry.k8s.io",
    # Security analysis tools / sandboxes (cited as references, not IOCs)
    "virustotal.com", "shodan.io", "censys.io", "greynoise.io", "alienvault.com",
    "hybrid-analysis.com", "any.run", "polyswarm.io", "intezer.com",
    "joesandbox.com", "app.any.run", "triage.abuse.ch", "urlscan.io",
    "malwarebazaar.abuse.ch", "bazaar.abuse.ch", "threatfox.abuse.ch", "abuse.ch",
    "otx.alienvault.com", "exchange.xforce.ibmcloud.com",
    # Security vendors (named in articles as tools/vendors, not as C2s)
    "crowdstrike.com", "sentinelone.com", "mandiant.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "checkpoint.com", "research.checkpoint.com",
    "fortinet.com", "symantec.com", "broadcom.com",
    "cisco.com", "talos-intelligence.com",
    "sophos.com", "news.sophos.com",
    "eset.com", "welivesecurity.com",
    "kaspersky.com", "securelist.com",
    "trendmicro.com", "mcafee.com", "trellix.com",
    "malwarebytes.com", "elastic.co", "microsoft.com",
    "recordedfuture.com", "anomali.com", "threatconnect.com",
    "aikido.io", "snyk.io", "semgrep.io",
    # Threat intel / govt / standards bodies
    "mitre.org", "nist.gov", "cisa.gov", "us-cert.gov", "cert.org",
    "nvd.nist.gov", "cve.org", "first.org",
    "sans.org", "owasp.org", "attack.mitre.org",
    # News / research (appear as references, not IOCs)
    "bleepingcomputer.com", "krebsonsecurity.com",
    "therecord.media", "darkreading.com", "securityweek.com",
    "wired.com", "techcrunch.com",
    "arstechnica.com", "thehackernews.com",
    "threatpost.com", "helpnetsecurity.com", "cyberscoop.com",
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
    "APT10":    ["apt10", "apt-10", "menupass", "menu pass", "stone panda", "cloud hopper",
                 "stonepanda", "cicada", "potassium", "red apollo", "cvnx", "hogfish",
                 "bronze riverside"],
    "APT29":    ["apt29", "apt-29", "cozy bear", "cozybear", "wellmess", "goldmax",
                 "hammertoss", "nobelium", "midnight blizzard", "yttrium", "iron ritual",
                 "iron hemlock", "noblebaron", "dark halo", "unc2452", "the dukes",
                 "cozyduke", "solarstorm", "blue kitsune", "unc3524"],
    "APT38":    ["apt38", "apt-38", "lazarus", "beagleboyz", "fastcash", "hidden cobra",
                 "bluenoroff", "nickel gladstone", "stardust chollima", "sapphire sleet",
                 "copernicium", "zinc", "nickel academy", "diamond sleet",
                 "labyrinth chollima"],

    # ── Chinese nation-state ──────────────────────────────────────────────────
    "APT1":     ["apt1", "apt-1", "comment crew", "comment group", "comment panda"],
    "APT3":     ["apt3", "apt-3", "gothic panda", "pirpi", "ups team", "buckeye",
                 "threat group-0110", "tg-0110"],
    "APT5":     ["apt5", "apt-5", "mulberry typhoon", "manganese", "bronze fleetwood",
                 "keyhole panda", "unc2630"],
    "APT12":    ["apt12", "apt-12", "ixeshe", "dyncalc", "numbered panda", "dnscalc"],
    "APT15":    ["apt15", "apt-15", "ke3chang", "mirage", "vixen panda", "gref",
                 "playful dragon", "royalapt", "nickel", "nylon typhoon"],
    "APT16":    ["apt16", "apt-16"],
    "APT17":    ["apt17", "apt-17", "deputy dog"],
    "APT18":    ["apt18", "apt-18", "wekby", "tg-0416", "dynamite panda",
                 "threat group-0416"],
    "APT19":    ["apt19", "apt-19", "codoso", "c0d0so0", "codoso team", "sunshop group"],
    "APT27":    ["apt27", "apt-27", "threat group-3390", "tg-3390", "emissary panda",
                 "bronze union", "iron tiger", "luckymouse", "lucky mouse",
                 "linen typhoon", "earth smilodon"],
    "APT30":    ["apt30", "apt-30"],
    "APT40":    ["apt40", "apt-40", "temp.periscope", "bronze mohawk", "gadolinium",
                 "radius typhoon", "kryptonite panda", "mudcarp", "temp.jumper",
                 "gingham typhoon", "leviathan"],
    "APT41":    ["apt41", "apt-41", "winnti", "barium", "double dragon", "bronze atlas",
                 "earth baku", "brass typhoon", "wicked panda"],
    "Hafnium":  ["hafnium", "silk typhoon", "operation exchange marauder"],
    "VoltTyphoon": ["volt typhoon", "volttyphoon", "bronze silhouette", "vanguard panda",
                    "dev-0391", "unc3236", "voltzite", "insidious taurus", "dazedtoad"],
    "Axiom":    ["axiom", "group 72"],
    "BlackTech": ["blacktech", "black tech", "palmerworm"],
    "BRONZE BUTLER": ["bronze butler", "redbaldknight"],
    "Daggerfly": ["daggerfly", "evasive panda", "bronze highland"],
    "Darkhotel": ["darkhotel", "dubnium", "zigzag hail"],
    "Deep Panda": ["deep panda", "deeppanda", "shell crew", "black vine"],
    "Earth Lusca": ["earth lusca", "earthlusca", "tag-22", "charcoal typhoon", "chromium"],
    "Elderwood": ["elderwood", "elderwood gang", "beijing group", "sneaky panda"],
    "GALLIUM":  ["gallium", "granite typhoon"],
    "Lotus Blossom": ["lotus blossom", "lotusblossom", "dragonfish", "spring dragon",
                      "raspberry typhoon", "bilbug"],
    "MirrorFace": ["mirrorface", "mirror face", "earth kasha"],
    "Mustang Panda": ["mustang panda", "mustangpanda", "ta416", "reddelta", "red delta",
                      "bronze president", "stately taurus", "fireant", "camaro dragon",
                      "earth preta", "twill typhoon", "tantalum", "temp.hex"],
    "Naikon":   ["naikon"],
    "Patchwork": ["patchwork", "hangover group", "dropping elephant", "monsoon",
                  "operation hangover"],
    "Salt Typhoon": ["salt typhoon", "salttyphoon"],
    "Tonto Team": ["tonto team", "tontoteam", "earth akhlut", "bronze huntley",
                   "cactuspete"],
    "ToddyCat": ["toddycat", "toddy cat"],
    "Tropic Trooper": ["tropic trooper", "tropictrooper", "pirate panda", "keyboy"],
    "Aquatic Panda": ["aquatic panda", "aquaticpanda"],
    "BackdoorDiplomacy": ["backdoordiplomacy", "backdoor diplomacy"],
    "LuminousMoth": ["luminousmoth", "lumious moth"],

    # ── Iranian nation-state ──────────────────────────────────────────────────
    "APT33":    ["apt33", "apt-33", "elfin", "refined kitten", "magnallium", "holmium",
                 "peach sandstorm"],
    "APT34":    ["apt34", "apt-34", "oilrig", "helix kitten", "crambus", "hazel sandstorm",
                 "cobalt gypsy", "irn2", "evasive serpens", "europium", "itg13",
                 "earth simnavaz", "ta452"],
    "APT35":    ["apt35", "apt-35", "charming kitten", "charmingkitten", "phosphorus",
                 "mint sandstorm", "newscaster", "ta453", "ballistic bobcat",
                 "cobalt illusion", "itg18", "magic hound"],
    "APT39":    ["apt39", "apt-39", "itg07", "chafer", "remix kitten"],
    "APT42":    ["apt42", "apt-42", "damselfly", "calanque"],
    "MuddyWater": ["muddywater", "muddy water", "static kitten", "seedworm",
                   "mercury", "mango sandstorm", "ta450", "earth vetala",
                   "temp.zagros", "muddykrill"],
    "Fox Kitten": ["fox kitten", "foxkitten", "unc757", "parisite", "pioneer kitten",
                   "rubidium", "lemon sandstorm"],
    "HEXANE":   ["hexane", "lyceum", "siamesekitten", "spirlin"],
    "CURIUM":   ["curium", "crimson sandstorm", "ta456", "tortoise shell", "yellow liderc"],
    "Agrius":   ["agrius", "pink sandstorm", "americium", "agonizing serpens",
                 "blackshadow", "black shadow"],
    "Ajax Security Team": ["ajax security team", "rocket kitten", "flying kitten",
                            "operation saffron rose"],
    "CyberAv3ngers": ["cyberav3ngers", "cyber av3ngers", "soldiers of soloman"],
    "VOID MANTICORE": ["void manticore", "cobalt mystique", "handala hack",
                        "homeland justice", "banished kitten", "red sandstorm"],
    "Moses Staff": ["moses staff", "mosesstaff", "dev-0500", "marigold sandstorm"],
    "POLONIUM": ["polonium", "plaid rain"],
    "CopyKittens": ["copykittens", "copy kittens"],
    "Molerats": ["molerats", "operation molerats", "gaza cybergang"],

    # ── Russian nation-state ──────────────────────────────────────────────────
    "APT28":    ["apt28", "apt-28", "fancy bear", "fancybear", "sofacy", "pawn storm",
                 "sednit", "strontium", "forest blizzard", "iron twilight", "snakemackerel",
                 "swallowtail", "group 74", "tsar team", "threat group-4127", "tg-4127",
                 "frozenlake", "gruesomelarch"],
    "Sandworm": ["sandworm", "sand worm", "apt44", "apt-44", "voodoo bear",
                 "seashell blizzard", "iridium", "electrum", "telebots", "iron viking",
                 "blackenergy", "quedagh", "frozenbarents"],
    "Turla":    ["turla", "snake", "venomous bear", "waterbug", "secret blizzard",
                 "uroboros", "penquin", "iron hunter", "group 88", "whitebear",
                 "krypton", "belugasturgeon"],
    "Gamaredon": ["gamaredon", "iron tilden", "primitive bear", "actinium", "armageddon",
                  "shuckworm", "dev-0157", "aqua blizzard", "nastyshrew"],
    "Ember Bear": ["ember bear", "emberbear", "unc2589", "bleeding bear", "dev-0586",
                   "cadet blizzard", "frozenvista"],
    "Dragonfly": ["dragonfly", "temp.isotope", "dymalloy", "berserk bear", "tg-4192",
                  "crouching yeti", "iron liberty", "energetic bear", "ghost blizzard",
                  "bromine"],
    "Star Blizzard": ["star blizzard", "starblizzard", "seaborgium", "callisto group",
                      "ta446", "coldriver"],
    "Indrik Spider": ["indrik spider", "indrikspider", "evil corp", "manatee tempest",
                      "dev-0243", "unc2165"],
    "Winter Vivern": ["winter vivern", "wintervivern", "ta473", "uac-0114"],
    "Inception": ["inception", "inception framework", "cloud atlas"],
    "TEMP.Veles": ["temp.veles", "xenotime"],
    "Strider":  ["strider", "projectsauron"],

    # ── North Korean ──────────────────────────────────────────────────────────
    "APT37":    ["apt37", "apt-37", "inkysquid", "scarcruft", "reaper", "group123",
                 "temp.reaper", "ricochet chollima"],
    "APT43":    ["apt43", "apt-43", "kimsuky", "thallium", "velvet chollima",
                 "babyshark", "golddragon", "black banshee", "emerald sleet",
                 "ta427", "springtail", "earth kumiho", "patheticslug"],
    "Andariel": ["andariel", "silent chollima", "stonefly", "onyx sleet",
                 "apt45", "apt-45", "guardians of peace", "plutonium"],
    "Moonstone Sleet": ["moonstone sleet", "moonstonesleet", "storm-1789"],
    "AppleJeus": ["applejeus", "gleaming pisces", "citrine sleet", "unc1720", "unc4736"],
    "Contagious Interview": ["contagious interview", "deceptivedevelopment",
                              "dev#popper", "purplebravo", "tag-121"],

    # ── Other nation-state / regional ─────────────────────────────────────────
    "APT32":    ["apt32", "apt-32", "ocean lotus", "oceanlotus", "cobalt kitty",
                 "canvas cyclone", "sealotus", "apt-c-00", "bismuth"],
    "SideWinder": ["sidewinder", "rattlesnake", "apt-c-17", "t-apt-04",
                   "hardcore nationalist"],
    "Transparent Tribe": ["transparent tribe", "copper fieldstone", "apt36", "apt-36",
                           "mythic leopard", "projectm"],
    "Arid Viper": ["arid viper", "desert falcon", "apt-c-23", "mantis", "tag-63",
                   "two-tailed scorpion"],
    "Blind Eagle": ["blind eagle", "apt-c-36", "aguilaciega"],
    "BITTER":   ["bitter", "t-apt-17"],
    "Sea Turtle": ["sea turtle", "seaturtle", "teal kurma", "marbled dust", "cosmic wolf"],
    "ALLANITE": ["allanite", "palmetto fusion"],
    "Silent Librarian": ["silent librarian", "ta407", "cobalt dickens"],
    "Bahamut":  ["bahamut", "windshift"],
    "LAPSUS$":  ["lapsus$", "lapsus", "dev-0537", "strawberry tempest"],
    "Scattered Spider": ["scattered spider", "roasted 0ktapus", "octo tempest",
                          "storm-0875", "unc3944"],

    # ── Financially motivated / ransomware ────────────────────────────────────
    "ALPHV":    ["alphv", "blackcat", "black cat", "noberus"],
    "LockBit":  ["lockbit", "lock bit", "abcd ransomware"],
    "Clop":     ["clop", "cl0p", "ta505", "fin11", "hive0065", "spandex tempest",
                 "chimborazo"],
    "Hive":     ["hive ransomware", "hiveransom"],
    "Medusa":   ["medusa ransomware", "medusalocker", "medusa blog"],
    "RansomHub": ["ransomhub", "ransom hub"],
    "BlackBasta": ["black basta", "blackbasta"],
    "WizardSpider": ["wizard spider", "wizardspider", "trickbot", "ryuk", "conti",
                     "team9", "unc1878", "temp.mixmaster", "grim spider", "fin12",
                     "gold blackburn", "itg23", "periwinkle tempest", "dev-0193",
                     "pistachio tempest", "dev-0237"],
    "Carbanak": ["carbanak", "anunak"],
    "Cobalt Group": ["cobalt group", "cobaltgroup", "gold kingswood", "cobalt gang",
                     "cobalt spider"],
    "FIN6":     ["fin6", "magecart group 6", "itg08", "skeleton spider", "taal",
                 "camouflage tempest"],
    "FIN7":     ["fin7", "gold niagara", "itg14", "carbon spider", "elbrus",
                 "sangria tempest"],
    "FIN8":     ["fin8", "syssphinx"],
    "FIN13":    ["fin13", "elephant beetle"],
    "REvil":    ["revil", "sodinokibi", "gold southfield", "pinchy spider"],
    "Akira":    ["akira ransomware", "gold sahara", "punk spider", "howling scorpius"],
    "Play":     ["play ransomware"],
    "INC Ransom": ["inc ransom", "gold ionic"],
    "BlackByte": ["blackbyte", "black byte", "hecamede"],
    "Cinnamon Tempest": ["cinnamon tempest", "dev-0401", "emperor dragonfly",
                          "bronze starlight"],
    "ShinyHunters": ["shinyhunters", "shiny hunters", "unc6240", "bling libra"],
    "Silence":  ["silence group", "whisper spider"],
    "TeamTNT":  ["teamtnt", "team tnt"],
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
            # Use word boundaries so e.g. "apt3" doesn't match inside "apt37"
            if re.search(r'(?<![a-z0-9])' + re.escape(alias) + r'(?![a-z0-9])', lower):
                return apt
    return None
