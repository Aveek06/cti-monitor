from datetime import datetime, timezone

LTV = {
    ("APT10", "domain"): 0.97,
    ("APT10", "hash"):   1.85,
    ("APT29", "domain"): 0.61,
    ("APT29", "hash"):   0.84,
    ("APT38", "domain"): 0.83,
    ("APT38", "hash"):   0.77,
}
TAU_DEFAULT = {"domain": 30, "hash": 60, "url": 30, "ip": 30}

# Minimum VT engine count to classify an IOC as confirmed malicious, by group.
# Hashes require more engines due to higher FP resistance; network IOCs are looser.
VT_MALICIOUS_THRESHOLD = {"hash": 5, "domain": 3, "ip": 3, "url": 3}

# Per-verdict decay parameters: (base_score, tau_multiplier, delta)
#
# Formula: base × (1 − (t / τ_eff)^(1/δ))  where τ_eff = τ × ltv × tau_mult
#
# delta < 1  →  score stays very high most of lifetime then drops sharply at the end
#               (slow-start curve; 1/δ > 1 means the inner term x^n is concave)
# delta > 1  →  score drops rapidly early then flattens before zero-crossing
#               (fast-start curve)
#
# Confirmed malicious: highest base, long effective life, slow-start curve.
# Clean (VT-verified 0 detections): low base, short life, fast-start curve.
VERDICT_PARAMS = {
    "malicious":  {"base": 100, "tau_mult": 1.5,  "delta": 0.25},  # 1.5× lifetime, slow-start curve
    "suspicious": {"base": 100, "tau_mult": 1.25, "delta": 0.40},  # 1.25× lifetime, moderately slow curve
    "unknown":    {"base": 100, "tau_mult": 1.0,  "delta": 0.50},  # original quadratic (δ=0.5 → x²)
    "clean":      {"base": 100, "tau_mult": 1.0,  "delta": 0.50},  # original quadratic
}


def ioc_group(ioc_type: str) -> str:
    if ioc_type in ("sha256", "sha1", "md5"):
        return "hash"
    if ioc_type == "url":
        return "url"
    if ioc_type in ("ipv4", "ipv6"):
        return "ip"
    return "domain"


def get_ltv(apt: str | None, ioc_type: str) -> float:
    return LTV.get((apt, ioc_group(ioc_type)), 1.0)


def tau_for(row: dict) -> float:
    if row.get("vt_ttl_days"):
        return float(row["vt_ttl_days"])
    return TAU_DEFAULT[ioc_group(row["type"])]


def get_verdict(row: dict) -> str:
    """Classify an IOC verdict by aggregating votes across all enrichment sources.

    Each source casts weighted votes: 2 for high-confidence signals, 1 for partial.
    3+ votes → malicious; 1-2 → suspicious; 0 + VT-verified clean → clean; else unknown.
    """
    group = ioc_group(row.get("type", "domain"))
    votes = 0

    # VirusTotal hash/IP enrichment
    if row.get("vt_verified"):
        vt_mal = row.get("vt_malicious") or 0
        thresh = VT_MALICIOUS_THRESHOLD.get(group, 3)
        if vt_mal >= thresh:
            votes += 2
        elif vt_mal >= 1:
            votes += 1

    # VirusTotal domain enrichment (separate enricher path)
    if row.get("vt_domain_checked") and group == "domain":
        vt_d = row.get("vt_domain_malicious") or 0
        thresh = VT_MALICIOUS_THRESHOLD["domain"]
        if vt_d >= thresh:
            votes += 2
        elif vt_d >= 1:
            votes += 1

    # AbuseIPDB (IPs only)
    if row.get("abuseipdb_checked") and group == "ip":
        ab = row.get("abuseipdb_score") or 0
        if ab >= 75:
            votes += 2
        elif ab >= 25:
            votes += 1

    # ThreatFox
    if row.get("tf_threat_type"):
        tf = row.get("tf_confidence") or 0
        if tf >= 75:
            votes += 2
        elif tf >= 25:
            votes += 1

    # GreyNoise
    if row.get("greynoise_classification") == "malicious":
        votes += 1

    # URLhaus (domain/URL actively hosting malware)
    if row.get("urlhaus_domain_status") == "online":
        votes += 1

    # Hybrid Analysis sandbox verdict (hash IOCs only)
    if row.get("ha_checked"):
        ha_v = row.get("ha_verdict")
        if ha_v == "malicious":
            votes += 2
        elif ha_v == "suspicious":
            votes += 1
        elif ha_v == "whitelisted":
            votes -= 1  # known-good by sandbox; counteracts other signals

    # CIRCL HASHLOOKUP: trust >= 70 means known-good (NSRL / software corpus)
    if row.get("hashlookup_checked") and row.get("hashlookup_known"):
        trust = row.get("hashlookup_trust")
        if trust is not None and trust >= 70:
            votes -= 1  # strong known-good signal reduces maliciousness confidence

    # Domain age: newly registered domains are a strong threat indicator.
    # < 90 days old → very high risk (+2); 90–299 days → elevated risk (+1).
    if group == "domain" and row.get("domain_registered"):
        try:
            reg_date = datetime.strptime(str(row["domain_registered"])[:10], "%Y-%m-%d").date()
            age_days = (datetime.now(timezone.utc).date() - reg_date).days
            if age_days < 90:
                votes += 2
            elif age_days < 300:
                votes += 1
        except (ValueError, TypeError):
            pass

    if votes >= 3:
        return "malicious"
    if votes >= 1:
        return "suspicious"

    # VT-verified with zero detections across all checked paths → likely benign
    vt_checked = row.get("vt_verified") or (row.get("vt_domain_checked") and group == "domain")
    if vt_checked:
        vt_total = (row.get("vt_malicious") or 0) + (row.get("vt_domain_malicious") or 0)
        if vt_total == 0:
            return "clean"

    return "unknown"


def compute_score(last_seen: str, tau: float, ltv: float, verdict: str = "unknown") -> float:
    """Polynomial decay: base × (1 − (t / τ_eff)^(1/δ))

    clean/unknown use δ=0.5 → (t/τ_eff)² — identical to the original quadratic formula.
    suspicious/malicious get extended τ_eff and a slower curve so they stay actionable longer.
    No verdict produces a lower score than the original formula would have.
    """
    today = datetime.now(timezone.utc).date()
    try:
        ls = datetime.strptime(str(last_seen), "%Y-%m-%d").date()
    except ValueError:
        return 0.0
    t = (today - ls).days

    params   = VERDICT_PARAMS.get(verdict, VERDICT_PARAMS["unknown"])
    base     = params["base"]
    tau_eff  = tau * ltv * params["tau_mult"]
    delta    = params["delta"]

    if tau_eff <= 0 or t < 0:
        return 0.0
    if t >= tau_eff:
        return 0.0

    raw = base * (1.0 - (t / tau_eff) ** (1.0 / delta))
    return max(0.0, round(raw, 2))
