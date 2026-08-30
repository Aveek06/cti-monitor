from datetime import datetime, timezone

LTV = {
    ("APT10", "domain"): 0.97,
    ("APT10", "hash"):   1.85,
    ("APT29", "domain"): 0.61,
    ("APT29", "hash"):   0.84,
    ("APT38", "domain"): 0.83,
    ("APT38", "hash"):   0.77,
}
TAU_DEFAULT = {"domain": 30, "hash": 60, "url": 7, "ip": 7}


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


def compute_score(last_seen: str, tau: float, ltv: float) -> float:
    today = datetime.now(timezone.utc).date()
    try:
        ls = datetime.strptime(str(last_seen), "%Y-%m-%d").date()
    except ValueError:
        return 0.0
    t = (today - ls).days
    denom = tau * ltv
    if denom <= 0:
        return 0.0
    return max(0.0, round(100 * (1.0 - (t / denom) ** 2), 2))
