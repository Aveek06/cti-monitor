"""Typosquat and brand-abuse detection for fqdn IOCs."""
import os
import json
import psycopg2.extras
from rapidfuzz.distance import Levenshtein

# Unicode confusable characters → ASCII equivalents
_HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p',
    'с': 'c', 'х': 'x', 'у': 'y', 'ѵ': 'v',
    # Greek lookalikes
    'α': 'a', 'ο': 'o', 'ν': 'v',
    # Digit substitutions
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '8': 'b',
    # Accented Latin
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a',
    'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
    'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
})

_PROTECTED: list[str] = []


def _load_protected() -> list[str]:
    global _PROTECTED
    if _PROTECTED:
        return _PROTECTED
    path = os.path.join(os.path.dirname(__file__), "protected_domains.txt")
    try:
        with open(path, encoding="utf-8") as f:
            _PROTECTED = [
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        _PROTECTED = []
    return _PROTECTED


def _sld(domain: str) -> str:
    """Second-level domain: 'www.microsoft.com' → 'microsoft'."""
    parts = domain.lower().rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _normalize(s: str) -> str:
    return s.translate(_HOMOGLYPH_MAP)


def check_domain(value: str) -> dict | None:
    """
    Returns {"is_typosquat": True, "typosquat_of": "paypal.com"} if flagged,
    or {"is_typosquat": False, "typosquat_of": None} if clean.
    Returns None if no protected list is loaded.
    """
    protected = _load_protected()
    if not protected:
        return None

    ioc_sld = _normalize(_sld(value))

    for protected_domain in protected:
        p_sld = _normalize(_sld(protected_domain))

        # Skip if they are the same domain (exact match = not a typosquat, it's the real thing)
        if ioc_sld == p_sld:
            return {"is_typosquat": False, "typosquat_of": None}

        # Edit distance ≤ 1 after homoglyph normalization
        if Levenshtein.distance(ioc_sld, p_sld) <= 1:
            return {"is_typosquat": True, "typosquat_of": protected_domain}

        # Protected brand embedded as substring (login-paypal, paypal-secure)
        if len(p_sld) >= 5 and len(ioc_sld) > len(p_sld) + 1 and p_sld in ioc_sld:
            return {"is_typosquat": True, "typosquat_of": protected_domain}

    return {"is_typosquat": False, "typosquat_of": None}


def enrich_pending_domains(conn, limit: int = 200) -> None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, value FROM ioc_indicators "
            "WHERE typosquat_checked = FALSE AND type = 'domain'"
            "ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        rows = cur.fetchall()
    flagged = 0
    for row in rows:
        try:
            result = check_domain(row["value"])
            if result is None:
                break  # no protected list — stop silently
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ioc_indicators SET typosquat_checked=TRUE, "
                    "is_typosquat=%s, typosquat_of=%s, updated_at=NOW() WHERE id=%s",
                    (result["is_typosquat"], result["typosquat_of"], row["id"]),
                )
            conn.commit()
            if result["is_typosquat"]:
                flagged += 1
        except Exception as e:
            print(f"Typosquat check error for {row['value']}: {e}")
            conn.rollback()
    if rows:
        print(f"Typosquat check: {len(rows)} domains checked, {flagged} flagged.")
