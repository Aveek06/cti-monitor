"""Shared logic for matching an external threat-actor source (MITRE ATT&CK,
ransomware.live) against our own canonical actor names in ioc_extractor.APT_ALIASES.

Both sync_mitre_groups.py and sync_ransomware_live.py use this so a group from
either external source only ever gets attached to a name already known to our
own pipeline -- neither script invents new canonical actor names.
"""


def build_alias_index() -> dict[str, str]:
    """Reverse index: lowercased name/alias -> our canonical actor name."""
    from ioc_extractor import APT_ALIASES
    index: dict[str, str] = {}
    for canonical, aliases in APT_ALIASES.items():
        for s in [canonical] + list(aliases):
            index.setdefault(s.lower().strip(), canonical)
    return index


def match_actor(index: dict[str, str], primary_name: str,
                 aliases: list[str] | None = None) -> tuple[str | None, str | None]:
    """Match an external group's primary name / alias list against our index.

    Returns (canonical_name, method) where method is "exact" or "alias",
    or (None, None) if nothing matches.
    """
    primary_norm = (primary_name or "").lower().strip()
    if primary_norm and primary_norm in index:
        return index[primary_norm], "exact"
    for a in (aliases or []):
        a_norm = (a or "").lower().strip()
        if a_norm and a_norm in index:
            return index[a_norm], "alias"
    return None, None
