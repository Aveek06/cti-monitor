"""Periodic bulk sync of MITRE ATT&CK Enterprise group (Intrusion Set) profiles
into threat_actor_profiles.

Deliberately NOT shaped like the per-item enrichers (vt_enricher.py etc.):
this is one bulk GET of the whole MITRE STIX bundle, not N per-item API
calls, so there is no rate-limit sleep, no *_checked gate, and no limit=N
batching. MITRE updates ATT&CK roughly twice a year -- this is meant to be
run monthly via .github/workflows/sync-mitre-groups.yml, not on every
pipeline invocation.

Usage:
    DATABASE_URL=... python sync_mitre_groups.py
"""
import os
import sys

import requests

import ioc_db
import actor_matching

ATTACK_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def _external_id(obj: dict, source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return ref["external_id"]
    return None


def _external_url(obj: dict, source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name and ref.get("url"):
            return ref["url"]
    return None


def fetch_bundle() -> list[dict]:
    resp = requests.get(ATTACK_BUNDLE_URL, timeout=180)
    resp.raise_for_status()
    return resp.json()["objects"]


def build_group_profiles(objects: list[dict]) -> dict[str, dict]:
    """Return {intrusion_set_id: profile_dict} keyed by STIX id."""
    intrusion_sets = {o["id"]: o for o in objects if o.get("type") == "intrusion-set"}
    campaigns_by_id = {o["id"]: o for o in objects if o.get("type") == "campaign"}
    software_by_id = {o["id"]: o for o in objects if o.get("type") in ("malware", "tool")}
    technique_by_id = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    relationships = [o for o in objects if o.get("type") == "relationship"]

    group_techniques: dict[str, set] = {gid: set() for gid in intrusion_sets}
    group_software: dict[str, set] = {gid: set() for gid in intrusion_sets}
    group_campaign_ids: dict[str, set] = {gid: set() for gid in intrusion_sets}

    # Pass 1: direct intrusion-set -> technique/software "uses" edges,
    # and campaign -> intrusion-set "attributed-to" edges.
    for r in relationships:
        src, tgt, rtype = r.get("source_ref"), r.get("target_ref"), r.get("relationship_type")
        if rtype == "uses" and src in intrusion_sets:
            if tgt in technique_by_id:
                tid = _external_id(technique_by_id[tgt])
                if tid:
                    group_techniques[src].add(tid)
            elif tgt in software_by_id:
                name = software_by_id[tgt].get("name")
                if name:
                    group_software[src].add(name)
        if rtype == "attributed-to" and src in campaigns_by_id and tgt in intrusion_sets:
            group_campaign_ids[tgt].add(src)

    # Pass 2: roll each campaign's own "uses" edges into its attributed group.
    campaign_to_groups: dict[str, set] = {}
    for gid, cids in group_campaign_ids.items():
        for cid in cids:
            campaign_to_groups.setdefault(cid, set()).add(gid)

    for r in relationships:
        src, tgt, rtype = r.get("source_ref"), r.get("target_ref"), r.get("relationship_type")
        if rtype == "uses" and src in campaigns_by_id:
            owning_groups = campaign_to_groups.get(src, set())
            if not owning_groups:
                continue
            if tgt in technique_by_id:
                tid = _external_id(technique_by_id[tgt])
                if tid:
                    for gid in owning_groups:
                        group_techniques[gid].add(tid)
            elif tgt in software_by_id:
                name = software_by_id[tgt].get("name")
                if name:
                    for gid in owning_groups:
                        group_software[gid].add(name)

    profiles = {}
    for gid, iset in intrusion_sets.items():
        campaigns = []
        for cid in group_campaign_ids.get(gid, set()):
            camp = campaigns_by_id[cid]
            campaigns.append({
                "name": camp.get("name"),
                "description": (camp.get("description") or "")[:500],
                "first_seen": camp.get("first_seen"),
                "last_seen": camp.get("last_seen"),
            })
        profiles[gid] = {
            "name": iset.get("name"),
            "aliases": iset.get("aliases", []),
            "description": iset.get("description"),
            "mitre_group_id": _external_id(iset),
            "mitre_url": _external_url(iset),
            "techniques": sorted(group_techniques.get(gid, set())),
            "software": sorted(group_software.get(gid, set())),
            "campaigns": campaigns,
        }
    return profiles


def sync(conn) -> dict:
    ioc_db.init_actor_profile_schema(conn)
    ioc_db.init_pipeline_state_schema(conn)

    print("sync_mitre_groups: fetching MITRE ATT&CK Enterprise bundle...")
    objects = fetch_bundle()
    profiles = build_group_profiles(objects)
    print(f"sync_mitre_groups: {len(profiles)} intrusion sets found in bundle.")

    index = actor_matching.build_alias_index()
    stats = {"exact": 0, "alias": 0, "unmatched": 0, "ambiguous": 0}

    for profile in profiles.values():
        canonical, method = actor_matching.match_actor(index, profile["name"], profile["aliases"])
        if not canonical:
            stats["unmatched"] += 1
            continue

        # Detect ambiguity: do any of this group's aliases also point at a
        # *different* canonical name than the one we picked?
        all_names = [profile["name"]] + list(profile["aliases"])
        distinct_hits = {index[n.lower().strip()] for n in all_names if n.lower().strip() in index}
        if len(distinct_hits) > 1:
            stats["ambiguous"] += 1
            print(f"sync_mitre_groups: WARNING - '{profile['name']}' aliases match multiple "
                  f"canonical names {sorted(distinct_hits)}; using '{canonical}'.")

        stats[method] += 1
        try:
            ioc_db.upsert_mitre_profile(
                conn, canonical, profile["mitre_group_id"], profile["mitre_url"],
                profile["aliases"], profile["description"], profile["techniques"],
                profile["software"], profile["campaigns"], method,
            )
        except Exception as e:
            print(f"sync_mitre_groups: upsert failed for '{canonical}': {e}")
            conn.rollback()

    print(f"sync_mitre_groups: done. exact={stats['exact']} alias={stats['alias']} "
          f"unmatched={stats['unmatched']} ambiguous={stats['ambiguous']}")

    try:
        exported = ioc_db.refresh_actor_export(conn)
        print(f"sync_mitre_groups: refreshed pipeline_state actor_export ({len(exported)} actors) "
              f"so the dashboard reflects this sync immediately.")
    except Exception as e:
        print(f"sync_mitre_groups: actor_export refresh failed: {e}")

    return stats


if __name__ == "__main__":
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("sync_mitre_groups: DATABASE_URL not set.")
        sys.exit(1)
    import psycopg2
    connection = psycopg2.connect(db_url)
    try:
        sync(connection)
    finally:
        connection.close()
