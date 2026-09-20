import os
import json
import psycopg2
import psycopg2.extras

SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id               SERIAL PRIMARY KEY,
    stix_id          TEXT UNIQUE NOT NULL,
    stix_object      JSONB NOT NULL,
    value            TEXT NOT NULL,
    type             TEXT NOT NULL,
    first_seen       DATE NOT NULL,
    last_seen        DATE NOT NULL,
    attributed_apt   TEXT,
    ltv              FLOAT NOT NULL DEFAULT 1.0,
    tau              FLOAT NOT NULL,
    source_article   TEXT,
    source_blog      TEXT,
    vt_verified      BOOLEAN DEFAULT FALSE,
    vt_malicious     INTEGER,
    vt_ttl_days      FLOAT,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(value, type)
);
"""


def get_connection():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def init_schema(conn):
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
        # Additive migrations — safe to run on existing tables
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS shodan_checked BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS shodan_tags   JSONB")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS shodan_ports  JSONB")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS abuseipdb_checked    BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS abuseipdb_score      INT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS abuseipdb_reports    INT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS abuseipdb_isp        TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS abuseipdb_usage_type TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS greynoise_checked    BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS greynoise_noise      BOOLEAN")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS greynoise_riot       BOOLEAN")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS greynoise_classification TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS greynoise_name       TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS ipinfo_checked       BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS ipinfo_org           TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS ipinfo_country       TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS ipinfo_city          TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS ipinfo_hostname      TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS vt_domain_checked    BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS vt_domain_malicious  INT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS vt_domain_categories JSONB")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS domain_meta_checked  BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS urlhaus_domain_status TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS urlhaus_domain_threat TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS domain_registered    TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS domain_registrar     TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS domain_resolves      BOOLEAN")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS domain_resolved_ips  JSONB")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS hash_meta_checked    BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS mb_file_type         TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS mb_file_name         TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS mb_signature         TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS mb_tags              JSONB")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS tf_threat_type       TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS tf_malware           TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS tf_confidence        INT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS source_count         INT DEFAULT 1")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS source_blogs         JSONB DEFAULT '[]'")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS apt_match_method     TEXT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS apt_site_reliability INT")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS typosquat_checked   BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS is_typosquat        BOOLEAN")
        cur.execute("ALTER TABLE ioc_indicators ADD COLUMN IF NOT EXISTS typosquat_of        TEXT")
    conn.commit()


def init_ratings_schema(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS site_ratings (
                id        SERIAL PRIMARY KEY,
                site_name TEXT NOT NULL,
                rating    INT  NOT NULL CHECK (rating BETWEEN 1 AND 5),
                note      TEXT,
                rater     TEXT,
                rated_at  TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_site_ratings_name ON site_ratings(site_name)")
    conn.commit()


def upsert_ioc(conn, stix_obj, value, ioc_type, first_seen, last_seen,
               apt, ltv, tau, source_article, source_blog,
               apt_match_method: str = "regex", site_reliability: int = 50):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO ioc_indicators
                (stix_id, stix_object, value, type, first_seen, last_seen,
                 attributed_apt, ltv, tau, source_article, source_blog,
                 source_blogs, apt_match_method, apt_site_reliability)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    jsonb_build_array(%s::text), %s, %s)
            ON CONFLICT (value, type) DO UPDATE SET
                last_seen      = EXCLUDED.last_seen,
                stix_object    = EXCLUDED.stix_object,
                source_article = EXCLUDED.source_article,
                source_blog    = EXCLUDED.source_blog,
                ltv            = EXCLUDED.ltv,
                updated_at     = NOW(),
                source_count = CASE
                    WHEN ioc_indicators.source_blog IS DISTINCT FROM EXCLUDED.source_blog
                    THEN COALESCE(ioc_indicators.source_count, 1) + 1
                    ELSE COALESCE(ioc_indicators.source_count, 1)
                END,
                source_blogs = CASE
                    WHEN COALESCE(ioc_indicators.source_blogs, '[]'::jsonb) ? EXCLUDED.source_blog
                    THEN COALESCE(ioc_indicators.source_blogs, '[]'::jsonb)
                    ELSE COALESCE(ioc_indicators.source_blogs, '[]'::jsonb) || to_jsonb(EXCLUDED.source_blog::text)
                END,
                apt_match_method = CASE
                    WHEN EXCLUDED.apt_match_method = 'ai' THEN 'ai'
                    ELSE COALESCE(ioc_indicators.apt_match_method, EXCLUDED.apt_match_method)
                END,
                apt_site_reliability = GREATEST(
                    COALESCE(ioc_indicators.apt_site_reliability, 0),
                    COALESCE(EXCLUDED.apt_site_reliability, 0)
                )
        """, (
            stix_obj["id"],
            json.dumps(stix_obj),
            value, ioc_type,
            first_seen, last_seen,
            apt, ltv, tau,
            source_article, source_blog,
            source_blog, apt_match_method, site_reliability,
        ))
    conn.commit()


def get_new_iocs_since(conn, date_str: str) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM ioc_indicators WHERE first_seen >= %s ORDER BY first_seen DESC",
            (date_str,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_active_iocs(conn, min_score=30.0) -> list[dict]:
    from ioc_scorer import tau_for, compute_score, get_verdict
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM ioc_indicators ORDER BY last_seen DESC")
        rows = [dict(r) for r in cur.fetchall()]
    result = []
    for row in rows:
        count = row.get("source_count") or 1
        corr = 1.0 + min(count - 1, 3) * 0.15  # ×1.0 / ×1.15 / ×1.30 / ×1.45
        effective_ltv = float(row.get("ltv") or 1.0) * corr
        verdict = get_verdict(row)
        score = compute_score(str(row["last_seen"]), tau_for(row), effective_ltv, verdict)
        if score >= min_score:
            row["score"] = score
            row["verdict"] = verdict
            result.append(row)
    return result


def get_all_stix_objects(conn) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT stix_object FROM ioc_indicators ORDER BY last_seen DESC")
        return [row["stix_object"] for row in cur.fetchall()]


def prune_expired(conn, grace_days: int = 90) -> int:
    """Delete IOCs whose last_seen is older than grace_days. Returns deleted row count."""
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM ioc_indicators WHERE last_seen < CURRENT_DATE - INTERVAL '%s days'",
            (grace_days,),
        )
        deleted = cur.rowcount
    conn.commit()
    return deleted


def prune_sigma_rules(conn, max_age_days: int = 7) -> int:
    """Delete sigma rules older than max_age_days. Returns deleted row count."""
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM sigma_rules WHERE created_at < NOW() - INTERVAL '%s days'",
            (max_age_days,),
        )
        deleted = cur.rowcount
    conn.commit()
    return deleted


TTP_SCHEMA = """
CREATE TABLE IF NOT EXISTS ttp_observations (
    id                SERIAL PRIMARY KEY,
    technique_id      TEXT NOT NULL,
    technique_name    TEXT,
    tactic            TEXT,
    source_article    TEXT NOT NULL,
    source_blog       TEXT,
    attributed_apt    TEXT,
    first_seen        DATE NOT NULL DEFAULT CURRENT_DATE,
    last_seen         DATE NOT NULL DEFAULT CURRENT_DATE,
    observation_count INT  NOT NULL DEFAULT 1,
    confidence        FLOAT DEFAULT NULL,
    evidence_text     TEXT DEFAULT NULL,
    UNIQUE(technique_id, source_article)
);
"""


def init_ttp_schema(conn):
    with conn.cursor() as cur:
        cur.execute(TTP_SCHEMA)
        # Migrate existing tables that predate confidence/evidence_text columns
        cur.execute("ALTER TABLE ttp_observations ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT NULL")
        cur.execute("ALTER TABLE ttp_observations ADD COLUMN IF NOT EXISTS evidence_text TEXT DEFAULT NULL")
    conn.commit()


def upsert_ttp(conn, technique_id: str, technique_name: str | None,
               tactic: str | None, source_article: str, source_blog: str | None,
               apt: str | None, date_str: str,
               confidence: float | None = None, evidence_text: str | None = None):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO ttp_observations
                (technique_id, technique_name, tactic,
                 source_article, source_blog, attributed_apt,
                 first_seen, last_seen, observation_count,
                 confidence, evidence_text)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s)
            ON CONFLICT (technique_id, source_article) DO UPDATE SET
                last_seen         = EXCLUDED.last_seen,
                technique_name    = COALESCE(EXCLUDED.technique_name, ttp_observations.technique_name),
                tactic            = COALESCE(EXCLUDED.tactic,         ttp_observations.tactic),
                observation_count = ttp_observations.observation_count + 1,
                confidence        = COALESCE(EXCLUDED.confidence,     ttp_observations.confidence),
                evidence_text     = COALESCE(EXCLUDED.evidence_text,  ttp_observations.evidence_text)
        """, (technique_id, technique_name, tactic,
              source_article, source_blog, apt, date_str, date_str,
              confidence, evidence_text))
    conn.commit()


SIGMA_SCHEMA = """
CREATE TABLE IF NOT EXISTS sigma_rules (
    id              SERIAL PRIMARY KEY,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT,
    tactic          TEXT,
    source_article  TEXT NOT NULL,
    source_blog     TEXT,
    attributed_apt  TEXT,
    sigma_yaml      TEXT NOT NULL,
    sigma_status    TEXT DEFAULT 'draft',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(technique_id, source_article)
);
"""


def init_sigma_schema(conn):
    with conn.cursor() as cur:
        cur.execute(SIGMA_SCHEMA)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sigma_technique ON sigma_rules(technique_id)")
    conn.commit()


# Threat actor profiles, enriched from two independent external sources:
# MITRE ATT&CK (nation-state groups) and ransomware.live (financial/extortion
# brands). Columns are grouped by which sync owns them so the two sync jobs
# never clobber each other's data on the same actor_name row.
ACTOR_PROFILE_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_actor_profiles (
    id                      SERIAL PRIMARY KEY,
    actor_name              TEXT UNIQUE NOT NULL,
    match_method            TEXT,
    -- MITRE-owned columns
    mitre_group_id          TEXT,
    mitre_url               TEXT,
    aliases                 JSONB DEFAULT '[]',
    description             TEXT,
    techniques              JSONB DEFAULT '[]',
    software                JSONB DEFAULT '[]',
    campaigns               JSONB DEFAULT '[]',
    mitre_synced            TIMESTAMPTZ,
    -- ransomware.live-owned columns
    ransomware_live_id      TEXT,
    ransomware_description  TEXT,
    victim_count            INT,
    first_seen_rw           DATE,
    last_seen_rw            DATE,
    recent_victims          JSONB DEFAULT '[]',
    sectors_targeted        JSONB DEFAULT '[]',
    tools                   JSONB DEFAULT '[]',
    ransomware_ttps         JSONB DEFAULT '[]',
    leak_sites              JSONB DEFAULT '[]',
    vulnerabilities         JSONB DEFAULT '[]',
    negotiation_stats       JSONB,
    ransom_note_names       JSONB DEFAULT '[]',
    ransom_notes            JSONB DEFAULT '[]',
    yara_rules              JSONB DEFAULT '[]',
    ransomware_synced       TIMESTAMPTZ,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);
"""


def init_actor_profile_schema(conn):
    with conn.cursor() as cur:
        cur.execute(ACTOR_PROFILE_SCHEMA)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_actor_profiles_mitre_id ON threat_actor_profiles(mitre_group_id)")
        # Migrate tables created before ransom_notes/yara_rules existed
        cur.execute("ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS ransom_notes JSONB DEFAULT '[]'")
        cur.execute("ALTER TABLE threat_actor_profiles ADD COLUMN IF NOT EXISTS yara_rules JSONB DEFAULT '[]'")
    conn.commit()


def upsert_mitre_profile(conn, actor_name: str, mitre_group_id: str | None, mitre_url: str | None,
                          aliases: list, description: str | None, techniques: list,
                          software: list, campaigns: list, match_method: str | None):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO threat_actor_profiles
                (actor_name, mitre_group_id, mitre_url, aliases, description,
                 techniques, software, campaigns, match_method, mitre_synced, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, NOW(), NOW())
            ON CONFLICT (actor_name) DO UPDATE SET
                mitre_group_id = EXCLUDED.mitre_group_id,
                mitre_url      = EXCLUDED.mitre_url,
                aliases        = EXCLUDED.aliases,
                description    = EXCLUDED.description,
                techniques     = EXCLUDED.techniques,
                software       = EXCLUDED.software,
                campaigns      = EXCLUDED.campaigns,
                mitre_synced   = NOW(),
                updated_at     = NOW(),
                match_method   = COALESCE(threat_actor_profiles.match_method, EXCLUDED.match_method)
        """, (actor_name, mitre_group_id, mitre_url, json.dumps(aliases), description,
              json.dumps(techniques), json.dumps(software), json.dumps(campaigns), match_method))
    conn.commit()


def upsert_ransomware_profile(conn, actor_name: str, ransomware_live_id: str | None,
                               ransomware_description: str | None, victim_count: int | None,
                               first_seen_rw: str | None, last_seen_rw: str | None,
                               recent_victims: list, sectors_targeted: list, tools,
                               ransomware_ttps: list, leak_sites: list, vulnerabilities: list,
                               negotiation_stats: dict | None, ransom_note_names: list,
                               ransom_notes: list, yara_rules: list,
                               match_method: str | None):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO threat_actor_profiles
                (actor_name, ransomware_live_id, ransomware_description, victim_count,
                 first_seen_rw, last_seen_rw, recent_victims, sectors_targeted, tools,
                 ransomware_ttps, leak_sites, vulnerabilities, negotiation_stats,
                 ransom_note_names, ransom_notes, yara_rules, match_method,
                 ransomware_synced, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                    %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb,
                    %s::jsonb, %s, NOW(), NOW())
            ON CONFLICT (actor_name) DO UPDATE SET
                ransomware_live_id     = EXCLUDED.ransomware_live_id,
                ransomware_description = EXCLUDED.ransomware_description,
                victim_count           = EXCLUDED.victim_count,
                first_seen_rw          = EXCLUDED.first_seen_rw,
                last_seen_rw           = EXCLUDED.last_seen_rw,
                recent_victims         = EXCLUDED.recent_victims,
                sectors_targeted       = EXCLUDED.sectors_targeted,
                tools                  = EXCLUDED.tools,
                ransomware_ttps        = EXCLUDED.ransomware_ttps,
                leak_sites             = EXCLUDED.leak_sites,
                vulnerabilities        = EXCLUDED.vulnerabilities,
                negotiation_stats      = EXCLUDED.negotiation_stats,
                ransom_note_names      = EXCLUDED.ransom_note_names,
                ransom_notes           = EXCLUDED.ransom_notes,
                yara_rules             = EXCLUDED.yara_rules,
                ransomware_synced      = NOW(),
                updated_at             = NOW(),
                match_method           = COALESCE(threat_actor_profiles.match_method, EXCLUDED.match_method)
        """, (actor_name, ransomware_live_id, ransomware_description, victim_count,
              first_seen_rw, last_seen_rw, json.dumps(recent_victims), json.dumps(sectors_targeted),
              json.dumps(tools), json.dumps(ransomware_ttps), json.dumps(leak_sites),
              json.dumps(vulnerabilities), json.dumps(negotiation_stats) if negotiation_stats else None,
              json.dumps(ransom_note_names), json.dumps(ransom_notes), json.dumps(yara_rules),
              match_method))
    conn.commit()


def upsert_sigma_rule(conn, technique_id: str, technique_name: str | None,
                      tactic: str | None, source_article: str, source_blog: str | None,
                      attributed_apt: str | None, sigma_yaml: str):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO sigma_rules
                (technique_id, technique_name, tactic, source_article,
                 source_blog, attributed_apt, sigma_yaml)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (technique_id, source_article) DO NOTHING
        """, (technique_id, technique_name, tactic, source_article,
              source_blog, attributed_apt, sigma_yaml))
    conn.commit()


def update_sigma_status(conn, rule_id: int, status: str):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE sigma_rules SET sigma_status=%s WHERE id=%s",
            (status, rule_id),
        )
    conn.commit()


def get_all_sigma_rules(conn) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM sigma_rules ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]


def get_all_ttps(conn) -> list[dict]:
    """Return TTPs aggregated by technique_id for dashboard export."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT
                technique_id,
                MAX(technique_name)                          AS technique_name,
                MAX(tactic)                                  AS tactic,
                COUNT(*)                                     AS article_count,
                SUM(observation_count)                       AS total_observations,
                MAX(last_seen::text)                         AS last_seen,
                ROUND(AVG(confidence) FILTER (WHERE confidence IS NOT NULL)::numeric, 1)
                                                             AS avg_confidence,
                array_agg(DISTINCT attributed_apt)
                    FILTER (WHERE attributed_apt IS NOT NULL) AS apts,
                json_agg(
                    json_build_object(
                        'url',        source_article,
                        'blog',       source_blog,
                        'apt',        attributed_apt,
                        'confidence', confidence,
                        'evidence',   evidence_text,
                        'last_seen',  last_seen::text
                    )
                    ORDER BY last_seen DESC
                ) FILTER (WHERE source_article IS NOT NULL)  AS sources
            FROM ttp_observations
            GROUP BY technique_id
            ORDER BY total_observations DESC, last_seen DESC
        """)
        return [dict(r) for r in cur.fetchall()]


def get_all_actors(conn) -> list[dict]:
    """Return threat actors aggregated across all TTP observations, enriched
    with external profile data (MITRE ATT&CK, ransomware.live) where available.

    Uses a FULL OUTER JOIN (not LEFT JOIN) so an actor with an external
    profile but zero of our own TTP observations still surfaces -- e.g. a
    ransomware brand our monitored blogs have never named by article, but
    that ransomware.live tracks richly. Such actors get article_count=0.
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT
                COALESCE(t.actor_name, p.actor_name)        AS actor,
                COALESCE(t.article_count, 0)                AS article_count,
                COALESCE(t.technique_count, 0)               AS technique_count,
                COALESCE(t.last_seen, p.last_seen_rw::text)  AS last_seen,
                COALESCE(t.techniques, ARRAY[]::text[])      AS techniques,
                COALESCE(t.sources, ARRAY[]::text[])         AS sources,
                p.mitre_group_id,
                p.mitre_url,
                p.aliases,
                p.description,
                p.techniques         AS mitre_techniques,
                p.software,
                p.campaigns,
                p.mitre_synced,
                p.ransomware_live_id,
                p.ransomware_description,
                p.victim_count,
                p.first_seen_rw,
                p.last_seen_rw,
                p.recent_victims,
                p.sectors_targeted,
                p.tools,
                p.ransomware_ttps,
                p.leak_sites,
                p.vulnerabilities,
                p.negotiation_stats,
                p.ransom_note_names,
                p.ransom_notes,
                p.yara_rules,
                p.ransomware_synced
            FROM (
                SELECT
                    attributed_apt                        AS actor_name,
                    COUNT(DISTINCT source_article)        AS article_count,
                    COUNT(DISTINCT technique_id)          AS technique_count,
                    MAX(last_seen::text)                  AS last_seen,
                    array_agg(DISTINCT technique_id)      AS techniques,
                    array_agg(DISTINCT source_article)    AS sources
                FROM ttp_observations
                WHERE attributed_apt IS NOT NULL
                GROUP BY attributed_apt
            ) t
            FULL OUTER JOIN threat_actor_profiles p ON p.actor_name = t.actor_name
            ORDER BY article_count DESC NULLS LAST, last_seen DESC NULLS LAST
        """)
        return [dict(r) for r in cur.fetchall()]


def refresh_actor_export(conn) -> list[dict]:
    """Recompute get_all_actors() and write it to pipeline_state["actor_export"].

    ioc_pipeline.py's run() already does this as part of the full daily
    pipeline. The standalone sync_mitre_groups.py and sync_ransomware_live.py
    scripts write directly to threat_actor_profiles/ioc_indicators but never
    touch pipeline_state -- without this, the dashboard (which reads the
    pipeline_state cache, not live queries) would keep showing stale actor
    data until the next full pipeline run. Both scripts call this at the end
    of their sync() so the dashboard reflects new data immediately.
    """
    actor_export = get_all_actors(conn)
    upsert_pipeline_state(conn, "actor_export", actor_export)
    return actor_export


PIPELINE_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_state (
    key        TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def init_pipeline_state_schema(conn):
    with conn.cursor() as cur:
        cur.execute(PIPELINE_STATE_SCHEMA)
    conn.commit()


def upsert_pipeline_state(conn, key: str, data) -> None:
    """Stores (or replaces) a JSON blob under the given key."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO pipeline_state (key, data, updated_at)
            VALUES (%s, %s::jsonb, NOW())
            ON CONFLICT (key) DO UPDATE
                SET data = EXCLUDED.data, updated_at = NOW()
            """,
            (key, json.dumps(data, default=str)),
        )
    conn.commit()


def get_pipeline_state(conn, key: str):
    """Returns parsed Python object for the given key, or None."""
    with conn.cursor() as cur:
        cur.execute("SELECT data FROM pipeline_state WHERE key = %s", (key,))
        row = cur.fetchone()
    return row[0] if row else None
