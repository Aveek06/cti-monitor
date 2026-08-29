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
    conn.commit()


def upsert_ioc(conn, stix_obj, value, ioc_type, first_seen, last_seen,
               apt, ltv, tau, source_article, source_blog):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO ioc_indicators
                (stix_id, stix_object, value, type, first_seen, last_seen,
                 attributed_apt, ltv, tau, source_article, source_blog)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (value, type) DO UPDATE SET
                last_seen      = EXCLUDED.last_seen,
                stix_object    = EXCLUDED.stix_object,
                source_article = EXCLUDED.source_article,
                source_blog    = EXCLUDED.source_blog,
                updated_at     = NOW()
        """, (
            stix_obj["id"],
            json.dumps(stix_obj),
            value, ioc_type,
            first_seen, last_seen,
            apt, ltv, tau,
            source_article, source_blog,
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
    from ioc_scorer import tau_for, compute_score
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM ioc_indicators ORDER BY last_seen DESC")
        rows = [dict(r) for r in cur.fetchall()]
    result = []
    for row in rows:
        score = compute_score(str(row["last_seen"]), tau_for(row), row["ltv"])
        if score >= min_score:
            row["score"] = score
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
    UNIQUE(technique_id, source_article)
);
"""


def init_ttp_schema(conn):
    with conn.cursor() as cur:
        cur.execute(TTP_SCHEMA)
    conn.commit()


def upsert_ttp(conn, technique_id: str, technique_name: str | None,
               tactic: str | None, source_article: str, source_blog: str | None,
               apt: str | None, date_str: str):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO ttp_observations
                (technique_id, technique_name, tactic,
                 source_article, source_blog, attributed_apt,
                 first_seen, last_seen, observation_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
            ON CONFLICT (technique_id, source_article) DO UPDATE SET
                last_seen         = EXCLUDED.last_seen,
                technique_name    = COALESCE(EXCLUDED.technique_name, ttp_observations.technique_name),
                tactic            = COALESCE(EXCLUDED.tactic,         ttp_observations.tactic),
                observation_count = ttp_observations.observation_count + 1
        """, (technique_id, technique_name, tactic,
              source_article, source_blog, apt, date_str, date_str))
    conn.commit()


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
                array_agg(DISTINCT attributed_apt)
                    FILTER (WHERE attributed_apt IS NOT NULL) AS apts,
                array_agg(DISTINCT source_blog)
                    FILTER (WHERE source_blog IS NOT NULL)    AS sources
            FROM ttp_observations
            GROUP BY technique_id
            ORDER BY total_observations DESC, last_seen DESC
        """)
        return [dict(r) for r in cur.fetchall()]
