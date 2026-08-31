import uuid
import json
from datetime import datetime, timezone

_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL

STIX_PATTERNS = {
    "sha256":     "[file:hashes.'SHA-256' = '{v}']",
    "sha1":       "[file:hashes.'SHA-1' = '{v}']",
    "md5":        "[file:hashes.'MD5' = '{v}']",
    "domain":     "[domain-name:value = '{v}']",
    "ipv4":       "[ipv4-addr:value = '{v}']",
    "ipv6":       "[ipv6-addr:value = '{v}']",
    "url":        "[url:value = '{v}']",
    "email-addr": "[email-addr:value = '{v}']",
}


def make_stix_id(value: str, ioc_type: str) -> str:
    uid = uuid.uuid5(_NAMESPACE, f"{value}:{ioc_type}")
    return f"indicator--{uid}"


def make_threat_actor_id(apt_name: str) -> str:
    uid = uuid.uuid5(_NAMESPACE, f"threat-actor:{apt_name}")
    return f"threat-actor--{uid}"


def ioc_to_indicator(value, ioc_type, article_date, article_url, blog_name, today_str=None):
    if today_str is None:
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": make_stix_id(value, ioc_type),
        "created": f"{article_date}T00:00:00Z",
        "modified": f"{today_str}T00:00:00Z",
        "name": value,
        "pattern": STIX_PATTERNS[ioc_type].format(v=value),
        "pattern_type": "stix",
        "valid_from": f"{article_date}T00:00:00Z",
        "labels": ["malicious-activity"],
        "description": f"Extracted from {blog_name}: {article_url}",
        "external_references": [{"source_name": blog_name, "url": article_url}],
    }


def make_threat_actor(apt_name: str) -> dict:
    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": make_threat_actor_id(apt_name),
        "created": "2020-01-01T00:00:00Z",
        "modified": "2020-01-01T00:00:00Z",
        "name": apt_name,
        "labels": ["nation-state"],
    }


def make_relationship(indicator_id: str, threat_actor_id: str, today_str=None) -> dict:
    if today_str is None:
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    uid = uuid.uuid5(_NAMESPACE, f"rel:{indicator_id}:{threat_actor_id}")
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uid}",
        "created": f"{today_str}T00:00:00Z",
        "modified": f"{today_str}T00:00:00Z",
        "relationship_type": "indicates",
        "source_ref": indicator_id,
        "target_ref": threat_actor_id,
    }
