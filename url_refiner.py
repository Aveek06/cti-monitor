"""URL IOC helpers: normalisation, host extraction and heuristic classification."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

_PAYLOAD_EXT = {
    "exe", "dll", "msi", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "hta", "lnk", "jar", "apk",
    "iso", "img", "zip", "rar", "7z", "gz", "docm", "xlsm", "pptm", "sh", "elf", "bin", "dmg", "pkg",
}

_ABUSED_TLDS = {
    "sbs", "top", "xyz", "click", "cc", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "buzz",
    "rest", "monster", "cfd", "su", "zip", "mov", "work", "support", "loan", "country",
}

_PHISH_WORDS = re.compile(
    r"login|log-in|signin|sign-in|verify|verification|webmail|password|wallet|secure-|account-|-account|update-",
    re.IGNORECASE,
)


def _strip_trailing(url: str) -> str:
    """Remove sentence punctuation stuck to a URL; drop a closing bracket only if unbalanced."""
    url = url.strip().strip("<>")
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last in ")]}" and url.count(last) > url.count({")": "(", "]": "[", "}": "{"}[last]):
            url = url[:-1]
        else:
            break
    return url


def normalize_url(url: str | None) -> str | None:
    """Canonical form: trimmed, lowercase scheme/host, default port and fragment removed."""
    if not url:
        return None
    u = _strip_trailing(url)
    try:
        p = urlsplit(u)
        port = p.port
    except ValueError:
        return None
    host = (p.hostname or "").rstrip(".").lower()
    if not p.scheme or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port == _DEFAULT_PORTS.get(p.scheme.lower()):
        port = None
    userinfo = p.netloc.rpartition("@")[0]
    netloc = (userinfo + "@" if userinfo else "") + host + (f":{port}" if port is not None else "")
    return urlunsplit((p.scheme.lower(), netloc, p.path, p.query, ""))


def host_of(url: str | None) -> str | None:
    try:
        host = urlsplit(url or "").hostname
    except ValueError:
        return None
    host = (host or "").rstrip(".").lower()
    return host or None


def is_ip_host(host: str | None) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def classify_url(url: str) -> tuple[str, list[str]]:
    """Return (type, flags). type is payload, c2, phishing or other; flags are risk traits."""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return "other", []
    host = host_of(url) or ""
    ip = is_ip_host(host)
    flags: list[str] = []
    if ip:
        flags.append("ip-host")
    if port is not None and port not in (80, 443):
        flags.append("odd-port")
    if not ip and host.rsplit(".", 1)[-1] in _ABUSED_TLDS:
        flags.append("abused-tld")
    if "xn--" in host:
        flags.append("punycode")

    last_seg = p.path.rsplit("/", 1)[-1].lower()
    ext = last_seg.rsplit(".", 1)[-1] if "." in last_seg else ""
    if ext in _PAYLOAD_EXT:
        return "payload", flags
    if p.scheme.lower() in ("ws", "wss") or (ip and "odd-port" in flags):
        return "c2", flags
    if not ip and _PHISH_WORDS.search(host + p.path):
        return "phishing", flags
    return "other", flags
