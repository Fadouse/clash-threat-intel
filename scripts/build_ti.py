#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[1]
INPUTS = ROOT / "inputs"
CLASH_DIR = ROOT / "clash" / "generated"
YARA_DIR = ROOT / "yara"
INTEL_DIR = ROOT / "intel"
META_DIR = ROOT / "meta"

for p in (INPUTS, CLASH_DIR, YARA_DIR, INTEL_DIR, META_DIR):
    p.mkdir(parents=True, exist_ok=True)

HTTP_TIMEOUT = 45
USER_AGENT = "fadouse-ti-builder/1.0"

THREATFOX_DAYS = int(os.getenv("THREATFOX_DAYS", "3"))
THREATFOX_CONFIDENCE = int(os.getenv("THREATFOX_CONFIDENCE", "50"))
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_ENRICH_LIMIT = int(os.getenv("VT_ENRICH_LIMIT", "20"))
VT_MIN_SCORE = int(os.getenv("VT_MIN_SCORE", "5"))
PUP_FILTER_URL = os.getenv("PUP_FILTER_URL", "").strip()

BLOCKLIST_ADS_URL = "https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt"
BLOCKLIST_TRACKING_URL = "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt"
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
URLHAUS_TEXT_URL = "https://urlhaus.abuse.ch/downloads/text/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY", "").strip()
MALWAREBAZAAR_RECENT_SHA256_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

STEALER_KEYWORDS = {
    "stealer",
    "stealc",
    "redline",
    "redlinestealer",
    "lumma",
    "vidar",
    "raccoon",
    "raccoonstealer",
    "deerstealer",
    "dogestealer",
    "atomic",
    "amos",
    "rhadamanthys",
}

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\.?$",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def log(msg: str) -> None:
    print(msg, flush=True)


def read_lines(path: pathlib.Path) -> list[str]:
    if not path.exists():
        path.write_text("", encoding="utf-8")
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]


def http_get_text(url: str, headers: dict[str, str] | None = None) -> str:
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def http_get_json(url: str, headers: dict[str, str] | None = None) -> dict:
    return json.loads(http_get_text(url, headers=headers))


def http_post_json(url: str, payload: dict, headers: dict[str, str] | None = None) -> dict:
    req_headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            content_type = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"HTTP {e.code} from {url}. Body preview: {body[:400]!r}"
        ) from e

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Non-JSON response from {url}. Content-Type={content_type!r}. "
            f"Body preview: {text[:400]!r}"
        ) from e


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def normalize_domain(value: str) -> str | None:
    s = value.strip().lower().rstrip(".")
    if not s:
        return None
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("||"):
        s = s[2:]
    s = s.split("^", 1)[0]
    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    if is_ip(s):
        return None
    m = DOMAIN_RE.match(s)
    if not m:
        return None
    return m.group(1).lower()


def normalize_ip_or_cidr(value: str) -> str | None:
    s = value.strip()
    if not s:
        return None

    # Remove brackets and port from URL
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1 and "." in s and "/" not in s:
        host, _, port = s.partition(":")
        if host and port.isdigit():
            s = host

    try:
        ip_obj = ipaddress.ip_address(s)
        if ip_obj.version == 4:
            return f"{ip_obj.compressed}/32"
        return f"{ip_obj.compressed}/128"
    except Exception:
        pass

    try:
        net = ipaddress.ip_network(s, strict=False)
        return str(net)
    except Exception:
        return None


def iter_domains_from_text_blocklist(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("#", "!", ";", "[")):
            continue

        if line.startswith("@@"):
            line = line[2:].strip()

        if line.startswith(("http://", "https://")):
            try:
                host = urllib.parse.urlparse(line).hostname or ""
            except Exception:
                host = ""
            domain = normalize_domain(host)
            if domain:
                yield domain
            continue

        if line.startswith("||"):
            domain = normalize_domain(line)
            if domain:
                yield domain
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            domain = normalize_domain(parts[1])
            if domain:
                yield domain
            continue

        domain = normalize_domain(line)
        if domain:
            yield domain


def iter_urls_from_urlhaus_text(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")):
            yield line


def extract_url_artifacts(url: str) -> tuple[set[str], set[str], set[str]]:
    domains: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return domains, ips, urls

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        urls.add(url)
        host = parsed.hostname or ""
        domain = normalize_domain(host)
        if domain:
            domains.add(domain)
        else:
            ipn = normalize_ip_or_cidr(host)
            if ipn:
                ips.add(ipn)
    return domains, ips, urls


def extract_ioc_artifacts(ioc_value: str, ioc_type: str) -> tuple[set[str], set[str], set[str]]:
    domains: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()

    value = (ioc_value or "").strip()
    kind = (ioc_type or "").strip().lower()

    if not value:
        return domains, ips, urls

    if value.startswith(("http://", "https://")) or "url" in kind:
        d, i, u = extract_url_artifacts(value)
        domains |= d
        ips |= i
        urls |= u
        return domains, ips, urls

    domain = normalize_domain(value)
    if domain and ("domain" in kind or "host" in kind or "." in value):
        domains.add(domain)
        return domains, ips, urls

    ipn = normalize_ip_or_cidr(value)
    if ipn and ("ip" in kind or ":" in value or "/" in value or is_ip(value)):
        ips.add(ipn)
        return domains, ips, urls

    return domains, ips, urls


def threatfox_headers() -> dict[str, str]:
    if not THREATFOX_AUTH_KEY:
        return {}
    return {"Auth-Key": THREATFOX_AUTH_KEY}


def fetch_threatfox_recent() -> list[dict]:
    if not THREATFOX_AUTH_KEY:
        log("THREATFOX_AUTH_KEY is missing, skipping ThreatFox recent")
        return []

    payload = {"query": "get_iocs", "days": THREATFOX_DAYS}
    try:
        data = http_post_json(THREATFOX_API_URL, payload, headers=threatfox_headers())
    except Exception as exc:
        log(f"ThreatFox recent fetch failed, continue: {exc}")
        return []

    rows = data.get("data") if isinstance(data, dict) else []
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def fetch_threatfox_family(family: str, limit: int = 200) -> list[dict]:
    if not THREATFOX_AUTH_KEY:
        return []

    payload = {"query": "malwareinfo", "malware": family, "limit": limit}
    try:
        data = http_post_json(THREATFOX_API_URL, payload, headers=threatfox_headers())
    except Exception as exc:
        log(f"ThreatFox family fetch failed for {family}, continue: {exc}")
        return []

    rows = data.get("data") if isinstance(data, dict) else []
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def score_threatfox_item(row: dict) -> int:
    value = row.get("confidence_level", 0)
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def row_has_stealer_signal(row: dict) -> bool:
    blob_parts = []
    for key in ("malware", "ioc", "ioc_type"):
        val = row.get(key)
        if isinstance(val, str):
            blob_parts.append(val.lower())
    tags = row.get("tags")
    if isinstance(tags, list):
        blob_parts.extend(str(t).lower() for t in tags)
    blob = " ".join(blob_parts)
    return any(k in blob for k in STEALER_KEYWORDS)


def vt_score_domain(domain: str) -> int:
    if not VT_API_KEY:
        return 0
    try:
        data = http_get_json(
            f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain, safe='')}",
            headers={"x-apikey": VT_API_KEY},
        )
        stats = (((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
        return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    except Exception:
        return 0


def vt_score_ip(network_or_ip: str) -> int:
    if not VT_API_KEY:
        return 0
    ip_only = network_or_ip.split("/", 1)[0]
    try:
        data = http_get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip_only, safe='')}",
            headers={"x-apikey": VT_API_KEY},
        )
        stats = (((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
        return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    except Exception:
        return 0


def enrich_with_vt(domains: set[str], ips: set[str]) -> tuple[set[str], set[str]]:
    if not VT_API_KEY:
        return set(), set()

    confirmed_domains: set[str] = set()
    confirmed_ips: set[str] = set()

    for domain in sorted(domains)[:VT_ENRICH_LIMIT]:
        if vt_score_domain(domain) >= VT_MIN_SCORE:
            confirmed_domains.add(domain)

    for ipn in sorted(ips)[:VT_ENRICH_LIMIT]:
        if vt_score_ip(ipn) >= VT_MIN_SCORE:
            confirmed_ips.add(ipn)

    return confirmed_domains, confirmed_ips


def to_classical_rules(domains: set[str], ips: set[str], title: str) -> str:
    lines = [
        f"# generated: {datetime.now(timezone.utc).isoformat()}",
        f"# title: {title}",
        f"# domains: {len(domains)}",
        f"# ips: {len(ips)}",
        "",
    ]
    for d in sorted(domains):
        lines.append(f"DOMAIN-SUFFIX,{d}")

    def ip_sort_key(v: str):
        net = ipaddress.ip_network(v, strict=False)
        return (net.version, int(net.network_address), net.prefixlen)

    for ipn in sorted(ips, key=ip_sort_key):
        net = ipaddress.ip_network(ipn, strict=False)
        if net.version == 4:
            lines.append(f"IP-CIDR,{net},no-resolve")
        else:
            lines.append(f"IP-CIDR6,{net},no-resolve")

    lines.append("")
    return "\n".join(lines)


def yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def chunked(seq: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def write_yara(categories: dict[str, dict[str, set[str]]]) -> None:
    out = []
    out.append("/* auto-generated from public TI feeds */")
    out.append("")

    for category, payload in categories.items():
        strings = sorted(
            set(payload["domains"]) | set(payload["ips"]) | set(payload["urls"])
        )
        if not strings:
            continue

        for idx, block in enumerate(chunked(strings, 500), start=1):
            rule_name = f"ti_{re.sub(r'[^a-z0-9]+', '_', category.lower()).strip('_')}_{idx}"
            out.append(f"rule {rule_name} {{")
            out.append("  meta:")
            out.append(f'    category = "{category}"')
            out.append('    source = "public-ti-automation"')
            out.append(f'    generated_utc = "{datetime.now(timezone.utc).isoformat()}"')
            out.append(f"    strings_count = {len(block)}")
            out.append("  strings:")
            for i, s in enumerate(block):
                out.append(f'    $s{i} = "{yara_escape(s)}" ascii nocase')
            out.append("  condition:")
            out.append("    any of them")
            out.append("}")
            out.append("")

    (YARA_DIR / "network_iocs_auto.yar").write_text("\n".join(out), encoding="utf-8")


def write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    allow_domains = {d for d in map(normalize_domain, read_lines(INPUTS / "allowlist_domains.txt")) if d}
    allow_ips = {i for i in map(normalize_ip_or_cidr, read_lines(INPUTS / "allowlist_ips.txt")) if i}

    categories: dict[str, dict[str, set[str]]] = {
        "ads": {"domains": set(), "ips": set(), "urls": set()},
        "privacy": {"domains": set(), "ips": set(), "urls": set()},
        "pua": {"domains": set(), "ips": set(), "urls": set()},
        "malware": {"domains": set(), "ips": set(), "urls": set()},
        "stealer": {"domains": set(), "ips": set(), "urls": set()},
    }

    stats = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "sources": {},
        "counts": {},
    }

    # ads
    log("Fetching ads feed")
    ads_text = http_get_text(BLOCKLIST_ADS_URL)
    categories["ads"]["domains"].update(iter_domains_from_text_blocklist(ads_text))
    stats["sources"]["ads"] = [BLOCKLIST_ADS_URL]

    # privacy
    log("Fetching privacy feed")
    tracking_text = http_get_text(BLOCKLIST_TRACKING_URL)
    categories["privacy"]["domains"].update(iter_domains_from_text_blocklist(tracking_text))
    stats["sources"]["privacy"] = [BLOCKLIST_TRACKING_URL]

    # pua
    pua_sources = []
    if PUP_FILTER_URL:
        try:
            log("Fetching PUA upstream")
            pua_text = http_get_text(PUP_FILTER_URL)
            categories["pua"]["domains"].update(iter_domains_from_text_blocklist(pua_text))
            pua_sources.append(PUP_FILTER_URL)
        except Exception as exc:
            log(f"PUA upstream failed, continue: {exc}")

    pua_manual = INPUTS / "pua.manual.txt"
    pua_manual_domains = {
        d for d in map(normalize_domain, read_lines(pua_manual)) if d
    }
    if pua_manual_domains:
        categories["pua"]["domains"].update(pua_manual_domains)
        pua_sources.append(str(pua_manual.relative_to(ROOT)))
    stats["sources"]["pua"] = pua_sources

    # URLhaus
    log("Fetching URLhaus hostfile")
    urlhaus_hostfile = http_get_text(URLHAUS_HOSTFILE_URL)
    urlhaus_domains = set(iter_domains_from_text_blocklist(urlhaus_hostfile))
    categories["malware"]["domains"].update(urlhaus_domains)

    log("Fetching URLhaus URLs")
    urlhaus_urls_text = http_get_text(URLHAUS_TEXT_URL)
    for url in iter_urls_from_urlhaus_text(urlhaus_urls_text):
        d, i, u = extract_url_artifacts(url)
        categories["malware"]["domains"].update(d)
        categories["malware"]["ips"].update(i)
        categories["malware"]["urls"].update(u)

    stats["sources"]["malware"] = [URLHAUS_HOSTFILE_URL, URLHAUS_TEXT_URL, THREATFOX_API_URL]

    # ThreatFox recent
    try:
        log("Fetching ThreatFox recent")
        tf_rows = fetch_threatfox_recent()
        for row in tf_rows:
            if score_threatfox_item(row) < THREATFOX_CONFIDENCE:
                continue
            d, i, u = extract_ioc_artifacts(str(row.get("ioc") or ""), str(row.get("ioc_type") or ""))
            categories["malware"]["domains"].update(d)
            categories["malware"]["ips"].update(i)
            categories["malware"]["urls"].update(u)

            if row_has_stealer_signal(row):
                categories["stealer"]["domains"].update(d)
                categories["stealer"]["ips"].update(i)
                categories["stealer"]["urls"].update(u)
    except Exception as exc:
        log(f"ThreatFox recent fetch failed, continue: {exc}")

    # ThreatFox stealer-focused family enrichment
    stealer_sources = [THREATFOX_API_URL]
    family_seeds = [
        "RedLineStealer",
        "Lumma",
        "Vidar",
        "StealC",
        "RaccoonStealer",
        "Rhadamanthys",
        "DeerStealer",
        "DogeStealer",
        "AtomicStealer",
    ]
    for family in family_seeds:
        try:
            log(f"Fetching ThreatFox family: {family}")
            rows = fetch_threatfox_family(family, limit=150)
            for row in rows:
                d, i, u = extract_ioc_artifacts(str(row.get("ioc") or ""), str(row.get("ioc_type") or ""))
                categories["stealer"]["domains"].update(d)
                categories["stealer"]["ips"].update(i)
                categories["stealer"]["urls"].update(u)
        except Exception as exc:
            log(f"ThreatFox family fetch failed for {family}: {exc}")

    stats["sources"]["stealer"] = stealer_sources

    # Optional VT confirmation hook
    # Only confirm a subset of stealer IOCs to avoid exhausting public API quota
    if VT_API_KEY:
        log("Running optional VT enrichment for stealer")
        vt_domains, vt_ips = enrich_with_vt(
            set(categories["stealer"]["domains"]),
            set(categories["stealer"]["ips"]),
        )
        categories["stealer"]["domains"].update(vt_domains)
        categories["stealer"]["ips"].update(vt_ips)
        stats["sources"]["stealer"].append("VirusTotal optional enrichment")

    # MalwareBazaar recent hashes sidecar
    try:
        log("Fetching MalwareBazaar recent SHA256")
        mb_text = http_get_text(MALWAREBAZAAR_RECENT_SHA256_URL)
        mb_hashes = [
            line.strip()
            for line in mb_text.splitlines()
            if SHA256_RE.fullmatch(line.strip())
        ]
        write_text(
            INTEL_DIR / "malwarebazaar_recent_sha256.txt",
            "\n".join(mb_hashes) + ("\n" if mb_hashes else ""),
        )
        stats["sources"]["malwarebazaar_recent_sha256"] = [MALWAREBAZAAR_RECENT_SHA256_URL]
        stats["counts"]["malwarebazaar_recent_sha256"] = len(mb_hashes)
    except Exception as exc:
        log(f"MalwareBazaar export failed, continue: {exc}")

    # allowlist
    for cat in categories.values():
        cat["domains"] = {d for d in cat["domains"] if d not in allow_domains}
        cat["ips"] = {i for i in cat["ips"] if i not in allow_ips}

    # write clash files
    for category, payload in categories.items():
        rules_text = to_classical_rules(payload["domains"], payload["ips"], f"TI {category}")
        write_text(CLASH_DIR / f"{category}.txt", rules_text)
        stats["counts"][category] = {
            "domains": len(payload["domains"]),
            "ips": len(payload["ips"]),
            "urls_for_yara": len(payload["urls"]),
        }

    # write yara
    write_yara(categories)

    # write metadata
    write_text(META_DIR / "stats.json", json.dumps(stats, ensure_ascii=False, indent=2) + "\n")

    log("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
