#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone

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
THREATFOX_MAX_RETRIES = 2
THREATFOX_RETRY_DELAY_SECONDS = 2

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

THREAT_CATEGORIES: dict[str, dict[str, set[str] | list[str]]] = {
    "stealer": {
        "keywords": {
            "stealer", "stealc", "redline", "redlinestealer", "lumma",
            "vidar", "raccoon", "raccoonstealer", "deerstealer",
            "dogestealer", "atomic", "amos", "rhadamanthys",
            "meta_stealer", "mystic_stealer", "aurora_stealer",
            "risepro", "strigoi",
        },
        "families": [
            "RedLineStealer", "Lumma", "Vidar", "StealC",
            "RaccoonStealer", "Rhadamanthys", "DeerStealer",
            "DogeStealer", "AtomicStealer", "MysticStealer",
            "AuroraStealer", "RisePro", "MetaStealer",
        ],
    },
    "ransomware": {
        "keywords": {
            "ransom", "ransomware", "lockbit", "blackcat", "alphv", "clop",
            "ryuk", "conti", "revil", "sodinokibi", "hive_ransom",
            "blackbasta", "royal_ransom", "akira", "play_ransom", "medusa_ransom",
            "phobos", "dharma", "djvu", "wannacry", "maze", "ragnarlocker",
            "avoslocker", "babuk", "karakurt", "bianlian", "cuba_ransom",
            "rhysida", "8base", "nokoyawa", "trigona", "cactus_ransom",
            "blacksuit", "inc_ransom",
        },
        "families": [
            "LockBit", "BlackCat", "ALPHV", "Clop", "Ryuk", "Conti",
            "REvil", "Sodinokibi", "Hive", "BlackBasta", "Royal",
            "Akira", "Play", "Medusa", "Phobos", "Dharma", "STOP",
            "Babuk", "BianLian", "Cuba", "Rhysida", "8Base",
            "Nokoyawa", "Trigona", "Cactus", "BlackSuit",
        ],
    },
    "c2": {
        "keywords": {
            "c2", "c&c", "command_and_control", "cobaltstrike", "cobalt_strike",
            "metasploit", "meterpreter", "sliver", "bruteratel", "brute_ratel",
            "havoc", "mythic", "poshc2", "empire", "covenant",
            "nighthawk", "deimos", "botnet_cc",
        },
        "families": [
            "CobaltStrike", "Metasploit", "Sliver", "BruteRatel",
            "Havoc", "Mythic", "PoshC2",
        ],
    },
    "rat": {
        "keywords": {
            "remote_access", "remcos", "asyncrat", "nanocore",
            "darkcomet", "njrat", "quasarrat", "warzone", "netwire",
            "orcusrat", "xworm", "dcrat", "venomrat", "limerat",
            "parallaxrat", "plugx", "darkgate", "revengerat",
        },
        "families": [
            "Remcos", "AsyncRAT", "NanoCore", "DarkComet",
            "njRAT", "QuasarRAT", "WarzoneRAT", "NetWire",
            "OrcusRAT", "XWorm", "DCRat", "VenomRAT",
            "LimeRAT", "DarkGate", "PlugX",
        ],
    },
    "botnet": {
        "keywords": {
            "botnet", "mirai", "emotet", "trickbot", "qakbot", "qbot",
            "dridex", "icedid", "bumblebee", "pikabot", "amadey",
            "smokeloader", "tofsee", "pushdo", "andromeda",
            "phorpiex", "socks5systemz", "mylobot", "botnet_cc",
        },
        "families": [
            "Emotet", "TrickBot", "QakBot", "Dridex",
            "IcedID", "BumbleBee", "PikaBot", "Amadey",
            "SmokeLoader", "Mirai", "Phorpiex",
        ],
    },
    "backdoor": {
        "keywords": {
            "backdoor", "sunburst", "kazuar", "turla", "regin",
            "uroburos", "winnti", "shadowpad", "bpfdoor", "deadglyph",
        },
        "families": [
            "ShadowPad", "Winnti", "BPFDoor",
        ],
    },
    "miner": {
        "keywords": {
            "miner", "cryptominer", "coinminer", "xmrig",
            "cryptojacking", "coinhive",
        },
        "families": [
            "XMRig", "CoinMiner",
        ],
    },
    "loader": {
        "keywords": {
            "loader", "dropper", "guloader", "batloader",
            "gootloader", "matanbuchus", "latrodectus",
            "fakebat", "nitrogen", "payload_delivery",
        },
        "families": [
            "GuLoader", "BatLoader", "GootLoader",
            "Matanbuchus", "Latrodectus", "FakeBat", "Nitrogen",
        ],
    },
    "banker": {
        "keywords": {
            "banker", "banking_trojan", "zloader", "zeus",
            "danabot", "tinba", "carbanak", "grandoreiro", "mekotio",
            "coper", "sharkbot",
        },
        "families": [
            "ZLoader", "DanaBot", "Grandoreiro",
            "Mekotio", "SharkBot", "TinyBanker",
        ],
    },
    "keylogger": {
        "keywords": {
            "keylogger", "hawkeye", "agenttesla", "agent_tesla",
            "formbook", "masslogger", "snakekeylogger", "404keylogger",
        },
        "families": [
            "AgentTesla", "FormBook", "MassLogger",
            "SnakeKeylogger", "HawkEye",
        ],
    },
    "rootkit": {
        "keywords": {
            "rootkit", "bootkit",
        },
        "families": [],
    },
    "worm": {
        "keywords": {
            "worm", "raspberry_robin",
        },
        "families": [
            "RaspberryRobin",
        ],
    },
    "exploit": {
        "keywords": {
            "exploit", "exploitkit",
        },
        "families": [],
    },
    "phishing": {
        "keywords": {
            "phishing", "phish", "credential_harvesting",
        },
        "families": [],
    },
}

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\.?$",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")

RETRYABLE_HTTP_STATUS_CODES = {408, 429, 500, 502, 503, 504}
JsonObject = dict[str, object]
ThreatFoxRow = dict[str, object]
CategoryPayload = dict[str, set[str]]
StatsCounts = dict[str, int | dict[str, int]]


class UpstreamResponseError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable: bool = retryable


def is_retryable_url_error(reason: object) -> bool:
    if isinstance(reason, ssl.SSLError):
        return False
    if isinstance(reason, TimeoutError):
        return True
    if isinstance(reason, OSError):
        return True
    return False


def log(msg: str) -> None:
    print(msg, flush=True)


def read_lines(path: pathlib.Path) -> list[str]:
    if not path.exists():
        _ = path.write_text("", encoding="utf-8")
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]


def http_get_text(url: str, headers: dict[str, str] | None = None) -> str:
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def http_get_json(url: str, headers: dict[str, str] | None = None) -> JsonObject:
    data = json.loads(http_get_text(url, headers=headers))
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected JSON root from {url}. Root type={type(data).__name__}")
    return data


def http_post_json(url: str, payload: Mapping[str, object], headers: dict[str, str] | None = None) -> JsonObject:
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
        raise UpstreamResponseError(
            f"HTTP {e.code} from {url}. Body preview: {body[:400]!r}",
            retryable=e.code in RETRYABLE_HTTP_STATUS_CODES,
        ) from e
    except urllib.error.URLError as e:
        raise UpstreamResponseError(
            f"Network error from {url}: {e.reason}",
            retryable=is_retryable_url_error(e.reason),
        ) from e

    stripped = text.strip()
    lowered = stripped[:200].lower()
    if not stripped:
        raise UpstreamResponseError(
            f"Empty response from {url}. Content-Type={content_type!r}",
            retryable=True,
        )
    if "html" in content_type.lower() or lowered.startswith("<!doctype html") or lowered.startswith("<html"):
        raise UpstreamResponseError(
            f"HTML response from {url}. Content-Type={content_type!r}. Body preview: {text[:400]!r}"
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise UpstreamResponseError(
            f"Non-JSON response from {url}. Content-Type={content_type!r}. Body preview: {text[:400]!r}"
        ) from e

    if not isinstance(data, dict):
        raise UpstreamResponseError(
            f"Unexpected JSON root from {url}. Root type={type(data).__name__}. Body preview: {text[:400]!r}"
        )
    return data


def is_ip(value: str) -> bool:
    try:
        _ = ipaddress.ip_address(value)
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
        raise RuntimeError("Missing THREATFOX_AUTH_KEY. Add it as a GitHub Actions secret.")
    return {"Auth-Key": THREATFOX_AUTH_KEY}


def threatfox_query(payload: Mapping[str, object], *, label: str) -> JsonObject:
    last_error: UpstreamResponseError | None = None
    total_attempts = THREATFOX_MAX_RETRIES + 1
    attempts_used = 0

    for attempt in range(1, total_attempts + 1):
        attempts_used = attempt
        try:
            data = http_post_json(THREATFOX_API_URL, payload, headers=threatfox_headers())
        except UpstreamResponseError as exc:
            last_error = exc
            if not exc.retryable or attempt >= total_attempts:
                break
            delay = THREATFOX_RETRY_DELAY_SECONDS * attempt
            log(
                f"ThreatFox {label} attempt {attempt}/{total_attempts} failed, retrying in {delay}s: {exc}"
            )
            time.sleep(delay)
            continue

        query_status = str(data.get("query_status") or "").strip().lower()
        if query_status == "ok":
            rows = data.get("data")
            if isinstance(rows, dict):
                return {"query_status": query_status, "data": [rows]}
            if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
                return {"query_status": query_status, "data": rows}
            raise RuntimeError(
                f"ThreatFox {label} returned query_status='ok' with unexpected data payload type "
                f"{type(rows).__name__}."
            )

        retryable_statuses = {"retry_after", "temporary_error", "rate_limit", "too_many_requests"}
        if query_status in retryable_statuses:
            last_error = UpstreamResponseError(
                f"ThreatFox {label} temporary query_status={query_status!r}",
                retryable=True,
            )
            if attempt >= total_attempts:
                break
            delay = THREATFOX_RETRY_DELAY_SECONDS * attempt
            log(
                f"ThreatFox {label} attempt {attempt}/{total_attempts} returned {query_status!r}, retrying in {delay}s"
            )
            time.sleep(delay)
            continue
        if query_status == "no_result":
            return {"query_status": query_status, "data": []}

        message = str(data.get("message") or data.get("error") or "").strip()
        details = f" message={message!r}" if message else ""
        raise RuntimeError(
            f"ThreatFox {label} query failed with query_status={query_status or '<missing>'!r}.{details}"
        )

    raise RuntimeError(
        f"ThreatFox {label} request failed after {attempts_used} attempt(s): {last_error}"
    )


def fetch_threatfox_recent() -> list[ThreatFoxRow]:
    if not THREATFOX_AUTH_KEY:
        log("THREATFOX_AUTH_KEY is missing, skipping ThreatFox recent")
        return []

    payload = {"query": "get_iocs", "days": THREATFOX_DAYS}
    data = threatfox_query(payload, label="recent")
    rows = data.get("data")
    if isinstance(rows, list):
        return rows
    raise RuntimeError(f"ThreatFox recent data payload was not normalized to a list: {type(rows).__name__}")


def fetch_threatfox_family(family: str, limit: int = 200) -> list[ThreatFoxRow]:
    if not THREATFOX_AUTH_KEY:
        return []

    payload = {"query": "malwareinfo", "malware": family, "limit": limit}
    data = threatfox_query(payload, label=f"family:{family}")
    rows = data.get("data")
    if isinstance(rows, list):
        return rows
    raise RuntimeError(f"ThreatFox family data payload was not normalized to a list: {type(rows).__name__}")


def score_threatfox_item(row: ThreatFoxRow) -> int:
    value = row.get("confidence_level", 0)
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def row_matches_category(row: ThreatFoxRow, keywords: set[str]) -> bool:
    """Check if a ThreatFox IOC row matches any keyword for a threat category.

    Inspects the malware, malware_printable, ioc_type, threat_type,
    threat_type_desc, and tags fields of the row.
    """
    blob_parts: list[str] = []
    for key in ("malware", "malware_printable", "ioc_type",
                "threat_type", "threat_type_desc"):
        val = row.get(key)
        if isinstance(val, str):
            blob_parts.append(val.lower())
    tags = row.get("tags")
    if isinstance(tags, list):
        blob_parts.extend(str(t).lower() for t in tags)
    blob = " ".join(blob_parts)
    return any(k in blob for k in keywords)


def nested_json_object(value: object, *keys: str) -> JsonObject:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    if isinstance(current, dict):
        return current
    return {}


def json_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def vt_score_domain(domain: str) -> int:
    if not VT_API_KEY:
        return 0
    try:
        data = http_get_json(
            f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain, safe='')}",
            headers={"x-apikey": VT_API_KEY},
        )
        stats = nested_json_object(data, "data", "attributes", "last_analysis_stats")
        return json_int(stats.get("malicious", 0)) + json_int(stats.get("suspicious", 0))
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
        stats = nested_json_object(data, "data", "attributes", "last_analysis_stats")
        return json_int(stats.get("malicious", 0)) + json_int(stats.get("suspicious", 0))
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


def write_yara(categories: dict[str, CategoryPayload]) -> None:
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

    _ = (YARA_DIR / "network_iocs_auto.yar").write_text("\n".join(out), encoding="utf-8")


def write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(text, encoding="utf-8")


def main() -> int:
    allow_domains = {d for d in map(normalize_domain, read_lines(INPUTS / "allowlist_domains.txt")) if d}
    allow_ips = {i for i in map(normalize_ip_or_cidr, read_lines(INPUTS / "allowlist_ips.txt")) if i}

    categories: dict[str, CategoryPayload] = {
        "ads": {"domains": set(), "ips": set(), "urls": set()},
        "privacy": {"domains": set(), "ips": set(), "urls": set()},
        "pua": {"domains": set(), "ips": set(), "urls": set()},
        "malware": {"domains": set(), "ips": set(), "urls": set()},
    }
    for tc_name in THREAT_CATEGORIES:
        categories.setdefault(tc_name, {"domains": set(), "ips": set(), "urls": set()})

    stats_sources: dict[str, list[str]] = {}
    stats_counts: StatsCounts = {}
    stats = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "sources": stats_sources,
        "counts": stats_counts,
    }

    # ads
    try:
        log("Fetching ads feed")
        ads_text = http_get_text(BLOCKLIST_ADS_URL)
        categories["ads"]["domains"].update(iter_domains_from_text_blocklist(ads_text))
        stats_sources["ads"] = [BLOCKLIST_ADS_URL]
    except Exception as exc:
        log(f"Ads feed failed, continue: {exc}")

    # privacy
    try:
        log("Fetching privacy feed")
        tracking_text = http_get_text(BLOCKLIST_TRACKING_URL)
        categories["privacy"]["domains"].update(iter_domains_from_text_blocklist(tracking_text))
        stats_sources["privacy"] = [BLOCKLIST_TRACKING_URL]
    except Exception as exc:
        log(f"Privacy feed failed, continue: {exc}")

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
    stats_sources["pua"] = pua_sources

    # URLhaus
    malware_sources: list[str] = []
    try:
        log("Fetching URLhaus hostfile")
        urlhaus_hostfile = http_get_text(URLHAUS_HOSTFILE_URL)
        urlhaus_domains = set(iter_domains_from_text_blocklist(urlhaus_hostfile))
        categories["malware"]["domains"].update(urlhaus_domains)
        malware_sources.append(URLHAUS_HOSTFILE_URL)
    except Exception as exc:
        log(f"URLhaus hostfile failed, continue: {exc}")

    try:
        log("Fetching URLhaus URLs")
        urlhaus_urls_text = http_get_text(URLHAUS_TEXT_URL)
        for url in iter_urls_from_urlhaus_text(urlhaus_urls_text):
            d, i, u = extract_url_artifacts(url)
            categories["malware"]["domains"].update(d)
            categories["malware"]["ips"].update(i)
            categories["malware"]["urls"].update(u)
        malware_sources.append(URLHAUS_TEXT_URL)
    except Exception as exc:
        log(f"URLhaus URLs failed, continue: {exc}")

    stats_sources["malware"] = malware_sources

    threatfox_recent_ok = False

    # ThreatFox recent
    try:
        log("Fetching ThreatFox recent")
        tf_rows = fetch_threatfox_recent()
        threatfox_recent_ok = True
        for row in tf_rows:
            if score_threatfox_item(row) < THREATFOX_CONFIDENCE:
                continue
            d, i, u = extract_ioc_artifacts(str(row.get("ioc") or ""), str(row.get("ioc_type") or ""))
            categories["malware"]["domains"].update(d)
            categories["malware"]["ips"].update(i)
            categories["malware"]["urls"].update(u)

            for tc_name, tc_conf in THREAT_CATEGORIES.items():
                if row_matches_category(row, tc_conf["keywords"]):
                    categories[tc_name]["domains"].update(d)
                    categories[tc_name]["ips"].update(i)
                    categories[tc_name]["urls"].update(u)
    except Exception as exc:
        log(f"ThreatFox recent fetch failed, continue: {exc}")

    if threatfox_recent_ok:
        malware_sources.append(THREATFOX_API_URL)

    # ThreatFox family enrichment for all threat categories
    for tc_name, tc_conf in THREAT_CATEGORIES.items():
        tc_sources: list[str] = []
        tc_family_ok = False
        families = tc_conf.get("families") or []
        for family in families:
            try:
                log(f"Fetching ThreatFox family: {family} (category: {tc_name})")
                rows = fetch_threatfox_family(family, limit=150)
                tc_family_ok = True
                for row in rows:
                    d, i, u = extract_ioc_artifacts(str(row.get("ioc") or ""), str(row.get("ioc_type") or ""))
                    categories[tc_name]["domains"].update(d)
                    categories[tc_name]["ips"].update(i)
                    categories[tc_name]["urls"].update(u)
                    categories["malware"]["domains"].update(d)
                    categories["malware"]["ips"].update(i)
                    categories["malware"]["urls"].update(u)
            except Exception as exc:
                log(f"ThreatFox family fetch failed for {family} ({tc_name}): {exc}")
            time.sleep(0.5)

        if tc_family_ok:
            tc_sources.append(THREATFOX_API_URL)
        stats_sources[tc_name] = tc_sources

    # Optional VT confirmation hook
    # Only confirm a subset of stealer IOCs to avoid exhausting public API quota
    if VT_API_KEY:
        try:
            log("Running optional VT enrichment for stealer")
            vt_domains, vt_ips = enrich_with_vt(
                set(categories["stealer"]["domains"]),
                set(categories["stealer"]["ips"]),
            )
            categories["stealer"]["domains"].update(vt_domains)
            categories["stealer"]["ips"].update(vt_ips)
            stealer_src = stats_sources.get("stealer", [])
            stealer_src.append("VirusTotal optional enrichment")
            stats_sources["stealer"] = stealer_src
        except Exception as exc:
            log(f"VT enrichment failed, continue: {exc}")

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
        stats_sources["malwarebazaar_recent_sha256"] = [MALWAREBAZAAR_RECENT_SHA256_URL]
        stats_counts["malwarebazaar_recent_sha256"] = len(mb_hashes)
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
        stats_counts[category] = {
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
