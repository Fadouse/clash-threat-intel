# Clash Threat Intel

Automated threat-intelligence feed aggregator that generates Clash / Mihomo rule-sets, YARA rules, and MalwareBazaar SHA-256 block-lists — updated automatically every 2 hours via GitHub Actions.

---

## Features

- **Domain & IP blocklists** for Clash / Mihomo in `clash/generated/`
- **YARA rules** for network IOCs in `yara/`
- **MalwareBazaar SHA-256 hashes** in `intel/`
- Build statistics in `meta/stats.json`
- IOC retention window (default 360 days) to prevent short-term feed dropouts from immediately removing active indicators
- Automatic allowlisting via `inputs/allowlist_domains.txt` and `inputs/allowlist_ips.txt`
- Optional manual PUA entries via `inputs/pua.manual.txt`
- Optional VirusTotal enrichment for additional confidence scoring

---

## Rule Categories

### Default categories (always enabled)

| Category | File | Description |
|----------|------|-------------|
| `malware` | `clash/generated/malware.txt` | General malware domains & IPs (URLhaus + ThreatFox) |
| `pua` | `clash/generated/pua.txt` | Potentially Unwanted Applications |
| `privacy` | `clash/generated/privacy.txt` | Tracking & telemetry domains |
| `ads` | `clash/generated/ads.txt` | Advertising domains |

### Granular threat categories (optional, disabled by default)

Enable by setting `ENABLE_ALL_CATEGORIES = true` in `clash/merge-ti.js`.

| Category | File | Examples |
|----------|------|---------|
| `stealer` | `stealer.txt` | RedLine, Lumma, Vidar, StealC, Raccoon |
| `ransomware` | `ransomware.txt` | LockBit, BlackCat, Clop, Ryuk, STOP/Djvu |
| `c2` | `c2.txt` | CobaltStrike, Sliver, BruteRatel, Havoc |
| `rat` | `rat.txt` | AsyncRAT, Remcos, njRAT, QuasarRAT, XWorm |
| `botnet` | `botnet.txt` | Emotet, QakBot, BumbleBee, PikaBot |
| `backdoor` | `backdoor.txt` | ShadowPad, BPFDoor, Winnti |
| `miner` | `miner.txt` | XMRig, CoinMiner |
| `loader` | `loader.txt` | GuLoader, GootLoader, Latrodectus, FakeBat |
| `banker` | `banker.txt` | ZLoader, DanaBot, Grandoreiro, SharkBot |
| `keylogger` | `keylogger.txt` | AgentTesla, FormBook, SnakeKeylogger |
| `rootkit` | `rootkit.txt` | Rootkits & bootkits |
| `worm` | `worm.txt` | RaspberryRobin |
| `exploit` | `exploit.txt` | Exploit kits |
| `phishing` | `phishing.txt` | Phishing & credential harvesting |

---

## Usage

### Option 1 — Mihomo Party / Clash Meta (merge script)

Copy the contents of [`clash/merge-ti.js`](clash/merge-ti.js) into the **Merge** script field of [Mihomo Party](https://github.com/mihomo-party-org/mihomo-party) or any Clash Meta frontend that supports merge scripts.

The script will:
1. Register a `rule-provider` for each enabled category (auto-updated every 15 minutes).
2. Create a `proxy-group` for each category so you can choose how to handle blocked traffic (`REJECT` or `DIRECT`).
3. Insert the corresponding `RULE-SET` rules before the `MATCH` catch-all.

To enable all 14 granular threat categories, open `clash/merge-ti.js` and change:

```js
const ENABLE_ALL_CATEGORIES = false;
// → change to:
const ENABLE_ALL_CATEGORIES = true;
```

### Option 2 — Direct rule-provider URLs

Reference the raw rule files directly in your Clash / Mihomo configuration:

```yaml
rule-providers:
  ti-malware:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/Fadouse/clash-threat-intel/main/clash/generated/malware.txt"
    path: ./ruleset/ti-malware.txt
    interval: 900

  ti-ads:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/Fadouse/clash-threat-intel/main/clash/generated/ads.txt"
    path: ./ruleset/ti-ads.txt
    interval: 900

rules:
  - RULE-SET,ti-malware,REJECT
  - RULE-SET,ti-ads,REJECT
  - MATCH,DIRECT
```

---

## Data Sources

| Source | Feed | Categories |
|--------|------|-----------|
| [URLhaus](https://urlhaus.abuse.ch/) | Host-file & text feed | malware |
| [ThreatFox](https://threatfox.abuse.ch/) | IOC API (last 3 days, confidence ≥ 90) | malware + all granular types |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Recent SHA-256 export | SHA-256 intel |
| [Blocklistproject](https://github.com/blocklistproject/Lists) | `ads.txt`, `tracking.txt` | ads, privacy |
| [PUP filter](https://gitlab.com/curben/pup-filter) | DNSCrypt blocked-names list (optional) | pua |
| [VirusTotal](https://www.virustotal.com/) | Domain/IP enrichment (optional) | malware + granular types |

---

## Configuration

The build pipeline is controlled by environment variables (set in the GitHub Actions workflow or locally):

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFOX_AUTH_KEY` | *(empty)* | ThreatFox API key (required for IOC lookups) |
| `THREATFOX_DAYS` | `3` | How many days of ThreatFox IOCs to fetch |
| `THREATFOX_CONFIDENCE` | `90` | Minimum confidence score (0–100) to include a ThreatFox IOC |
| `VT_API_KEY` | *(empty)* | VirusTotal API key (optional enrichment) |
| `VT_ENRICH_LIMIT` | `20` | Maximum number of IOCs to enrich per run |
| `VT_MIN_SCORE` | `5` | Minimum VirusTotal detection count to include an IOC |
| `PUP_FILTER_URL` | *(empty)* | URL of a PUP/adware DNSCrypt block-list for the `pua` category |
| `IOC_RETENTION_DAYS` | `360` | Keep IOCs seen within this many days; older items are purged |

---

## Manual Inputs

Files in `inputs/` are committed to the repository and let you fine-tune the pipeline without code changes:

| File | Purpose |
|------|---------|
| `inputs/allowlist_domains.txt` | Domains that will **never** be blocked (one per line) |
| `inputs/allowlist_ips.txt` | IP addresses that will **never** be blocked (one per line) |
| `inputs/pua.manual.txt` | Extra PUA domains to add to the `pua` category (one per line) |

Lines beginning with `#` are treated as comments and ignored.

---

## Running Locally

```bash
# No external dependencies required — pure Python stdlib
THREATFOX_AUTH_KEY=<your-key> \
THREATFOX_DAYS=3 \
THREATFOX_CONFIDENCE=90 \
python scripts/build_ti.py
```

Generated files are written to:
- `clash/generated/` — Clash rule-set text files
- `yara/network_iocs_auto.yar` — YARA rule file
- `intel/malwarebazaar_recent_sha256.txt` — MalwareBazaar SHA-256 hashes
- `meta/stats.json` — Build statistics
- `meta/ioc_history.json` — IOC last-seen cache used for retention / anti-flap behavior

Retention behavior:
- If an IOC is observed again, it remains and its `last_seen` timestamp is refreshed.
- If an IOC temporarily disappears from upstream feeds, it is kept until it has not been seen for more than `IOC_RETENTION_DAYS`.
- Duplicate entries are automatically deduplicated via set-based aggregation.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         build_ti.py                                 │
│                                                                     │
│  URLhaus hostfile  ──┐                                              │
│  URLhaus text      ──┤                                              │
│  ThreatFox API     ──┼──► categorise ──► deduplicate               │
│  BlocklistProject  ──┤              ──► allowlist filter            │
│  PUP filter        ──┘              ──► write rule-set files        │
│                                                                     │
│  MalwareBazaar SHA-256 ──► intel/                                   │
│  (VT enrichment optional)                                           │
│  Network IOCs ──► YARA rules ──► yara/                              │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼  (GitHub Actions: every 2 hours)
  clash/generated/*.txt   meta/stats.json
         │
         ▼  (merge-ti.js in Clash client)
  rule-providers + proxy-groups injected into running config
```

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Intelligence data is provided by third-party feeds under their respective terms of service. See each source's website for details.
