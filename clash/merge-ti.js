function main(config) {
  config = config || {};
  config.rules = Array.isArray(config.rules) ? config.rules : [];
  config["proxy-groups"] = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  config["rule-providers"] =
    config["rule-providers"] && typeof config["rule-providers"] === "object"
      ? config["rule-providers"]
      : {};

  const RAW_BASE =
    "https://raw.githubusercontent.com/Fadouse/clash-threat-intel/main/clash/generated";

  const categories = [
    { key: "stealer", group: "TI stealer", file: "stealer.txt" },
    { key: "malware", group: "TI malware", file: "malware.txt" },
    { key: "pua", group: "TI pua", file: "pua.txt" },
    { key: "privacy", group: "TI privacy", file: "privacy.txt" },
    { key: "ads", group: "TI ads", file: "ads.txt" }
  ];

  function ensureRuleProvider(name, url) {
    config["rule-providers"][name] = {
      ...(config["rule-providers"][name] || {}),
      type: "http",
      behavior: "classical",
      format: "text",
      path: `./ruleset/${name}.txt`,
      url,
      interval: 900,
      proxy: "DIRECT",
      "size-limit": 10485760,
      header: {
        "User-Agent": ["mihomo-party-ti/1.0"]
      }
    };
  }

  function ensureGroup(name, extraProxies) {
    let group = config["proxy-groups"].find(g => g && g.name === name);
    if (!group) {
      group = {
        name,
        type: "select",
        proxies: [],
        "include-all-proxies": true
      };
      config["proxy-groups"].push(group);
    }

    group.type = "select";
    group.proxies = Array.isArray(group.proxies) ? group.proxies : [];
    group["include-all-proxies"] = true;

    const wanted = extraProxies || [];
    for (const p of wanted) {
      if (!group.proxies.includes(p)) {
        group.proxies.push(p);
      }
    }

    return group;
  }

  function ensureRuleBeforeMatch(rule) {
    if (config.rules.includes(rule)) return;

    const idx = config.rules.findIndex(
      r => typeof r === "string" && r.startsWith("MATCH,")
    );

    if (idx >= 0) {
      config.rules.splice(idx, 0, rule);
    } else {
      config.rules.push(rule);
    }
  }

  // Category-specific groups
  for (const item of categories) {
    ensureRuleProvider(`ti-${item.key}`, `${RAW_BASE}/${item.file}`);
    ensureGroup(item.group, ["REJECT", "DIRECT"]);
  }

  // Master group
  ensureGroup("Threat intelligence IOC", [
    "TI stealer",
    "TI malware",
    "TI pua",
    "TI privacy",
    "TI ads",
    "REJECT",
    "DIRECT"
  ]);

  // Rule priority from most to least restrictive
  for (const item of categories) {
    ensureRuleBeforeMatch(`RULE-SET,ti-${item.key},${item.group}`);
  }

  return config;
}
