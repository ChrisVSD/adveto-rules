import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const listsDirectory = path.join(root, "Lists");
const rulesPath = path.join(root, "rules.json");
const cosmeticPath = path.join(root, "cosmetic-rules.json");
const nsfwRulesPath = path.join(root, "rules-nsfw.json");
const maxNetworkRules = 59800;
const maxCosmeticRules = 25000;
const maxNsfwRules = 29900;

// Kept separate from remoteSources/highPrioritySources: this list alone has 100k+
// domains, far more than the ad/tracker rule budget. Mixing it in would push out
// working ad-blocking rules. It gets its own ruleset file and its own budget
// instead (see nsfw_rules in manifest.json), enabled independently at runtime
// only if the device has spare static-rule capacity.
const nsfwSourceUrl = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt";

const remoteSources = [
  "https://easylist.to/easylist/easylist.txt",
  "https://easylist.to/easylist/easyprivacy.txt",
  "https://easylist.to/easylist/fanboy-annoyance.txt",
  "https://easylist.to/easylist/fanboy-social.txt",
  "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt"
];

// Sources whose block rules get bumped to high priority so they always survive
// the cutoff into the always-enabled primary ruleset (rules.json), instead of
// risking being pushed into the optional/extra ruleset. Reserved for sources
// where missing a rule has real-world safety impact (redirect/malvertising
// protection), not just general ad annoyance.
const highPrioritySources = new Set([
  "priority-hosts.txt",
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt"
]);

const resourceTypes = new Set([
  "main_frame", "sub_frame", "stylesheet", "script", "image", "font",
  "object", "xmlhttprequest", "ping", "media", "websocket", "other"
]);
const resourceTypeAliases = new Map([
  ["subdocument", ["sub_frame"]],
  ["document", ["main_frame", "sub_frame"]],
  ["popup", ["main_frame"]],
  ["popunder", ["main_frame"]],
  ["tabunder", ["main_frame"]],
  ["frame", ["sub_frame"]]
]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function isComment(line) {
  return !line || line.startsWith("!") || line.startsWith("[") || line.startsWith("# ");
}

function parseDomains(value) {
  const domains = [];
  const excludedDomains = [];
  for (const item of value.split("|")) {
    if (!item) continue;
    const excluded = item.startsWith("~");
    const domain = (excluded ? item.slice(1) : item).replace(/^\*\./, "").toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(domain)) continue;
    if (excluded) excludedDomains.push(domain);
    else domains.push(domain);
  }
  return { domains, excludedDomains };
}

function parseNetworkFilter(line) {
  const allow = line.startsWith("@@");
  let source = allow ? line.slice(2) : line;
  const hostsMatch = source.match(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)/);
  if (hostsMatch) source = `||${hostsMatch[1]}^`;
  const [filterPart, optionPart] = source.split("$", 2);
  if (!filterPart || filterPart.includes("##") || filterPart.includes("#?#")) return null;
  let rulePriority = allow ? 2 : 1;

  const condition = {};
  if (filterPart.startsWith("/") && filterPart.endsWith("/")) {
    condition.regexFilter = filterPart.slice(1, -1);
  } else {
    condition.urlFilter = filterPart;
  }

  if (optionPart) {
    const options = optionPart.split(",");
    const types = options.flatMap(option => resourceTypes.has(option)
      ? [option]
      : (resourceTypeAliases.get(option) || []));
    if (types.length) condition.resourceTypes = types;
    if (options.includes("third-party") || options.includes("3p")) condition.domainType = "thirdParty";
    if (options.includes("~third-party") || options.includes("~3p") || options.includes("first-party") || options.includes("1p")) condition.domainType = "firstParty";
    if (options.includes("match-case")) condition.isUrlFilterCaseSensitive = true;
    if (options.includes("important")) rulePriority = 4;

    const domainOption = options.find(option => option.startsWith("domain="));
    if (domainOption) {
      const { domains, excludedDomains } = parseDomains(domainOption.slice(7));
      if (domains.length) condition.initiatorDomains = domains;
      if (excludedDomains.length) condition.excludedInitiatorDomains = excludedDomains;
    }
  }

  if (!condition.urlFilter && !condition.regexFilter) return null;
  // A bare "*" would match every request in the browser; only allow it when it is scoped to specific pages.
  if ((condition.urlFilter === "*" || condition.urlFilter === "") && !condition.initiatorDomains) return null;
  return {
    priority: rulePriority,
    action: { type: allow ? "allow" : "block" },
    condition
  };
}

function parseCosmeticFilter(line) {
  const exception = line.includes("#@#");
  const separator = exception ? "#@#" : line.includes("#?#") ? "#?#" : line.includes("##") ? "##" : null;
  if (!separator || line.startsWith("@@")) return null;
  const [domainPart, selector] = line.split(separator, 2);
  if (!selector || selector.length > 1000 || selector.includes("{ ")) return null;
  const domains = domainPart ? domainPart.split(",").filter(Boolean) : [];
  if (domains.some(domain => domain.startsWith("~"))) return null;
  return { domains, selector, exception };
}

function parseList(text) {
  const network = [];
  const cosmetic = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (isComment(line)) continue;
    const cosmeticRule = parseCosmeticFilter(line);
    if (cosmeticRule) cosmetic.push(cosmeticRule);
    else {
      const networkRule = parseNetworkFilter(line);
      if (networkRule) network.push(networkRule);
    }
  }
  return { network, cosmetic };
}

function ruleSpecificity(rule) {
  const filter = rule.condition.urlFilter || "";
  const isBroadHost = filter.startsWith("||") && filter.endsWith("^") && !filter.slice(2, -1).includes("/");
  return isBroadHost ? 0 : 1;
}

async function loadSources() {
  const sources = [];
  const priorityFile = path.join(root, "priority-hosts.txt");
  sources.push({ name: "priority-hosts.txt", text: await fs.readFile(priorityFile, "utf8") });
  // The Lists/ folder is optional so this exact script can also run in the standalone rules repository.
  const listEntries = await fs.readdir(listsDirectory, { withFileTypes: true }).catch(() => []);
  const localFiles = listEntries
    .filter(entry => entry.isFile() && entry.name.toLowerCase().endsWith(".txt"))
    .map(entry => path.join(listsDirectory, entry.name));

  for (const file of localFiles) {
    sources.push({ name: path.basename(file), text: await fs.readFile(file, "utf8") });
  }

  for (const url of remoteSources) {
    sources.push({ name: url, text: await fetchText(url) });
  }
  return sources;
}

async function fetchText(url) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.text();
    } catch (error) {
      lastError = error;
      if (attempt < 2) await new Promise(resolve => setTimeout(resolve, 500 * (2 ** attempt)));
    }
  }
  throw new Error(`Failed to fetch required rules source ${url}: ${lastError?.message || lastError}`);
}

async function main() {
  const sources = await loadSources();
  const networkByKey = new Map();
  const cosmeticByKey = new Map();

  for (const source of sources) {
    const parsed = parseList(source.text);
    for (const rule of parsed.network) {
      if (highPrioritySources.has(source.name) && rule.action.type === "block") rule.priority = 3;
      const key = JSON.stringify(rule);
      networkByKey.set(key, rule);
    }
    for (const rule of parsed.cosmetic) {
      const key = JSON.stringify(rule);
      cosmeticByKey.set(key, rule);
    }
  }

  const allNetworkRules = [...networkByKey.values()]
    .sort((left, right) => right.priority - left.priority ||
      Number(Boolean(right.condition.resourceTypes?.includes("main_frame"))) -
      Number(Boolean(left.condition.resourceTypes?.includes("main_frame"))) ||
      ruleSpecificity(left) - ruleSpecificity(right))
    .slice(0, maxNetworkRules)
    .map((rule, index) => ({ id: index + 1, ...rule }));
  const networkRules = allNetworkRules.slice(0, 29900);
  const extraNetworkRules = allNetworkRules.slice(29900);
  const cosmeticRules = [...cosmeticByKey.values()].slice(0, maxCosmeticRules);

  if (!networkRules.length) throw new Error("No valid network rules were generated");
  await fs.writeFile(rulesPath, `${JSON.stringify(networkRules, null, 2)}\n`);
  await fs.writeFile(path.join(root, "rules-extra.json"), `${JSON.stringify(extraNetworkRules, null, 2)}\n`);
  await fs.writeFile(cosmeticPath, `${JSON.stringify(cosmeticRules, null, 2)}\n`);

  // NSFW protection is its own ruleset with its own budget (see nsfwSourceUrl above).
  let nsfwRules = [];
  let nsfwSourceMeta = null;
  try {
    const nsfwText = await fetchText(nsfwSourceUrl);
    const nsfwByKey = new Map();
    for (const rule of parseList(nsfwText).network) {
      if (rule.action.type === "block") rule.priority = Math.max(rule.priority || 1, 3);
      const key = JSON.stringify(rule);
      nsfwByKey.set(key, rule);
    }
    nsfwRules = [...nsfwByKey.values()]
      .sort((left, right) => ruleSpecificity(left) - ruleSpecificity(right))
      .slice(0, maxNsfwRules)
      .map((rule, index) => ({ id: index + 1, ...rule }));
    if (nsfwRules.length < 10000) throw new Error(`Only generated ${nsfwRules.length} NSFW rules`);
    nsfwSourceMeta = { name: nsfwSourceUrl, sha256: sha256(nsfwText) };
  } catch (error) {
    throw new Error(`Could not build the required NSFW ruleset: ${error.message}`);
  }
  await fs.writeFile(nsfwRulesPath, `${JSON.stringify(nsfwRules, null, 2)}\n`);

  await fs.writeFile(path.join(root, "rules-meta.json"), `${JSON.stringify({
    generatedAt: new Date().toISOString(),
    sources: sources.map(source => ({ name: source.name, sha256: sha256(source.text) })),
    networkRules: allNetworkRules.length,
    primaryNetworkRules: networkRules.length,
    extraNetworkRules: extraNetworkRules.length,
    cosmeticRules: cosmeticRules.length,
    nsfwSource: nsfwSourceMeta,
    nsfwRules: nsfwRules.length
  }, null, 2)}\n`);
  console.log(`Generated ${networkRules.length} network, ${cosmeticRules.length} cosmetic, and ${nsfwRules.length} NSFW rules from ${sources.length + (nsfwSourceMeta ? 1 : 0)} sources.`);
}

await main();