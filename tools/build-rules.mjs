import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const rulesPath = path.join(root, "rules.json");
const cosmeticPath = path.join(root, "cosmetic-rules.json");
const maxNetworkRules = 59800;
const maxCosmeticRules = 25000;
const remoteSources = [
  "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
  "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt",
  "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt",
  "https://easylist.to/easylist/easyprivacy.txt",
  "https://easylist.to/easylist/fanboy-annoyance.txt",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
];
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
  const condition = filterPart.startsWith("/") && filterPart.endsWith("/")
    ? { regexFilter: filterPart.slice(1, -1) }
    : { urlFilter: filterPart };

  if (optionPart) {
    const options = optionPart.split(",");
    const types = options.flatMap(option => resourceTypes.has(option)
      ? [option]
      : (resourceTypeAliases.get(option) || []));
    if (types.length) condition.resourceTypes = types;
    if (options.includes("third-party")) condition.domainType = "thirdParty";
    if (options.includes("~third-party")) condition.domainType = "firstParty";
    if (options.includes("match-case")) condition.isUrlFilterCaseSensitive = true;
    if (options.includes("important")) rulePriority = 4;
    const domainOption = options.find(option => option.startsWith("domain="));
    if (domainOption) {
      const { domains, excludedDomains } = parseDomains(domainOption.slice(7));
      if (domains.length) condition.requestDomains = domains;
      if (excludedDomains.length) condition.excludedRequestDomains = excludedDomains;
    }
  }
  return condition.urlFilter || condition.regexFilter
    ? { priority: rulePriority, action: { type: allow ? "allow" : "block" }, condition }
    : null;
}

function parseCosmeticFilter(line) {
  const exception = line.includes("#@#");
  const separator = exception ? "#@#" : line.includes("#?#") ? "#?#" : line.includes("##") ? "##" : null;
  if (!separator || line.startsWith("@@")) return null;
  const [domainPart, selector] = line.split(separator, 2);
  if (!selector || selector.length > 1000 || selector.includes("{ ")) return null;
  const domains = domainPart ? domainPart.split(",").filter(Boolean) : [];
  return domains.some(domain => domain.startsWith("~")) ? null : { domains, selector, exception };
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
  const sources = [{
    name: "priority-hosts.txt",
    text: await fs.readFile(path.join(root, "priority-hosts.txt"), "utf8")
  }];
  for (const url of remoteSources) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      sources.push({ name: url, text: await response.text() });
    } catch (error) {
      console.warn(`Skipping ${url}: ${error.message}`);
    }
  }
  return sources;
}

const sources = await loadSources();
const networkByKey = new Map();
const cosmeticByKey = new Map();
for (const source of sources) {
  const parsed = parseList(source.text);
  for (const rule of parsed.network) {
    if (source.name === "priority-hosts.txt" && rule.action.type === "block") rule.priority = 3;
    networkByKey.set(JSON.stringify(rule), rule);
  }
  for (const rule of parsed.cosmetic) cosmeticByKey.set(JSON.stringify(rule), rule);
}

const allNetworkRules = [...networkByKey.values()]
  .sort((left, right) => right.priority - left.priority || ruleSpecificity(left) - ruleSpecificity(right))
  .slice(0, maxNetworkRules)
  .map((rule, index) => ({ id: index + 1, ...rule }));
const networkRules = allNetworkRules.slice(0, 29900);
const extraNetworkRules = allNetworkRules.slice(29900);
const cosmeticRules = [...cosmeticByKey.values()].slice(0, maxCosmeticRules);
if (!networkRules.length) throw new Error("No valid network rules were generated");
await fs.writeFile(rulesPath, `${JSON.stringify(networkRules, null, 2)}\n`);
await fs.writeFile(path.join(root, "rules-extra.json"), `${JSON.stringify(extraNetworkRules, null, 2)}\n`);
await fs.writeFile(cosmeticPath, `${JSON.stringify(cosmeticRules, null, 2)}\n`);
await fs.writeFile(path.join(root, "rules-meta.json"), `${JSON.stringify({
  generatedAt: new Date().toISOString(),
  sources: sources.map(source => ({ name: source.name, sha256: sha256(source.text) })),
  networkRules: allNetworkRules.length,
  primaryNetworkRules: networkRules.length,
  extraNetworkRules: extraNetworkRules.length,
  cosmeticRules: cosmeticRules.length
}, null, 2)}\n`);
console.log(`Generated ${networkRules.length} network and ${cosmeticRules.length} cosmetic rules from ${sources.length} sources.`);