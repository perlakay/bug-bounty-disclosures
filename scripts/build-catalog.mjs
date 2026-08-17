import fs from "node:fs";
import path from "node:path";
import { code4renaCatalogRecords, parseCode4renaHtml } from "./parse-code4rena.mjs";
import { parseHistoricalPlatformReports } from "./parse-historical-platforms.mjs";

const root = path.resolve(import.meta.dirname, "..");
const sourcePaths = {
  hackerone: process.env.H1_INDEX || "/tmp/h1-index.json",
  immunefi: process.env.IMMUNEFI_INDEX || "/tmp/immunefi-posts.xml",
  bugcrowd: process.env.BUGCROWD_DIR || "/tmp",
  code4rena: process.env.CODE4RENA_INDEX || "/tmp/code4rena-reports.html",
  historicalPlatforms: process.env.HISTORICAL_PLATFORM_INDEX || "/tmp/pentesterland-writeups.md"
};

const clean = value => decode(String(value || "")
  .replace(/<[^>]*>/g, " ")
  .replace(/\s+/g, " ")
  .trim());

function decode(value) {
  const entities = { amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", nbsp: " " };
  return value.replace(/&(#x?[0-9a-f]+|\w+);/gi, (_, code) => {
    if (code[0] === "#") {
      const hex = code[1]?.toLowerCase() === "x";
      return String.fromCodePoint(parseInt(code.slice(hex ? 2 : 1), hex ? 16 : 10));
    }
    return entities[code.toLowerCase()] || `&${code};`;
  });
}

function classify(value = "") {
  const text = value.toLowerCase();
  const rules = [
    ["Cross-site scripting", /\bxss\b|cross[ -]site scripting/],
    ["Access control", /idor|access control|authorization|privilege/],
    ["Authentication", /authentication|oauth|sso|2fa|password|account takeover|ato\b/],
    ["Information disclosure", /information disclosure|data leak|sensitive data|exposure/],
    ["SSRF", /\bssrf\b|server[ -]side request/],
    ["SQL injection", /\bsqli?\b|sql injection/],
    ["Command execution", /\brce\b|remote code|command injection|code execution/],
    ["CSRF", /\bcsrf\b|cross[ -]site request forgery/],
    ["Business logic", /business logic|logic flaw|logic error|race condition/],
    ["Subdomain takeover", /subdomain takeover|dangling cname/],
    ["XXE", /\bxxe\b|external entit/],
    ["File security", /file upload|path traversal|directory traversal|\blfi\b|\brfi\b/],
    ["Smart contracts", /smart contract|reentrancy|oracle|flashloan|flash loan|mint|consensus|defi|web3/],
    ["Request smuggling", /request smuggling|http desync/],
    ["Injection", /injection|template injection|ssti|crlf/]
  ];
  return rules.find(([, pattern]) => pattern.test(text))?.[0] || "Other";
}

function parseMoney(value) {
  const amounts = String(value || "").replaceAll(",", "").match(/\d+(?:\.\d+)?/g);
  return amounts?.length ? Math.max(...amounts.map(Number)) : null;
}

function parseHackerOne() {
  const data = JSON.parse(fs.readFileSync(sourcePaths.hackerone, "utf8"));
  return data.map(item => ({
    id: `h1-${item.id}`,
    title: clean(item.title) || "Untitled disclosure",
    program: clean(item.program) || "Unlisted program",
    researcher: clean(item.reporter) || "Anonymous",
    platform: "HackerOne",
    url: item.url,
    vulnerabilityClass: classify(`${item.weakness || ""} ${item.title || ""}`),
    weakness: clean(item.weakness) || null,
    severity: item.severity ? item.severity[0].toUpperCase() + item.severity.slice(1) : "Unrated",
    bounty: Number(item.bounty) || null,
    disclosedAt: item.disclosed_at || null,
    votes: Number(item.votes) || 0,
    cves: item.cve_ids || [],
    kind: "Platform disclosure",
    indexedVia: "HackerOne Disclosed Reports index"
  }));
}

function parseImmunefi() {
  const xml = fs.readFileSync(sourcePaths.immunefi, "utf8");
  return [...xml.matchAll(/<url>([\s\S]*?)<\/url>/gi)].flatMap((match, index) => {
    const url = match[1].match(/<loc>(.*?)<\/loc>/)?.[1];
    const lastmod = match[1].match(/<lastmod>(.*?)<\/lastmod>/)?.[1]?.slice(0, 10) || null;
    if (!url || !/(bug-?fix-reviews|vulnerability|hack-analysis)/i.test(url)) return [];
    const slug = url.split("/").filter(Boolean).pop();
    const title = slug.split("-").map(word => /^(rce|dos|defi|nft|dao|evm)$/i.test(word) ? word.toUpperCase() : word[0].toUpperCase() + word.slice(1)).join(" ")
      .replace(/ Bugfix Review$/i, " — Bugfix Review");
    const program = title.split(/ —| Bugfix| Vulnerability| Hack Analysis/i)[0];
    return [{
      id: `immunefi-${index}`,
      title,
      program,
      researcher: "Immunefi community",
      platform: "Immunefi",
      url,
      vulnerabilityClass: classify(title),
      weakness: null,
      severity: "Unrated",
      bounty: parseMoney(title),
      disclosedAt: lastmod,
      votes: 0,
      cves: [],
      kind: "Bug-fix review",
      indexedVia: "Immunefi public sitemap"
    }];
  });
}

function parseBugcrowd() {
  const names = fs.readdirSync(sourcePaths.bugcrowd).filter(name => /^crowdstream-\d+\.json$/.test(name));
  const rows = names.flatMap(name => JSON.parse(fs.readFileSync(path.join(sourcePaths.bugcrowd, name), "utf8")).results || []);
  return rows.filter(row => row.disclosed && row.disclosure_report_url && row.title).map(row => ({
    id: `bc-${row.id}`,
    title: clean(row.title),
    program: clean(row.engagement_name) || "Unlisted program",
    researcher: clean(row.researcher_username) || "Anonymous",
    platform: "Bugcrowd",
    url: `https://bugcrowd.com${row.disclosure_report_url}`,
    vulnerabilityClass: classify(row.title),
    weakness: null,
    severity: ({ 1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Informational" })[row.priority] || "Unrated",
    bounty: Number(row.amount) || null,
    disclosedAt: row.disclosed_at || null,
    votes: 0,
    cves: [],
    kind: "Platform disclosure",
    indexedVia: "Bugcrowd CrowdStream"
  }));
}

function parseCode4rena() {
  const rows = parseCode4renaHtml(fs.readFileSync(sourcePaths.code4rena, "utf8"));
  return code4renaCatalogRecords(rows);
}

const all = [...parseHackerOne(), ...parseImmunefi(), ...parseBugcrowd(), ...parseCode4rena(), ...parseHistoricalPlatformReports(fs.readFileSync(sourcePaths.historicalPlatforms,"utf8"))];
const seen = new Set();
const catalog = all.filter(item => {
  const key = item.url.replace(/\/$/, "").toLowerCase();
  if (seen.has(key)) return false;
  seen.add(key);
  return true;
});

fs.mkdirSync(path.join(root, "data"), { recursive: true });
fs.writeFileSync(path.join(root, "data", "catalog.js"), `window.DISCLOSURE_REPORTS=${JSON.stringify(catalog)};\n`);

const counts = Object.fromEntries([...new Set(catalog.map(item => item.platform))].sort().map(platform => [platform, catalog.filter(item => item.platform === platform).length]));
console.log(JSON.stringify({ total: catalog.length, platforms: counts }, null, 2));
