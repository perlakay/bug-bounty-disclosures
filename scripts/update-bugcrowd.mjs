import path from "node:path";
import { assertResponseOrigin, deduplicate, normalizeOutcome, readCatalog, readLimitedJson, writeCatalog } from "./catalog-utils.mjs";

const root = path.resolve(import.meta.dirname, "..");
const catalogPath = path.join(root, "data/catalog.js");
const baseUrl = "https://bugcrowd.com/crowdstream.json?filter_by=disclosures";
const headers = { "Accept": "application/json", "User-Agent": "DisclosureIndex/1.0 (+public metadata index)" };

async function getPage(page) {
  const response = await fetch(`${baseUrl}&page=${page}`, { headers, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`Bugcrowd page ${page} returned HTTP ${response.status}`);
  assertResponseOrigin(response, ["https://bugcrowd.com"]);
  const body = await readLimitedJson(response, 2_000_000);
  if (!Array.isArray(body.results)) throw new Error(`Bugcrowd page ${page} has an invalid response`);
  return body;
}

function isoDate(value) {
  const match = String(value || "").match(/^(\d{1,2}) ([A-Za-z]{3}) (\d{4})$/);
  if (!match) return value || null;
  const month = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"].indexOf(match[2]) + 1;
  return month ? `${match[3]}-${String(month).padStart(2,"0")}-${match[1].padStart(2,"0")}` : value;
}

function money(value) {
  const parsed = Number(String(value || "").replace(/[^\d.]/g, ""));
  return parsed > 0 ? parsed : null;
}

function classify(value = "") {
  const text = value.toLowerCase();
  const rules = [["Cross-site scripting",/\bxss\b|cross[ -]site scripting/],["Access control",/idor|access control|authorization|privilege/],["Authentication",/authentication|oauth|sso|2fa|password|account takeover|ato\b/],["Information disclosure",/information disclosure|data leak|sensitive data|exposure/],["SSRF",/\bssrf\b|server[ -]side request/],["SQL injection",/\bsqli?\b|sql injection/],["Command execution",/\brce\b|remote code|command injection|code execution/],["CSRF",/\bcsrf\b|cross[ -]site request forgery/],["Business logic",/business logic|logic flaw|logic error|race condition/],["Subdomain takeover",/subdomain takeover|dangling cname/],["XXE",/\bxxe\b|external entit/],["File security",/file upload|path traversal|directory traversal|\blfi\b|\brfi\b/],["Request smuggling",/request smuggling|http desync/],["Injection",/injection|template injection|ssti|crlf/]];
  return rules.find(([, pattern]) => pattern.test(text))?.[0] || "Other";
}

const first = await getPage(1);
const totalPages = Number(first.pagination_meta?.total_pages);
if (!Number.isInteger(totalPages) || totalPages < 1 || totalPages > 100) throw new Error(`Unsafe Bugcrowd page count: ${totalPages}`);
const remaining = await Promise.all(Array.from({ length: totalPages - 1 }, (_, index) => getPage(index + 2)));
const sourceRows = [first, ...remaining].flatMap(page => page.results).filter(row => row.disclosed && row.disclosure_report_url && row.title);
if (sourceRows.length < 700 || sourceRows.length > 5000) throw new Error(`Safety check failed: unexpected Bugcrowd disclosure count ${sourceRows.length}`);

const incoming = sourceRows.map(row => ({
  id: `bc-${row.id}`,
  title: String(row.title).trim(),
  program: String(row.engagement_name || "Unlisted program").trim(),
  researcher: String(row.researcher_username || "Anonymous").trim(),
  platform: "Bugcrowd",
  url: new URL(row.disclosure_report_url, "https://bugcrowd.com").href,
  vulnerabilityClass: classify(row.title),
  weakness: null,
  severity: ({ 1:"Critical",2:"High",3:"Medium",4:"Low",5:"Informational" })[row.priority] || "Unrated",
  outcome: normalizeOutcome(row.substate),
  sourceOutcome: row.substate || null,
  bounty: money(row.amount),
  disclosedAt: isoDate(row.disclosed_at),
  votes: 0,
  cves: [],
  kind: "Platform disclosure",
  indexedVia: "Bugcrowd CrowdStream"
}));

const existing = readCatalog(catalogPath).filter(row => row.platform !== "Bugcrowd" && !String(row.indexedVia).startsWith("PentesterLand") && row.platform !== "Independent publications");
const catalog = deduplicate([...existing, ...incoming]);
writeCatalog(catalogPath, catalog);
console.log(JSON.stringify({ total: catalog.length, bugcrowd: incoming.length, pages: totalPages, refreshedAt: new Date().toISOString() }, null, 2));
