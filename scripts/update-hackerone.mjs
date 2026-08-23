import path from "node:path";
import { assertResponseOrigin, deduplicate, normalizeOutcome, readCatalog, readLimitedJson, writeCatalog } from "./catalog-utils.mjs";

const root = path.resolve(import.meta.dirname, "..");
const catalogPath = path.join(root, "data/catalog.js");
const sourceUrl = "https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/index.json";
const response = await fetch(sourceUrl, { headers: { "User-Agent": "DisclosureIndex/1.0 (+public metadata index)" }, signal: AbortSignal.timeout(30000) });
if (!response.ok) throw new Error(`HackerOne index returned HTTP ${response.status}`);
assertResponseOrigin(response, ["https://raw.githubusercontent.com"]);
const sourceRows = await readLimitedJson(response, 25_000_000);
if (!Array.isArray(sourceRows) || sourceRows.length < 9000 || sourceRows.length > 15000) throw new Error(`Safety check failed: unexpected HackerOne record count ${sourceRows?.length || 0}`);

const classify = (value = "") => {
  const text = value.toLowerCase();
  const rules = [["Cross-site scripting",/\bxss\b|cross[ -]site scripting/],["Access control",/idor|access control|authorization|privilege/],["Authentication",/authentication|oauth|sso|2fa|password|account takeover|ato\b/],["Information disclosure",/information disclosure|data leak|sensitive data|exposure/],["SSRF",/\bssrf\b|server[ -]side request/],["SQL injection",/\bsqli?\b|sql injection/],["Command execution",/\brce\b|remote code|command injection|code execution/],["CSRF",/\bcsrf\b|cross[ -]site request forgery/],["Business logic",/business logic|logic flaw|logic error|race condition/],["Subdomain takeover",/subdomain takeover|dangling cname/],["XXE",/\bxxe\b|external entit/],["File security",/file upload|path traversal|directory traversal|\blfi\b|\brfi\b/],["Request smuggling",/request smuggling|http desync/],["Injection",/injection|template injection|ssti|crlf/]];
  return rules.find(([, pattern]) => pattern.test(text))?.[0] || "Other";
};
const clean = value => String(value || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
const incoming = sourceRows.map(item => ({ id:`h1-${item.id}`,title:clean(item.title)||"Untitled disclosure",program:clean(item.program)||"Unlisted program",researcher:clean(item.reporter)||"Anonymous",platform:"HackerOne",url:item.url,vulnerabilityClass:classify(`${item.weakness||""} ${item.title||""}`),weakness:clean(item.weakness)||null,severity:item.severity?item.severity[0].toUpperCase()+item.severity.slice(1):"Unrated",outcome:normalizeOutcome(item.substate),sourceOutcome:item.substate||null,bounty:Number(item.bounty)||null,disclosedAt:item.disclosed_at||null,votes:Number(item.votes)||0,cves:item.cve_ids||[],kind:"Platform disclosure",indexedVia:"HackerOne Disclosed Reports index" }));

const existing = readCatalog(catalogPath).filter(row => row.platform !== "HackerOne" && !String(row.indexedVia).startsWith("PentesterLand") && row.platform !== "Independent publications");
const catalog = deduplicate([...existing, ...incoming]);
writeCatalog(catalogPath, catalog);
console.log(JSON.stringify({ total:catalog.length,hackerone:incoming.length,refreshedAt:new Date().toISOString() },null,2));
