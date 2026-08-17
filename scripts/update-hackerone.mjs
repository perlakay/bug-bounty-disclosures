import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = path.resolve(import.meta.dirname, "..");
const catalogPath = path.join(root, "data/catalog.js");
const sourceUrl = "https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/index.json";
const response = await fetch(sourceUrl, { headers: { "User-Agent": "DisclosureIndex/1.0 (+public metadata index)" } });
if (!response.ok) throw new Error(`HackerOne index returned HTTP ${response.status}`);
const sourceRows = await response.json();
if (!Array.isArray(sourceRows) || sourceRows.length < 9000) throw new Error(`Safety check failed: only ${sourceRows?.length || 0} HackerOne records found`);

const classify = (value = "") => {
  const text = value.toLowerCase();
  const rules = [["Cross-site scripting",/\bxss\b|cross[ -]site scripting/],["Access control",/idor|access control|authorization|privilege/],["Authentication",/authentication|oauth|sso|2fa|password|account takeover|ato\b/],["Information disclosure",/information disclosure|data leak|sensitive data|exposure/],["SSRF",/\bssrf\b|server[ -]side request/],["SQL injection",/\bsqli?\b|sql injection/],["Command execution",/\brce\b|remote code|command injection|code execution/],["CSRF",/\bcsrf\b|cross[ -]site request forgery/],["Business logic",/business logic|logic flaw|logic error|race condition/],["Subdomain takeover",/subdomain takeover|dangling cname/],["XXE",/\bxxe\b|external entit/],["File security",/file upload|path traversal|directory traversal|\blfi\b|\brfi\b/],["Request smuggling",/request smuggling|http desync/],["Injection",/injection|template injection|ssti|crlf/]];
  return rules.find(([, pattern]) => pattern.test(text))?.[0] || "Other";
};
const clean = value => String(value || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
const incoming = sourceRows.map(item => ({ id:`h1-${item.id}`,title:clean(item.title)||"Untitled disclosure",program:clean(item.program)||"Unlisted program",researcher:clean(item.reporter)||"Anonymous",platform:"HackerOne",url:item.url,vulnerabilityClass:classify(`${item.weakness||""} ${item.title||""}`),weakness:clean(item.weakness)||null,severity:item.severity?item.severity[0].toUpperCase()+item.severity.slice(1):"Unrated",bounty:Number(item.bounty)||null,disclosedAt:item.disclosed_at||null,votes:Number(item.votes)||0,cves:item.cve_ids||[],kind:"Platform disclosure",indexedVia:"HackerOne Disclosed Reports index" }));

const context = { window: {} };
vm.runInNewContext(fs.readFileSync(catalogPath, "utf8"), context);
const existing = context.window.DISCLOSURE_REPORTS.filter(row => row.platform !== "HackerOne" && row.indexedVia !== "PentesterLand" && row.platform !== "Independent publications");
const seen = new Set();
const catalog = [...existing, ...incoming].filter(row => { const key=row.url.replace(/\/$/,"").toLowerCase();if(seen.has(key))return false;seen.add(key);return true; });
fs.writeFileSync(catalogPath, `window.DISCLOSURE_REPORTS=${JSON.stringify(catalog)};\n`);
console.log(JSON.stringify({ total:catalog.length,hackerone:incoming.length,refreshedAt:new Date().toISOString() },null,2));
