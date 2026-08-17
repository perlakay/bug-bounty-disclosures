import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { code4renaCatalogRecords, parseCode4renaHtml } from "./parse-code4rena.mjs";

const root = path.resolve(import.meta.dirname, "..");
const catalogPath = path.join(root, "data/catalog.js");
const response = await fetch("https://code4rena.com/reports", { headers: { "User-Agent": "DisclosureIndex/1.0 (+public metadata index)" } });
if (!response.ok) throw new Error(`Code4rena returned HTTP ${response.status}`);
const sourceRows = parseCode4renaHtml(await response.text());
if (sourceRows.length < 100) throw new Error(`Safety check failed: only ${sourceRows.length} Code4rena records found`);

const context = { window: {} };
vm.runInNewContext(fs.readFileSync(catalogPath, "utf8"), context);
const existing = context.window.DISCLOSURE_REPORTS.filter(row => row.platform !== "Code4rena" && row.indexedVia !== "PentesterLand" && row.platform !== "Independent publications");
const incoming = code4renaCatalogRecords(sourceRows);
const seen = new Set();
const catalog = [...existing, ...incoming].filter(row => {
  const key = row.url.replace(/\/$/, "").toLowerCase();
  if (seen.has(key)) return false;
  seen.add(key);
  return true;
});
fs.writeFileSync(catalogPath, `window.DISCLOSURE_REPORTS=${JSON.stringify(catalog)};\n`);
console.log(JSON.stringify({ total: catalog.length, code4rena: incoming.length, refreshedAt: new Date().toISOString() }, null, 2));
