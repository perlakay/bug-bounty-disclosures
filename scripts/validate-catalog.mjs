import path from "node:path";
import { readCatalog } from "./catalog-utils.mjs";

const rows = readCatalog(path.resolve(import.meta.dirname, "../data/catalog.js"));
if (rows.length < 10000 || rows.length > 50000) throw new Error(`Catalog has an unexpected record count: ${rows.length}`);
const required = ["id", "title", "program", "platform", "url", "kind"];
const stringLimits = { id: 128, title: 1000, program: 1000, researcher: 500, platform: 100, url: 2048, vulnerabilityClass: 200, weakness: 1000, severity: 100, outcome: 100, sourceOutcome: 100, disclosedAt: 100, kind: 200, indexedVia: 500 };
for (const [index, row] of rows.entries()) {
  if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error(`Record ${index} is not an object`);
  for (const key of required) if (!row[key]) throw new Error(`Record ${index} is missing ${key}`);
  for (const [key, limit] of Object.entries(stringLimits)) {
    if (row[key] != null && (typeof row[key] !== "string" || row[key].length > limit)) throw new Error(`Record ${index} has an invalid ${key}`);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(row.id)) throw new Error(`Record ${index} has an invalid ID`);
  const url = new URL(row.url);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error(`Record ${row.id} has an unsafe URL`);
  for (const key of ["bounty", "votes"]) if (row[key] != null && (!Number.isFinite(row[key]) || row[key] < 0)) throw new Error(`Record ${row.id} has an invalid ${key}`);
  if (!Array.isArray(row.cves) || row.cves.length > 50 || row.cves.some(value => typeof value !== "string" || value.length > 100)) throw new Error(`Record ${row.id} has invalid CVE data`);
}
const ids = new Set(rows.map(row => row.id));
const urls = new Set(rows.map(row => row.url.replace(/\/$/, "").toLowerCase()));
if (ids.size !== rows.length) throw new Error("Catalog contains duplicate IDs");
if (urls.size !== rows.length) throw new Error("Catalog contains duplicate canonical URLs");
console.log(JSON.stringify({ records: rows.length, platforms: new Set(rows.map(row => row.platform)).size }, null, 2));
