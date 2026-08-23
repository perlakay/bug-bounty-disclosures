import path from "node:path";
import { code4renaCatalogRecords, parseCode4renaHtml } from "./parse-code4rena.mjs";
import { assertResponseOrigin, deduplicate, readCatalog, readLimitedText, writeCatalog } from "./catalog-utils.mjs";

const root = path.resolve(import.meta.dirname, "..");
const catalogPath = path.join(root, "data/catalog.js");
const response = await fetch("https://code4rena.com/reports", { headers: { "User-Agent": "DisclosureIndex/1.0 (+public metadata index)" }, signal: AbortSignal.timeout(30000) });
if (!response.ok) throw new Error(`Code4rena returned HTTP ${response.status}`);
assertResponseOrigin(response, ["https://code4rena.com"]);
const sourceRows = parseCode4renaHtml(await readLimitedText(response, 15_000_000));
if (sourceRows.length < 100 || sourceRows.length > 2000) throw new Error(`Safety check failed: unexpected Code4rena record count ${sourceRows.length}`);

const existing = readCatalog(catalogPath).filter(row => row.platform !== "Code4rena" && !String(row.indexedVia).startsWith("PentesterLand") && row.platform !== "Independent publications");
const incoming = code4renaCatalogRecords(sourceRows);
const catalog = deduplicate([...existing, ...incoming]);
writeCatalog(catalogPath, catalog);
console.log(JSON.stringify({ total: catalog.length, code4rena: incoming.length, refreshedAt: new Date().toISOString() }, null, 2));
