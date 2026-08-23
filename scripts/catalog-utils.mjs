import fs from "node:fs";

const PREFIX = "window.DISCLOSURE_REPORTS=";

export function assertResponseOrigin(response, allowedOrigins) {
  const origin = new URL(response.url).origin;
  if (!allowedOrigins.includes(origin)) throw new Error(`Refusing redirected source origin: ${origin}`);
}

export async function readLimitedText(response, maximumBytes) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maximumBytes) throw new Error(`Source response exceeds ${maximumBytes} bytes`);
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new Error(`Source response exceeds ${maximumBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString("utf8");
}

export async function readLimitedJson(response, maximumBytes) {
  try {
    return JSON.parse(await readLimitedText(response, maximumBytes));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("Source returned invalid JSON");
    throw error;
  }
}

export function readCatalog(catalogPath) {
  const source = fs.readFileSync(catalogPath, "utf8").trim();
  if (!source.startsWith(PREFIX) || !source.endsWith(";")) throw new Error("Catalog format is invalid");
  const rows = JSON.parse(source.slice(PREFIX.length, -1));
  if (!Array.isArray(rows)) throw new Error("Catalog must contain an array");
  return rows;
}

export function writeCatalog(catalogPath, rows) {
  fs.writeFileSync(catalogPath, `${PREFIX}${JSON.stringify(rows)};\n`);
}

export function deduplicate(rows) {
  const seen = new Set();
  return rows.filter(row => {
    const key = String(row.url || "").replace(/\/$/, "").toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function normalizeOutcome(value) {
  const source = String(value || "").trim().toLowerCase();
  return ({
    resolved: "Resolved",
    unresolved: "Unresolved",
    duplicate: "Duplicate",
    "not-applicable": "Not applicable",
    informative: "Informational",
    informational: "Informational",
    spam: "Spam"
  })[source] || null;
}
