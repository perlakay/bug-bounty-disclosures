import fs from "node:fs";

export function parseCode4renaHtml(html) {
  const normalized = html.replace(/\\"/g, '"').replace(/\\n/g, " ");
  const parsed = [...normalized.matchAll(/\{"alt_url":.*?\}\}/gs)].flatMap(match => {
    try { return [JSON.parse(match[0])]; } catch { return []; }
  });
  return [...new Map(parsed.filter(item => item.slug && item.title && item.date).map(item => [item.slug, item])).values()];
}

export function code4renaCatalogRecords(rows) {
  return rows.map(row => ({
    id: `c4-${row.contest || row.slug}`,
    title: `${row.title} — Code4rena audit report`,
    program: row.sponsor || row.title,
    researcher: "Code4rena wardens",
    platform: "Code4rena",
    url: row.alt_url || `https://code4rena.com/reports/${row.slug}`,
    vulnerabilityClass: "Smart contracts",
    weakness: null,
    severity: "Unrated",
    bounty: null,
    disclosedAt: String(row.date).match(/\d{4}-\d{2}-\d{2}/)?.[0] || null,
    votes: 0,
    cves: [],
    kind: "Competitive audit report",
    indexedVia: "Code4rena official reports"
  }));
}

if (process.argv[1] === import.meta.filename) {
  const source = process.argv[2];
  if (!source) throw new Error("Usage: node scripts/parse-code4rena.mjs /path/to/code4rena-reports.html");
  const reports = parseCode4renaHtml(fs.readFileSync(source, "utf8"));
  console.log(JSON.stringify({ count: reports.length, first: reports[0]?.slug, last: reports.at(-1)?.slug }, null, 2));
}
