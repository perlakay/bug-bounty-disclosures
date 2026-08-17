import http from "node:http";
import { readFile, readFileSync, stat } from "node:fs";
import { extname, resolve, sep } from "node:path";
import vm from "node:vm";

const ROOT = resolve(import.meta.dirname);
const PORT = Number(process.env.PORT || 8080);
const context = { window: {} };
vm.runInNewContext(readFileSync(resolve(ROOT, "data/catalog.js"), "utf8"), context);
const reports = context.window.DISCLOSURE_REPORTS;

const mime = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml" };
const lower = value => String(value ?? "").toLowerCase();
const year = value => String(value ?? "").match(/\d{4}/)?.[0] || "";
const exact = (value, wanted) => !wanted || lower(value) === lower(wanted);

function sendJson(res, status, body, head = false) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, { "Content-Type": mime[".json"], "Content-Length": Buffer.byteLength(payload), "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS", "Cache-Control": "public, max-age=300" });
  res.end(head ? undefined : payload);
}

function queryReports(params) {
  const q = lower(params.get("q")).trim();
  const fields = ["title", "program", "researcher", "platform", "vulnerabilityClass", "weakness", "severity", "kind", "indexedVia"];
  const filtered = reports.filter(report => {
    const haystack = `${fields.map(field => report[field] ?? "").join(" ")} ${(report.cves || []).join(" ")}`.toLowerCase();
    return (!q || haystack.includes(q)) && exact(report.platform, params.get("platform")) && exact(report.severity, params.get("severity")) && exact(report.vulnerabilityClass, params.get("class")) && exact(report.researcher, params.get("researcher")) && exact(report.program, params.get("program")) && exact(year(report.disclosedAt), params.get("year")) && exact(report.kind, params.get("kind"));
  });
  const sort = params.get("sort") || "recent";
  if (sort === "title") filtered.sort((a, b) => a.title.localeCompare(b.title));
  else if (sort === "bounty") filtered.sort((a, b) => (b.bounty || 0) - (a.bounty || 0));
  else if (sort === "popular") filtered.sort((a, b) => (b.votes || 0) - (a.votes || 0));
  else filtered.sort((a, b) => String(b.disclosedAt || "").localeCompare(String(a.disclosedAt || "")));
  return filtered;
}

function api(req, res, url) {
  const head = req.method === "HEAD";
  if (url.pathname === "/api" || url.pathname === "/api/") return sendJson(res, 200, { name: "Disclosure Index API", version: "1.0", endpoints: ["GET /api/reports", "GET /api/reports/{id}", "GET /api/stats"], filters: ["q", "platform", "severity", "class", "researcher", "program", "year", "kind", "sort", "limit", "offset"] }, head);
  if (url.pathname === "/api/stats") {
    const countBy = key => Object.fromEntries([...new Set(reports.map(r => r[key]).filter(Boolean))].sort().map(value => [value, reports.filter(r => r[key] === value).length]));
    return sendJson(res, 200, { total: reports.length, researchers: new Set(reports.map(r => r.researcher).filter(Boolean)).size, withBountyData: reports.filter(r => r.bounty).length, byPlatform: countBy("platform"), bySeverity: countBy("severity"), byType: countBy("kind") }, head);
  }
  if (url.pathname === "/api/reports") {
    const rows = queryReports(url.searchParams);
    const limit = Math.min(100, Math.max(1, Number.parseInt(url.searchParams.get("limit") || "25", 10) || 25));
    const offset = Math.max(0, Number.parseInt(url.searchParams.get("offset") || "0", 10) || 0);
    const nextOffset = offset + limit < rows.length ? offset + limit : null;
    return sendJson(res, 200, { meta: { total: rows.length, limit, offset, nextOffset }, data: rows.slice(offset, offset + limit) }, head);
  }
  if (url.pathname.startsWith("/api/reports/")) {
    const id = decodeURIComponent(url.pathname.slice(13));
    const report = reports.find(row => row.id === id);
    return report ? sendJson(res, 200, { data: report }, head) : sendJson(res, 404, { error: "Record not found" }, head);
  }
  return sendJson(res, 404, { error: "API endpoint not found" }, head);
}

function serveFile(req, res, url) {
  const pathname = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const path = resolve(ROOT, `.${pathname}`);
  if (path !== ROOT && !path.startsWith(`${ROOT}${sep}`)) return sendJson(res, 403, { error: "Forbidden" });
  stat(path, (error, info) => {
    if (error || !info.isFile()) return sendJson(res, 404, { error: "Not found" });
    res.writeHead(200, { "Content-Type": mime[extname(path)] || "application/octet-stream", "Content-Length": info.size, "Cache-Control": extname(path) === ".html" ? "no-cache" : "public, max-age=3600" });
    if (req.method === "HEAD") return res.end();
    readFile(path, (readError, data) => readError ? sendJson(res, 500, { error: "Unable to read file" }) : res.end(data));
  });
}

http.createServer((req, res) => {
  if (req.method === "OPTIONS") { res.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS" }); return res.end(); }
  if (!(["GET", "HEAD"].includes(req.method))) return sendJson(res, 405, { error: "Method not allowed" });
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  return url.pathname.startsWith("/api") ? api(req, res, url) : serveFile(req, res, url);
}).listen(PORT, () => console.log(`Disclosure Index available at http://localhost:${PORT}`));
