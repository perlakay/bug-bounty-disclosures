import http from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname);
const PORT = positiveInteger(process.env.PORT, 8080, 1, 65535);
const HOST = process.env.HOST || "0.0.0.0";
const RATE_LIMIT_MAX = positiveInteger(process.env.RATE_LIMIT_MAX, 120, 1, 10000);
const RATE_LIMIT_WINDOW_MS = positiveInteger(process.env.RATE_LIMIT_WINDOW_MS, 60000, 1000, 3600000);
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const MAX_URL_LENGTH = 2048;
const MAX_PARAMETER_LENGTH = 200;
const MAX_PARAMETERS = 20;

function positiveInteger(value, fallback, minimum, maximum) {
  if (value == null || value === "") return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function loadCatalog() {
  const source = readFileSync(resolve(ROOT, "data/catalog.js"), "utf8").trim();
  const prefix = "window.DISCLOSURE_REPORTS=";
  if (!source.startsWith(prefix) || !source.endsWith(";")) throw new Error("Catalog format is invalid");
  const parsed = JSON.parse(source.slice(prefix.length, -1));
  if (!Array.isArray(parsed)) throw new Error("Catalog must contain an array");
  return parsed;
}

const reports = loadCatalog();
const lower = value => String(value ?? "").toLowerCase();
const year = value => String(value ?? "").match(/\d{4}/)?.[0] || "";
const exact = (value, wanted) => !wanted || lower(value) === lower(wanted);
const searchRows = reports.map(report => ({ report, haystack: `${report.title} ${report.program} ${report.researcher} ${report.platform} ${report.vulnerabilityClass} ${report.weakness || ""} ${report.severity} ${report.kind} ${report.indexedVia} ${(report.cves || []).join(" ")}`.toLowerCase() }));
const reportsById = new Map(reports.map(report => [report.id, report]));
const countBy = key => Object.fromEntries([...new Set(reports.map(report => report[key]).filter(Boolean))].sort().map(value => [value, reports.filter(report => report[key] === value).length]));
const statistics = { total: reports.length, researchers: new Set(reports.map(report => report.researcher).filter(Boolean)).size, withBountyData: reports.filter(report => report.bounty).length, byPlatform: countBy("platform"), bySeverity: countBy("severity"), byType: countBy("kind") };

const staticFiles = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8", cache: "no-cache" }],
  ["/index.html", { file: "index.html", type: "text/html; charset=utf-8", cache: "no-cache" }],
  ["/styles.css", { file: "styles.css", type: "text/css; charset=utf-8", cache: "public, max-age=3600" }],
  ["/app.js", { file: "app.js", type: "text/javascript; charset=utf-8", cache: "public, max-age=3600" }],
  ["/data/catalog.js", { file: "data/catalog.js", type: "text/javascript; charset=utf-8", cache: "public, max-age=3600" }]
]);
for (const entry of staticFiles.values()) entry.body = readFileSync(resolve(ROOT, entry.file));

const rateBuckets = new Map();
let rateChecks = 0;

function securityHeaders(apiResponse = false) {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": apiResponse ? "cross-origin" : "same-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  };
}

function sendJson(res, status, body, head = false, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { ...securityHeaders(true), "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(payload), "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS", "Cache-Control": "public, max-age=300", ...res.rateLimitHeaders, ...extraHeaders });
  res.end(head ? undefined : payload);
}

function clientAddress(req) {
  if (TRUST_PROXY) {
    const raw = Array.isArray(req.headers["x-forwarded-for"]) ? req.headers["x-forwarded-for"][0] : req.headers["x-forwarded-for"];
    const forwarded = raw?.split(",")[0].trim();
    if (forwarded && /^[0-9a-f:.]+$/i.test(forwarded)) return forwarded;
  }
  return req.socket.remoteAddress || "unknown";
}

function allowApiRequest(req, res) {
  const now = Date.now();
  const key = clientAddress(req);
  let bucket = rateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) bucket = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  const resetSeconds = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
  res.rateLimitHeaders = { "RateLimit-Limit": String(RATE_LIMIT_MAX), "RateLimit-Remaining": String(Math.max(0, RATE_LIMIT_MAX - bucket.count - 1)), "RateLimit-Reset": String(resetSeconds) };
  if (bucket.count >= RATE_LIMIT_MAX) {
    rateBuckets.set(key, bucket);
    sendJson(res, 429, { error: "Rate limit exceeded" }, req.method === "HEAD", { "Retry-After": String(resetSeconds), "Cache-Control": "no-store" });
    return false;
  }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  if (++rateChecks % 500 === 0) for (const [address, value] of rateBuckets) if (now >= value.resetAt) rateBuckets.delete(address);
  return true;
}

function validateParameters(params) {
  const entries = [...params.entries()];
  if (entries.length > MAX_PARAMETERS) return "Too many query parameters";
  if (entries.some(([key, value]) => key.length > 40 || value.length > MAX_PARAMETER_LENGTH)) return `Query parameter values are limited to ${MAX_PARAMETER_LENGTH} characters`;
  return null;
}

function boundedInteger(value, fallback, minimum, maximum) {
  if (value == null || value === "") return fallback;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
}

function queryReports(params) {
  const q = lower(params.get("q")).trim();
  const filtered = searchRows.filter(({ report, haystack }) => (!q || haystack.includes(q)) && exact(report.platform, params.get("platform")) && exact(report.severity, params.get("severity")) && exact(report.vulnerabilityClass, params.get("class")) && exact(report.researcher, params.get("researcher")) && exact(report.program, params.get("program")) && exact(year(report.disclosedAt), params.get("year")) && exact(report.kind, params.get("kind"))).map(row => row.report);
  const sort = params.get("sort") || "recent";
  if (sort === "title") filtered.sort((a, b) => a.title.localeCompare(b.title));
  else if (sort === "bounty") filtered.sort((a, b) => (b.bounty || 0) - (a.bounty || 0));
  else if (sort === "popular") filtered.sort((a, b) => (b.votes || 0) - (a.votes || 0));
  else filtered.sort((a, b) => String(b.disclosedAt || "").localeCompare(String(a.disclosedAt || "")));
  return filtered;
}

function api(req, res, url) {
  const head = req.method === "HEAD";
  const parameterError = validateParameters(url.searchParams);
  if (parameterError) return sendJson(res, 400, { error: parameterError }, head, { "Cache-Control": "no-store" });
  if (url.pathname === "/api" || url.pathname === "/api/") return sendJson(res, 200, { name: "Disclosure Index API", version: "1.1", rateLimit: { requests: RATE_LIMIT_MAX, windowMs: RATE_LIMIT_WINDOW_MS }, endpoints: ["GET /api/reports", "GET /api/reports/{id}", "GET /api/stats"], filters: ["q", "platform", "severity", "class", "researcher", "program", "year", "kind", "sort", "limit", "offset"] }, head);
  if (url.pathname === "/api/stats") return sendJson(res, 200, statistics, head);
  if (url.pathname === "/api/reports") {
    const limit = boundedInteger(url.searchParams.get("limit"), 25, 1, 100);
    const offset = boundedInteger(url.searchParams.get("offset"), 0, 0, 1000000);
    const sort = url.searchParams.get("sort") || "recent";
    if (limit == null || offset == null) return sendJson(res, 400, { error: "limit must be 1–100 and offset must be 0–1000000" }, head, { "Cache-Control": "no-store" });
    if (!new Set(["recent", "title", "bounty", "popular"]).has(sort)) return sendJson(res, 400, { error: "Unsupported sort value" }, head, { "Cache-Control": "no-store" });
    const rows = queryReports(url.searchParams);
    const nextOffset = offset + limit < rows.length ? offset + limit : null;
    return sendJson(res, 200, { meta: { total: rows.length, limit, offset, nextOffset }, data: rows.slice(offset, offset + limit) }, head);
  }
  if (url.pathname.startsWith("/api/reports/")) {
    const id = decodeURIComponent(url.pathname.slice(13));
    if (!id || id.length > 128) return sendJson(res, 400, { error: "Invalid record identifier" }, head, { "Cache-Control": "no-store" });
    const report = reportsById.get(id);
    return report ? sendJson(res, 200, { data: report }, head) : sendJson(res, 404, { error: "Record not found" }, head, { "Cache-Control": "no-store" });
  }
  return sendJson(res, 404, { error: "API endpoint not found" }, head, { "Cache-Control": "no-store" });
}

function serveFile(req, res, url) {
  const entry = staticFiles.get(url.pathname);
  if (!entry) return sendJson(res, 404, { error: "Not found" }, req.method === "HEAD", { "Cache-Control": "no-store" });
  res.writeHead(200, { ...securityHeaders(false), "Content-Type": entry.type, "Content-Length": entry.body.length, "Cache-Control": entry.cache });
  res.end(req.method === "HEAD" ? undefined : entry.body);
}

const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 5000, keepAliveTimeout: 5000 }, (req, res) => {
  try {
    if (req.url.length > MAX_URL_LENGTH) return sendJson(res, 414, { error: "Request URL is too long" }, req.method === "HEAD", { "Cache-Control": "no-store" });
    const url = new URL(req.url, "http://localhost");
    if (url.pathname.startsWith("/api") && !allowApiRequest(req, res)) return;
    if (req.method === "OPTIONS") {
      if (!url.pathname.startsWith("/api")) return sendJson(res, 404, { error: "Not found" });
      res.writeHead(204, { ...securityHeaders(true), ...res.rateLimitHeaders, "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS", "Access-Control-Max-Age": "86400" });
      return res.end();
    }
    if (!["GET", "HEAD"].includes(req.method)) return sendJson(res, 405, { error: "Method not allowed" }, false, { "Allow": "GET, HEAD, OPTIONS", "Cache-Control": "no-store" });
    return url.pathname.startsWith("/api") ? api(req, res, url) : serveFile(req, res, url);
  } catch {
    return sendJson(res, 400, { error: "Malformed request" }, req.method === "HEAD", { "Cache-Control": "no-store" });
  }
});
server.maxHeadersCount = 50;
server.maxRequestsPerSocket = 100;
server.setTimeout(15000, socket => socket.destroy());
server.listen(PORT, HOST, () => console.log(`Disclosure Index available at http://${HOST}:${PORT}`));
