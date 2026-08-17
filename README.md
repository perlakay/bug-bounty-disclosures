# Disclosure Index

A searchable, provenance-first index of public platform disclosures and competitive security reports.

## Current snapshot

The August 2026 platform-focused build contains 11,304 unique canonical URLs:

| Source channel | Records |
| --- | ---: |
| HackerOne | 9,991 |
| Bugcrowd | 804 |
| Code4rena | 410 |
| Immunefi | 92 |
| Intigriti | 6 |
| YesWeHack | 1 |

The 4,260 unrelated independent-blog entries from PentesterLand were removed because that directory ends in 2022. Its 57 records explicitly associated with HackerOne, Bugcrowd, Intigriti, or YesWeHack are retained as an archival discovery layer and labeled `PentesterLand historical platform index (through 2022)`. Official-feed records take precedence during URL deduplication.

## Features

- Search across titles, programs, researchers, weakness labels, CVEs, and platforms
- Platform, vulnerability class, severity, year, and report-type filtering
- Lazy rendering in batches of 36 for a responsive 11K-record catalog
- Bounty, popularity, recency, and alphabetical sorting
- Local bookmarks and CSV export
- Canonical source links and normalized cross-source vulnerability classes
- Responsive desktop and mobile layouts
- Read-only JSON API with search, field filters, sorting, and pagination

## Run locally

```bash
npm start
```

Open `http://localhost:8080`.

## API

The zero-dependency Node server exposes the collection at:

```text
GET /api
GET /api/reports?q=xss&severity=high&limit=25&offset=0
GET /api/reports/{id}
GET /api/stats
```

`/api/reports` accepts `q`, `platform`, `severity`, `class`, `researcher`, `program`, `year`, `kind`, `sort`, `limit`, and `offset`. The maximum page size is 100. CORS is enabled for read-only use.

## Data sources

- HackerOne structured public-disclosure index: `ajaysenr/HackerOne-Disclosed-Reports`
- Bugcrowd public CrowdStream JSON feed; only records marked `disclosed` are imported
- Immunefi's public bug-fix review and vulnerability-analysis sitemap
- Code4rena's official audit reports index
- PentesterLand's historical index, restricted to records explicitly associated with a named bug-bounty platform

The generated browser dataset is [data/catalog.js](data/catalog.js). The normalization and deduplication logic is [scripts/build-catalog.mjs](scripts/build-catalog.mjs).

To rebuild, download source snapshots and point the environment variables at them:

```bash
H1_INDEX=/path/to/index.json \
IMMUNEFI_INDEX=/path/to/sitemap-posts.xml \
BUGCROWD_DIR=/path/to/crowdstream-pages \
CODE4RENA_INDEX=/path/to/code4rena-reports.html \
HISTORICAL_PLATFORM_INDEX=/path/to/list-of-bug-bounty-writeups.md \
node scripts/build-catalog.mjs
```

Refresh the maintained HackerOne index and Code4rena's official reports page:

```bash
npm run update:platforms
```

## Collection policy

Only index material intentionally made public by the researcher, affected program, or publishing platform. Retain the canonical URL and attribution. Do not ingest private-program activity, reports visible through privileged access, leaked material, secrets, personal data, or unpublished vulnerability details.

The project stores factual metadata and short normalized labels rather than mirroring full reports. Source-native weakness labels are retained where available. Normalized classes are editorial aids and may be corrected. Takedown, attribution, and correction requests should be honored promptly.
