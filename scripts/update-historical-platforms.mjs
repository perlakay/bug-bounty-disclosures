import path from "node:path";
import { parseHistoricalPlatformReports } from "./parse-historical-platforms.mjs";
import { assertResponseOrigin, deduplicate, readCatalog, readLimitedText, writeCatalog } from "./catalog-utils.mjs";

const root=path.resolve(import.meta.dirname,".."),catalogPath=path.join(root,"data/catalog.js");
const sourceUrl="https://raw.githubusercontent.com/pentesterland/pentesterland.github.io/master/_pages/list-of-bug-bounty-writeups.md";
const response=await fetch(sourceUrl,{headers:{"User-Agent":"DisclosureIndex/1.0 (+public metadata index)"},signal:AbortSignal.timeout(30000)});
if(!response.ok)throw new Error(`Historical index returned HTTP ${response.status}`);
assertResponseOrigin(response,["https://raw.githubusercontent.com"]);
const incoming=parseHistoricalPlatformReports(await readLimitedText(response,15_000_000));
if(incoming.length<50||incoming.length>500)throw new Error(`Safety check failed: unexpected historical platform record count ${incoming.length}`);
const existing=readCatalog(catalogPath).filter(row=>row.indexedVia!=="PentesterLand historical platform index (through 2022)"&&row.platform!=="Independent publications");
const catalog=deduplicate([...existing,...incoming]);
writeCatalog(catalogPath,catalog);
const added=catalog.filter(row=>row.indexedVia==="PentesterLand historical platform index (through 2022)");
console.log(JSON.stringify({total:catalog.length,historicalPlatformRecords:added.length,platforms:Object.fromEntries([...new Set(added.map(row=>row.platform))].sort().map(platform=>[platform,added.filter(row=>row.platform===platform).length]))},null,2));
