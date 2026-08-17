import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { parseHistoricalPlatformReports } from "./parse-historical-platforms.mjs";

const root=path.resolve(import.meta.dirname,".."),catalogPath=path.join(root,"data/catalog.js");
const sourceUrl="https://raw.githubusercontent.com/pentesterland/pentesterland.github.io/master/_pages/list-of-bug-bounty-writeups.md";
const response=await fetch(sourceUrl,{headers:{"User-Agent":"DisclosureIndex/1.0 (+public metadata index)"}});
if(!response.ok)throw new Error(`Historical index returned HTTP ${response.status}`);
const incoming=parseHistoricalPlatformReports(await response.text());
if(incoming.length<50)throw new Error(`Safety check failed: only ${incoming.length} platform-associated records found`);
const context={window:{}};vm.runInNewContext(fs.readFileSync(catalogPath,"utf8"),context);
const existing=context.window.DISCLOSURE_REPORTS.filter(row=>row.indexedVia!=="PentesterLand historical platform index (through 2022)"&&row.platform!=="Independent publications");
const seen=new Set(),catalog=[...existing,...incoming].filter(row=>{const key=row.url.replace(/\/$/,"").toLowerCase();if(seen.has(key))return false;seen.add(key);return true;});
fs.writeFileSync(catalogPath,`window.DISCLOSURE_REPORTS=${JSON.stringify(catalog)};\n`);
const added=catalog.filter(row=>row.indexedVia==="PentesterLand historical platform index (through 2022)");
console.log(JSON.stringify({total:catalog.length,historicalPlatformRecords:added.length,platforms:Object.fromEntries([...new Set(added.map(row=>row.platform))].sort().map(platform=>[platform,added.filter(row=>row.platform===platform).length]))},null,2));
