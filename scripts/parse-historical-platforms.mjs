const decode = value => String(value || "").replace(/&(#x?[0-9a-f]+|\w+);/gi, (_, code) => {
  const entities = { amp:"&",quot:'"',apos:"'",lt:"<",gt:">",nbsp:" " };
  if (code[0] === "#") { const hex=code[1]?.toLowerCase()==="x";return String.fromCodePoint(parseInt(code.slice(hex?2:1),hex?16:10)); }
  return entities[code.toLowerCase()] || `&${code};`;
});
const clean = value => decode(String(value || "").replace(/<[^>]*>/g," ").replace(/\s+/g," ").trim());
const classify = value => {
  const text=String(value||"").toLowerCase();
  const rules=[["Cross-site scripting",/\bxss\b|cross[ -]site scripting/],["Access control",/idor|access control|authorization|privilege/],["Authentication",/authentication|oauth|sso|2fa|password|account takeover|ato\b/],["Information disclosure",/information disclosure|data leak|sensitive data|exposure/],["SSRF",/\bssrf\b|server[ -]side request/],["SQL injection",/\bsqli?\b|sql injection/],["Command execution",/\brce\b|remote code|command injection|code execution/],["CSRF",/\bcsrf\b|cross[ -]site request forgery/],["Business logic",/business logic|logic flaw|logic error|race condition/],["Subdomain takeover",/subdomain takeover|dangling cname/],["XXE",/\bxxe\b|external entit/],["File security",/file upload|path traversal|directory traversal|\blfi\b|\brfi\b/],["Request smuggling",/request smuggling|http desync/],["Injection",/injection|template injection|ssti|crlf/]];
  return rules.find(([,pattern])=>pattern.test(text))?.[0]||"Other";
};
const platformFor = (text,url) => { const value=`${text} ${url}`.toLowerCase();if(value.includes("hackerone"))return "HackerOne";if(value.includes("bugcrowd"))return "Bugcrowd";if(value.includes("intigriti"))return "Intigriti";if(value.includes("yeswehack"))return "YesWeHack";if(value.includes("immunefi"))return "Immunefi";return null; };
const money = value => { const amounts=String(value||"").replaceAll(",","").match(/\d+(?:\.\d+)?/g);return amounts?.length?Math.max(...amounts.map(Number)):null; };

export function parseHistoricalPlatformReports(markdown) {
  return [...markdown.matchAll(/<tr>([\s\S]*?)<\/tr>/gi)].flatMap((match,index)=>{
    const cells=[...match[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map(cell=>cell[1]);
    if(cells.length<6)return [];
    const url=cells[0].match(/href="([^"]+)"/i)?.[1],title=clean(cells[0]);
    if(!url||!title)return [];
    const author=clean(cells[1])||"Unknown researcher",program=clean(cells[2])||"Unlisted program",weakness=clean(cells[3]),reward=clean(cells[4]),rawDate=clean(cells[5]);
    const platform=platformFor(`${title} ${author} ${program}`,url);
    if(!platform)return [];
    return [{id:`archive-${index}`,title,program:program==="-"?"Unlisted program":program,researcher:author==="-"?"Unknown researcher":author,platform,url,vulnerabilityClass:classify(`${weakness} ${title}`),weakness:weakness==="-"?null:weakness,severity:"Unrated",bounty:money(reward),disclosedAt:/^\d{2}\/\d{2}\/\d{4}$/.test(rawDate)?rawDate.split("/").reverse().join("-"):null,votes:0,cves:[],kind:"Historical platform-associated writeup",indexedVia:"PentesterLand historical platform index (through 2022)"}];
  });
}
