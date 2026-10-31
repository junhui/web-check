import net from 'net';
import middleware from './_common/middleware.js';
import { parseTarget, baseDomain } from './_common/parse-target.js';

const googleUrl = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;

// Build Google dork queries for a domain; makes no requests itself
const buildDorks = (d) =>
  [
    [
      'Exposed documents',
      `site:${d} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)`,
    ],
    [
      'Login pages',
      `site:${d} (inurl:login OR inurl:signin OR inurl:admin OR intitle:login OR intitle:"sign in")`,
    ],
    ['Directory listings', `site:${d} intitle:"index of"`],
    [
      'Config files',
      `site:${d} (ext:xml OR ext:conf OR ext:cnf OR ext:cfg OR ext:ini OR ext:yml OR ext:yaml OR ext:env)`,
    ],
    ['Log files', `site:${d} ext:log`],
    ['Database files', `site:${d} (ext:sql OR ext:dbf OR ext:mdb OR ext:db)`],
    ['Environment files', `site:${d} (inurl:.env OR filetype:env OR intext:"DB_PASSWORD")`],
    ['Backup files', `site:${d} (ext:bak OR ext:backup OR ext:old OR ext:swp OR ext:bkp)`],
    ['Error pages', `site:${d} (inurl:error OR intitle:error OR intext:"stack trace")`],
    [
      'SQL errors',
      `site:${d} (intext:"sql syntax" OR intext:"mysql_fetch" OR intext:"ORA-" OR intext:"syntax error")`,
    ],
    ['Pastebin mentions', `site:pastebin.com "${d}"`],
    ['GitHub mentions', `site:github.com "${d}"`],
    ['Trello mentions', `site:trello.com "${d}"`],
    ['Subdomains', `site:*.${d} -www`],
  ].map(([title, query]) => ({ title, query, url: googleUrl(query) }));

const dorksHandler = async (url) => {
  const { hostname } = parseTarget(url);
  const domain = net.isIP(hostname) ? hostname : baseDomain(hostname);
  return buildDorks(domain);
};

export const handler = middleware(dorksHandler);
export default handler;
