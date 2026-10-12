/**
 * Albatross URL Scanner
 *
 * Passive security reconnaissance of a single URL, run from a Cloudflare Worker.
 * Collects:
 *   - Target decoding (base64 / base64url / percent-encoded / hex / plain) and SSRF guards
 *   - Redirect chain (manual hop-by-hop following, downgrade + cross-domain detection)
 *   - HTTP protocol support (HTTP/1.1, HTTP/2 via TLS ALPN + DNS HTTPS record, HTTP/3 via Alt-Svc + DNS HTTPS record)
 *   - TLS protocol support (raw ClientHello probes for TLS 1.0 / 1.1 / 1.2 / 1.3) and leaf certificate details
 *   - Domain registration data (RDAP: creation/expiry date, registrar, age)
 *   - DNS (A/AAAA/CNAME/NS/MX/CAA/HTTPS, SPF, DMARC, DNSSEC)
 *   - Hosting network (ASN via Cloudflare Radar, abuse score via AbuseIPDB) and CDN detection
 *   - Technology fingerprinting (frameworks, libraries, server software + versions) matched
 *     against a small static table of known-vulnerable / end-of-life versions
 *   - Security headers, cookie flags, Subresource Integrity, mixed content, security.txt
 *   - A screenshot of the rendered page (Cloudflare Browser Rendering)
 *
 * Runtime-specific dependencies (cloudflare:sockets `connect`, @cloudflare/puppeteer) are
 * injected by the caller so this module can also be exercised under plain Node.js.
 */

export const SCAN_LIMITS = {
  maxRedirects: 10,
  maxBodyBytes: 1_000_000,
  fetchTimeoutMs: 10_000,
  redirectBudgetMs: 25_000,
  tlsTimeoutMs: 6_000,
  screenshotTimeoutMs: 20_000,
  maxUrlLength: 2048,
  maxIpLookups: 4
};

const SCANNER_USER_AGENT = 'Mozilla/5.0 (compatible; AlbatrossURLScanner/1.0; +https://albatross.devnomadic.com)';
const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const RDAP_BOOTSTRAP_URL = 'https://rdap.org/domain/';

// ---------------------------------------------------------------------------
// Target extraction / decoding / validation
// ---------------------------------------------------------------------------

/**
 * Finds a URL-scan target in the request's ORIGINAL (case-preserved) query string.
 * The main worker lowercases the request URL for HMAC + parameter parsing, which would
 * corrupt base64, so this must be called with the untouched URL.
 *
 * Looks at the dedicated `url` / `scanurl` / `target` parameters first, then checks
 * whether the `ipaddress` parameter actually contains an (optionally encoded) URL.
 *
 * @param {URL} originalUrl - The request URL with original casing
 * @returns {{ raw: string, param: string } | null}
 */
export function extractScanTarget(originalUrl) {
  const byLowerKey = new Map();
  for (const [key, value] of originalUrl.searchParams) {
    const lower = key.toLowerCase();
    if (!byLowerKey.has(lower)) byLowerKey.set(lower, value);
  }

  for (const key of ['url', 'scanurl', 'target']) {
    const value = byLowerKey.get(key);
    if (value && value.trim()) return { raw: value.trim(), param: key };
  }

  // Auto-detect: an encoded or plain URL supplied in the ipaddress field
  const ipValue = byLowerKey.get('ipaddress');
  if (ipValue && decodeScanTarget(ipValue).ok) {
    return { raw: ipValue.trim(), param: 'ipaddress' };
  }

  return null;
}

/**
 * Detects the encoding of a URL-scan target and decodes it.
 * Supported: plain URL, percent-encoded URL, base64, base64url, hex.
 *
 * @param {string} raw
 * @returns {{ ok: boolean, url?: string, encoding?: string, error?: string }}
 */
export function decodeScanTarget(raw) {
  const value = (raw || '').trim();
  if (!value) return { ok: false, error: 'Empty URL' };
  if (value.length > SCAN_LIMITS.maxUrlLength * 2) return { ok: false, error: 'URL is too long' };

  const looksLikeUrl = (s) => /^https?:\/\/[^\s]+$/i.test(s);

  if (looksLikeUrl(value)) return { ok: true, url: value, encoding: 'plain' };

  if (/^https?%3a%2f%2f/i.test(value)) {
    try {
      const decoded = decodeURIComponent(value);
      if (looksLikeUrl(decoded)) return { ok: true, url: decoded, encoding: 'percent' };
    } catch { /* fall through */ }
  }

  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) {
    try {
      const isUrlSafe = /[-_]/.test(value);
      let b64 = value.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      const binary = atob(b64);
      const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
      if (looksLikeUrl(decoded)) {
        return { ok: true, url: decoded, encoding: isUrlSafe || !value.endsWith('=') ? 'base64url' : 'base64' };
      }
    } catch { /* fall through */ }
  }

  if (/^(?:[0-9a-f]{2})+$/i.test(value)) {
    try {
      const bytes = new Uint8Array(value.match(/../g).map((h) => parseInt(h, 16)));
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
      if (looksLikeUrl(decoded)) return { ok: true, url: decoded, encoding: 'hex' };
    } catch { /* fall through */ }
  }

  return { ok: false, error: 'Value is not an http(s) URL or a base64/base64url/hex/percent-encoded http(s) URL' };
}

/**
 * Validates and normalizes a scan target. Blocks non-http(s) schemes, credentials in URL,
 * unusual ports, local hostnames and private / reserved IP literals.
 *
 * @param {string} urlString
 * @returns {{ ok: boolean, url?: URL, error?: string }}
 */
export function validateScanTarget(urlString) {
  if (!urlString || urlString.length > SCAN_LIMITS.maxUrlLength) {
    return { ok: false, error: `URL must be between 1 and ${SCAN_LIMITS.maxUrlLength} characters` };
  }

  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { ok: false, error: 'Malformed URL' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: 'Only http:// and https:// URLs can be scanned' };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'URLs containing credentials are not allowed' };
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    return { ok: false, error: 'Only ports 80, 443, 8080 and 8443 are allowed' };
  }

  const hostCheck = checkHostAllowed(url.hostname);
  if (!hostCheck.ok) return hostCheck;

  if (!url.hostname.includes('.') && !isIpLiteral(url.hostname)) {
    return { ok: false, error: 'Hostname must be a fully qualified domain name' };
  }

  return { ok: true, url };
}

function checkHostAllowed(hostname) {
  const host = (hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host) return { ok: false, error: 'Missing hostname' };

  if (host === 'localhost' || /\.(localhost|local|internal|intranet|lan|home|corp|arpa)$/.test(host)) {
    return { ok: false, error: 'Local / internal hostnames are not allowed' };
  }
  if (isIpLiteral(host) && !isPublicIp(host)) {
    return { ok: false, error: 'Private, loopback and reserved IP addresses are not allowed' };
  }
  return { ok: true };
}

export function isIpLiteral(host) {
  const h = (host || '').replace(/^\[|\]$/g, '');
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
}

/**
 * Returns true when an IPv4/IPv6 address is publicly routable.
 */
export function isPublicIp(ip) {
  const addr = (ip || '').replace(/^\[|\]$/g, '').toLowerCase();

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) {
    const o = addr.split('.').map(Number);
    if (o.some((n) => n > 255)) return false;
    if (o[0] === 0 || o[0] === 10 || o[0] === 127) return false;
    if (o[0] === 100 && (o[1] & 0xc0) === 64) return false; // CGNAT
    if (o[0] === 169 && o[1] === 254) return false;
    if (o[0] === 172 && (o[1] & 0xf0) === 16) return false;
    if (o[0] === 192 && o[1] === 0 && (o[2] === 0 || o[2] === 2)) return false;
    if (o[0] === 192 && o[1] === 88 && o[2] === 99) return false;
    if (o[0] === 192 && o[1] === 168) return false;
    if (o[0] === 198 && (o[1] & 0xfe) === 18) return false;
    if (o[0] === 198 && o[1] === 51 && o[2] === 100) return false;
    if (o[0] === 203 && o[1] === 0 && o[2] === 113) return false;
    if (o[0] >= 224) return false; // multicast + reserved + broadcast
    return true;
  }

  if (addr.includes(':')) {
    if (addr === '::' || addr === '::1') return false;
    if (/^::ffff:/.test(addr)) return isPublicIp(addr.substring(7));
    if (/^fe[89ab]/.test(addr)) return false; // link-local fe80::/10
    if (/^f[cd]/.test(addr)) return false; // unique local fc00::/7
    if (/^ff/.test(addr)) return false; // multicast
    if (/^2001:0?db8:/.test(addr)) return false; // documentation
    if (/^64:ff9b:/.test(addr)) return false; // NAT64
    return true;
  }

  return false;
}

/**
 * Best-effort registrable domain ("eTLD+1") without a full Public Suffix List.
 */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'org.nz', 'net.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.za', 'org.za', 'gov.za',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'com.mx', 'org.mx', 'gob.mx',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'com.sg', 'edu.sg', 'gov.sg', 'com.hk', 'org.hk',
  'co.kr', 'or.kr', 'com.tr', 'com.ar', 'co.il', 'org.il',
  'com.tw', 'org.tw', 'com.my', 'co.id', 'com.ph', 'com.vn', 'com.pk',
  'com.ng', 'com.eg', 'com.sa', 'com.ua', 'co.th', 'in.th'
]);

export function getRegistrableDomain(hostname) {
  const host = (hostname || '').toLowerCase().replace(/\.$/, '');
  if (!host || isIpLiteral(host)) return null;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return MULTI_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

async function fetchWithTimeout(url, init = {}, timeoutMs = SCAN_LIMITS.fetchTimeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`Timed out after ${timeoutMs}ms`)), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function readBodyLimited(response, maxBytes = SCAN_LIMITS.maxBodyBytes) {
  if (!response.body) return { text: '', truncated: false, bytes: 0 };
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total >= maxBytes) {
        truncated = true;
        break;
      }
    }
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  const merged = concatBytes(...chunks).subarray(0, maxBytes);
  return { text: new TextDecoder('utf-8').decode(merged), truncated, bytes: merged.length };
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function compareVersions(a, b) {
  const pa = String(a).split(/[^0-9]+/).filter(Boolean).map(Number);
  const pb = String(b).split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function daysBetween(from, to) {
  return Math.floor((to.getTime() - from.getTime()) / 86_400_000);
}

function safeHost(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// DNS over HTTPS
// ---------------------------------------------------------------------------

async function dohQuery(name, type) {
  try {
    const res = await fetchWithTimeout(`${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { Accept: 'application/dns-json' }
    }, 5000);
    if (!res.ok) return { ok: false, error: `DoH HTTP ${res.status}` };
    const json = await res.json();
    return {
      ok: true,
      status: json.Status,
      authenticated: json.AD === true,
      answers: (json.Answer || []).map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: a.data }))
    };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

const DNS_TYPE_CODES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, HTTPS: 65, CAA: 257 };

async function collectDns(hostname, registrableDomain) {
  if (isIpLiteral(hostname)) {
    return { skipped: true, reason: 'Target is an IP address', a: [], aaaa: [], cname: [] };
  }

  const [a, aaaa, cname, https, ns, mx, txt, caa, dmarc] = await Promise.all([
    dohQuery(hostname, 'A'),
    dohQuery(hostname, 'AAAA'),
    dohQuery(hostname, 'CNAME'),
    dohQuery(hostname, 'HTTPS'),
    dohQuery(registrableDomain || hostname, 'NS'),
    dohQuery(registrableDomain || hostname, 'MX'),
    dohQuery(registrableDomain || hostname, 'TXT'),
    dohQuery(registrableDomain || hostname, 'CAA'),
    dohQuery(`_dmarc.${registrableDomain || hostname}`, 'TXT')
  ]);

  const pick = (result, typeCode) => (result.ok ? result.answers.filter((x) => x.type === typeCode).map((x) => x.data) : []);
  const unquote = (s) => s.replace(/^"|"$/g, '').replace(/"\s*"/g, '');

  // CNAME chain: the A/AAAA answer section also contains CNAMEs that were followed
  const cnameChain = [...new Set([
    ...pick(cname, DNS_TYPE_CODES.CNAME),
    ...pick(a, DNS_TYPE_CODES.CNAME),
    ...pick(aaaa, DNS_TYPE_CODES.CNAME)
  ].map((c) => c.replace(/\.$/, '').toLowerCase()))];

  const txtRecords = pick(txt, DNS_TYPE_CODES.TXT).map(unquote);
  const spf = txtRecords.find((t) => /^v=spf1/i.test(t)) || null;
  const dmarcRecord = pick(dmarc, DNS_TYPE_CODES.TXT).map(unquote).find((t) => /^v=DMARC1/i.test(t)) || null;

  const httpsRecords = pick(https, DNS_TYPE_CODES.HTTPS);
  const alpn = [...new Set(httpsRecords.flatMap((rec) => {
    const m = /alpn="?([^"\s]+)"?/i.exec(rec);
    return m ? m[1].split(',') : [];
  }))];

  return {
    skipped: false,
    a: pick(a, DNS_TYPE_CODES.A),
    aaaa: pick(aaaa, DNS_TYPE_CODES.AAAA),
    cname: cnameChain,
    ns: pick(ns, DNS_TYPE_CODES.NS).map((n) => n.replace(/\.$/, '')),
    mx: pick(mx, DNS_TYPE_CODES.MX),
    caa: pick(caa, DNS_TYPE_CODES.CAA),
    httpsRecord: httpsRecords,
    httpsRecordAlpn: alpn,
    spf,
    dmarc: dmarcRecord,
    dnssec: a.ok ? a.authenticated : null,
    errors: [a, aaaa, ns].filter((r) => !r.ok).map((r) => r.error)
  };
}

// ---------------------------------------------------------------------------
// RDAP domain registration
// ---------------------------------------------------------------------------

async function lookupRdap(domain) {
  if (!domain) return { success: false, error: 'No registrable domain (IP address target)' };
  try {
    const res = await fetchWithTimeout(`${RDAP_BOOTSTRAP_URL}${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': SCANNER_USER_AGENT },
      redirect: 'follow'
    }, 8000);
    if (!res.ok) return { success: false, error: `RDAP lookup failed: HTTP ${res.status}` };
    const json = await res.json();

    const eventDate = (action) => json.events?.find((e) => e.eventAction === action)?.eventDate || null;
    const created = eventDate('registration');
    const expires = eventDate('expiration');
    const updated = eventDate('last changed');

    const registrarEntity = (json.entities || []).find((e) => (e.roles || []).includes('registrar'));
    const vcardFn = registrarEntity?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3] || null;

    const now = new Date();
    const createdDate = created ? new Date(created) : null;
    const expiresDate = expires ? new Date(expires) : null;

    return {
      success: true,
      domain: json.ldhName?.toLowerCase() || domain,
      created,
      expires,
      updated,
      ageDays: createdDate && !isNaN(createdDate) ? daysBetween(createdDate, now) : null,
      daysUntilExpiry: expiresDate && !isNaN(expiresDate) ? daysBetween(now, expiresDate) : null,
      registrar: vcardFn,
      status: json.status || [],
      nameservers: (json.nameservers || []).map((n) => n.ldhName?.toLowerCase().replace(/\.$/, '')).filter(Boolean),
      source: res.url || 'rdap'
    };
  } catch (error) {
    return { success: false, error: `RDAP lookup failed: ${error.message}` };
  }
}

// ---------------------------------------------------------------------------
// HTTP: redirect chain + main page fetch
// ---------------------------------------------------------------------------

async function followRedirects(startUrl) {
  const chain = [];
  const seen = new Set();
  const deadline = Date.now() + SCAN_LIMITS.redirectBudgetMs;
  let current = startUrl;

  for (let hop = 0; hop <= SCAN_LIMITS.maxRedirects; hop++) {
    if (Date.now() > deadline) {
      return { chain, finalUrl: current, response: null, error: `Redirect chain exceeded ${SCAN_LIMITS.redirectBudgetMs / 1000}s time budget` };
    }
    const validation = validateScanTarget(current);
    if (!validation.ok) {
      return { chain, finalUrl: current, response: null, error: `Redirect blocked: ${validation.error}` };
    }
    if (seen.has(current)) {
      return { chain, finalUrl: current, response: null, error: 'Redirect loop detected' };
    }
    seen.add(current);

    const started = Date.now();
    let res;
    try {
      res = await fetchWithTimeout(current, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': SCANNER_USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.8'
        }
      });
    } catch (error) {
      return { chain, finalUrl: current, response: null, error: `Request failed: ${error.message}` };
    }

    const location = res.headers.get('location');
    const isRedirect = res.status >= 300 && res.status < 400 && location;
    const entry = {
      url: current,
      statusCode: res.status,
      statusText: res.statusText,
      server: res.headers.get('server'),
      timeMs: Date.now() - started
    };

    if (!isRedirect) {
      chain.push(entry);
      return { chain, finalUrl: current, response: res, error: null };
    }

    let next;
    try {
      next = new URL(location, current).href;
    } catch {
      chain.push({ ...entry, location });
      return { chain, finalUrl: current, response: res, error: `Invalid redirect location: ${location}` };
    }

    entry.location = next;
    entry.httpsDowngrade = current.startsWith('https:') && next.startsWith('http:');
    entry.crossDomain = getRegistrableDomain(safeHost(current)) !== getRegistrableDomain(safeHost(next));
    chain.push(entry);
    try { await res.body?.cancel(); } catch { /* ignore */ }
    current = next;
  }

  return { chain, finalUrl: current, response: null, error: `Too many redirects (> ${SCAN_LIMITS.maxRedirects})` };
}

/**
 * Checks whether plain http:// on the target host redirects to https://
 */
async function checkHttpsEnforcement(hostname) {
  try {
    const res = await fetchWithTimeout(`http://${hostname}/`, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'User-Agent': SCANNER_USER_AGENT }
    }, 6000);
    try { await res.body?.cancel(); } catch { /* ignore */ }
    const location = res.headers.get('location') || '';
    return {
      checked: true,
      statusCode: res.status,
      location: location || null,
      enforced: res.status >= 300 && res.status < 400 && /^https:\/\//i.test(new URL(location || '/', `http://${hostname}/`).href)
    };
  } catch (error) {
    return { checked: false, error: error.message };
  }
}

async function checkSecurityTxt(origin) {
  try {
    const url = `${origin}/.well-known/security.txt`;
    const res = await fetchWithTimeout(url, { headers: { 'User-Agent': SCANNER_USER_AGENT } }, 5000);
    const { text } = await readBodyLimited(res, 32_768);
    const present = res.ok && /^\s*(contact|expires|policy)\s*:/im.test(text);
    return { present, url, statusCode: res.status };
  } catch (error) {
    return { present: false, error: error.message };
  }
}

// ---------------------------------------------------------------------------
// Header analysis
// ---------------------------------------------------------------------------

const INTERESTING_HEADERS = [
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'via', 'x-cache',
  'cf-ray', 'cf-cache-status', 'x-amz-cf-id', 'x-amz-cf-pop', 'x-served-by', 'x-fastly-request-id',
  'x-azure-ref', 'x-vercel-id', 'x-nf-request-id', 'alt-svc', 'content-type', 'strict-transport-security',
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'x-content-type-options',
  'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy',
  'cross-origin-embedder-policy', 'access-control-allow-origin', 'access-control-allow-credentials', 'x-xss-protection'
];

function pickHeaders(headers) {
  const out = {};
  for (const name of INTERESTING_HEADERS) {
    const value = headers.get(name);
    if (value !== null) out[name] = value.length > 500 ? `${value.substring(0, 500)}…` : value;
  }
  return out;
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const raw = headers.get('set-cookie');
  return raw ? raw.split(/,(?=\s*[^;,=\s]+=[^;,]*)/) : [];
}

function analyzeCookies(headers, isHttps) {
  return getSetCookies(headers).slice(0, 30).map((cookie) => {
    const [nameValue, ...attrs] = cookie.split(';').map((s) => s.trim());
    const name = nameValue.split('=')[0];
    const attrLower = attrs.map((a) => a.toLowerCase());
    const sameSite = attrLower.find((a) => a.startsWith('samesite='))?.split('=')[1] || null;
    return {
      name,
      secure: attrLower.includes('secure'),
      httpOnly: attrLower.includes('httponly'),
      sameSite,
      issues: [
        ...(isHttps && !attrLower.includes('secure') ? ['missing Secure'] : []),
        ...(!attrLower.includes('httponly') ? ['missing HttpOnly'] : []),
        ...(!sameSite ? ['missing SameSite'] : []),
        ...(sameSite === 'none' && !attrLower.includes('secure') ? ['SameSite=None without Secure'] : [])
      ]
    };
  });
}

function analyzeSecurityHeaders(headers, isHttps) {
  const results = [];
  const add = (name, status, value, note) => results.push({ name, status, value: value ?? null, note });

  const hsts = headers.get('strict-transport-security');
  if (!isHttps) {
    add('Strict-Transport-Security', 'n/a', hsts, 'Not applicable to plain HTTP responses');
  } else if (!hsts) {
    add('Strict-Transport-Security', 'missing', null, 'HSTS not set; browsers may be downgraded to HTTP on first visit');
  } else {
    const maxAge = parseInt(/max-age=(\d+)/i.exec(hsts)?.[1] || '0', 10);
    const weak = maxAge < 15_552_000; // 180 days
    add('Strict-Transport-Security', weak ? 'weak' : 'good', hsts,
      weak ? 'max-age below 180 days' : `${/includesubdomains/i.test(hsts) ? 'includeSubDomains' : 'host only'}${/preload/i.test(hsts) ? ', preload' : ''}`);
  }

  const csp = headers.get('content-security-policy');
  if (!csp) {
    add('Content-Security-Policy', headers.get('content-security-policy-report-only') ? 'weak' : 'missing',
      headers.get('content-security-policy-report-only'), headers.get('content-security-policy-report-only') ? 'Report-only mode, not enforced' : 'No CSP; XSS impact is not mitigated');
  } else {
    const unsafe = /'unsafe-inline'|'unsafe-eval'/.test(csp) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(csp);
    add('Content-Security-Policy', unsafe ? 'weak' : 'good', csp, unsafe ? "Allows 'unsafe-inline' / 'unsafe-eval'" : 'Present');
  }

  const xfo = headers.get('x-frame-options');
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  add('X-Frame-Options', xfo || frameAncestors ? 'good' : 'missing', xfo,
    xfo ? 'Present' : frameAncestors ? 'Covered by CSP frame-ancestors' : 'Page can be framed (clickjacking)');

  const xcto = headers.get('x-content-type-options');
  add('X-Content-Type-Options', xcto && /nosniff/i.test(xcto) ? 'good' : 'missing', xcto, xcto ? 'Present' : 'MIME sniffing not disabled');

  const rp = headers.get('referrer-policy');
  add('Referrer-Policy', rp ? (/unsafe-url/i.test(rp) ? 'weak' : 'good') : 'missing', rp, rp ? 'Present' : 'Browser default referrer policy');

  const pp = headers.get('permissions-policy');
  add('Permissions-Policy', pp ? 'good' : 'missing', pp, pp ? 'Present' : 'Browser features not restricted');

  const coop = headers.get('cross-origin-opener-policy');
  add('Cross-Origin-Opener-Policy', coop ? 'good' : 'missing', coop, coop ? 'Present' : 'Not set');

  const acao = headers.get('access-control-allow-origin');
  if (acao) {
    const credentials = (headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
    add('Access-Control-Allow-Origin', acao === '*' && credentials ? 'weak' : 'info', acao,
      acao === '*' ? (credentials ? 'Wildcard CORS combined with credentials' : 'Wildcard CORS') : 'CORS enabled for specific origin');
  }

  return results;
}

// ---------------------------------------------------------------------------
// Technology fingerprinting
// ---------------------------------------------------------------------------

/**
 * Static table of known-vulnerable or end-of-life versions.
 * This is intentionally small and conservative; it is not a substitute for a full SCA / CVE database.
 */
const KNOWN_VULNERABILITIES = [
  { name: 'jQuery', below: '1.9.0', severity: 'high', advisories: ['CVE-2012-6708', 'CVE-2015-9251'], note: 'XSS via selector / cross-domain AJAX handling' },
  { name: 'jQuery', below: '3.5.0', severity: 'medium', advisories: ['CVE-2019-11358', 'CVE-2020-11022', 'CVE-2020-11023'], note: 'Prototype pollution and XSS in htmlPrefilter' },
  { name: 'jQuery UI', below: '1.13.0', severity: 'medium', advisories: ['CVE-2021-41182', 'CVE-2021-41183', 'CVE-2021-41184'], note: 'XSS in several widget options' },
  { name: 'Bootstrap', below: '3.4.1', severity: 'medium', advisories: ['CVE-2018-14040', 'CVE-2018-14041', 'CVE-2019-8331'], note: 'XSS in tooltip / data-* attributes' },
  { name: 'Bootstrap', from: '4.0.0', below: '4.3.1', severity: 'medium', advisories: ['CVE-2019-8331'], note: 'XSS in tooltip / popover data-template' },
  { name: 'AngularJS', below: '2.0.0', severity: 'medium', advisories: [], note: 'AngularJS 1.x is end-of-life (Dec 2021) and receives no security fixes' },
  { name: 'Lodash', below: '4.17.21', severity: 'high', advisories: ['CVE-2020-8203', 'CVE-2021-23337'], note: 'Prototype pollution / command injection in template' },
  { name: 'Moment.js', below: '2.29.4', severity: 'medium', advisories: ['CVE-2022-24785', 'CVE-2022-31129'], note: 'Path traversal / ReDoS' },
  { name: 'Handlebars', below: '4.7.7', severity: 'high', advisories: ['CVE-2021-23369', 'CVE-2021-23383'], note: 'Remote code execution via templates' },
  { name: 'Underscore', below: '1.13.0', severity: 'medium', advisories: ['CVE-2021-23358'], note: 'Arbitrary code execution in template' },
  { name: 'Vue', below: '3.0.0', severity: 'low', advisories: [], note: 'Vue 2 reached end-of-life on Dec 31, 2023' },
  { name: 'PHP', below: '8.2.0', severity: 'high', advisories: [], note: 'PHP below 8.2 is end-of-life and no longer receives security fixes' },
  { name: 'Apache HTTP Server', below: '2.4.0', severity: 'high', advisories: [], note: 'Apache 2.2 and older are end-of-life' },
  { name: 'Apache HTTP Server', exact: ['2.4.49', '2.4.50'], severity: 'critical', advisories: ['CVE-2021-41773', 'CVE-2021-42013'], note: 'Path traversal / remote code execution' },
  { name: 'nginx', below: '1.20.1', severity: 'medium', advisories: ['CVE-2021-23017'], note: 'DNS resolver off-by-one heap write' },
  { name: 'Microsoft IIS', below: '10.0', severity: 'high', advisories: [], note: 'IIS versions below 10 ship with end-of-life Windows Server releases' },
  { name: 'OpenSSL', below: '3.0.0', severity: 'high', advisories: [], note: 'OpenSSL 1.1.1 and older are end-of-life' }
];

function matchVulnerabilities(name, version) {
  if (!version || !/^\d/.test(version)) return [];
  return KNOWN_VULNERABILITIES.filter((v) => {
    if (v.name !== name) return false;
    if (v.exact) return v.exact.includes(version);
    if (v.from && compareVersions(version, v.from) < 0) return false;
    return compareVersions(version, v.below) < 0;
  }).map(({ severity, advisories, note }) => ({ severity, advisories, note }));
}

const SCRIPT_LIBRARIES = [
  { name: 'jQuery UI', category: 'JavaScript library', tokens: ['jquery-ui', 'jqueryui', 'jquery.ui'] },
  { name: 'jQuery Migrate', category: 'JavaScript library', tokens: ['jquery-migrate', 'jquery.migrate'] },
  { name: 'jQuery', category: 'JavaScript library', tokens: ['jquery'] },
  { name: 'Bootstrap', category: 'UI framework', tokens: ['bootstrap'], generic: true },
  { name: 'AngularJS', category: 'JavaScript framework', tokens: ['angular.js', 'angular.min.js', 'angularjs'] },
  { name: 'React', category: 'JavaScript framework', tokens: ['react-dom', 'react'], generic: true },
  { name: 'Vue', category: 'JavaScript framework', tokens: ['vue'], generic: true },
  { name: 'Lodash', category: 'JavaScript library', tokens: ['lodash'] },
  { name: 'Underscore', category: 'JavaScript library', tokens: ['underscore'], generic: true },
  { name: 'Moment.js', category: 'JavaScript library', tokens: ['moment'], generic: true },
  { name: 'Handlebars', category: 'JavaScript library', tokens: ['handlebars'] },
  { name: 'D3', category: 'JavaScript library', tokens: ['d3'], generic: true },
  { name: 'Popper', category: 'JavaScript library', tokens: ['popper'], generic: true },
  { name: 'Font Awesome', category: 'Font library', tokens: ['font-awesome', 'fontawesome'] },
  { name: 'Swiper', category: 'JavaScript library', tokens: ['swiper'], generic: true },
  { name: 'GSAP', category: 'JavaScript library', tokens: ['gsap'] },
  { name: 'Axios', category: 'JavaScript library', tokens: ['axios'], generic: true },
  { name: 'DOMPurify', category: 'JavaScript library', tokens: ['dompurify', 'purify'], generic: true },
  { name: 'Chart.js', category: 'JavaScript library', tokens: ['chart.js', 'chart.umd', 'chart.min'] },
  { name: 'Alpine.js', category: 'JavaScript framework', tokens: ['alpinejs', 'alpine'], generic: true },
  { name: 'htmx', category: 'JavaScript library', tokens: ['htmx'] }
];

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Identify a library + version from a script/style URL.
 */
function identifyAssetUrl(assetUrl) {
  const lower = assetUrl.toLowerCase();
  const file = lower.split(/[?#]/)[0];
  for (const lib of SCRIPT_LIBRARIES) {
    for (const token of lib.tokens) {
      const t = escapeRegex(token);
      // token must be a whole path segment component (avoid "react" in "reactive", "jquery" in "jquery-ui")
      const boundary = `(?:^|[/@._-])${t}(?=$|[/@._-])`;
      if (!new RegExp(boundary).test(file)) continue;
      if (lib.name === 'jQuery' && /jquery[-._]?(ui|migrate|validate|mobile|cookie|easing|lazy)/.test(file)) continue;

      const versionPatterns = [
        new RegExp(`${t}[@/-]v?(\\d+\\.\\d+(?:\\.\\d+)?)`),           // jquery-3.6.0.js, jquery@3.6.0, jquery/3.6.0/
        new RegExp(`${t}\\.(\\d+\\.\\d+\\.\\d+)`),                     // jquery.3.6.0.min.js
        new RegExp(`/(\\d+\\.\\d+\\.\\d+)/(?:[^/]*/)*[^/]*${t}`),      // /3.6.0/jquery.min.js (cdnjs)
        new RegExp(`${t}[^?]*\\?(?:.*&)?v(?:er)?=(\\d+\\.\\d+(?:\\.\\d+)?)`) // jquery.min.js?ver=3.6.0 (WordPress)
      ];
      let version = null;
      for (const pattern of versionPatterns) {
        const m = pattern.exec(lower);
        if (m) {
          version = m[1];
          break;
        }
      }
      // Common words (e.g. a site's own "bootstrap.js" loader) only count with a version or from a public CDN
      if (lib.generic && !version && !PUBLIC_CDN_HOSTS.test(lower)) return null;
      return { name: lib.name, category: lib.category, version };
    }
  }
  return null;
}

const PUBLIC_CDN_HOSTS = /\/\/(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|ajax\.googleapis\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|ajax\.aspnetcdn\.com|cdn\.skypack\.dev|esm\.sh)\//;

const HTML_FINGERPRINTS = [
  { name: 'WordPress', category: 'CMS', pattern: /\/wp-(content|includes)\// },
  { name: 'Drupal', category: 'CMS', pattern: /Drupal\.settings|\/sites\/default\/files\/|drupal\.js|data-drupal-/ },
  { name: 'Joomla', category: 'CMS', pattern: /\/media\/(jui|system)\/js\/|Joomla!/ },
  { name: 'Magento', category: 'E-commerce', pattern: /Mage\.Cookies|\/static\/version\d+\/|data-mage-init/ },
  { name: 'Shopify', category: 'E-commerce', pattern: /cdn\.shopify\.com|Shopify\.theme/ },
  { name: 'WooCommerce', category: 'E-commerce', pattern: /woocommerce/ },
  { name: 'Squarespace', category: 'Website builder', pattern: /static1?\.squarespace\.com|Squarespace\./ },
  { name: 'Wix', category: 'Website builder', pattern: /static\.wixstatic\.com|wix-bolt|_wixCssImports/ },
  { name: 'Webflow', category: 'Website builder', pattern: /data-wf-site|webflow\.js|assets\.website-files\.com/ },
  { name: 'Ghost', category: 'CMS', pattern: /ghost-(?:portal|sdk)|content="Ghost/ },
  { name: 'Next.js', category: 'JavaScript framework', pattern: /\/_next\/static\/|__NEXT_DATA__/ },
  { name: 'Nuxt', category: 'JavaScript framework', pattern: /\/_nuxt\/|window\.__NUXT__/ },
  { name: 'Gatsby', category: 'Static site generator', pattern: /id="___gatsby"|\/page-data\/app-data\.json/ },
  { name: 'SvelteKit', category: 'JavaScript framework', pattern: /\/_app\/immutable\/|__sveltekit_/ },
  { name: 'Astro', category: 'JavaScript framework', pattern: /\/_astro\/|astro-island/ },
  { name: 'Remix', category: 'JavaScript framework', pattern: /__remixContext|__remixManifest/ },
  { name: 'Angular', category: 'JavaScript framework', pattern: /ng-version="/ },
  { name: 'React', category: 'JavaScript framework', pattern: /data-reactroot|react-dom/ },
  { name: 'Vue', category: 'JavaScript framework', pattern: /data-v-[0-9a-f]{8}|data-v-app/ },
  { name: 'Blazor', category: 'Web framework', pattern: /_framework\/blazor\.(webassembly|server|web)\.js/ },
  { name: 'ASP.NET Web Forms', category: 'Web framework', pattern: /__VIEWSTATE|WebResource\.axd/ },
  { name: 'Laravel', category: 'Web framework', pattern: /laravel_session|csrf-token" content=/ },
  { name: 'Google Tag Manager', category: 'Analytics', pattern: /googletagmanager\.com\/gtm\.js/ },
  { name: 'Google Analytics', category: 'Analytics', pattern: /google-analytics\.com\/(analytics|ga)\.js|googletagmanager\.com\/gtag\/js/ },
  { name: 'Cloudflare Web Analytics', category: 'Analytics', pattern: /static\.cloudflareinsights\.com\/beacon/ },
  { name: 'Hotjar', category: 'Analytics', pattern: /static\.hotjar\.com/ },
  { name: 'Google reCAPTCHA', category: 'Security', pattern: /google\.com\/recaptcha|gstatic\.com\/recaptcha/ },
  { name: 'hCaptcha', category: 'Security', pattern: /hcaptcha\.com\/1\/api\.js/ },
  { name: 'Cloudflare Turnstile', category: 'Security', pattern: /challenges\.cloudflare\.com\/turnstile/ }
];

const COOKIE_FINGERPRINTS = [
  { pattern: /^PHPSESSID$/i, name: 'PHP', category: 'Programming language' },
  { pattern: /^JSESSIONID$/i, name: 'Java Servlet', category: 'Web framework' },
  { pattern: /^(ASP\.NET_SessionId|\.AspNetCore\.)/i, name: 'ASP.NET', category: 'Web framework' },
  { pattern: /^laravel_session$/i, name: 'Laravel', category: 'Web framework' },
  { pattern: /^(csrftoken|django_language)$/i, name: 'Django', category: 'Web framework' },
  { pattern: /^_[a-z0-9_]+_session$/i, name: 'Ruby on Rails', category: 'Web framework' },
  { pattern: /^connect\.sid$/i, name: 'Express', category: 'Web framework' },
  { pattern: /^(wordpress_|wp-settings)/i, name: 'WordPress', category: 'CMS' },
  { pattern: /^(__cf_bm|__cfruid|cf_clearance)$/i, name: 'Cloudflare', category: 'CDN / Security' },
  { pattern: /^AWSALB(CORS)?$/i, name: 'AWS Elastic Load Balancing', category: 'Load balancer' },
  { pattern: /^ARRAffinity(SameSite)?$/i, name: 'Azure App Service', category: 'PaaS' },
  { pattern: /^(incap_ses|visid_incap)/i, name: 'Imperva Incapsula', category: 'CDN / Security' },
  { pattern: /^_shopify/i, name: 'Shopify', category: 'E-commerce' }
];

function parseServerSoftware(value) {
  const results = [];
  if (!value) return results;
  const productMap = [
    [/^apache$/i, 'Apache HTTP Server', 'Web server'],
    [/^nginx$/i, 'nginx', 'Web server'],
    [/^openresty$/i, 'OpenResty', 'Web server'],
    [/^microsoft-iis$/i, 'Microsoft IIS', 'Web server'],
    [/^litespeed$/i, 'LiteSpeed', 'Web server'],
    [/^openssl$/i, 'OpenSSL', 'TLS library'],
    [/^php$/i, 'PHP', 'Programming language'],
    [/^gunicorn$/i, 'Gunicorn', 'Web server'],
    [/^caddy$/i, 'Caddy', 'Web server'],
    [/^kestrel$/i, 'Kestrel', 'Web server'],
    [/^envoy$/i, 'Envoy', 'Proxy'],
    [/^cloudflare$/i, 'Cloudflare', 'CDN / Security'],
    [/^amazons3$/i, 'Amazon S3', 'Storage'],
    [/^github\.com$/i, 'GitHub Pages', 'Hosting'],
    [/^vercel$/i, 'Vercel', 'Hosting'],
    [/^netlify$/i, 'Netlify', 'Hosting'],
    [/^gws$/i, 'Google Web Server', 'Web server'],
    [/^tengine$/i, 'Tengine', 'Web server'],
    [/^jetty$/i, 'Jetty', 'Web server'],
    [/^tomcat|apache-coyote$/i, 'Apache Tomcat', 'Web server'],
    [/^express$/i, 'Express', 'Web framework'],
    [/^asp\.net$/i, 'ASP.NET', 'Web framework'],
    [/^next\.js$/i, 'Next.js', 'JavaScript framework'],
    [/^nuxt$/i, 'Nuxt', 'JavaScript framework'],
    [/^wordpress$/i, 'WordPress', 'CMS'],
    [/^drupal$/i, 'Drupal', 'CMS'],
    [/^varnish$/i, 'Varnish', 'Cache']
  ];
  const tokenRegex = /([A-Za-z][A-Za-z0-9._-]*)(?:\/([0-9][0-9A-Za-z._-]*))?/g;
  let m;
  while ((m = tokenRegex.exec(value)) !== null) {
    const [, product, version] = m;
    const entry = productMap.find(([re]) => re.test(product));
    if (entry) results.push({ name: entry[1], category: entry[2], version: version ? (/^\d+(?:\.\d+)*[a-z]?/i.exec(version)?.[0] || version) : null, rawVersion: version || null });
  }
  return results;
}

function fingerprintTechnologies({ headers, html, cookies, runtimeLibraries, renderedRequests }) {
  const techs = new Map();
  const add = (name, category, version, source, evidence) => {
    const existing = techs.get(name);
    if (existing) {
      if (!existing.version && version) existing.version = version;
      if (!existing.sources.includes(source)) existing.sources.push(source);
      if (evidence && existing.evidence.length < 3 && !existing.evidence.includes(evidence)) existing.evidence.push(evidence);
      return;
    }
    techs.set(name, { name, category, version: version || null, sources: [source], evidence: evidence ? [evidence] : [] });
  };

  // Headers
  for (const t of parseServerSoftware(headers.get('server'))) add(t.name, t.category, t.version, 'header', `Server: ${headers.get('server')}`);
  for (const t of parseServerSoftware(headers.get('x-powered-by'))) add(t.name, t.category, t.version, 'header', `X-Powered-By: ${headers.get('x-powered-by')}`);
  if (headers.get('x-aspnet-version')) add('ASP.NET', 'Web framework', headers.get('x-aspnet-version'), 'header', `X-AspNet-Version: ${headers.get('x-aspnet-version')}`);
  if (headers.get('x-aspnetmvc-version')) add('ASP.NET MVC', 'Web framework', headers.get('x-aspnetmvc-version'), 'header', `X-AspNetMvc-Version: ${headers.get('x-aspnetmvc-version')}`);
  if (headers.get('x-drupal-cache') || headers.get('x-drupal-dynamic-cache')) add('Drupal', 'CMS', null, 'header', 'X-Drupal-Cache');
  if (headers.get('x-shopify-stage') || headers.get('x-shopid')) add('Shopify', 'E-commerce', null, 'header', 'X-Shopify-Stage');
  if (headers.get('x-wix-request-id')) add('Wix', 'Website builder', null, 'header', 'X-Wix-Request-Id');
  if (headers.get('x-pingback') || /wp-json/.test(headers.get('link') || '')) add('WordPress', 'CMS', null, 'header', 'X-Pingback / wp-json link');
  if (headers.get('x-litespeed-cache')) add('LiteSpeed Cache', 'Cache', null, 'header', 'X-LiteSpeed-Cache');
  if (headers.get('x-varnish')) add('Varnish', 'Cache', null, 'header', 'X-Varnish');
  if (headers.get('x-nextjs-cache') || headers.get('x-nextjs-prerender')) add('Next.js', 'JavaScript framework', null, 'header', 'X-Nextjs-Cache');
  const generatorHeader = headers.get('x-generator');
  if (generatorHeader) add(generatorHeader.split(/\s+/)[0], 'CMS', /\d+(\.\d+)+/.exec(generatorHeader)?.[0], 'header', `X-Generator: ${generatorHeader}`);

  // Cookies
  for (const cookie of cookies) {
    const fp = COOKIE_FINGERPRINTS.find((f) => f.pattern.test(cookie.name));
    if (fp) add(fp.name, fp.category, null, 'cookie', `Cookie: ${cookie.name}`);
  }

  // HTML
  if (html) {
    const generators = [...html.matchAll(/<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/gi), ...html.matchAll(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/gi)];
    for (const g of generators) {
      const content = g[1];
      const version = /(\d+(?:\.\d+)+)/.exec(content)?.[1] || null;
      const name = content.replace(/\s*v?\d+(\.\d+)+.*$/, '').trim() || content;
      add(name, 'CMS / Generator', version, 'html', `meta generator: ${content}`);
    }

    for (const fp of HTML_FINGERPRINTS) {
      if (fp.pattern.test(html)) add(fp.name, fp.category, null, 'html', fp.pattern.source.substring(0, 60));
    }

    const ngVersion = /ng-version="([\d.]+)"/.exec(html)?.[1];
    if (ngVersion) add('Angular', 'JavaScript framework', ngVersion, 'html', `ng-version="${ngVersion}"`);

    for (const asset of extractAssetUrls(html)) {
      const lib = identifyAssetUrl(asset);
      if (lib) add(lib.name, lib.category, lib.version, 'html', asset.length > 120 ? `${asset.substring(0, 120)}…` : asset);
    }
  }

  // Rendered page (browser runtime)
  for (const [name, version] of Object.entries(runtimeLibraries || {})) {
    const lib = RUNTIME_LIBRARY_NAMES[name] || { name, category: 'JavaScript library' };
    add(lib.name, lib.category, typeof version === 'string' && /^\d/.test(version) ? version : null, 'runtime', `window global: ${name}`);
  }
  for (const req of renderedRequests || []) {
    if (req.type !== 'script' && req.type !== 'stylesheet') continue;
    const lib = identifyAssetUrl(req.url);
    if (lib) add(lib.name, lib.category, lib.version, 'network', req.url.length > 120 ? `${req.url.substring(0, 120)}…` : req.url);
  }

  return [...techs.values()].map((t) => ({ ...t, vulnerabilities: matchVulnerabilities(t.name, t.version) }))
    .sort((a, b) => (b.vulnerabilities.length - a.vulnerabilities.length) || a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
}

const RUNTIME_LIBRARY_NAMES = {
  jQuery: { name: 'jQuery', category: 'JavaScript library' },
  jQueryUI: { name: 'jQuery UI', category: 'JavaScript library' },
  React: { name: 'React', category: 'JavaScript framework' },
  Vue: { name: 'Vue', category: 'JavaScript framework' },
  Angular: { name: 'Angular', category: 'JavaScript framework' },
  AngularJS: { name: 'AngularJS', category: 'JavaScript framework' },
  NextJS: { name: 'Next.js', category: 'JavaScript framework' },
  Nuxt: { name: 'Nuxt', category: 'JavaScript framework' },
  Lodash: { name: 'Lodash', category: 'JavaScript library' },
  Underscore: { name: 'Underscore', category: 'JavaScript library' },
  Moment: { name: 'Moment.js', category: 'JavaScript library' },
  Bootstrap: { name: 'Bootstrap', category: 'UI framework' },
  Modernizr: { name: 'Modernizr', category: 'JavaScript library' },
  D3: { name: 'D3', category: 'JavaScript library' },
  Handlebars: { name: 'Handlebars', category: 'JavaScript library' },
  Ember: { name: 'Ember.js', category: 'JavaScript framework' },
  Backbone: { name: 'Backbone.js', category: 'JavaScript framework' },
  Knockout: { name: 'Knockout', category: 'JavaScript framework' },
  Prototype: { name: 'Prototype', category: 'JavaScript library' },
  MooTools: { name: 'MooTools', category: 'JavaScript library' },
  DOMPurify: { name: 'DOMPurify', category: 'JavaScript library' },
  Alpine: { name: 'Alpine.js', category: 'JavaScript framework' },
  htmx: { name: 'htmx', category: 'JavaScript library' },
  Gatsby: { name: 'Gatsby', category: 'Static site generator' },
  Blazor: { name: 'Blazor', category: 'Web framework' },
  WordPress: { name: 'WordPress', category: 'CMS' },
  Shopify: { name: 'Shopify', category: 'E-commerce' },
  GoogleTagManager: { name: 'Google Tag Manager', category: 'Analytics' }
};

function extractAssetUrls(html) {
  const urls = [];
  const re = /<(?:script|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = re.exec(html)) !== null && urls.length < 300) urls.push(m[1]);
  return urls;
}

function analyzeContent(html, pageUrl) {
  if (!html) return { title: null, scripts: { total: 0, external: 0, withoutSri: [] }, mixedContent: [], insecureForms: [], thirdPartyScriptHosts: [] };

  const page = new URL(pageUrl);
  const pageDomain = getRegistrableDomain(page.hostname);
  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1]?.replace(/\s+/g, ' ').trim().substring(0, 200) || null;

  const scripts = [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1]);
  const external = [];
  const withoutSri = [];
  const thirdPartyHosts = new Set();
  const mixedContent = [];

  for (const attrs of scripts) {
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1];
    if (!src) continue;
    let abs;
    try {
      abs = new URL(src, page);
    } catch {
      continue;
    }
    external.push(abs.href);
    const isThirdParty = getRegistrableDomain(abs.hostname) !== pageDomain;
    if (isThirdParty) {
      thirdPartyHosts.add(abs.hostname);
      if (!/\bintegrity\s*=/i.test(attrs)) withoutSri.push(abs.href);
    }
    if (page.protocol === 'https:' && abs.protocol === 'http:') mixedContent.push(abs.href);
  }

  if (page.protocol === 'https:') {
    for (const m of html.matchAll(/<(?:link|img|iframe|source|video|audio)\b[^>]*?\b(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)) {
      if (mixedContent.length < 20) mixedContent.push(m[1]);
    }
  }

  const insecureForms = [...html.matchAll(/<form\b[^>]*\baction\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]).slice(0, 10);
  const hasPasswordField = /<input\b[^>]*type\s*=\s*["']password["']/i.test(html);

  return {
    title,
    scripts: { total: scripts.length, external: external.length, withoutSri: withoutSri.slice(0, 20) },
    mixedContent: [...new Set(mixedContent)].slice(0, 20),
    insecureForms,
    hasPasswordField,
    thirdPartyScriptHosts: [...thirdPartyHosts].slice(0, 40)
  };
}

// ---------------------------------------------------------------------------
// CDN detection
// ---------------------------------------------------------------------------

const CDN_SIGNATURES = [
  { name: 'Cloudflare', headers: ['cf-ray', 'cf-cache-status'], server: /cloudflare/i, cname: /cdn\.cloudflare\.net$|cloudflare/, asn: /cloudflare/i },
  { name: 'Amazon CloudFront', headers: ['x-amz-cf-id', 'x-amz-cf-pop'], server: /cloudfront/i, cname: /cloudfront\.net$/, via: /cloudfront/i },
  { name: 'Fastly', headers: ['x-fastly-request-id'], cname: /fastly(lb)?\.net$|fastly/, via: /varnish/i, servedBy: /cache-/i, asn: /fastly/i },
  { name: 'Akamai', headers: ['x-akamai-transformed', 'x-akamai-request-id', 'akamai-grn'], server: /akamai/i, cname: /akamai(edge|hd|technologies)?\.net$|edgekey\.net$|edgesuite\.net$|akamaized\.net$/, asn: /akamai/i },
  { name: 'Azure Front Door / Azure CDN', headers: ['x-azure-ref', 'x-fd-healthprobe'], cname: /azurefd\.net$|azureedge\.net$|trafficmanager\.net$|msecnd\.net$/ },
  { name: 'Google Cloud CDN', server: /^(gws|Google Frontend)$/i, via: /google/i, cname: /googlehosted\.com$|ghs\.google/ },
  { name: 'Vercel', headers: ['x-vercel-id', 'x-vercel-cache'], server: /vercel/i, cname: /vercel-dns\.com$|vercel\.app$/ },
  { name: 'Netlify', headers: ['x-nf-request-id'], server: /netlify/i, cname: /netlify(globalcdn)?\.(com|app)$/ },
  { name: 'Bunny CDN', server: /bunnycdn/i, cname: /b-cdn\.net$/ },
  { name: 'Imperva Incapsula', headers: ['x-iinfo'], cname: /incapdns\.net$/, cdnHeader: /incapsula/i },
  { name: 'Sucuri', headers: ['x-sucuri-id'], server: /sucuri/i },
  { name: 'StackPath / Highwinds', headers: ['x-hw'], cname: /stackpathdns\.com$|hwcdn\.net$/ },
  { name: 'Edgio / Edgecast', server: /^ECS|^ECAcc/i, cname: /edgecastcdn\.net$|systemcdn\.net$/ },
  { name: 'GitHub / GitHub Pages', headers: ['x-github-request-id'], server: /github\.com/i, cname: /github\.io$/ },
  { name: 'Fly.io', headers: ['fly-request-id'], server: /fly\/?/i, cname: /fly\.dev$/ },
  { name: 'KeyCDN', server: /keycdn/i, cname: /kxcdn\.com$/ },
  { name: 'CDN77', server: /cdn77/i, cname: /cdn77\.org$/ }
];

function detectCdn(headers, cnames, asnNames) {
  const providers = [];
  const server = headers?.get('server') || '';
  const via = headers?.get('via') || '';
  const servedBy = headers?.get('x-served-by') || '';
  const cdnHeader = headers?.get('x-cdn') || '';

  for (const sig of CDN_SIGNATURES) {
    const evidence = [];
    for (const h of sig.headers || []) if (headers?.get(h)) evidence.push(`header ${h}`);
    if (sig.server && sig.server.test(server)) evidence.push(`Server: ${server}`);
    if (sig.via && sig.via.test(via)) evidence.push(`Via: ${via}`);
    if (sig.servedBy && sig.servedBy.test(servedBy)) evidence.push(`X-Served-By: ${servedBy}`);
    if (sig.cdnHeader && sig.cdnHeader.test(cdnHeader)) evidence.push(`X-CDN: ${cdnHeader}`);
    for (const c of cnames || []) if (sig.cname && sig.cname.test(c)) evidence.push(`CNAME ${c}`);
    for (const a of asnNames || []) if (sig.asn && a && sig.asn.test(a)) evidence.push(`ASN ${a}`);
    if (evidence.length) providers.push({ name: sig.name, evidence: [...new Set(evidence)] });
  }

  return {
    detected: providers.length > 0,
    providers,
    cacheStatus: headers?.get('cf-cache-status') || headers?.get('x-cache') || headers?.get('x-vercel-cache') || null
  };
}

// ---------------------------------------------------------------------------
// TLS probing (raw ClientHello over cloudflare:sockets)
// ---------------------------------------------------------------------------

const TLS_VERSION_CODES = { tls1_0: 0x0301, tls1_1: 0x0302, tls1_2: 0x0303, tls1_3: 0x0304 };
const TLS_VERSION_NAMES = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';

const CIPHER_NAMES = {
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256', 0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256', 0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
  0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305', 0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
  0xc023: 'ECDHE-ECDSA-AES128-SHA256', 0xc024: 'ECDHE-ECDSA-AES256-SHA384',
  0xc027: 'ECDHE-RSA-AES128-SHA256', 0xc028: 'ECDHE-RSA-AES256-SHA384',
  0xc009: 'ECDHE-ECDSA-AES128-SHA', 0xc00a: 'ECDHE-ECDSA-AES256-SHA',
  0xc013: 'ECDHE-RSA-AES128-SHA', 0xc014: 'ECDHE-RSA-AES256-SHA',
  0x0033: 'DHE-RSA-AES128-SHA', 0x0039: 'DHE-RSA-AES256-SHA',
  0x009c: 'AES128-GCM-SHA256', 0x009d: 'AES256-GCM-SHA384', 0x003c: 'AES128-SHA256', 0x003d: 'AES256-SHA256',
  0x002f: 'AES128-SHA', 0x0035: 'AES256-SHA', 0x000a: 'DES-CBC3-SHA'
};

const TLS12_CIPHERS = [0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc023, 0xc027, 0xc024, 0xc028, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x003c, 0x003d, 0x002f, 0x0035, 0x000a, 0x00ff];
const LEGACY_CIPHERS = [0xc009, 0xc013, 0xc00a, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035, 0x000a, 0x00ff];
const TLS13_CIPHERS = [0x1301, 0x1302, 0x1303, ...TLS12_CIPHERS.slice(0, 6)];

const u8 = (n) => [n & 0xff];
const u16 = (n) => [(n >> 8) & 0xff, n & 0xff];
const u24 = (n) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
const withU8Len = (bytes) => [...u8(bytes.length), ...bytes];
const withU16Len = (bytes) => [...u16(bytes.length), ...bytes];
const extension = (type, data) => [...u16(type), ...withU16Len(data)];

export function buildClientHello(hostname, versionKey) {
  const isTls13 = versionKey === 'tls1_3';
  const clientVersion = isTls13 ? 0x0303 : TLS_VERSION_CODES[versionKey];
  const random = [...crypto.getRandomValues(new Uint8Array(32))];
  const sessionId = isTls13 ? [...crypto.getRandomValues(new Uint8Array(32))] : [];
  const ciphers = isTls13 ? TLS13_CIPHERS : versionKey === 'tls1_2' ? TLS12_CIPHERS : LEGACY_CIPHERS;

  const nameBytes = [...new TextEncoder().encode(hostname)];
  const extensions = [];
  if (!isIpLiteral(hostname)) {
    extensions.push(...extension(0x0000, withU16Len([0x00, ...withU16Len(nameBytes)])));
  }
  extensions.push(...extension(0x000a, withU16Len([...u16(0x001d), ...u16(0x0017), ...u16(0x0018)]))); // supported_groups
  extensions.push(...extension(0x000b, withU8Len([0x00]))); // ec_point_formats
  if (versionKey === 'tls1_2' || isTls13) {
    const sigAlgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201, 0x0203];
    extensions.push(...extension(0x000d, withU16Len(sigAlgs.flatMap(u16))));
    const alpn = ['h2', 'http/1.1'].flatMap((p) => withU8Len([...new TextEncoder().encode(p)]));
    extensions.push(...extension(0x0010, withU16Len(alpn)));
  }
  if (isTls13) {
    extensions.push(...extension(0x002b, withU8Len(u16(0x0304)))); // supported_versions: TLS 1.3 only
    const keyShare = [...u16(0x001d), ...withU16Len([...crypto.getRandomValues(new Uint8Array(32))])];
    extensions.push(...extension(0x0033, withU16Len(keyShare))); // key_share (x25519)
    extensions.push(...extension(0x002d, withU8Len([0x01]))); // psk_key_exchange_modes
  }
  extensions.push(...extension(0xff01, [0x00])); // renegotiation_info

  const body = [
    ...u16(clientVersion),
    ...random,
    ...withU8Len(sessionId),
    ...withU16Len(ciphers.flatMap(u16)),
    ...withU8Len([0x00]), // compression: null
    ...withU16Len(extensions)
  ];
  const handshake = [0x01, ...u24(body.length), ...body];
  return new Uint8Array([0x16, ...u16(0x0301), ...u16(handshake.length), ...handshake]);
}

function parseServerHello(body) {
  let p = 0;
  const legacyVersion = (body[p] << 8) | body[p + 1];
  p += 2;
  const random = [...body.subarray(p, p + 32)].map((b) => b.toString(16).padStart(2, '0')).join('');
  p += 32;
  const sidLen = body[p];
  p += 1 + sidLen;
  const cipher = (body[p] << 8) | body[p + 1];
  p += 3; // cipher + compression
  let selectedVersion = null;
  let alpn = null;
  if (p + 2 <= body.length) {
    const extEnd = p + 2 + ((body[p] << 8) | body[p + 1]);
    p += 2;
    while (p + 4 <= extEnd) {
      const type = (body[p] << 8) | body[p + 1];
      const len = (body[p + 2] << 8) | body[p + 3];
      const data = body.subarray(p + 4, p + 4 + len);
      if (type === 0x002b && len >= 2) selectedVersion = (data[0] << 8) | data[1];
      if (type === 0x0010 && len >= 3) alpn = new TextDecoder().decode(data.subarray(3, 3 + data[2]));
      p += 4 + len;
    }
  }
  return {
    version: selectedVersion || legacyVersion,
    cipher,
    alpn,
    helloRetryRequest: random === HRR_RANDOM
  };
}

function parseCertificateMessage(body) {
  const certs = [];
  let p = 3; // total length (u24)
  while (p + 3 <= body.length && certs.length < 6) {
    const len = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
    p += 3;
    certs.push(body.slice(p, p + len));
    p += len;
  }
  return certs;
}

async function tlsHandshakeProbe(connect, hostname, port, versionKey) {
  // Hard cap covering the TCP connect too: a filtered port can otherwise hang until the OS connect timeout
  let socket;
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      try { socket?.close(); } catch { /* ignore */ }
      resolve({ version: versionKey, supported: false, error: `No TLS response on port ${port} within ${SCAN_LIMITS.tlsTimeoutMs / 1000}s (port closed or filtered)` });
    }, SCAN_LIMITS.tlsTimeoutMs);
  });
  const probe = runTlsHandshakeProbe(connect, hostname, port, versionKey, (s) => { socket = s; });
  try {
    return await Promise.race([probe, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function runTlsHandshakeProbe(connect, hostname, port, versionKey, onSocket) {
  const result = { version: versionKey, supported: false };
  let socket;
  try {
    socket = connect({ hostname, port }, { secureTransport: 'off', allowHalfOpen: false });
    onSocket(socket);
    const writer = socket.writable.getWriter();
    await writer.write(buildClientHello(hostname, versionKey));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const deadline = Date.now() + SCAN_LIMITS.tlsTimeoutMs;
    let recordBuf = new Uint8Array(0);
    let handshakeBuf = new Uint8Array(0);
    let received = 0;
    let done = false;

    while (!done) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('TLS handshake timed out');
      let timer;
      const chunk = await Promise.race([
        reader.read(),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('TLS handshake timed out')), remaining); })
      ]).finally(() => clearTimeout(timer));
      if (chunk.done) break;
      received += chunk.value.length;
      if (received > 262_144) break;
      recordBuf = concatBytes(recordBuf, chunk.value);

      while (recordBuf.length >= 5 && !done) {
        const type = recordBuf[0];
        const len = (recordBuf[3] << 8) | recordBuf[4];
        if (recordBuf.length < 5 + len) break;
        const payload = recordBuf.subarray(5, 5 + len);
        recordBuf = recordBuf.slice(5 + len);

        if (type === 0x15) {
          result.alert = { level: payload[0], description: payload[1] };
          done = true;
        } else if (type === 0x16) {
          handshakeBuf = concatBytes(handshakeBuf, payload);
          while (handshakeBuf.length >= 4 && !done) {
            const msgType = handshakeBuf[0];
            const msgLen = (handshakeBuf[1] << 16) | (handshakeBuf[2] << 8) | handshakeBuf[3];
            if (handshakeBuf.length < 4 + msgLen) break;
            const msg = handshakeBuf.subarray(4, 4 + msgLen);
            handshakeBuf = handshakeBuf.slice(4 + msgLen);
            if (msgType === 2) {
              const hello = parseServerHello(msg);
              result.negotiatedVersion = TLS_VERSION_NAMES[hello.version] || `0x${hello.version.toString(16)}`;
              result.supported = hello.version === TLS_VERSION_CODES[versionKey];
              result.cipherSuite = CIPHER_NAMES[hello.cipher] || `0x${hello.cipher.toString(16).padStart(4, '0')}`;
              result.alpn = hello.alpn;
              result.helloRetryRequest = hello.helloRetryRequest;
              if (hello.version === 0x0304 || !result.supported) done = true; // rest of TLS 1.3 handshake is encrypted
            } else if (msgType === 11) {
              result.certificates = parseCertificateMessage(msg);
              done = true;
            } else if (msgType === 14) {
              done = true;
            }
          }
        } else {
          done = true; // ChangeCipherSpec / application data
        }
      }
    }
    try { reader.releaseLock(); } catch { /* ignore */ }
    if (!result.negotiatedVersion && !result.alert) result.error = 'Connection closed without a ServerHello';
  } catch (error) {
    result.error = error.message;
  } finally {
    try { await socket?.close(); } catch { /* ignore */ }
  }
  return result;
}

async function probeTls(connect, hostname, port) {
  if (!connect) {
    return { probed: false, error: 'Raw socket support (cloudflare:sockets) is not available in this runtime' };
  }

  const keys = ['tls1_3', 'tls1_2', 'tls1_1', 'tls1_0'];
  const probes = await Promise.all(keys.map((k) => tlsHandshakeProbe(connect, hostname, port, k)));
  const byKey = Object.fromEntries(keys.map((k, i) => [k, probes[i]]));

  const anyResponse = probes.some((p) => p.negotiatedVersion || p.alert);
  if (!anyResponse) {
    const err = probes.find((p) => p.error)?.error || `No TLS response on port ${port}`;
    const blocked = /proxy request failed|cannot connect to the specified address|Cloudflare/i.test(err);
    return {
      probed: false,
      error: blocked
        ? 'Target resolves to Cloudflare IP space; Workers sockets cannot connect to Cloudflare-proxied hosts, so TLS versions could not be probed directly'
        : err
    };
  }

  const certSource = byKey.tls1_2.certificates?.length ? byKey.tls1_2 : byKey.tls1_1.certificates?.length ? byKey.tls1_1 : byKey.tls1_0;
  let certificate = null;
  let chain = [];
  if (certSource?.certificates?.length) {
    try {
      chain = certSource.certificates.map(parseX509);
      certificate = { ...chain[0], hostnameMatch: certificateMatchesHost(chain[0], hostname), chainLength: chain.length };
    } catch (error) {
      certificate = { error: `Failed to parse certificate: ${error.message}` };
    }
  }

  return {
    probed: true,
    versions: Object.fromEntries(keys.map((k) => [k, byKey[k].supported])),
    preferredCipher: byKey.tls1_3.supported ? byKey.tls1_3.cipherSuite : byKey.tls1_2.cipherSuite || null,
    tls12Cipher: byKey.tls1_2.supported ? byKey.tls1_2.cipherSuite : null,
    alpn: byKey.tls1_2.alpn || null,
    certificate,
    chain: chain.slice(1).map((c) => ({ subject: c.subject?.CN || c.subjectString, issuer: c.issuer?.CN || c.issuerString, validTo: c.validTo })),
    certificateNote: certificate ? null : 'Server only accepts TLS 1.3, where the certificate is encrypted; certificate details unavailable from the probe',
    probes: probes.map((p) => ({ version: p.version, supported: p.supported, negotiated: p.negotiatedVersion || null, cipher: p.cipherSuite || null, alert: p.alert ? TLS_ALERTS[p.alert.description] || `alert ${p.alert.description}` : null, error: p.error || null }))
  };
}

const TLS_ALERTS = { 40: 'handshake_failure', 47: 'illegal_parameter', 50: 'decode_error', 70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback', 112: 'unrecognized_name' };

// ---------------------------------------------------------------------------
// Minimal X.509 DER parser
// ---------------------------------------------------------------------------

function derRead(bytes, pos) {
  const tag = bytes[pos];
  let len = bytes[pos + 1];
  let header = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[pos + 2 + i];
    header = 2 + n;
  }
  const start = pos + header;
  if (start + len > bytes.length) throw new Error('DER length out of range');
  return { tag, start, end: start + len };
}

function derChildren(bytes, node) {
  const out = [];
  let p = node.start;
  while (p < node.end) {
    const child = derRead(bytes, p);
    out.push(child);
    p = child.end;
  }
  return out;
}

function derOid(bytes, node) {
  const b = bytes.subarray(node.start, node.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let value = 0;
  for (let i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function derString(bytes, node) {
  const b = bytes.subarray(node.start, node.end);
  if (node.tag === 0x1e) {
    let s = '';
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
    return s;
  }
  return new TextDecoder('utf-8').decode(b);
}

function derTime(bytes, node) {
  const s = derString(bytes, node);
  let y;
  let rest;
  if (node.tag === 0x17) {
    const yy = parseInt(s.substring(0, 2), 10);
    y = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = s.substring(2);
  } else {
    y = parseInt(s.substring(0, 4), 10);
    rest = s.substring(4);
  }
  const [mo, d, h, mi, se] = [0, 2, 4, 6, 8].map((i) => parseInt(rest.substring(i, i + 2) || '0', 10));
  return new Date(Date.UTC(y, mo - 1, d, h, mi, se)).toISOString();
}

const NAME_OIDS = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST' };
const SIG_ALG_OIDS = {
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512', '1.3.101.112': 'Ed25519'
};
const CURVE_OIDS = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521' };

function parseName(bytes, node) {
  const attrs = {};
  const parts = [];
  for (const set of derChildren(bytes, node)) {
    for (const seq of derChildren(bytes, set)) {
      const [oidNode, valueNode] = derChildren(bytes, seq);
      const key = NAME_OIDS[derOid(bytes, oidNode)];
      if (!key) continue;
      const value = derString(bytes, valueNode);
      if (!attrs[key]) attrs[key] = value;
      parts.push(`${key}=${value}`);
    }
  }
  return { attrs, string: parts.join(', ') };
}

export function parseX509(der) {
  const cert = derRead(der, 0);
  const [tbs, sigAlg] = derChildren(der, cert);
  const tbsParts = derChildren(der, tbs);
  let i = 0;
  if (tbsParts[0].tag === 0xa0) i++; // explicit version
  const serialNode = tbsParts[i++];
  i++; // signature algorithm (inner)
  const issuer = parseName(der, tbsParts[i++]);
  const [notBefore, notAfter] = derChildren(der, tbsParts[i++]);
  const subject = parseName(der, tbsParts[i++]);
  const spki = tbsParts[i++];

  // Public key
  const [algSeq, bitString] = derChildren(der, spki);
  const [algOidNode, algParam] = derChildren(der, algSeq);
  const keyOid = derOid(der, algOidNode);
  let keyAlgorithm = keyOid;
  let keySize = null;
  if (keyOid === '1.2.840.113549.1.1.1') {
    keyAlgorithm = 'RSA';
    const rsaSeq = derRead(der, bitString.start + 1);
    const modulus = derChildren(der, rsaSeq)[0];
    let first = modulus.start;
    while (der[first] === 0 && first < modulus.end) first++;
    keySize = (modulus.end - first) * 8 - Math.clz32(der[first]) + 24;
  } else if (keyOid === '1.2.840.10045.2.1') {
    const curve = algParam && algParam.tag === 0x06 ? CURVE_OIDS[derOid(der, algParam)] : null;
    keyAlgorithm = `EC${curve ? ` (${curve})` : ''}`;
    keySize = curve ? parseInt(curve.substring(2), 10) : null;
  } else if (keyOid === '1.3.101.112') {
    keyAlgorithm = 'Ed25519';
    keySize = 256;
  }

  // Extensions: subjectAltName
  const sans = [];
  for (const part of tbsParts.slice(i)) {
    if (part.tag !== 0xa3) continue;
    const extSeq = derChildren(der, part)[0];
    for (const ext of derChildren(der, extSeq)) {
      const extParts = derChildren(der, ext);
      if (derOid(der, extParts[0]) !== '2.5.29.17') continue;
      const octet = extParts[extParts.length - 1];
      const sanSeq = derRead(der, octet.start);
      for (const name of derChildren(der, sanSeq)) {
        if (name.tag === 0x82) sans.push(new TextDecoder().decode(der.subarray(name.start, name.end)));
        if (name.tag === 0x87 && name.end - name.start === 4) sans.push([...der.subarray(name.start, name.end)].join('.'));
      }
    }
  }

  const validFrom = derTime(der, notBefore);
  const validTo = derTime(der, notAfter);
  const now = Date.now();
  return {
    subject: subject.attrs,
    subjectString: subject.string,
    issuer: issuer.attrs,
    issuerString: issuer.string,
    serialNumber: [...der.subarray(serialNode.start, serialNode.end)].map((b) => b.toString(16).padStart(2, '0')).join(':'),
    validFrom,
    validTo,
    daysRemaining: Math.floor((new Date(validTo).getTime() - now) / 86_400_000),
    expired: new Date(validTo).getTime() < now,
    notYetValid: new Date(validFrom).getTime() > now,
    signatureAlgorithm: SIG_ALG_OIDS[derOid(der, derChildren(der, sigAlg)[0])] || derOid(der, derChildren(der, sigAlg)[0]),
    keyAlgorithm,
    keySize,
    subjectAltNames: sans.slice(0, 50),
    selfSigned: subject.string === issuer.string
  };
}

function certificateMatchesHost(cert, hostname) {
  const host = hostname.toLowerCase();
  const names = cert.subjectAltNames?.length ? cert.subjectAltNames : [cert.subject?.CN].filter(Boolean);
  return names.some((n) => {
    const name = n.toLowerCase();
    if (name === host) return true;
    if (name.startsWith('*.')) {
      const suffix = name.substring(1);
      return host.endsWith(suffix) && host.split('.').length === name.split('.').length;
    }
    return false;
  });
}

// ---------------------------------------------------------------------------
// Network: ASN + abuse score for resolved IPs
// ---------------------------------------------------------------------------

async function lookupIpIntel(ips, { radarApiUrl, radarToken, abuseApiUrl, abuseApiKey }) {
  const selected = ips.slice(0, SCAN_LIMITS.maxIpLookups);
  const firstV4 = selected.find((ip) => !ip.includes(':'));

  const radar = await Promise.all(selected.map(async (ip) => {
    if (!radarToken || radarToken.includes('WILL_BE_INJECTED')) return null;
    try {
      const res = await fetchWithTimeout(`${radarApiUrl}?ip=${encodeURIComponent(ip)}`, {
        headers: { Authorization: `Bearer ${radarToken}`, 'User-Agent': 'Albatross-Worker/1.0' },
        cf: { cacheTtl: 3600, cacheEverything: true }
      }, 5000);
      if (!res.ok) return null;
      const json = await res.json();
      return json.result?.asn || null;
    } catch {
      return null;
    }
  }));

  let abuse = null;
  if (firstV4 && abuseApiKey && !abuseApiKey.includes('WILL_BE_INJECTED')) {
    try {
      const res = await fetchWithTimeout(`${abuseApiUrl}?ipAddress=${encodeURIComponent(firstV4)}&maxAgeInDays=90`, {
        headers: { Key: abuseApiKey, Accept: 'application/json', 'User-Agent': 'Albatross-Worker/1.0' },
        cf: { cacheTtl: 300, cacheEverything: true }
      }, 5000);
      if (res.ok) abuse = (await res.json()).data || null;
    } catch { /* ignore */ }
  }

  return selected.map((ip, idx) => ({
    ip,
    version: ip.includes(':') ? 6 : 4,
    asn: radar[idx]?.asn ?? null,
    asnName: radar[idx]?.name || radar[idx]?.aka || null,
    asnOrg: radar[idx]?.orgName || null,
    country: radar[idx]?.country || (ip === firstV4 ? abuse?.countryCode : null) || null,
    ...(ip === firstV4 && abuse ? {
      abuseConfidenceScore: abuse.abuseConfidenceScore,
      abuseTotalReports: abuse.totalReports,
      isp: abuse.isp,
      usageType: abuse.usageType
    } : {})
  }));
}

// ---------------------------------------------------------------------------
// Screenshot (Cloudflare Browser Rendering)
// ---------------------------------------------------------------------------

/* Runs inside the page via page.evaluate - must be self-contained */
function detectRuntimeLibraries() {
  const r = {};
  const w = window;
  const set = (k, fn) => {
    try {
      const v = fn();
      if (v) r[k] = typeof v === 'string' ? v : 'detected';
    } catch (e) { /* ignore */ }
  };
  set('jQuery', () => w.jQuery && w.jQuery.fn && w.jQuery.fn.jquery);
  set('jQueryUI', () => w.jQuery && w.jQuery.ui && w.jQuery.ui.version);
  set('React', () => (w.React && w.React.version) || (document.querySelector('[data-reactroot]') || (w.__REACT_DEVTOOLS_GLOBAL_HOOK__ && w.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers && w.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size) ? true : null));
  set('Vue', () => (w.Vue && w.Vue.version) || (document.querySelector('[data-v-app]') && document.querySelector('[data-v-app]').__vue_app__ && document.querySelector('[data-v-app]').__vue_app__.version));
  set('Angular', () => document.querySelector('[ng-version]') && document.querySelector('[ng-version]').getAttribute('ng-version'));
  set('AngularJS', () => w.angular && w.angular.version && w.angular.version.full);
  set('NextJS', () => (w.next && w.next.version) || (w.__NEXT_DATA__ ? true : null));
  set('Nuxt', () => w.__NUXT__ || w.$nuxt ? true : null);
  set('Lodash', () => w._ && typeof w._.chunk === 'function' && w._.VERSION);
  set('Underscore', () => w._ && typeof w._.chunk !== 'function' && w._.VERSION);
  set('Moment', () => w.moment && w.moment.version);
  set('Bootstrap', () => (w.bootstrap && w.bootstrap.Tooltip && w.bootstrap.Tooltip.VERSION) || (w.jQuery && w.jQuery.fn && w.jQuery.fn.tooltip && w.jQuery.fn.tooltip.Constructor && w.jQuery.fn.tooltip.Constructor.VERSION));
  set('Modernizr', () => w.Modernizr && (w.Modernizr._version || true));
  set('D3', () => w.d3 && w.d3.version);
  set('Handlebars', () => w.Handlebars && w.Handlebars.VERSION);
  set('Ember', () => w.Ember && w.Ember.VERSION);
  set('Backbone', () => w.Backbone && w.Backbone.VERSION);
  set('Knockout', () => w.ko && w.ko.version);
  set('Prototype', () => w.Prototype && w.Prototype.Version);
  set('MooTools', () => w.MooTools && w.MooTools.version);
  set('DOMPurify', () => w.DOMPurify && w.DOMPurify.version);
  set('Alpine', () => w.Alpine && (w.Alpine.version || true));
  set('htmx', () => w.htmx && (w.htmx.version || true));
  set('Gatsby', () => w.___gatsby ? true : null);
  set('Blazor', () => w.Blazor ? true : null);
  set('WordPress', () => w.wp && w.wp.i18n ? true : null);
  set('Shopify', () => w.Shopify ? true : null);
  set('GoogleTagManager', () => w.google_tag_manager ? true : null);
  return r;
}

async function captureScreenshot(puppeteer, env, url, targetDomain) {
  if (!puppeteer || !env?.BROWSER) {
    return { success: false, error: 'Screenshot unavailable: Browser Rendering binding (BROWSER) is not configured on this worker' };
  }
  const budgetMs = SCAN_LIMITS.screenshotTimeoutMs + 15_000; // navigation + browser launch / capture overhead
  const holder = {};
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      holder.browser?.close().catch(() => {});
      resolve({ success: false, error: `Screenshot timed out after ${budgetMs / 1000}s` });
    }, budgetMs);
  });
  try {
    return await Promise.race([renderPage(puppeteer, env, url, targetDomain, holder), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function renderPage(puppeteer, env, url, targetDomain, holder) {
  let browser;
  try {
    browser = await puppeteer.launch(env.BROWSER);
    holder.browser = browser;
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    const requests = [];
    page.on('request', (req) => {
      const reqUrl = req.url();
      if (requests.length < 400 && /^https?:/i.test(reqUrl)) requests.push({ url: reqUrl, type: req.resourceType() });
    });

    let navigationWarning = null;
    try {
      await page.goto(url, { waitUntil: 'networkidle2', timeout: SCAN_LIMITS.screenshotTimeoutMs });
    } catch (error) {
      navigationWarning = error.message; // still screenshot whatever loaded
    }

    const runtimeLibraries = await page.evaluate(detectRuntimeLibraries).catch(() => ({}));
    const image = await page.screenshot({ type: 'jpeg', quality: 60, encoding: 'base64' });

    const hosts = new Map();
    for (const r of requests) {
      const host = safeHost(r.url);
      if (!host) continue;
      hosts.set(host, (hosts.get(host) || 0) + 1);
    }
    const thirdPartyHosts = [...hosts.entries()]
      .filter(([host]) => getRegistrableDomain(host) !== targetDomain)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 40)
      .map(([host, count]) => ({ host, requests: count }));

    return {
      success: true,
      image: `data:image/jpeg;base64,${image}`,
      width: 1280,
      height: 800,
      finalUrl: page.url(),
      navigationWarning,
      requestCount: requests.length,
      thirdPartyHosts,
      runtimeLibraries,
      _requests: requests
    };
  } catch (error) {
    return { success: false, error: `Screenshot failed: ${error.message}` };
  } finally {
    if (browser) {
      try { await browser.close(); } catch { /* ignore */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Findings + scoring
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHTS = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function buildFindings(report) {
  const findings = [];
  const add = (severity, category, title, detail) => findings.push({ severity, category, title, detail });

  // Redirects
  const r = report.redirects;
  if (r.httpsDowngrade) add('high', 'Redirects', 'HTTPS to HTTP downgrade in redirect chain', 'A redirect sends visitors from an encrypted URL to an unencrypted one.');
  if (r.crossDomain) add('low', 'Redirects', 'Redirects to a different domain', `Final destination: ${report.summary.finalUrl}`);
  if (r.count >= 4) add('low', 'Redirects', `Long redirect chain (${r.count} hops)`, 'Long chains slow page loads and can hide malicious hops.');
  if (r.error) add('medium', 'Redirects', 'Redirect chain could not be completed', r.error);

  // Transport
  const finalIsHttps = (report.summary.finalUrl || '').startsWith('https:');
  if (!finalIsHttps) add('high', 'Transport', 'Page is served over plain HTTP', 'Traffic to the final URL is not encrypted.');
  if (report.http.httpsEnforcement?.checked && !report.http.httpsEnforcement.enforced) {
    add('medium', 'Transport', 'HTTP is not redirected to HTTPS', `http://${report.target.hostname}/ returned ${report.http.httpsEnforcement.statusCode} without redirecting to HTTPS.`);
  }

  // TLS
  const tls = report.tls;
  if (tls.probed) {
    if (tls.versions.tls1_0) add('medium', 'TLS', 'TLS 1.0 is enabled', 'TLS 1.0 is deprecated (RFC 8996) and vulnerable to downgrade attacks.');
    if (tls.versions.tls1_1) add('medium', 'TLS', 'TLS 1.1 is enabled', 'TLS 1.1 is deprecated (RFC 8996).');
    if (!tls.versions.tls1_3) add('low', 'TLS', 'TLS 1.3 is not supported', 'TLS 1.3 offers faster handshakes and removes legacy cryptography.');
    if (!tls.versions.tls1_2 && !tls.versions.tls1_3) add('critical', 'TLS', 'No modern TLS version supported', 'Neither TLS 1.2 nor TLS 1.3 negotiated.');
    if (tls.tls12Cipher && /(-SHA$|DES|RC4|^AES)/.test(tls.tls12Cipher)) {
      add('low', 'TLS', `Weak preferred TLS 1.2 cipher: ${tls.tls12Cipher}`, 'Prefer ECDHE with AES-GCM or ChaCha20-Poly1305.');
    }
    const cert = tls.certificate;
    if (cert && !cert.error) {
      if (cert.expired) add('critical', 'Certificate', 'Certificate has expired', `Expired on ${cert.validTo}.`);
      else if (cert.daysRemaining < 14) add('medium', 'Certificate', `Certificate expires in ${cert.daysRemaining} days`, `Valid until ${cert.validTo}.`);
      if (cert.notYetValid) add('high', 'Certificate', 'Certificate is not yet valid', `Valid from ${cert.validFrom}.`);
      if (cert.selfSigned) add('high', 'Certificate', 'Self-signed certificate', 'Browsers will not trust this certificate.');
      if (cert.hostnameMatch === false) add('high', 'Certificate', 'Certificate does not match hostname', `Names: ${(cert.subjectAltNames || []).slice(0, 5).join(', ')}`);
      if (/sha1|md5/i.test(cert.signatureAlgorithm || '')) add('high', 'Certificate', `Weak signature algorithm (${cert.signatureAlgorithm})`, 'SHA-1 and MD5 signatures are broken.');
      if (cert.keyAlgorithm === 'RSA' && cert.keySize && cert.keySize < 2048) add('high', 'Certificate', `Weak RSA key (${cert.keySize} bits)`, 'RSA keys below 2048 bits are considered insecure.');
    }
  }

  // Headers
  for (const h of report.http.securityHeaders || []) {
    if (h.status === 'missing') {
      const severity = h.name === 'Strict-Transport-Security' || h.name === 'Content-Security-Policy' ? 'medium' : 'low';
      add(severity, 'Security headers', `Missing ${h.name}`, h.note);
    } else if (h.status === 'weak') {
      add('low', 'Security headers', `Weak ${h.name}`, h.note);
    }
  }
  const server = report.http.headers?.server || '';
  const poweredBy = report.http.headers?.['x-powered-by'];
  if (/\d+\.\d+/.test(server)) add('low', 'Information disclosure', 'Server header discloses version', `Server: ${server}`);
  if (poweredBy) add('low', 'Information disclosure', 'X-Powered-By header discloses technology', `X-Powered-By: ${poweredBy}`);
  if (report.http.headers?.['x-aspnet-version']) add('low', 'Information disclosure', 'X-AspNet-Version header present', report.http.headers['x-aspnet-version']);

  // Cookies
  const badCookies = (report.http.cookies || []).filter((c) => c.issues.length);
  if (badCookies.length) {
    add('low', 'Cookies', `${badCookies.length} cookie(s) missing security flags`, badCookies.slice(0, 5).map((c) => `${c.name}: ${c.issues.join(', ')}`).join('; '));
  }

  // Content
  const content = report.content;
  if (content.mixedContent?.length) add('medium', 'Content', 'Mixed content', `${content.mixedContent.length} resource(s) loaded over HTTP on an HTTPS page.`);
  if (content.insecureForms?.length) add('high', 'Content', 'Form submits to HTTP', content.insecureForms.slice(0, 3).join(', '));
  if (content.hasPasswordField && !finalIsHttps) add('critical', 'Content', 'Password field on unencrypted page', 'Credentials would be sent in clear text.');
  if (content.scripts?.withoutSri?.length) add('low', 'Content', 'Third-party scripts without Subresource Integrity', `${content.scripts.withoutSri.length} external script(s) lack an integrity attribute.`);
  if (report.securityTxt && !report.securityTxt.present) add('info', 'Disclosure', 'No security.txt', 'Publish /.well-known/security.txt (RFC 9116) so researchers can report issues.');

  // Technologies
  for (const tech of report.technologies || []) {
    for (const v of tech.vulnerabilities) {
      add(v.severity, 'Dependencies', `${tech.name} ${tech.version} is vulnerable / outdated`, `${v.note}${v.advisories.length ? ` (${v.advisories.join(', ')})` : ''}`);
    }
  }

  // Domain
  const reg = report.domain.registration;
  if (reg?.success && reg.ageDays !== null) {
    if (reg.ageDays < 30) add('high', 'Domain', `Domain registered ${reg.ageDays} day(s) ago`, 'Newly registered domains are frequently used for phishing and malware.');
    else if (reg.ageDays < 180) add('medium', 'Domain', `Domain is young (${reg.ageDays} days)`, 'Domains under six months old carry elevated risk.');
  }
  if (reg?.success && reg.daysUntilExpiry !== null && reg.daysUntilExpiry < 30) add('low', 'Domain', `Domain expires in ${reg.daysUntilExpiry} day(s)`, reg.expires);
  const dns = report.domain.dns;
  if (dns && !dns.skipped) {
    if (!dns.dmarc) add('low', 'Email security', 'No DMARC record', `_dmarc.${report.target.registrableDomain} has no v=DMARC1 TXT record.`);
    else if (/p=none/i.test(dns.dmarc)) add('info', 'Email security', 'DMARC policy is p=none', 'Spoofed mail is reported but not rejected.');
    if (!dns.spf) add('low', 'Email security', 'No SPF record', 'The domain does not publish an SPF policy.');
    else if (/\+all/i.test(dns.spf)) add('high', 'Email security', 'SPF allows any sender (+all)', dns.spf);
    if (dns.dnssec === false) add('info', 'DNS', 'DNSSEC not validated', 'DNS answers for this host are not DNSSEC-signed.');
    if (!dns.caa?.length) add('info', 'DNS', 'No CAA record', 'Any certificate authority may issue certificates for this domain.');
  }

  // Network reputation
  for (const ip of report.network.ips || []) {
    if (typeof ip.abuseConfidenceScore === 'number' && ip.abuseConfidenceScore >= 50) {
      add(ip.abuseConfidenceScore >= 80 ? 'high' : 'medium', 'Reputation', `Hosting IP ${ip.ip} has abuse score ${ip.abuseConfidenceScore}%`, `${ip.abuseTotalReports} AbuseIPDB report(s).`);
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  return findings;
}

function scoreFindings(findings) {
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] || 0), 0);
  const securityScore = Math.max(0, 100 - penalty);
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const riskLevel = counts.critical > 0 || securityScore < 25 ? 'critical'
    : counts.high > 0 || securityScore < 50 ? 'high'
      : securityScore < 75 ? 'medium' : 'low';
  return { securityScore, riskLevel, counts };
}

// ---------------------------------------------------------------------------
// Optional AI assessment
// ---------------------------------------------------------------------------

async function runAiAssessment(env, model, report) {
  if (!env?.AI) return { success: false, error: 'AI service not available', analysis: null };
  const compact = {
    url: report.target.url,
    finalUrl: report.summary.finalUrl,
    redirects: report.redirects.chain.map((h) => `${h.statusCode} ${h.url}`),
    tls: report.tls.probed ? report.tls.versions : report.tls.error,
    certificate: report.tls.certificate ? { issuer: report.tls.certificate.issuer?.O || report.tls.certificate.issuer?.CN, daysRemaining: report.tls.certificate.daysRemaining } : null,
    domainAgeDays: report.domain.registration?.ageDays ?? null,
    registrar: report.domain.registration?.registrar ?? null,
    cdn: report.network.cdn.providers.map((p) => p.name),
    hosting: report.network.ips.map((i) => `${i.ip} AS${i.asn ?? '?'} ${i.asnName ?? ''}`),
    technologies: report.technologies.slice(0, 25).map((t) => `${t.name}${t.version ? ` ${t.version}` : ''}`),
    findings: report.findings.slice(0, 25).map((f) => `[${f.severity}] ${f.title}`),
    pageTitle: report.content.title
  };

  const prompt = `You are a web application security analyst. Assess this passive URL scan and respond ONLY with JSON:
{
  "riskLevel": "low|medium|high|critical",
  "securityScore": <0-100, higher is safer>,
  "summary": "<2-3 sentence overall assessment>",
  "phishingLikelihood": "low|medium|high",
  "keyRisks": ["<risk>", "..."],
  "recommendations": ["<action>", "..."]
}
Consider domain age, redirects, TLS posture, outdated dependencies, missing security headers and hosting reputation. Do not invent facts not present in the data.

Scan data:
${JSON.stringify(compact)}`;

  try {
    const response = await env.AI.run(model, {
      messages: [
        { role: 'system', content: 'You are a cybersecurity expert. Respond only with valid JSON, no markdown formatting or code blocks.' },
        { role: 'user', content: prompt }
      ],
      max_tokens: 900,
      temperature: 0.2
    });
    const text = response?.response ?? response?.choices?.[0]?.message?.content ?? null;
    if (!text) return { success: false, error: 'AI response was empty', analysis: null, model };
    const raw = typeof text === 'string' ? text : JSON.stringify(text);
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    const analysis = JSON.parse(start >= 0 && end > start ? raw.substring(start, end + 1) : raw);
    return { success: true, error: null, analysis, model, timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, error: `AI assessment failed: ${error.message}`, analysis: null, model };
  }
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/**
 * Runs a full URL scan.
 *
 * @param {string} rawTarget - The raw (possibly encoded) target from the request
 * @param {object} options
 * @param {object} options.env - Worker env (AI, BROWSER bindings)
 * @param {Function} [options.connect] - cloudflare:sockets connect()
 * @param {object} [options.puppeteer] - @cloudflare/puppeteer default export
 * @param {boolean} [options.enableAI]
 * @param {string} [options.aiModel]
 * @param {boolean} [options.screenshot]
 * @param {string} [options.radarApiUrl]
 * @param {string} [options.radarToken]
 * @param {string} [options.abuseApiUrl]
 * @param {string} [options.abuseApiKey]
 * @returns {Promise<{ status: number, body: object }>}
 */
export async function runUrlScan(rawTarget, options = {}) {
  const started = Date.now();
  const decoded = decodeScanTarget(rawTarget);
  if (!decoded.ok) {
    return { status: 400, body: { scanType: 'url', error: `Invalid URL: ${decoded.error}` } };
  }

  const validation = validateScanTarget(decoded.url);
  if (!validation.ok) {
    return { status: 400, body: { scanType: 'url', error: `URL not allowed: ${validation.error}`, input: { encoding: decoded.encoding, url: decoded.url } } };
  }

  const target = validation.url;
  const hostname = target.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const registrableDomain = getRegistrableDomain(hostname);

  // Phase 1: DNS + RDAP (DNS also gates the SSRF check)
  const [dns, registration] = await Promise.all([
    collectDns(hostname, registrableDomain),
    lookupRdap(registrableDomain)
  ]);

  const resolvedIps = isIpLiteral(hostname) ? [hostname] : [...dns.a, ...dns.aaaa];
  if (!isIpLiteral(hostname) && resolvedIps.length === 0) {
    return {
      status: 422,
      body: { scanType: 'url', error: `Hostname ${hostname} does not resolve (no A/AAAA records)`, input: { encoding: decoded.encoding, url: target.href }, domain: { registration, dns } }
    };
  }
  if (resolvedIps.some((ip) => !isPublicIp(ip))) {
    return {
      status: 400,
      body: { scanType: 'url', error: `URL not allowed: ${hostname} resolves to a private or reserved IP address`, input: { encoding: decoded.encoding, url: target.href } }
    };
  }

  // Phase 2: everything that talks to the target, in parallel
  const tlsPort = target.protocol === 'https:' && target.port ? parseInt(target.port, 10) : 443;
  const wantScreenshot = options.screenshot !== false;

  const [redirects, httpsEnforcement, tls, ipIntel, screenshot] = await Promise.all([
    followRedirects(target.href),
    target.port === '' ? checkHttpsEnforcement(hostname) : Promise.resolve({ checked: false }),
    probeTls(options.connect, hostname, tlsPort),
    lookupIpIntel(resolvedIps, options),
    wantScreenshot ? captureScreenshot(options.puppeteer, options.env, target.href, registrableDomain) : Promise.resolve({ success: false, error: 'Screenshot not requested' })
  ]);

  const finalResponse = redirects.response;
  const finalUrl = redirects.finalUrl;
  const finalIsHttps = finalUrl.startsWith('https:');
  const headers = finalResponse?.headers || new Headers();
  const body = finalResponse ? await readBodyLimited(finalResponse).catch(() => ({ text: '', truncated: false, bytes: 0 })) : { text: '', truncated: false, bytes: 0 };
  const isHtml = /html|xml/i.test(headers.get('content-type') || '') || /^\s*<(!doctype|html)/i.test(body.text);

  let securityTxt = null;
  try {
    securityTxt = await checkSecurityTxt(new URL(finalUrl).origin);
  } catch { /* ignore */ }

  const cookies = analyzeCookies(headers, finalIsHttps);
  const technologies = fingerprintTechnologies({
    headers,
    html: isHtml ? body.text : '',
    cookies,
    runtimeLibraries: screenshot.runtimeLibraries,
    renderedRequests: screenshot._requests
  });

  const altSvc = headers.get('alt-svc') || '';
  const http2 = tls.alpn === 'h2' || dns.httpsRecordAlpn?.includes('h2') ? true : (tls.probed && tls.alpn ? false : null);
  const http3 = /\bh3(-\d+)?=/.test(altSvc) || dns.httpsRecordAlpn?.includes('h3') ? true : null;
  const httpVersionEvidence = [
    ...(finalResponse ? ['HTTP/1.1: response received by scanner'] : []),
    ...(tls.alpn ? [`TLS ALPN negotiated "${tls.alpn}"`] : []),
    ...(dns.httpsRecordAlpn?.length ? [`DNS HTTPS record alpn=${dns.httpsRecordAlpn.join(',')}`] : []),
    ...(altSvc ? [`Alt-Svc: ${altSvc.substring(0, 120)}`] : [])
  ];

  const asnNames = ipIntel.map((i) => i.asnName).filter(Boolean);
  const cdn = detectCdn(headers, dns.cname, asnNames);

  const screenshotPublic = { ...screenshot };
  delete screenshotPublic._requests;
  delete screenshotPublic.runtimeLibraries;

  const report = {
    scanType: 'url',
    input: { raw: rawTarget.length > 300 ? `${rawTarget.substring(0, 300)}…` : rawTarget, encoding: decoded.encoding, url: target.href },
    target: { url: target.href, scheme: target.protocol.replace(':', ''), hostname, port: target.port || (target.protocol === 'https:' ? '443' : '80'), registrableDomain },
    summary: {
      finalUrl,
      statusCode: finalResponse?.status ?? null,
      title: null,
      contentType: headers.get('content-type'),
      bodyBytesScanned: body.bytes,
      bodyTruncated: body.truncated,
      fetchError: finalResponse ? null : redirects.error
    },
    redirects: {
      count: Math.max(0, redirects.chain.length - 1),
      chain: redirects.chain,
      crossDomain: redirects.chain.some((h) => h.crossDomain),
      httpsDowngrade: redirects.chain.some((h) => h.httpsDowngrade),
      error: redirects.error
    },
    http: {
      versions: { 'http/1.1': finalResponse ? true : null, h2: http2, h3: http3 },
      evidence: httpVersionEvidence,
      httpsEnforcement,
      headers: pickHeaders(headers),
      securityHeaders: finalResponse ? analyzeSecurityHeaders(headers, finalIsHttps) : [],
      cookies
    },
    tls,
    domain: { name: registrableDomain, registration, dns },
    network: { ips: ipIntel, cdn },
    technologies,
    content: isHtml ? analyzeContent(body.text, finalUrl) : { title: null, scripts: { total: 0, external: 0, withoutSri: [] }, mixedContent: [], insecureForms: [], thirdPartyScriptHosts: [] },
    securityTxt,
    screenshot: screenshotPublic
  };
  report.summary.title = report.content.title;
  if (screenshot.thirdPartyHosts) report.content.renderedThirdPartyHosts = screenshot.thirdPartyHosts;

  report.findings = buildFindings(report);
  const score = scoreFindings(report.findings);
  report.summary.securityScore = score.securityScore;
  report.summary.riskLevel = score.riskLevel;
  report.summary.findingCounts = score.counts;

  report.aiAssessment = options.enableAI
    ? await runAiAssessment(options.env, options.aiModel, report)
    : { success: false, error: 'AI analysis disabled', analysis: null };

  report.summary.durationMs = Date.now() - started;
  return { status: 200, body: report };
}

// Exported for unit testing
export const _internal = {
  identifyAssetUrl,
  parseServerSoftware,
  matchVulnerabilities,
  analyzeSecurityHeaders,
  analyzeContent,
  detectCdn,
  compareVersions,
  parseServerHello,
  buildFindings,
  scoreFindings,
  fingerprintTechnologies,
  probeTls,
  followRedirects,
  collectDns,
  lookupRdap
};
