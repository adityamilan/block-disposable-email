'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const dns = require('node:dns/promises');
const isEmail = require('validator/lib/isEmail');

const DEFAULT_BLOCKLIST_URL =
  'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf';
const SEED_FILE = path.join(__dirname, '..', 'data', 'disposable_domains.txt');
const DEFAULT_CACHE_FILE = path.join(os.tmpdir(), 'block-disposable-email-list.txt');

// Providers where "user+tag@" delivers to "user@".
const PLUS_ALIAS_DOMAINS = new Set([
  'gmail.com', 'outlook.com', 'hotmail.com', 'live.com',
  'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'fastmail.com',
]);

const MESSAGES = {
  INVALID_SYNTAX: 'Please enter a valid email address.',
  DISPOSABLE: 'Temporary email addresses are not accepted. Please use a permanent email address.',
  NO_MX: 'This email domain cannot receive mail. Please check the address.',
  DISPOSABLE_MX: 'Temporary email addresses are not accepted. Please use a permanent email address.',
};

function parseList(text) {
  const out = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.trim().toLowerCase();
    if (line && !line.startsWith('#')) out.add(line);
  }
  return out;
}

/** "a.b.example.com" -> ["a.b.example.com", "b.example.com", "example.com"] */
function domainSuffixes(domain) {
  const labels = domain.split('.');
  const out = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join('.'));
  return out;
}

/**
 * Canonical form for uniqueness checks (one account per inbox).
 * Store this alongside the address the user typed; keep sending mail to the original.
 */
function canonicalize(email) {
  let [local, domain] = email.trim().toLowerCase().split('@');
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (PLUS_ALIAS_DOMAINS.has(domain)) local = local.split('+')[0];
  if (domain === 'gmail.com') local = local.replace(/\./g, '');
  return `${local}@${domain}`;
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error('DNS timeout'), { code: 'ETIMEOUT' })), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * @param {object}   [opts]
 * @param {string}   [opts.seedFile]           Bundled blocklist shipped with the package.
 * @param {string|false} [opts.cacheFile]      Where refreshed lists are saved. false = memory only.
 * @param {string}   [opts.blocklistUrl]       Remote list, one domain per line.
 * @param {number}   [opts.refreshIntervalMs]  0 disables auto-refresh. Default 24h.
 * @param {string[]} [opts.allow]              Domains never blocked (e.g. privacy relays you accept).
 * @param {string[]} [opts.block]              Extra domains to block.
 * @param {string[]} [opts.blockMxSuffixes]    Extra mail-server suffixes to block.
 * @param {boolean}  [opts.checkMx]            Do the DNS lookup. Default true.
 * @param {number}   [opts.dnsTimeoutMs]       Default 3000.
 * @param {boolean}  [opts.failOpenOnDnsError] Accept the address when DNS itself fails. Default true.
 * @param {Function} [opts.resolveMx]          Injectable resolver (for tests).
 * @param {Function} [opts.logger]             (level, message) => void
 */
function createEmailGuard(opts = {}) {
  const {
    seedFile = SEED_FILE,
    cacheFile = DEFAULT_CACHE_FILE,
    blocklistUrl = DEFAULT_BLOCKLIST_URL,
    refreshIntervalMs = 24 * 60 * 60 * 1000,
    allow = [],
    block = [],
    blockMxSuffixes = [],
    checkMx = true,
    dnsTimeoutMs = 3000,
    failOpenOnDnsError = true,
    resolveMx = (d) => dns.resolveMx(d),
    logger = () => {},
  } = opts;

  let blocked = new Set();
  try {
    blocked = parseList(fs.readFileSync(seedFile, 'utf8'));
  } catch {
    logger('warn', `block-disposable-email: no bundled list at ${seedFile}`);
  }
  if (cacheFile) {
    try {
      // A previously refreshed list is newer than the bundled one.
      const cached = parseList(fs.readFileSync(cacheFile, 'utf8'));
      if (cached.size >= 1000) blocked = cached;
    } catch {
      /* no cache yet */
    }
  }
  const allowSet = new Set(allow.map((d) => d.toLowerCase()));
  const extraBlock = new Set(block.map((d) => d.toLowerCase()));
  const mxSuffixes = blockMxSuffixes.map((d) => d.toLowerCase());

  const mxCache = new Map(); // domain -> { at, value }
  const MX_TTL = 60 * 60 * 1000;
  const MX_CACHE_MAX = 5000;

  function isDisposableDomain(domain) {
    const suffixes = domainSuffixes(domain.toLowerCase());
    if (suffixes.some((s) => allowSet.has(s))) return false;
    return suffixes.some((s) => blocked.has(s) || extraBlock.has(s));
  }

  /** @returns {Promise<string[]|null>} MX hosts, [] if none, null if DNS failed. */
  async function lookupMx(domain) {
    const hit = mxCache.get(domain);
    if (hit && Date.now() - hit.at < MX_TTL) return hit.value;
    let value;
    try {
      const records = await withTimeout(resolveMx(domain), dnsTimeoutMs);
      value = records
        .map((r) => String(r.exchange || '').toLowerCase().replace(/\.$/, ''))
        .filter(Boolean); // drops the RFC 7505 "null MX"
    } catch (err) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') value = [];
      else return null; // timeout / SERVFAIL: don't cache
    }
    if (mxCache.size >= MX_CACHE_MAX) mxCache.delete(mxCache.keys().next().value);
    mxCache.set(domain, { at: Date.now(), value });
    return value;
  }

  /**
   * @returns {Promise<{ok:boolean, code?:string, message?:string, email?:string, canonical?:string, domain?:string}>}
   */
  async function check(input) {
    const fail = (code, extra = {}) => ({ ok: false, code, message: MESSAGES[code], ...extra });

    if (typeof input !== 'string') return fail('INVALID_SYNTAX');
    const email = input.trim().toLowerCase();
    if (email.length > 254 || !isEmail(email, { allow_ip_domain: false, require_tld: true })) {
      return fail('INVALID_SYNTAX');
    }
    const domain = email.slice(email.lastIndexOf('@') + 1);

    if (isDisposableDomain(domain)) return fail('DISPOSABLE', { domain });

    if (checkMx && !allowSet.has(domain)) {
      const hosts = await lookupMx(domain);
      if (hosts === null) {
        if (!failOpenOnDnsError) return fail('NO_MX', { domain });
        logger('warn', `block-disposable-email: DNS lookup failed for ${domain}, allowing`);
      } else if (hosts.length === 0) {
        return fail('NO_MX', { domain });
      } else if (
        hosts.some((h) => isDisposableDomain(h) || mxSuffixes.some((s) => h === s || h.endsWith(`.${s}`)))
      ) {
        // New throwaway domain pointing at a known disposable provider's mail servers.
        return fail('DISPOSABLE_MX', { domain });
      }
    }

    return { ok: true, email, canonical: canonicalize(email), domain };
  }

  /** Pull the latest list, swap it in, and cache it to disk. */
  async function refresh() {
    const res = await fetch(blocklistUrl, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`blocklist fetch failed: HTTP ${res.status}`);
    const text = await res.text();
    const next = parseList(text);
    if (next.size < 1000) throw new Error(`blocklist looks wrong (${next.size} entries), keeping old one`);
    blocked = next;
    if (cacheFile) {
      try {
        const tmp = `${cacheFile}.${process.pid}.tmp`;
        await fsp.mkdir(path.dirname(cacheFile), { recursive: true });
        await fsp.writeFile(tmp, text);
        await fsp.rename(tmp, cacheFile);
      } catch (e) {
        logger('warn', `block-disposable-email: could not write cache (${e.message})`);
      }
    }
    logger('info', `block-disposable-email: blocklist refreshed (${next.size} domains)`);
    return next.size;
  }

  let timer = null;
  function start() {
    if (!refreshIntervalMs || timer) return;
    const run = () => refresh().catch((e) => logger('warn', `block-disposable-email: ${e.message}`));
    run();
    timer = setInterval(run, refreshIntervalMs);
    timer.unref();
  }
  function stop() {
    clearInterval(timer);
    timer = null;
  }

  return { check, isDisposableDomain, refresh, start, stop, get size() { return blocked.size; } };
}

let defaultGuard;
/**
 * Quick synchronous check against the bundled list only (no DNS, no refresh).
 * For the full check use createEmailGuard().check(email).
 */
function isDisposableEmail(email) {
  if (typeof email !== 'string' || !email.includes('@')) return false;
  defaultGuard ??= createEmailGuard({ refreshIntervalMs: 0, checkMx: false });
  return defaultGuard.isDisposableDomain(email.slice(email.lastIndexOf('@') + 1).trim());
}

module.exports = { createEmailGuard, isDisposableEmail, canonicalize, MESSAGES };
