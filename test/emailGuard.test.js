'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { createEmailGuard, canonicalize, rejectDisposableEmail, isDisposableEmail } = require('../src');

const MX = {
  'gmail.com': [{ exchange: 'gmail-smtp-in.l.google.com', priority: 5 }],
  'acme-corp.com': [{ exchange: 'aspmx.l.google.com', priority: 1 }],
  'brand-new-temp.xyz': [{ exchange: 'mail.mailinator.com', priority: 10 }],
  'custom-mx.io': [{ exchange: 'mx1.throwaway-host.net', priority: 10 }],
  'null-mx.org': [{ exchange: '', priority: 0 }],
};
const resolveMx = async (d) => {
  if (d === 'slow.example') return new Promise(() => {});
  if (MX[d]) return MX[d];
  throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
};
const make = (o = {}) =>
  createEmailGuard({ resolveMx, refreshIntervalMs: 0, dnsTimeoutMs: 50, cacheFile: false, ...o });

test('accepts a normal address', async () => {
  const r = await make().check('  Aditya@Gmail.com ');
  assert.equal(r.ok, true);
  assert.equal(r.email, 'aditya@gmail.com');
});

test('accepts a custom business domain', async () => {
  assert.equal((await make().check('me@acme-corp.com')).ok, true);
});

test('rejects bad syntax', async () => {
  for (const bad of ['nope', 'a@b', 'a@@b.com', '', null, 'a b@c.com', 'a@127.0.0.1']) {
    assert.equal((await make().check(bad)).code, 'INVALID_SYNTAX', String(bad));
  }
});

test('rejects known disposable domains, including subdomains', async () => {
  for (const e of ['x@mailinator.com', 'x@guerrillamail.com', 'x@10minutemail.com', 'x@abc.mailinator.com']) {
    assert.equal((await make().check(e)).code, 'DISPOSABLE', e);
  }
});

test('rejects domains with no MX or a null MX', async () => {
  assert.equal((await make().check('x@does-not-exist-zz.com')).code, 'NO_MX');
  assert.equal((await make().check('x@null-mx.org')).code, 'NO_MX');
});

test('rejects unlisted domains whose MX points at a disposable provider', async () => {
  assert.equal((await make().check('x@brand-new-temp.xyz')).code, 'DISPOSABLE_MX');
  const g = make({ blockMxSuffixes: ['throwaway-host.net'] });
  assert.equal((await g.check('x@custom-mx.io')).code, 'DISPOSABLE_MX');
});

test('allow and block options override the list', async () => {
  assert.equal((await make({ allow: ['mailinator.com'] }).check('x@mailinator.com')).ok, true);
  assert.equal((await make({ block: ['acme-corp.com'] }).check('x@acme-corp.com')).code, 'DISPOSABLE');
});

test('DNS timeout fails open by default, closed when configured', async () => {
  assert.equal((await make().check('x@slow.example')).ok, true);
  assert.equal((await make({ failOpenOnDnsError: false }).check('x@slow.example')).code, 'NO_MX');
});

test('checkMx:false skips DNS', async () => {
  assert.equal((await make({ checkMx: false }).check('x@does-not-exist-zz.com')).ok, true);
});

test('canonicalize collapses aliases', () => {
  assert.equal(canonicalize('A.d.i.tya+promo@GoogleMail.com'), 'aditya@gmail.com');
  assert.equal(canonicalize('first.last+x@outlook.com'), 'first.last@outlook.com');
  assert.equal(canonicalize('first.last+x@acme-corp.com'), 'first.last+x@acme-corp.com');
});

test('middleware: 422 for disposable, passes genuine through', async () => {
  const app = express();
  app.use(express.json());
  app.post('/signup', rejectDisposableEmail(make()), (req, res) => res.status(201).json(req.emailCheck));
  const server = http.createServer(app).listen(0);
  const url = `http://127.0.0.1:${server.address().port}/signup`;
  const post = (body) =>
    fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const bad = await post({ email: 'x@mailinator.com' });
    assert.equal(bad.status, 422);
    assert.equal((await bad.json()).error.code, 'DISPOSABLE');

    const missing = await post({});
    assert.equal(missing.status, 422);

    const good = await post({ email: 'Some.One+1@gmail.com' });
    assert.equal(good.status, 201);
    assert.equal((await good.json()).canonical, 'someone@gmail.com');
  } finally {
    server.close();
  }
});

test('isDisposableEmail: sync list-only helper', () => {
  assert.equal(isDisposableEmail('x@mailinator.com'), true);
  assert.equal(isDisposableEmail('x@sub.mailinator.com'), true);
  assert.equal(isDisposableEmail('x@gmail.com'), false);
  assert.equal(isDisposableEmail('garbage'), false);
});

test('refresh writes a cache that the next instance loads', async () => {
  const os = require('node:os'), path = require('node:path'), fs = require('node:fs');
  const cacheFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bde-')), 'list.txt');
  const list = Array.from({ length: 1500 }, (_, i) => `temp${i}.example`).join('\n') + '\nfresh-temp.dev\n';
  const srv = http.createServer((q, r) => r.end(list)).listen(0);
  try {
    const blocklistUrl = `http://127.0.0.1:${srv.address().port}/`;
    const a = createEmailGuard({ refreshIntervalMs: 0, cacheFile, blocklistUrl, checkMx: false });
    assert.equal(a.isDisposableDomain('fresh-temp.dev'), false);
    assert.equal(await a.refresh(), 1501);
    assert.equal(a.isDisposableDomain('fresh-temp.dev'), true);
    const b = createEmailGuard({ refreshIntervalMs: 0, cacheFile, checkMx: false });
    assert.equal(b.isDisposableDomain('fresh-temp.dev'), true);
  } finally {
    srv.close();
  }
});
