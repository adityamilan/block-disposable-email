# block-disposable-email

Block disposable, temporary and throwaway email addresses at signup. A Node.js email validator and Express middleware with an auto-updating blocklist, MX record checks and Gmail alias normalization.

```bash
npm install block-disposable-email
```

## Why this one

Most disposable email checkers only look a domain up in a list that was frozen when you installed the package. This one adds:

- **Auto-updating blocklist** — refreshes at runtime every 24 hours, no redeploy needed
- **MX record check** — rejects domains that cannot receive mail
- **MX match** — catches brand-new temp mail domains that point at a known disposable provider's mail servers
- **Subdomain matching** — `anything.mailinator.com` is blocked too
- **Alias normalization** — `j.o.h.n+promo@gmail.com` and `john@gmail.com` map to one account
- **Express middleware** included, TypeScript types included, one dependency

## Quick start

### One-line check (sync, bundled list only)

```js
const { isDisposableEmail } = require('block-disposable-email');

isDisposableEmail('someone@mailinator.com'); // true
isDisposableEmail('someone@gmail.com');      // false
```

### Express middleware (full check)

```js
const express = require('express');
const { createEmailGuard, rejectDisposableEmail } = require('block-disposable-email');

const guard = createEmailGuard();
guard.start(); // refresh the blocklist now and every 24h

const app = express();
app.use(express.json());

app.post('/signup', rejectDisposableEmail(guard), (req, res) => {
  const { email, canonical } = req.emailCheck;
  // unique index on `canonical`; send the confirmation mail to `email`
  res.status(201).json({ ok: true });
});
```

A temp mail signup gets:

```json
HTTP 422
{ "error": { "code": "DISPOSABLE", "message": "Temporary email addresses are not accepted. Please use a permanent email address.", "field": "email" } }
```

### Without Express

```js
const result = await guard.check('someone@example.com');
// { ok: true, email, canonical, domain }
// { ok: false, code, message }
```

ESM and TypeScript work too: `import { createEmailGuard } from 'block-disposable-email'`.

## What it checks, in order

1. **Syntax**
2. **Blocklist** — the domain and its parent domains
3. **MX lookup** — the domain must have mail servers
4. **MX match** — the mail servers must not belong to a disposable provider

| Code | Meaning |
|---|---|
| `INVALID_SYNTAX` | Not a valid email address |
| `DISPOSABLE` | Domain is on the blocklist |
| `NO_MX` | Domain cannot receive mail |
| `DISPOSABLE_MX` | Mail servers belong to a disposable provider |

## Options

```js
createEmailGuard({
  allow: ['privaterelay.appleid.com'], // never block these
  block: ['spammy-domain.com'],        // always block these
});
```

| Option | Default | Purpose |
|---|---|---|
| `allow` | `[]` | Domains never blocked |
| `block` | `[]` | Extra domains to block |
| `blockMxSuffixes` | `[]` | Extra mail-server hostnames to block |
| `checkMx` | `true` | Turn the DNS lookup off |
| `dnsTimeoutMs` | `3000` | DNS timeout |
| `failOpenOnDnsError` | `true` | Accept the address if DNS itself is down |
| `refreshIntervalMs` | 24h | `0` disables auto-refresh |
| `blocklistUrl` | community list | Any one-domain-per-line source |
| `cacheFile` | OS temp dir | Where refreshed lists are saved; `false` for memory only |
| `logger` | none | `(level, message) => void` |

Middleware options: `rejectDisposableEmail(guard, { field: 'email', status: 422 })`.

## API

- `createEmailGuard(options)` → `{ check, isDisposableDomain, refresh, start, stop, size }`
- `rejectDisposableEmail(guard, options)` → Express middleware
- `isDisposableEmail(email)` → `boolean` (sync, bundled list, no DNS)
- `canonicalize(email)` → alias-free address for uniqueness checks

## Notes

- Privacy relays (Apple Hide My Email, Firefox Relay, DuckDuckGo) belong to real users. Add them to `allow` if the list ever blocks one you want to accept.
- Use `canonical` for the uniqueness check only; keep sending mail to `email`.
- This does not replace a confirmation email or OTP, and no blocklist catches every new domain.
- Requires Node.js 18 or newer.

## Credits

The blocklist comes from the community-maintained
[disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) project.

## Contributing

Issues and pull requests are welcome at
[github.com/adityamilan/block-disposable-email](https://github.com/adityamilan/block-disposable-email).

## License

MIT © Aditya Milan
