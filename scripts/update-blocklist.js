'use strict';

// Manual refresh: npm run update-blocklist
const { createEmailGuard } = require('../src');

// Maintainers: rewrites the bundled list before publishing.
const path = require('node:path');
createEmailGuard({
  refreshIntervalMs: 0,
  cacheFile: path.join(__dirname, '..', 'data', 'disposable_domains.txt'),
})
  .refresh()
  .then((n) => console.log(`blocklist updated: ${n} domains`))
  .catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
