'use strict';

// npm install express block-disposable-email && node express-server.js
const express = require('express');
const { createEmailGuard, rejectDisposableEmail } = require('block-disposable-email');

const guard = createEmailGuard({
  // Privacy relays used by real, long-term users. Remove any you want blocked.
  allow: ['privaterelay.appleid.com', 'mozmail.com', 'duck.com', 'simplelogin.com'],
  logger: (level, msg) => console[level](msg),
});
guard.start(); // refresh the blocklist now and every 24h

const app = express();
app.use(express.json());

app.post('/signup', rejectDisposableEmail(guard), (req, res) => {
  const { email, canonical } = req.emailCheck;
  // 1. Enforce uniqueness on `canonical` (stops user+1@gmail.com duplicates).
  // 2. Save `email`, then send the confirmation link / OTP to it.
  res.status(201).json({ ok: true, email, canonical });
});

app.listen(3000, () => console.log(`listening on :3000 (${guard.size} blocked domains loaded)`));
