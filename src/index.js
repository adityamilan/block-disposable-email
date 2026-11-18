'use strict';

const { createEmailGuard, isDisposableEmail, canonicalize, MESSAGES } = require('./emailGuard');
const { rejectDisposableEmail } = require('./middleware');

module.exports.createEmailGuard = createEmailGuard;
module.exports.isDisposableEmail = isDisposableEmail;
module.exports.rejectDisposableEmail = rejectDisposableEmail;
module.exports.canonicalize = canonicalize;
module.exports.MESSAGES = MESSAGES;
