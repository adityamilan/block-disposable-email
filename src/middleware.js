'use strict';

/**
 * Express middleware. Requires express.json() (or urlencoded) before it.
 *
 *   app.post('/signup', rejectDisposableEmail(guard), handler)
 *
 * On success: req.body[field] is the trimmed, lowercased address and
 * req.emailCheck = { email, canonical, domain }.
 * On failure: 422 { error: { code, message, field } }.
 */
function rejectDisposableEmail(guard, { field = 'email', status = 422 } = {}) {
  return async function emailGuardMiddleware(req, res, next) {
    try {
      const result = await guard.check(req.body?.[field]);
      if (!result.ok) {
        return res.status(status).json({
          error: { code: result.code, message: result.message, field },
        });
      }
      req.body[field] = result.email;
      req.emailCheck = result;
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { rejectDisposableEmail };
