const { UniqueConstraintError } = require('sequelize');

function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

// Central error handler: clients get a short generic message, never a stack trace,
// SQL text or internal details. Full details are logged on the server only.
// Express recognizes an error handler by its 4 arguments, so `next` must stay.
function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  // Same message for a taken username or email.
  if (err instanceof UniqueConstraintError) {
    return res.status(409).json({ error: 'Username or email is already in use' });
  }

  // Body-parser errors: malformed JSON, body over the size limit, bad encoding.
  if (err.expose && err.status >= 400 && err.status < 500) {
    return res.status(err.status).json({ error: 'Invalid request body' });
  }

  console.error(err.stack || err);
  return res.status(500).json({ error: 'Internal server error' });
}

module.exports = { notFound, errorHandler };
