const { z } = require('zod');

/**
 * Validates req.body against a Zod schema. On success the parsed, normalized
 * data is placed on req.validatedBody - route handlers must use only that.
 * Error messages never echo the submitted values (so a password is never reflected).
 */
function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const { formErrors, fieldErrors } = z.flattenError(result.error);
      return res.status(400).json({ error: 'Validation failed', formErrors, fieldErrors });
    }
    req.validatedBody = result.data;
    return next();
  };
}

module.exports = validate;
