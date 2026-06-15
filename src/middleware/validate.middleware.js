const { validationResult } = require('express-validator');

module.exports = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Données invalides.',
        details: errors.array().map(e => ({ field: e.path, message: e.msg }))
      }
    });
  }
  next();
};