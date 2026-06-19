const { validationResult } = require('express-validator');

// Centralise la gestion des erreurs express-validator
// À placer après les règles de validation dans la chaîne de middleware
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
