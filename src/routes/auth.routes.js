const router = require('express').Router();
const { body } = require('express-validator');
const validate = require('../middleware/validate.middleware');
const ctrl = require('../controllers/auth.controller');
const identity = require('../middleware/identity.middleware');

const registerRules = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Le nom d\'utilisateur doit faire entre 3 et 50 caractères.')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres et underscores.'),
  body('email')
    .isEmail()
    .withMessage('Email invalide.')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Le mot de passe doit faire au moins 8 caractères.')
    .matches(/(?=.*[A-Z])/)
    .withMessage('Le mot de passe doit contenir au moins une majuscule.')
    .matches(/(?=.*[0-9])/)
    .withMessage('Le mot de passe doit contenir au moins un chiffre.'),
];

const loginRules = [
  body('email')
    .isEmail()
    .withMessage('Email invalide.')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Mot de passe requis.'),
];

router.post('/register', registerRules, validate, ctrl.register);
router.post('/login',    loginRules,    validate, ctrl.login);
router.post('/refresh',  ctrl.refresh);
router.post('/logout',   ctrl.logout);
router.get('/me', identity, ctrl.me);

// Route interne — uniquement accessible depuis les services internes via INTERNAL_SECRET
router.post('/internal/ban', ctrl.internalBan);

module.exports = router;