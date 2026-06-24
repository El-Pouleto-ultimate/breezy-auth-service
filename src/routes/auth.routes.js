const router = require('express').Router();
const { body } = require('express-validator');
const validate = require('../middleware/validate.middleware');
const ctrl = require('../controllers/auth.controller');
const identity = require('../middleware/identity.middleware');

// Règles de validation pour l'inscription
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

// Règles de validation pour la connexion
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

const changePasswordRules = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Mot de passe actuel requis.'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Le mot de passe doit faire au moins 8 caractères.')
    .matches(/(?=.*[A-Z])/)
    .withMessage('Le mot de passe doit contenir au moins une majuscule.')
    .matches(/(?=.*[0-9])/)
    .withMessage('Le mot de passe doit contenir au moins un chiffre.'),
];

router.post('/change-password', identity, changePasswordRules, validate, ctrl.changePassword);

const updateUsernameRules = [
  body('newUsername')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Le nom d\'utilisateur doit faire entre 3 et 50 caractères.')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres et underscores.'),
];
router.patch('/username', identity, updateUsernameRules, validate, ctrl.updateUsername);

// Route admin — réservée aux administrateurs authentifiés
const adminCreateUserRules = [
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
  body('role')
    .isIn(['user', 'moderator', 'admin'])
    .withMessage('Rôle invalide.'),
];
router.post('/admin/create-user', identity, adminCreateUserRules, validate, ctrl.adminCreateUser);

// Routes internes — uniquement accessibles depuis les services internes via INTERNAL_SECRET
router.post('/internal/ban', ctrl.internalBan);
router.get('/internal/users/:id/role', ctrl.internalGetRole);

module.exports = router;
