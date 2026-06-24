const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const RefreshToken = require('../models/refreshToken.model');
const { generateAccessToken, generateRefreshToken, hashToken } = require('../utils/jwt.utils');
const axios = require('axios');

// Lus une seule fois au démarrage pour éviter de relire l'env à chaque requête
const BCRYPT_ROUNDS = Number.parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
const REFRESH_TTL_MS = (Number.parseInt(process.env.REFRESH_TOKEN_DAYS, 10) || 7) * 24 * 60 * 60 * 1000;

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Strict',
  maxAge: REFRESH_TTL_MS,
};

// Crée le compte, synchronise le profil vers le user-service, puis retourne les tokens
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const emailTaken = await User.findOne({ where: { email } });
    if (emailTaken) {
      return res.status(409).json({ error: { code: 'EMAIL_TAKEN', message: 'Cet email est déjà utilisé.' } });
    }

    const usernameTaken = await User.findOne({ where: { username } });
    if (usernameTaken) {
      return res.status(409).json({ error: { code: 'USERNAME_TAKEN', message: 'Ce nom d\'utilisateur est déjà pris.' } });
    }

    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await User.create({ username, email, password_hash });

    // Non bloquant : si le user-service est indisponible, l'inscription reste valide
    try {
      await axios.post(`${process.env.USER_SERVICE_URL}/users/sync`, {
        id: user.id,
        username: user.username,
        role: user.role,
      }, {
        headers: { 'x-internal-secret': process.env.INTERNAL_SECRET },
        timeout: 3000,
      });
    } catch (err) {
      console.warn('[Auth] Sync user-service échoué (non critique):', err.message);
    }

    const token = generateAccessToken(user);
    const refreshToken = generateRefreshToken();

    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await RefreshToken.create({
      user_id: user.id,
      token_hash: hashToken(refreshToken),
      expires_at: expiresAt,
    });

    res.cookie('refreshToken', refreshToken, cookieOptions);

    return res.status(201).json({
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
      token,
    });
  } catch (err) {
    console.error('[Auth] register error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

// Vérifie les credentials et rejette immédiatement si le compte est banni ou inactif
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });
    const passwordMatches = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!user || !passwordMatches) {
      return res.status(401).json({ error: { code: 'INVALID_CREDENTIALS', message: 'Email ou mot de passe incorrect.' } });
    }

    if (user.is_banned) {
      return res.status(403).json({ error: { code: 'ACCOUNT_BANNED', message: 'Votre compte a été suspendu.' } });
    }

    if (!user.is_active) {
      return res.status(403).json({ error: { code: 'ACCOUNT_INACTIVE', message: 'Votre compte est inactif.' } });
    }

    const token = generateAccessToken(user);
    const refreshToken = generateRefreshToken();

    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await RefreshToken.create({
      user_id: user.id,
      token_hash: hashToken(refreshToken),
      expires_at: expiresAt,
    });

    res.cookie('refreshToken', refreshToken, cookieOptions);

    return res.json({
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
      token,
    });
  } catch (err) {
    console.error('[Auth] login error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

// Rotation du refresh token : l'ancien est révoqué et un nouveau est émis
// Si le token présenté est déjà révoqué, tous les tokens du compte sont révoqués (détection de vol)
exports.refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!refreshToken) {
      return res.status(400).json({ error: { code: 'MISSING_TOKEN', message: 'Refresh token manquant.' } });
    }

    const tokenHash = hashToken(refreshToken);
    const stored = await RefreshToken.findOne({
      where: { token_hash: tokenHash },
      include: [{ model: User, as: 'User' }]
    });

    if (!stored) {
      res.clearCookie('refreshToken', cookieOptions);
      return res.status(401).json({ error: { code: 'INVALID_REFRESH_TOKEN', message: 'Session invalide.' } });
    }

    if (stored.is_revoked) {
      // Token déjà utilisé : possible vol de session, on révoque tout
      await RefreshToken.update({ is_revoked: true }, { where: { user_id: stored.user_id } });
      res.clearCookie('refreshToken', cookieOptions);
      return res.status(401).json({ error: { code: 'INVALID_REFRESH_TOKEN', message: 'Session invalide.' } });
    }

    if (new Date() > stored.expires_at) {
      await stored.update({ is_revoked: true });
      res.clearCookie('refreshToken', cookieOptions);
      return res.status(401).json({ error: { code: 'INVALID_REFRESH_TOKEN', message: 'Session expirée.' } });
    }

    const user = await User.findByPk(stored.user_id);
    if (!user || !user.is_active || user.is_banned) {
      await stored.update({ is_revoked: true });
      res.clearCookie('refreshToken', cookieOptions);
      return res.status(401).json({ error: { code: 'INVALID_REFRESH_TOKEN', message: 'Utilisateur invalide.' } });
    }

    await stored.update({ is_revoked: true });
    const newRefreshToken = generateRefreshToken();
    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await RefreshToken.create({ user_id: user.id, token_hash: hashToken(newRefreshToken), expires_at: expiresAt });

    res.cookie('refreshToken', newRefreshToken, cookieOptions);

    const newAccessToken = generateAccessToken(user);
    return res.json({ token: newAccessToken });
  } catch (err) {
    console.error('[Auth] refresh error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

// Révoque le refresh token actif sans exiger d'authentification JWT
exports.logout = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    if (refreshToken) {
      await RefreshToken.update({ is_revoked: true }, { where: { token_hash: hashToken(refreshToken) } });
    }
    res.clearCookie('refreshToken', cookieOptions);
    return res.status(204).send();
  } catch (err) {
    console.error('[Auth] logout error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR' } });
  }
};

// Retourne les informations de l'utilisateur connecté (id fourni par le middleware identity)
exports.me = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findByPk(userId, {
      attributes: ['id', 'username', 'email', 'role', 'is_active', 'is_banned'],
    });
    if (!user) return res.status(404).json({ error: { code: 'USER_NOT_FOUND', message: 'Utilisateur non trouvé.' } });
    return res.json({ user });
  } catch (err) {
    console.error('[Auth] me error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findByPk(req.userId);
    if (!user) {
      return res.status(404).json({ error: { code: 'USER_NOT_FOUND', message: 'Utilisateur non trouvé.' } });
    }

    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: { code: 'INVALID_PASSWORD', message: 'Mot de passe actuel incorrect.' } });
    }

    const password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await user.update({ password_hash });

    await RefreshToken.update({ is_revoked: true }, { where: { user_id: req.userId } });

    return res.json({ message: 'Mot de passe modifié avec succès.' });
  } catch (err) {
    console.error('[Auth] changePassword error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

// Met à jour le username dans auth-service, synchronise vers user-service, retourne un nouveau JWT
exports.updateUsername = async (req, res) => {
  try {
    const { newUsername } = req.body;
    const userId = req.userId;

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: { code: 'USER_NOT_FOUND', message: 'Utilisateur non trouvé.' } });
    }

    if (user.username === newUsername) {
      return res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role } });
    }

    const taken = await User.findOne({ where: { username: newUsername } });
    if (taken) {
      return res.status(409).json({ error: { code: 'USERNAME_TAKEN', message: 'Ce nom d\'utilisateur est déjà pris.' } });
    }

    await user.update({ username: newUsername });

    try {
      await axios.post(`${process.env.USER_SERVICE_URL}/users/sync`, {
        id: user.id,
        username: newUsername,
        role: user.role,
      }, {
        headers: { 'x-internal-secret': process.env.INTERNAL_SECRET },
        timeout: 3000,
      });
    } catch (err) {
      console.warn('[Auth] Sync username user-service échoué (non critique):', err.message);
    }

    // Nouveau JWT avec le username mis à jour
    const token = generateAccessToken(user);
    return res.json({
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
      token,
    });
  } catch (err) {
    console.error('[Auth] updateUsername error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

// Réservé aux admins — crée un compte avec le rôle spécifié et synchronise vers le user-service
exports.adminCreateUser = async (req, res) => {
  try {
    if (req.userRole !== 'admin') {
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Action réservée aux administrateurs.' } });
    }

    const { username, email, password, role } = req.body;

    const validRoles = ['user', 'moderator', 'admin'];
    if (!role || !validRoles.includes(role)) {
      return res.status(400).json({ error: { code: 'INVALID_ROLE', message: 'Rôle invalide. Valeurs acceptées : user, moderator, admin.' } });
    }

    const emailTaken = await User.findOne({ where: { email } });
    if (emailTaken) {
      return res.status(409).json({ error: { code: 'EMAIL_TAKEN', message: 'Cet email est déjà utilisé.' } });
    }

    const usernameTaken = await User.findOne({ where: { username } });
    if (usernameTaken) {
      return res.status(409).json({ error: { code: 'USERNAME_TAKEN', message: 'Ce nom d\'utilisateur est déjà pris.' } });
    }

    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await User.create({ username, email, password_hash, role });

    try {
      await axios.post(`${process.env.USER_SERVICE_URL}/users/sync`, {
        id: user.id,
        username: user.username,
        role: user.role,
      }, {
        headers: { 'x-internal-secret': process.env.INTERNAL_SECRET },
        timeout: 3000,
      });
    } catch (err) {
      console.warn('[Auth] Sync user-service échoué (non critique):', err.message);
    }

    return res.status(201).json({
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('[Auth] adminCreateUser error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

// Endpoint interne — retourne le rôle réel d'un utilisateur (source de vérité)
exports.internalGetRole = async (req, res) => {
  try {
    if (req.headers['x-internal-secret'] !== process.env.INTERNAL_SECRET) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED' } });
    }
    const user = await User.findByPk(req.params.id, { attributes: ['id', 'role'] });
    if (!user) return res.status(404).json({ error: { code: 'USER_NOT_FOUND' } });
    return res.json({ role: user.role });
  } catch (err) {
    console.error('[Auth] internalGetRole error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR' } });
  }
};

// Endpoint réservé aux services internes — protégé par INTERNAL_SECRET, pas par JWT
exports.internalBan = async (req, res) => {
  try {
    if (req.headers['x-internal-secret'] !== process.env.INTERNAL_SECRET) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Non autorisé.' } });
    }

    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ error: { code: 'MISSING_USER_ID', message: 'userId manquant.' } });
    }

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: { code: 'USER_NOT_FOUND', message: 'Utilisateur introuvable.' } });
    }

    await user.update({ is_banned: true });
    return res.json({ ok: true });
  } catch (err) {
    console.error('[Auth] internalBan error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};
