const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const RefreshToken = require('../models/refreshToken.model');
const { generateAccessToken, generateRefreshToken, hashToken } = require('../utils/jwt.utils');

const BCRYPT_ROUNDS = Number.parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;
const REFRESH_TTL_MS = (Number.parseInt(process.env.REFRESH_TOKEN_DAYS, 10) || 7) * 24 * 60 * 60 * 1000;
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Strict',
  maxAge: REFRESH_TTL_MS,
};

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

    const token = generateAccessToken(user);
    const refreshToken = generateRefreshToken();

    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await RefreshToken.create({
      user_id: user.id,
      token_hash: hashToken(refreshToken),
      expires_at: expiresAt,
    });

    // Set refresh token in HttpOnly cookie
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

    const token = generateAccessToken(user);
    const refreshToken = generateRefreshToken();

    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await RefreshToken.create({
      user_id: user.id,
      token_hash: hashToken(refreshToken),
      expires_at: expiresAt,
    });

    // Set refresh token in HttpOnly cookie
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

exports.refresh = async (req, res) => {
  try {
    // Support token from cookie or body for backward compatibility
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
      // Unknown token -> possible reuse or tampering
      res.clearCookie('refreshToken', cookieOptions);
      return res.status(401).json({ error: { code: 'INVALID_REFRESH_TOKEN', message: 'Session invalide.' } });
    }

    if (stored.is_revoked) {
      // Token already revoked — revoke all tokens for this user as precaution
      await RefreshToken.update({ is_revoked: true }, { where: { user_id: stored.user_id } });
      res.clearCookie('refreshToken', cookieOptions);
      return res.status(401).json({ error: { code: 'INVALID_REFRESH_TOKEN', message: 'Session invalide.' } });
    }

    if (new Date() > stored.expires_at) {
      // expired
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

    // Rotate: revoke old token, create a new one
    await stored.update({ is_revoked: true });
    const newRefreshToken = generateRefreshToken();
    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
    await RefreshToken.create({ user_id: user.id, token_hash: hashToken(newRefreshToken), expires_at: expiresAt });

    // Set new refresh token cookie
    res.cookie('refreshToken', newRefreshToken, cookieOptions);

    const newAccessToken = generateAccessToken(user);
    return res.json({ token: newAccessToken });
  } catch (err) {
    console.error('[Auth] refresh error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erreur serveur.' } });
  }
};

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

exports.me = async (req, res) => {
  try {
    const userId = req.userId; // injected by identity.middleware
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