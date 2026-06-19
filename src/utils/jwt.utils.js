const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Génère un access token JWT signé (courte durée, ex : 15 min)
const generateAccessToken = (user) =>
  jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
  );

// Génère un refresh token aléatoire (longue durée, stocké hashé en base)
const generateRefreshToken = () =>
  crypto.randomBytes(64).toString('hex');

// Hash un token avec SHA-256 avant de le stocker en base (jamais en clair)
const hashToken = (token) =>
  crypto.createHash('sha256').update(token).digest('hex');

// Vérifie et décode un JWT — retourne null si invalide ou expiré
const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
};

module.exports = { generateAccessToken, generateRefreshToken, hashToken, verifyToken };
