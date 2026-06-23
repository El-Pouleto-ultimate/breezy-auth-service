const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// Arrêt immédiat si la clé JWT est absente — le service ne peut pas fonctionner sans elle
if (!process.env.JWT_SECRET) {
  console.error('[auth-service] JWT_SECRET manquant. Arrêt...');
  process.exit(1);
}

const allowedOrigin = process.env.CORS_ORIGIN || 'http://localhost:3000';
app.use(cors({
  origin: allowedOrigin,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id', 'X-User-Role', 'X-User-Username'],
  credentials: true,
}));

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

require('./models/user.model');
require('./models/refreshToken.model');

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'auth-service' }));
app.use('/auth', require('./routes/auth.routes'));

app.use((err, req, res, next) => {
  console.error('[auth-service] Erreur non gérée:', err.message);
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Erreur serveur.'
    }
  });
});

module.exports = app;
