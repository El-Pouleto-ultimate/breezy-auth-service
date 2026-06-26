// Import de Sequelize (ORM pour PostgreSQL)
const { Sequelize } = require('sequelize');
// Charge les variables d'environnement depuis un fichier .env
require('dotenv').config();

// Instancie Sequelize avec l'URL de connexion fournie par l'environnement.
// `dialect: 'postgres'` indique l'utilisation de PostgreSQL.
// `logging: false` désactive les logs SQL pour éviter le bruit en console.
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
});

// Fonction asynchrone qui ouvre la connexion et synchronise les modèles.
// Appeler `connectDB()` au démarrage de l'application (ex: dans app.js).
const connectDB = async () => {
  // Vérifie l'authentification/connexion à la base PostgreSQL.
  await sequelize.authenticate();
  console.log('[Auth DB] Connexion PostgreSQL OK');

  // Synchronise les modèles Sequelize avec la base.
  // `alter: true` ajuste les tables existantes pour correspondre aux modèles.
  // Attention : utile en dev mais potentiellement risqué en prod (perte de données possible).
  await sequelize.sync({ alter: true });
  console.log('[Auth DB] Tables synchronisées');
};

// Exporte l'instance Sequelize et la fonction de connexion pour usage ailleurs.
module.exports = { sequelize, connectDB };