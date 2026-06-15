const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
});

const connectDB = async () => {
  await sequelize.authenticate();
  console.log('[Auth DB] Connexion PostgreSQL OK');
  await sequelize.sync({ alter: true });
  console.log('[Auth DB] Tables synchronisées');
};

module.exports = { sequelize, connectDB };