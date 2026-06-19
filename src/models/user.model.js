const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

// Représente un compte utilisateur avec ses credentials et son statut
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  email: {
    type: DataTypes.STRING(255),
    unique: true,
    allowNull: false,
  },
  username: {
    type: DataTypes.STRING(50),
    unique: true,
    allowNull: false,
  },
  password_hash: {
    type: DataTypes.STRING(255),
    allowNull: false,
  },
  // user par défaut, moderator et admin pour la gestion de la modération
  role: {
    type: DataTypes.ENUM('user', 'moderator', 'admin'),
    defaultValue: 'user',
  },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  is_banned:  { type: DataTypes.BOOLEAN, defaultValue: false },
}, {
  tableName: 'users',
  underscored: true,
});

module.exports = User;
