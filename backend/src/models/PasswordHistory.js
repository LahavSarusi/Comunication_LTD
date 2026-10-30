const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

// Previous salt+hash pairs per user, so change-password can block reuse of the
// last N passwords (policy: historyCount). Registration stores the first entry.
const PasswordHistory = sequelize.define(
  'PasswordHistory',
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    salt: {
      type: DataTypes.STRING(32),
      allowNull: false,
      validate: { is: /^[0-9a-f]{32}$/ },
    },
    passwordHash: {
      type: DataTypes.STRING(64),
      allowNull: false,
      validate: { is: /^[0-9a-f]{64}$/ },
    },
  },
  {
    tableName: 'password_history',
    underscored: true,
    updatedAt: false, // history rows are never modified
  },
);

module.exports = PasswordHistory;
