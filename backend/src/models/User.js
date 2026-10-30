const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const SENSITIVE_FIELDS = ['salt', 'passwordHash', 'failedLoginAttempts', 'lockedUntil'];

const User = sequelize.define(
  'User',
  {
    // Random UUID instead of 1, 2, 3... so IDs cannot be guessed or enumerated.
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    // Stored lowercased (normalized by the validation layer), so UNIQUE is effectively case-insensitive.
    username: {
      type: DataTypes.STRING(30),
      allowNull: false,
      unique: true,
      validate: { len: [3, 30] },
    },
    email: {
      type: DataTypes.STRING(254),
      allowNull: false,
      unique: true,
      validate: { isEmail: true },
    },
    salt: {
      type: DataTypes.STRING(32),
      allowNull: false,
      validate: { is: /^[0-9a-f]{32}$/ },
    },
    // HMAC-SHA256 result. The plaintext password is never stored.
    passwordHash: {
      type: DataTypes.STRING(64),
      allowNull: false,
      validate: { is: /^[0-9a-f]{64}$/ },
    },
    // Prepared for the login stage (policy: maxLoginAttempts).
    failedLoginAttempts: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      validate: { min: 0 },
    },
    lockedUntil: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  },
  {
    tableName: 'users',
    underscored: true,
    // Secrets are excluded from every query by default; code that really needs
    // them (e.g. login) must opt in explicitly with User.scope('withCredentials').
    defaultScope: { attributes: { exclude: SENSITIVE_FIELDS } },
    scopes: { withCredentials: {} },
  },
);

// Defense in depth: even if a full instance is serialized by mistake, secrets are dropped.
User.prototype.toJSON = function toJSON() {
  const values = { ...this.get() };
  for (const field of SENSITIVE_FIELDS) delete values[field];
  return values;
};

module.exports = User;
