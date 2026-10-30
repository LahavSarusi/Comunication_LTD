const sequelize = require('../config/database');
const User = require('./User');
const PasswordHistory = require('./PasswordHistory');

// users 1 ──< password_history (deleting a user deletes their history)
User.hasMany(PasswordHistory, {
  as: 'passwordHistory',
  foreignKey: { name: 'userId', allowNull: false },
  onDelete: 'CASCADE',
});
PasswordHistory.belongsTo(User, {
  foreignKey: { name: 'userId', allowNull: false },
});

module.exports = { sequelize, User, PasswordHistory };
