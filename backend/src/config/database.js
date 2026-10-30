const fs = require('node:fs');
const path = require('node:path');
const { Sequelize } = require('sequelize');
const { DB_STORAGE } = require('./env');

const storage = path.resolve(__dirname, '../..', DB_STORAGE);
fs.mkdirSync(path.dirname(storage), { recursive: true });

// The ORM sends every value as a bound parameter (prepared statement), never by
// string concatenation - this is the core protection against SQL injection.
// SQL logging is off so query values never end up in the console or log files.
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage,
  logging: false,
});

module.exports = sequelize;
