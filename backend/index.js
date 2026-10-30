// Loading these first validates backend/.env and config/password-policy.json;
// the process exits with a clear message if either is missing or invalid.
const { HOST, PORT } = require('./src/config/env');
require('./src/config/passwordPolicy');

const { sequelize } = require('./src/models');
const app = require('./src/app');

async function start() {
  await sequelize.authenticate();
  await sequelize.sync(); // creates missing tables; never drops existing data

  app.listen(PORT, HOST, (error) => {
    if (error) {
      console.error(`Failed to start server: ${error.message}`);
      process.exit(1);
    }
    console.log(`Communication_LTD API listening on http://${HOST}:${PORT}`);
  });
}

start().catch((err) => {
  console.error(`Failed to start server: ${err.message}`);
  process.exit(1);
});
