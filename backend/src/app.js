const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { CORS_ORIGIN } = require('./config/env');
const authRoutes = require('./routes/auth.routes');
const { notFound, errorHandler } = require('./middleware/errorHandler');

const app = express();

// Security headers (CSP, X-Content-Type-Options, frame protection...); also removes X-Powered-By.
app.use(helmet());

// Allowlist of exactly one origin (no "*"). Requests from any other site get no
// Access-Control-Allow-Origin header, so the browser blocks them from reading responses.
app.use(
  cors({
    origin: [CORS_ORIGIN],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
    credentials: false,
    maxAge: 600,
  }),
);

// Only JSON bodies (objects/arrays) of up to 10 KB are accepted.
app.use(express.json({ limit: '10kb', strict: true }));

app.use('/api/auth', authRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
