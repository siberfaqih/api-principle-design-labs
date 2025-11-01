const express = require('express');
const helmet = require('helmet');
const { Pool } = require('pg');
const { body, param, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3001;
const isProd = (process.env.NODE_ENV || 'production') === 'production';

app.use(helmet());
app.use(express.json());

// Request ID for correlation
app.use((req, res, next) => {
  try {
    req.requestId = global.crypto?.randomUUID ? global.crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
  } catch (_) {
    req.requestId = `${Date.now()}-${Math.random()}`;
  }
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

// DB pool
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  database: process.env.PGDATABASE || 'app_db',
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'secure-api' });
});

// Centralized error response formatter
function sendError(res, req, status, code, message) {
  res.status(status).json({
    error: { code, message },
    requestId: req.requestId,
  });
}

// Validation and safe error handling
app.get('/users/:id',
  [param('id').isInt({ min: 1 }).withMessage('id must be a positive integer')],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, req, 400, 'INVALID_USER_ID', errors.array()[0].msg);
    }
    try {
      const id = Number(req.params.id);
      const result = await pool.query(
        'SELECT id, email, name, created_at FROM users WHERE id = $1',
        [id]
      );
      if (result.rows.length === 0) {
        return sendError(res, req, 404, 'USER_NOT_FOUND', 'User not found');
      }
      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

app.post('/users',
  [
    body('email').isEmail().withMessage('email must be valid'),
    body('name').isString().isLength({ min: 1, max: 100 }).withMessage('name is required'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendError(res, req, 400, 'VALIDATION_ERROR', errors.array()[0].msg);
    }
    const { email, name } = req.body;
    try {
      const result = await pool.query(
        'INSERT INTO users (email, name) VALUES ($1, $2) RETURNING id, email, name, created_at',
        [email, name]
      );
      res.status(201).json(result.rows[0]);
    } catch (err) {
      // Map known Postgres errors
      if (err && err.code === '23505') {
        return sendError(res, req, 409, 'USER_EMAIL_EXISTS', 'Email already exists');
      }
      next(err);
    }
  }
);

// Simulate an error but handle it safely
app.get('/debug', (req, res, next) => {
  next(new Error('Simulated internal error')); // will be handled centrally
});

// Avoid crashing: route-level capture of rejected promise
app.get('/crash', async (req, res, next) => {
  try {
    await Promise.reject(new Error('Simulated async failure'));
    res.json({ triggered: true });
  } catch (err) {
    next(err);
  }
});

// Centralized error handler: log internal details, hide from clients
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // Server-side logging only
  console.error(`[${req.requestId}]`, err && err.stack ? err.stack : err);

  // Generic message for clients
  sendError(res, req, 500, 'INTERNAL_SERVER_ERROR', 'Something went wrong');
});

// Process-level safeguards
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});
process.on('uncaughtException', (error) => {
  console.error('[uncaughtException]', error && error.stack ? error.stack : error);
  // In production, consider graceful shutdown: here we keep the process alive for demo
});

app.listen(PORT, () => {
  console.log(`secure-api listening on port ${PORT}`);
});