const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Create a simple Pool using environment variables
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  database: process.env.PGDATABASE || 'app_db',
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vuln-api' });
});

// Intentionally throw to expose stack trace (bad practice)
app.get('/debug', (req, res) => {
  throw new Error('Debug error to leak stack');
});

// Intentionally crash the process (bad practice)
app.get('/crash', (req, res) => {
  res.json({ triggered: true });
  setImmediate(() => {
    throw new Error('Process crash via unhandled exception');
  });
});

// Get user by id - poor error handling: passes raw DB errors through
app.get('/users/:id', async (req, res) => {
  try {
    const id = req.params.id; // no validation
    const result = await pool.query(
      'SELECT id, email, name, created_at FROM users WHERE id = $1',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    // BAD: leak raw error object including stack and internal details
    res.status(500).json(err);
  }
});

// Create user - no validation, leaks raw DB error (e.g., unique violation)
app.post('/users', async (req, res) => {
  try {
    const { email, name } = req.body; // not validated
    const result = await pool.query(
      'INSERT INTO users (email, name) VALUES ($1, $2) RETURNING id, email, name, created_at',
      [email, name]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    // BAD: directly expose DB errors, constraint names, stack, etc.
    res.status(500).json(err);
  }
});

app.listen(PORT, () => {
  console.log(`vuln-api listening on port ${PORT}`);
});