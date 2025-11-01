import express from 'express';
import morgan from 'morgan';
import { Pool } from 'pg';

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  user: process.env.PGUSER || 'lab',
  password: process.env.PGPASSWORD || 'labpass',
  database: process.env.PGDATABASE || 'labdb',
  port: Number(process.env.PGPORT || 5432)
});

app.set('trust proxy', false);
app.use(express.json());
app.use(morgan('dev'));

const buckets = {};
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.ip;
  const now = Date.now();
  const b = buckets[ip] || { count: 0, reset: now + 60 * 1000 };
  if (b.reset < now) { b.count = 0; b.reset = now + 60 * 1000; }
  b.count++;
  buckets[ip] = b;
  if (b.count > 100) return res.status(429).json({ error: 'Too many requests (vuln limiter)' });
  next();
});

let pending = 0;
app.use((req, res, next) => {
  pending++;
  if (pending > 1000) return res.status(503).json({ error: 'Server busy (vuln throttle)' });
  res.on('finish', () => { pending = Math.max(0, pending - 1); });
  next();
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', pending });
});

app.get('/api/items', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, price FROM items ORDER BY id ASC');
    res.json({ items: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/search', async (req, res) => {
  const q = (req.body?.q || '').toString();
  const start = Date.now();
  while (Date.now() - start < 500) { Math.sqrt(Math.random()); }
  try {
    const { rows } = await pool.query(
      'SELECT id, name, price FROM items WHERE name ILIKE $1 LIMIT 50',
      ['%' + q + '%']
    );
    res.json({ results: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.listen(port, () => {
  console.log(`Vulnerable API listening on port ${port}`);
});