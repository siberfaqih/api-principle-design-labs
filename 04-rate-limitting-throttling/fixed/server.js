import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import { Pool } from 'pg';
import rateLimit from 'express-rate-limit';
import { createClient } from 'redis';
import { RedisStore } from 'rate-limit-redis';
import Bottleneck from 'bottleneck';

const app = express();
const port = process.env.PORT || 3001;

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  user: process.env.PGUSER || 'lab',
  password: process.env.PGPASSWORD || 'labpass',
  database: process.env.PGDATABASE || 'labdb',
  port: Number(process.env.PGPORT || 5432)
});

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
const redisClient = createClient({ url: redisUrl });
await redisClient.connect();

app.use(helmet());
app.use(express.json());
app.use(morgan('combined'));
app.set('trust proxy', false);

async function authMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return next();
  try {
    const { rows } = await pool.query('SELECT id, name, plan, api_key FROM users WHERE api_key = $1', [apiKey]);
    req.user = rows[0] || null;
  } catch (err) {
    console.error(err);
  }
  next();
}
app.use(authMiddleware);

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => (req.user?.plan === 'pro' ? 300 : 60),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.api_key || req.ip,
  message: { error: 'Too many requests (secure limiter)' },
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) })
});
app.use(limiter);

const perKeyLimiters = new Map();
function getLimiterForKey(key, plan) {
  const maxConcurrent = plan === 'pro' ? 5 : 2;
  const highWater = maxConcurrent * 2;
  let lim = perKeyLimiters.get(key);
  if (!lim) {
    lim = new Bottleneck({ maxConcurrent, highWater, strategy: Bottleneck.strategy.BLOCK });
    perKeyLimiters.set(key, lim);
  } else {
    lim.updateSettings({ maxConcurrent, highWater, strategy: Bottleneck.strategy.BLOCK });
  }
  return lim;
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
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

async function heavySearchQuery(q) {
  const start = Date.now();
  while (Date.now() - start < 500) { Math.sqrt(Math.random()); }
  const { rows } = await pool.query(
    'SELECT id, name, price FROM items WHERE name ILIKE $1 LIMIT 50',
    ['%' + q + '%']
  );
  return rows;
}

app.post('/api/search', async (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || null;
  const idKey = apiKey || req.ip;
  const plan = req.user?.plan || 'free';
  if (!apiKey) return res.status(401).json({ error: 'Missing X-API-Key' });
  const limiterForKey = getLimiterForKey(idKey, plan);
  try {
    const results = await limiterForKey.schedule(() => heavySearchQuery((req.body?.q || '').toString()));
    res.json({ results });
  } catch (err) {
    console.error(err);
    next(err);
  }
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => {
  console.log(`Fixed API listening on port ${port}`);
});