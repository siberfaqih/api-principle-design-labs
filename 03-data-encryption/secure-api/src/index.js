import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import { encryptObject, decryptObject } from './crypto.js';

dotenv.config();

const app = express();
app.use(morgan('dev'));
app.use(cors());

// Parser scoped: tools routes use JSON; /users uses text/plain

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Secure admin list - returns base64 ciphertext only, not PII plaintext
app.get('/admin/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, encode(ciphertext, \'base64\') AS ciphertext_b64, role FROM users_secure');
    res.json({ users: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Secure insert: decrypt full-body encrypted request, re-encrypt for at-rest
app.post('/users', express.text({ type: '*/*', limit: '1mb' }), async (req, res) => {
  try {
    const decrypted = decryptObject(req.body);
    const { full_name, email, national_id } = decrypted;
    if (!full_name || !email || !national_id) return res.status(400).json({ error: 'missing-fields' });
    const ciphertextB64 = encryptObject({ full_name, email, national_id });
    const ciphertext = Buffer.from(ciphertextB64, 'base64');
    const result = await pool.query('INSERT INTO users_secure (ciphertext) VALUES ($1) RETURNING id', [ciphertext]);
    res.json({ id: result.rows[0].id });
  } catch (e) {
    res.status(400).json({ error: 'bad-encrypted-body', detail: e.message });
  }
});

// Helper to encrypt body (for clients)
app.post('/tools/encrypt', express.json(), (req, res) => {
  try {
    const b64 = encryptObject(req.body);
    res.json({ encrypted: b64 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Helper to decrypt body (for verification)
app.post('/tools/decrypt', express.text({ type: '*/*' }), (req, res) => {
  try {
    const obj = decryptObject(req.body);
    res.json({ decrypted: obj });
  } catch (e) {
    res.status(400).json({ error: 'bad-encrypted-body', detail: e.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const port = 3001;
app.listen(port, () => console.log(`secure-api listening on ${port}`));