import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';

dotenv.config();

const app = express();
app.use(morgan('dev'));
app.use(cors());
// VULN: plaintext in-transit, parse JSON directly
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// VULN: admin can read plaintext PII from DB
app.get('/admin/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, full_name, email, national_id, role FROM users_plain');
    res.json({ users: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// VULN: in-transit plaintext body, at-rest plaintext insert
app.post('/users', async (req, res) => {
  const { full_name, email, national_id } = req.body; // plaintext
  if (!full_name || !email || !national_id) return res.status(400).json({ error: 'missing-fields' });
  try {
    const result = await pool.query(
      'INSERT INTO users_plain (full_name, email, national_id) VALUES ($1, $2, $3) RETURNING id',
      [full_name, email, national_id]
    );
    res.json({ id: result.rows[0].id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const port = 3000;
app.listen(port, () => console.log(`vuln-api listening on ${port}`));