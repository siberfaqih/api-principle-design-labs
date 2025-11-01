# 1. Authentication & Authorization
## Overview
Lab ini mendemonstrasikan berbagai kerentanan keamanan yang umum ditemukan pada authentication dan authorization REST API dan cara memperbaikinya. Terdapat dua versi API:
- **Vulnerable API** (port 3000): Mengandung berbagai kerentanan keamanan
- **Fixed API** (port 3001): Versi yang telah diperbaiki dengan implementasi keamanan yang proper
## Environment & Running
- Database: Postgres 16 via layanan `db` di `docker-compose.yml`
- Jalankan: `docker compose up -d --build` 
- Kedua API menggunakan environment:
  - `PGHOST=db`, `PGPORT=5432`, `PGDATABASE=labdb`, `PGUSER=labuser`, `PGPASSWORD=labpass`
- Catatan: Compose dapat memberi peringatan header `version`; aman diabaikan atau dihapus.
## Test Users
- **alice** (password: password1) - user, tenant t1
- **bob** (password: password2) - admin, tenant t1  
- **charlie** (password: password3) - user, tenant t1
- **diana** (password: password4) - user, tenant t2
## a. Authentication Vulnerabilities
**Vulnerability**: JWT verification tanpa algorithm enforcement dan weak secret (random)
- **Location**: `GET /whoami` dan JWT verification
- **Issue**: 
  - Tidak ada algorithm enforcement, vulnerable terhadap algorithm confusion attacks
  - Weak JWT secret ('random') mudah di-brute force
  - `ignoreExpiration: true` mengabaikan token expiration
  - Tidak ada audience dan issuer validation
  - Memungkinkan serangan "alg=none" dan signature bypass

**Exploitation**:
1. Algorithm Confusion Attack - menggunakan alg=none
```bash
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":1,"role":"admin","tenant_id":"t1"}
# Signature: (kosong)
NONE_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsInRlbmFudF9pZCI6InQxIn0."

curl http://localhost:3000/whoami \
  -H "Authorization: Bearer $NONE_TOKEN"
```

2. Algorithm Confusion Attack - menggunakan alg=none
```bash
# 2. Weak Secret Brute Force
# Secret 'random' dapat di-crack dengan mudah
# Kemudian buat token palsu dengan role admin
FORGED_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsInRlbmFudF9pZCI6InQxIn0.signature_with_cracked_secret"

curl http://localhost:3000/whoami \
  -H "Authorization: Bearer $FORGED_TOKEN"
```

3. Token yang sudah expired masih diterima
	-  Karena ignoreExpiration: true
**Fix**: 
- Algorithm enforcement dengan whitelist (hanya HS256)
- Strong JWT secret dengan entropy tinggi
- Proper expiration validation
- Audience dan issuer validation
- Signature verification yang ketat

### JWT Attack - Unverified Signature - Code
Sebelum (vuln_api/app.js):
```js
// VULNERABLE: Weak secret dan tidak ada algorithm enforcement
const SECRET = process.env.JWT_SECRET || 'random';

// Token creation tanpa expiration, audience, issuer
app.post('/auth/login', (req, res) => {
  // ... authentication logic ...
  
  // VULNERABLE: No expiration, audience, issuer
  const token = jwt.sign({ sub: user.id, role: user.role, tenant_id: user.tenant_id }, SECRET, { algorithm: 'HS256' });
  return res.json({ access_token: token });
});

// VULNERABLE: JWT verification tanpa algorithm enforcement
app.get('/whoami', (req, res) => {
  const auth = req.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    // VULNERABLE: 
    // - No algorithm enforcement (vulnerable to alg=none attacks)
    // - ignoreExpiration: true (accepts expired tokens)
    // - No audience/issuer validation
    const decoded = jwt.verify(token, SECRET, { ignoreExpiration: true });
    return res.json({ decoded });
  } catch (e) {
    return res.status(401).json({ error: 'invalid token', detail: e.message });
  }
});
```
Sesudah (fixed_api/app.js):
```js
// SECURE: Strong secret
const SECRET = process.env.JWT_SECRET || 'replace-with-secure-secret';

// Token creation dengan proper expiration, audience, issuer
app.post('/auth/login', (req, res) => {
  // ... secure authentication logic ...
  
  // SECURE: Proper JWT dengan expiration, audience, issuer
  const token = jwt.sign(
    { sub: user.id, role: user.role, tenant_id: user.tenant_id },
    SECRET,
    { algorithm: 'HS256', expiresIn: '1h', audience: 'secure-api', issuer: 'auth.myorg' }
  );
  return res.json({ access_token: token });
});

// SECURE: JWT verification dengan algorithm enforcement
function authMiddleware(req, res, next) {
  const auth = req.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    // SECURE:
    // - Algorithm enforcement (only HS256 allowed)
    // - Proper expiration validation
    // - Audience and issuer validation
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],
      audience: 'secure-api',
      issuer: 'auth.myorg'
    });
    req.user = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// Secure whoami endpoint menggunakan authMiddleware
app.get('/whoami', authMiddleware, (req, res) => {
  // Token sudah diverifikasi oleh middleware
  pool.query('SELECT id, username, role, tenant_id, display_name, bio FROM users WHERE id = $1', 
    [req.user.sub], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const user = result.rows[0];
      if (!user) return res.status(404).json({ error: 'User not found' });
      return res.json({ user, token_info: req.user });
    });
});
```
## b. Insecure Direct Object Reference (IDOR)
**Vulnerability**: Tidak ada authorization check pada endpoint projects (vuln_api)
- **Location**: `GET /projects/:id`, `GET /projects`
- **Issue**: User dapat mengakses project milik user lain tanpa authorization

**Exploitation**:
```bash
# Akses project milik user lain tanpa authentication
curl http://localhost:3000/projects/1
curl http://localhost:3000/projects/2
curl http://localhost:3000/projects
```

**Fix**: 
- Implementasi authentication middleware
- Ownership verification sebelum mengakses resource
- Role-based access control

### Projects Endpoint
Sebelum (vuln_api/app.js):
```js
// IDOR: tidak cek ownership
app.get('/projects/:id', (req, res) => {
  const projId = parseInt(req.params.id);
  pool.query('SELECT * FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    return res.json(project);
  });
});
// Tidak ada filtering
app.get('/projects', (req, res) => {
  pool.query('SELECT * FROM projects', [], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    return res.json(result.rows);
  });
});
```
Sesudah (fixed_api/app.js):
```js
// Enforce ownership/admin
app.get('/projects/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  pool.query('SELECT * FROM projects WHERE id = $1', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'no project' });
    if (project.owner_id !== req.user.sub && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    return res.json(project);
  });
});
// Filtering sesuai role
app.get('/projects', authMiddleware, (req, res) => {
  let query = '', params = [];
  if (req.user.role === 'admin') {
    query = 'SELECT * FROM projects WHERE tenant_id = $1';
    params = [req.user.tenant_id];
  } else {
    query = 'SELECT * FROM projects WHERE owner_id = $1';
    params = [req.user.sub];
  }
  pool.query(query, params, (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    return res.json(result.rows);
  });
});
```

## c. Missing Authentication
### 1) Create Project Without Authentication
Sebelum (vuln_api/app.js):
```js
// VULNERABLE: No authentication required
app.post('/projects', (req, res) => {
  const { name, description, owner_id, tenant_id, secret } = req.body;
  
  // VULNERABLE: No authentication or input validation
  pool.query(
    'INSERT INTO projects(name, description, owner_id, tenant_id, secret) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [name, description, owner_id, tenant_id, secret],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      return res.json({ id: result.rows[0].id, message: 'Project created' });
    }
  );
});
```
Sesudah (fixed_api/app.js):
```js
// SECURE: Authentication required via authMiddleware
app.post('/projects', authMiddleware, (req, res) => {
  const { name, description, secret } = req.body;
  
  // Input validation
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Project name is required' });
  }
  
  // Use authenticated user's info (no manual owner_id/tenant_id manipulation)
  const owner_id = req.user.sub;
  const tenant_id = req.user.tenant_id;
  const projectSecret = secret || 'default-secret-' + Date.now();
  
  // Pre-check for duplicate name per owner
  pool.query('SELECT id FROM projects WHERE name = $1 AND owner_id = $2', [name.trim(), owner_id], (checkErr, checkResult) => {
    if (checkErr) return res.status(500).json({ error: 'Database error' });
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ error: 'Project name already exists for this owner' });
    }

    pool.query(
      'INSERT INTO projects(name, description, owner_id, tenant_id, secret) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, description, owner_id, tenant_id, created_at, updated_at',
      [name.trim(), description || '', owner_id, tenant_id, projectSecret],
      (err, result) => {
        if (err) {
          if (err.code === '23505') {
            return res.status(409).json({ error: 'Project name already exists for this owner' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        const project = result.rows[0];
        return res.status(201).json(project);
      }
    );
  });
});
```

### 2) Update Other User's Project
Sebelum (vuln_api/app.js):
```js
// VULNERABLE: No authentication or ownership check
app.patch('/projects/:id', (req, res) => {
  const projId = parseInt(req.params.id);
  const updates = req.body;
  
  // VULNERABLE: No authentication or ownership verification
  const keys = Object.keys(updates);
  if (keys.length === 0) return res.status(400).json({ error: 'No fields' });
  const fields = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
  const values = keys.map(k => updates[k]);
  values.push(projId);
  
  pool.query(`UPDATE projects SET ${fields} WHERE id = $${values.length}`, values, (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (result.rowCount === 0) return res.status(404).json({ error: 'Project not found' });
    return res.json({ message: 'Project updated' });
  });
});
```
Sesudah (fixed_api/app.js):
```js
// SECURE: Authentication and ownership verification required
app.patch('/projects/:id', authMiddleware, (req, res) => {
  const projId = parseInt(req.params.id);
  
  // First check if project exists and user has permission
  pool.query('SELECT * FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    
    // Check ownership or admin role
    if (project.owner_id !== req.user.sub && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    
    // Whitelist allowed fields for update
    const allowedFields = ['name', 'description'];
    const updates = {};
    
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    // Add updated_at timestamp (server-side)
    const keys = Object.keys(updates);
    const setClause = keys.map((k, idx) => `${k} = $${idx + 1}`).join(', ');
    const values = keys.map(k => updates[k]);
    values.push(projId);
    
    const sql = `UPDATE projects SET ${setClause}, updated_at = NOW() WHERE id = $${values.length}`;
    pool.query(sql, values, (err2) => {
      if (err2) {
        if (err2.code === '23505') {
          return res.status(409).json({ error: 'Project name already exists for this owner' });
        }
        return res.status(500).json({ error: 'Database error' });
      }
      return res.json({ message: 'Project updated' });
    });
  });
});
```

### 3) Delete Other User's Project
Sebelum (vuln_api/app.js):
```js
// VULNERABLE: No authentication or ownership check
app.delete('/projects/:id', (req, res) => {
  const projId = parseInt(req.params.id);
  
  // VULNERABLE: No authentication or ownership verification
  pool.query('DELETE FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (result.rowCount === 0) return res.status(404).json({ error: 'Project not found' });
    return res.json({ message: 'Project deleted' });
  });
});
```
Sesudah (fixed_api/app.js):
```js
// SECURE: Authentication and ownership verification required
app.delete('/projects/:id', authMiddleware, (req, res) => {
  const projId = parseInt(req.params.id);
  
  // First check if project exists and user has permission
  pool.query('SELECT * FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    
    // Check ownership or admin role
    if (project.owner_id !== req.user.sub && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    
    pool.query('DELETE FROM projects WHERE id = $1', [projId], (err2) => {
      if (err2) return res.status(500).json({ error: 'Database error' });
      return res.json({ message: 'Project deleted' });
    });
  });
});
```
