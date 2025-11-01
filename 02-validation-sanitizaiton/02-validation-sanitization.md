# Hands-on Lab: Secure API Design Principles (Node.js)

**Duration:** 90–120 minutes  
**Audience:** Backend developers familiar with Node.js and Express  

## 🎯 Learning Objectives

By the end of this lab, you will:
- Understand why input validation and sanitization are critical for secure APIs
- Identify common validation & sanitization mistakes and their consequences
- Implement robust validation and sanitization for banking inputs (email, Indonesian NIK, account number, amounts)
- Learn how to harden API endpoints with prepared statements, parameterized queries, output sanitization, rate limiting, and HTTP security headers
- Compare vulnerable implementations with secure, production-ready implementations

## 📋 Prerequisites

- Node.js 16+ installed
- Basic knowledge of Express.js and SQL
- Understanding of HTTP requests (curl or Postman)
- Text editor or IDE

## 🚀 Setup Instructions

### 1. Start with Docker Compose (recommended)

```bash
npm run docker:up
```

This starts:
- Postgres `bankdb` on `localhost:5432` (credentials in `docker-compose.yml`)
- Vulnerable server at `http://localhost:3001`
- Secure server at `http://localhost:3002`

Database seeding is automatic on `docker compose up` via the `db-seed` job, and will run only when the `users` table is missing (first run or after a destructive reset).

Quick reset and fresh seed:

```bash
npm run docker:reset
```

### 2. Verify Health Endpoints

```bash
curl http://localhost:3001/api/health
curl http://localhost:3002/api/health
```

### 3. Stop the stack

```bash
npm run docker:down
```

### Alternative: Manual (non-Docker) run

```bash
npm run vuln-server
npm run secure-server
```

Note: Manual run expects a Postgres instance with the same `DB_*` env vars and the schema/data loaded from `db/init.sql`. The previous SQLite-based `init-db` step is deprecated.

## ⚠️ Part 1: Exploiting Vulnerabilities

### 🔓 Task 1.1: SQL Injection in User Registration

**Objective:** Demonstrate SQL injection vulnerability in user registration.

**Attack Command:**
```bash
curl -X POST http://localhost:3001/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "hacker@evil.com",
    "nik": "1234567890123456",
    "full_name": "Evil Hacker",
    "account_number": "ACC999999999999",
    "initial_balance": "1000000); DROP TABLE users; --",
    "profile_bio": "Just a normal user"
  }'
```

**Expected Result:** The vulnerable server will execute the malicious SQL, potentially dropping the users table.

**Learning Point:** String interpolation in SQL queries allows attackers to inject arbitrary SQL commands.

### 🔓 Task 1.2: SQL Injection in User Search

**Attack Command:**
```bash
curl "http://localhost:3001/api/users/search?email=john.doe@email.com' OR '1'='1"
```

**Expected Result:** Returns all users instead of just the searched user.

**More Advanced Attack (Postgres):**
```bash
curl "http://localhost:3001/api/users/search?email='; SELECT table_name FROM information_schema.tables; --"
```

**Learning Point:** Query parameters are vulnerable to SQL injection when not properly sanitized.

### 🔓 Task 1.3: Stored XSS via Profile Bio

**Step 1 - Inject XSS Payload:**
```bash
curl -X PUT http://localhost:3001/api/profile/ACC001234567890/bio \
  -H "Content-Type: application/json" \
  -d '{
    "profile_bio": "<script>alert(\"XSS Attack! Your session could be stolen!\"); document.body.innerHTML = \"<h1 style=\"color:red\">HACKED!</h1>\";</script>"
  }'
```

**Step 2 - View Profile to Trigger XSS:**
```bash
curl http://localhost:3001/api/profile/ACC001234567890
```

Or open in browser: `http://localhost:3001/api/profile/ACC001234567890`

**Expected Result:** The malicious script executes when the profile is viewed.

**Learning Point:** Unescaped user input in HTML output creates stored XSS vulnerabilities.

### 🔓 Task 1.4: Business Logic Bypass - Overdraft Attack

**Attack Command:**
```bash
curl -X POST http://localhost:3001/api/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from_account": "ACC001234567893",
    "to_account": "ACC001234567890",
    "amount": 999999999,
    "description": "Overdraft attack - stealing money!"
  }'
```

**Expected Result:** Transfer succeeds even though Alice only has Rp 250,000, creating a negative balance.

**Learning Point:** Lack of balance validation allows unauthorized overdrafts.

### 🔓 Task 1.5: Information Disclosure

**Attack Command:**
```bash
curl http://localhost:3001/api/users
```

**Expected Result:** Exposes all user data including sensitive NIK numbers and balances.

**Learning Point:** APIs should never expose sensitive information without proper authorization.

### 🔓 Task 1.6: Unauthorized Account Deletion

**Attack Command:**
```bash
curl -X DELETE http://localhost:3001/api/users/ACC001234567892
```

**Expected Result:** Deletes Bob's account without any authentication or authorization.

**Learning Point:** Destructive operations must require proper authentication and authorization.

## ✅ Part 2: Verifying Security Fixes

### 🔒 Task 2.1: SQL Injection Prevention

**Test Command:**
```bash
curl -X POST http://localhost:3002/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "hacker@evil.com",
    "nik": "1234567890123456",
    "full_name": "Evil Hacker",
    "account_number": "ACC999999999999",
    "initial_balance": "1000000); DROP TABLE users; --",
    "profile_bio": "Just a normal user"
  }'
```

**Expected Result:**
```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "initial_balance",
      "message": "Initial balance must be between 0 and 100,000,000",
      "value": "1000000); DROP TABLE users; --"
    }
  ]
}
```

**Learning Point:** Input validation catches malicious input before it reaches the database.

### 🔒 Task 2.2: Email Validation

**Test Command:**
```bash
curl -X POST http://localhost:3002/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "not-an-email",
    "nik": "1234567890123456",
    "full_name": "Test User",
    "account_number": "ACC999999999998"
  }'
```

**Expected Result:**
```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "email",
      "message": "Valid email is required",
      "value": "not-an-email"
    }
  ]
}
```

### 🔒 Task 2.3: Indonesian NIK Validation

**Test Command:**
```bash
curl -X POST http://localhost:3002/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "nik": "123",
    "full_name": "Test User",
    "account_number": "ACC999999999997"
  }'
```

**Expected Result:**
```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "nik",
      "message": "NIK must be exactly 16 digits",
      "value": "123"
    }
  ]
}
```

### 🔒 Task 2.4: XSS Prevention

**Step 1 - Try to Inject XSS:**
```bash
curl -X PUT http://localhost:3002/api/profile/ACC001234567890/bio \
  -H "Content-Type: application/json" \
  -d '{
    "profile_bio": "<script>alert(\"XSS Attack!\");</script><img src=x onerror=alert(\"XSS\")>"
  }'
```

**Step 2 - View Profile:**
```bash
curl http://localhost:3002/api/profile/ACC001234567890
```

**Expected Result:** The malicious script is sanitized and rendered as plain text, not executed.

### 🔒 Task 2.5: Transfer Amount Validation

**Test Command:**
```bash
curl -X POST http://localhost:3002/api/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from_account": "ACC001234567893",
    "to_account": "ACC001234567890",
    "amount": 999999999,
    "description": "Trying to overdraft"
  }'
```

**Expected Result:**
```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "amount",
      "message": "Amount must be between 0.01 and 10,000,000",
      "value": 999999999
    }
  ]
}
```

### 🔒 Task 2.6: Insufficient Balance Protection

**Test Command:**
```bash
curl -X POST http://localhost:3002/api/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from_account": "ACC001234567893",
    "to_account": "ACC001234567890",
    "amount": 300000,
    "description": "Trying to overdraft with valid amount"
  }'
```

**Expected Result:**
```json
{
  "error": "Insufficient balance",
  "currentBalance": 250000,
  "requestedAmount": 300000
}
```

## 🧪 Part 3: Extra Challenges

### Challenge 1: Race Condition Testing

Try to create a race condition by running multiple transfers simultaneously:

```bash
# Terminal 1
curl -X POST http://localhost:3001/api/transfer \
  -H "Content-Type: application/json" \
  -d '{"from_account": "ACC001234567890", "to_account": "ACC001234567891", "amount": 500000, "description": "Race test 1"}' &

# Terminal 2 (run immediately)
curl -X POST http://localhost:3001/api/transfer \
  -H "Content-Type: application/json" \
  -d '{"from_account": "ACC001234567890", "to_account": "ACC001234567892", "amount": 500000, "description": "Race test 2"}' &
```

**Vulnerable Server:** May allow both transfers even if total exceeds balance.  
**Secure Server:** Uses database transactions to prevent race conditions.

### Challenge 2: Input Size Attack

Try sending extremely large payloads:

```bash
# Create a large string
python3 -c "print('A' * 1000000)" > large_input.txt

curl -X POST http://localhost:3001/api/register \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"test@example.com\", \"nik\": \"1234567890123456\", \"full_name\": \"$(cat large_input.txt)\", \"account_number\": \"ACC999999999996\"}"
```

**Vulnerable Server:** Accepts the large input.  
**Secure Server:** Rejects with size limit error.

## 📊 Learning Checkpoints & Questions

### Checkpoint 1: Input Validation
**Question:** Why is server-side validation necessary even if client-side validation exists?  
**Answer:** Client-side validation can be bypassed by attackers who can send direct HTTP requests to the server.

### Checkpoint 2: SQL Injection
**Question:** What's the difference between prepared statements and string interpolation?  
**Answer:** Prepared statements separate SQL code from data, preventing malicious input from being interpreted as SQL commands.

### Checkpoint 3: XSS Prevention
**Question:** What's the difference between stored XSS and reflected XSS?  
**Answer:** Stored XSS persists in the database and affects all users who view the content, while reflected XSS only affects the current request.

### Checkpoint 4: Business Logic
**Question:** Why are atomic database transactions important for financial operations?  
**Answer:** They ensure that either all operations succeed or all fail, preventing inconsistent states where money could be lost or duplicated.

## 🔍 Security Comparison Summary

| Vulnerability      | Vulnerable Server      | Secure Server           |
| ------------------ | ---------------------- | ----------------------- |
| SQL Injection      | ❌ String interpolation | ✅ Prepared statements   |
| Input Validation   | ❌ No validation        | ✅ express-validator     |
| XSS Protection     | ❌ Raw HTML output      | ✅ sanitize-html         |
| Security Headers   | ❌ No headers           | ✅ Helmet.js             |
| Transaction Safety | ❌ No atomicity         | ✅ Database transactions |
| Error Handling     | ❌ Exposes internals    | ✅ Generic messages      |
| Authorization      | ❌ No checks            | ✅ Proper validation     |

## 🎓 Key Takeaways

1. **Never trust user input** - Always validate and sanitize
2. **Use prepared statements** - Prevent SQL injection
3. **Sanitize output** - Prevent XSS attacks
4. **Implement rate limiting** - Prevent abuse
5. **Use security headers** - Add defense in depth
6. **Handle errors securely** - Don't expose internal details
7. **Use database transactions** - Ensure data consistency
8. **Validate business logic** - Prevent unauthorized operations

## 🛠️ Production Recommendations

1. **Use HTTPS** in production
2. **Implement proper authentication** (JWT, OAuth)
3. **Add logging and monitoring**
4. **Use environment variables** for configuration
5. **Implement proper error tracking**
6. **Add API documentation** (OpenAPI/Swagger)
7. **Use database connection pooling**
8. **Implement backup and recovery procedures**

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

**⚠️ Important:** The vulnerable server is for educational purposes only. Never use similar code in production environments!

## 🧩 Pembahasan Source Code: Vulnerable vs Fixed

Bagian ini membandingkan implementasi di `vuln-server.js` (rentan) dan `secure-server.js` (diperbaiki) untuk tiap concern keamanan: SQL Injection, XSS, validasi input, konsistensi transaksi, dan disclosure data.

### 1) Registrasi Pengguna (SQL Injection vs Prepared Statements)

- Vulnerable: Query dibangun dengan string interpolation sehingga input pengguna bisa menyisipkan SQL tambahan.

```js
// vuln-server.js
app.post('/api/register', (req, res) => {
  const { email, nik, full_name, account_number, initial_balance, profile_bio } = req.body;
  // TIDAK ADA VALIDASI / SANITISASI
  const query = `INSERT INTO users (email, nik, full_name, account_number, balance, profile_bio)
                 VALUES ('${email}', '${nik}', '${full_name}', '${account_number}', ${initial_balance || 0}, '${profile_bio}')`;

  // Mengeksekusi tiap statement yang dipisah oleh ; (berbahaya)
  const statements = query.split(';').filter(stmt => stmt.trim());
  statements.forEach(statement => pool.query(statement.trim(), /* ... */));
});
```

- Fixed: Menggunakan `express-validator` untuk validasi input, `sanitize-html` untuk sanitasi, dan prepared statements (parameter `?` dikonversi menjadi `$1`, `$2`, dst. agar kompatibel dengan Postgres).

```js
// secure-server.js
app.post('/api/register', strictLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('nik').custom(validateIndonesianNIK).withMessage('NIK must be exactly 16 digits'),
  body('full_name').isLength({ min: 2, max: 100 }).matches(/^[a-zA-Z\s]+$/),
  body('account_number').custom(validateAccountNumber),
  body('initial_balance').optional().isFloat({ min: 0, max: 100000000 })
], handleValidationErrors, (req, res) => {
  const sanitizedData = {
    email: req.body.email.toLowerCase().trim(),
    nik: req.body.nik.trim(),
    full_name: sanitizeInput(req.body.full_name.trim()),
    account_number: req.body.account_number.trim(),
    initial_balance: req.body.initial_balance || 0,
    profile_bio: sanitizeInput(req.body.profile_bio || '')
  };
  const query = `INSERT INTO users (email, nik, full_name, account_number, balance, profile_bio)
                 VALUES (?, ?, ?, ?, ?, ?) RETURNING id`;
  db.run(query, [
    sanitizedData.email,
    sanitizedData.nik,
    sanitizedData.full_name,
    sanitizedData.account_number,
    sanitizedData.initial_balance,
    sanitizedData.profile_bio
  ], /* ... */);
});
```

### 2) Pencarian Pengguna (SQL Injection vs Parameter Binding)

- Vulnerable: Query string dibangun dari parameter `email`/`nik` tanpa binding.

```js
// vuln-server.js
let query = 'SELECT * FROM users WHERE 1=1';
if (emailTrim) query += ` AND email = '${emailTrim}'`;
if (nikTrim)   query += ` AND nik = '${nikTrim}'`;
pool.query(query, /* ... */);
```

- Fixed: Validasi format parameter dan gunakan parameter binding, serta batasi kolom yang dikembalikan (non-sensitive saja).

```js
// secure-server.js
let query = 'SELECT id, email, full_name, account_number, created_at FROM users WHERE 1=1';
const params = [];
if (trimmedEmail) { query += ' AND email = ?'; params.push(trimmedEmail.toLowerCase()); }
if (trimmedNik)   { query += ' AND nik = ?';   params.push(trimmedNik); }
db.all(query, params, /* ... */);
```

### 3) Tampilan Profil (XSS Raw vs Output Sanitization)

- Vulnerable: HTML dirender dengan memasukkan `user.profile_bio` apa adanya (stored XSS akan dieksekusi saat halaman dibuka).

```js
// vuln-server.js
const profileHtml = `
  <!DOCTYPE html>
  <html>
  <body>
    <div class="profile">
      <h3>Bio:</h3>
      <div>${user.profile_bio}</div> <!-- TIDAK DISANITASI -->
    </div>
  </body>
  </html>
`;
res.send(profileHtml);
```

- Fixed: Semua field yang akan dirender di HTML disanitasi dengan `sanitizeHtml` pada saat output.

```js
// secure-server.js
const sanitizedUser = {
  full_name: sanitizeHtml(user.full_name),
  email: sanitizeHtml(user.email),
  nik: sanitizeHtml(user.nik),
  account_number: sanitizeHtml(user.account_number),
  profile_bio: sanitizeHtml(user.profile_bio || '')
};
// Lalu gunakan sanitizedUser.* saat membangun HTML
```

### 4) Update Bio (Input Sanitization sebelum ke DB)

- Vulnerable: Memperbarui bio tanpa sanitasi, dan merefleksikan input kembali sebagai respons (reflected XSS di klien yang menampilkan respons mentah).

```js
// vuln-server.js
app.put('/api/profile/:accountNumber/bio', (req, res) => {
  const query = 'UPDATE users SET profile_bio = $1 WHERE account_number = $2';
  pool.query(query, [req.body.profile_bio, req.params.accountNumber], (err, result) => {
    res.json({ message: 'Profile bio updated', updatedBio: req.body.profile_bio });
  });
});
```

- Fixed: Input disanitasi terlebih dahulu, baru disimpan; respons mengembalikan `sanitizedBio`.

```js
// secure-server.js
const sanitizedBio = sanitizeInput(req.body.profile_bio);
const query = 'UPDATE users SET profile_bio = ? WHERE account_number = ?';
db.run(query, [sanitizedBio, accountNumber], function(err) {
  res.json({ message: 'Profile bio updated successfully', sanitizedBio });
});
```

### 5) Transfer Uang (Race Condition & Overdraft vs Atomic Transactions)

- Vulnerable:
  - TIDAK ada validasi jumlah.
  - TIDAK ada cek saldo cukup (overdraft bisa terjadi).
  - Dua `UPDATE` dilakukan tanpa transaksi; jika salah satu gagal, state menjadi tidak konsisten.

```js
// vuln-server.js
const balanceQuery = `SELECT balance FROM users WHERE account_number = '${from_account}'`;
// ... hitung newBalance lalu UPDATE sender dan UPDATE receiver tanpa BEGIN/COMMIT
```

- Fixed:
  - Validasi format akun dan batas jumlah (`0.01`–`10,000,000`).
  - Cek saldo cukup sebelum transfer.
  - Gunakan transaksi database (`BEGIN`/`COMMIT`/`ROLLBACK`) dan parameter binding (`$1`, `$2`).

```js
// secure-server.js
await client.query('BEGIN');
const { rows: senderRows } = await client.query('SELECT balance FROM users WHERE account_number = $1', [from]);
if (sender.balance < amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient balance' }); }
await client.query('UPDATE users SET balance = balance - $1 WHERE account_number = $2', [amount, from]);
await client.query('UPDATE users SET balance = balance + $1 WHERE account_number = $2', [amount, to]);
await client.query('COMMIT');
```

### 6) Daftar Pengguna & Penghapusan (Information Disclosure & Authorization)

- Vulnerable:
  - Endpoint `GET /api/users` mengembalikan SELURUH kolom (termasuk `nik`, `balance`).
  - Endpoint `DELETE /api/users/:accountNumber` tanpa autentikasi/otorisasi.

- Fixed:
  - `GET /api/users` hanya menampilkan kolom non-sensitif: `id`, `full_name`, `account_number`, `created_at`.
  - Tidak ada endpoint `DELETE`; praktik aman adalah melakukan deactivation dan audit.

### 7) Middleware Keamanan & Error Handling

- Vulnerable:
  - Body limit sangat besar (`50mb`), tanpa `helmet`, tanpa rate limiting.
  - Error handler mengembalikan `stack trace` dan `query` ke klien.

- Fixed:
  - `helmet` dengan Content Security Policy (CSP).
  - Rate limiting umum dan ketat untuk operasi sensitif.
  - Body size limit `1mb`, pesan error generik tanpa membocorkan detail internal.

### Inti Perbaikan

- Validasi dan sanitasi input sebelum menyentuh database atau dirender.
- Prepared statements/parameterized queries untuk semua akses DB.
- Sanitasi output saat merender HTML (mencegah XSS).
- Transaksi atomik untuk operasi finansial agar konsisten.
- Batasi informasi yang diekspos dan hindari operasi destruktif tanpa otorisasi.