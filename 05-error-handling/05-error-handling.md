# Lab: Secure API Design Principles (Error Handling) – Node.js

Lab hands-on untuk mempelajari prinsip Secure API Design khususnya Error Handling dengan dua implementasi: `vuln-api` (rentan) dan `secure-api` (diperbaiki). Lab ini menyiapkan database Postgres dengan data dummy dan dua service API yang siap dieksplorasi via Docker Compose.

## Tujuan Belajar
- Mendesain format error yang konsisten, aman, dan non-bocor.
- Memetakan error internal menjadi HTTP status dan kode error yang tepat.
- Membedakan error operasional (misconfig, DB conflict) vs programmer error.
- Menangani unhandled rejections/exceptions agar service tetap andal.
- Menambahkan korelasi `requestId` untuk observabilitas.

## Arsitektur
- `db` (Postgres): auto-init tabel `users` + seed data via `db/init.sql`.
- `vuln-api`: implementasi buruk dalam penanganan error (leak stack/DB details, crash route).
- `secure-api`: implementasi aman (validasi, centralized error handler, mapping, redaksi pesan).

## Menjalankan Lab
1. Pastikan Docker terpasang.
2. Jalankan: `docker-compose up --build -d`
3. Service:
   - DB: `localhost:5434`
   - vuln-api: `http://localhost:3000`
   - secure-api: `http://localhost:3001`

Data awal pada tabel `users`: `alice@example.com`, `bob@example.com`, `carol@example.com`.

## Endpoint Utama
- `GET /health` – health check.
- `GET /users/:id` – ambil user by `id`.
- `POST /users` – buat user baru `{ email, name }`.
- `GET /debug` – memicu error untuk observasi handler.
- `GET /crash` – simulasi kegagalan (vuln: crash proses; secure: ditangani).

## Eksploitasi: API Rentan (vuln-api)
Semua contoh di bawah menggunakan `http://localhost:3000`.

1) Bocor stack trace via `/debug`
```
curl -i http://localhost:3000/debug
```
Ekspektasi: Response 500 yang berisi `stack` dari Node/Express dan detail internal (buruk untuk keamanan karena mengungkap struktur aplikasi).

2) Bocor detail DB pada constraint error via `POST /users`
```
curl -i -X POST http://localhost:3000/users \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","name":"Another Alice"}'
```
Ekspektasi: Response 500 yang mengandung field seperti `code: 23505`, `detail`, dan nama constraint Postgres (mis. `users_email_key`). Informasi ini dapat membantu penyerang memahami skema internal dan menyusun serangan lanjutan.

3) Memicu invalid input untuk DB dan melihat bocoran
```
curl -i http://localhost:3000/users/abc
```
Ekspektasi: Response 500 JSON berisi error Postgres `invalid input syntax for type integer` (internal DB detail bocor).

4) Crash proses via `/crash`
```
curl -i http://localhost:3000/crash
# Lalu coba health
curl -i http://localhost:3000/health
```
Ekspektasi: Endpoint `/health` tidak merespon karena proses crash. Server down akibat unhandled exception.

## Perilaku Aman: API Diperbaiki (secure-api)
Gunakan `http://localhost:3001` untuk perbandingan.

1) `/debug` memberikan error aman
```
curl -i http://localhost:3001/debug
```
Ekspektasi: Response 500 dengan format konsisten:
```
{
  "error": {"code": "INTERNAL_SERVER_ERROR", "message": "Something went wrong"},
  "requestId": "..."
}
```
Tanpa stack trace atau detail internal.

2) Validasi input mencegah error DB yang tidak perlu
```
curl -i -X POST http://localhost:3001/users \
  -H 'Content-Type: application/json' \
  -d '{"email":"not-an-email","name":"Alice"}'
```
Ekspektasi: Response 400 `VALIDATION_ERROR` dengan pesan ringkas, bukan error Postgres.

3) Mapping constraint error menjadi 409
```
curl -i -X POST http://localhost:3001/users \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","name":"Another Alice"}'
```
Ekspektasi: Response 409 dengan kode `USER_EMAIL_EXISTS` tanpa detail DB.

4) `GET /users/:id` validasi parameter dan not-found yang jelas
```
curl -i http://localhost:3001/users/abc    # 400 INVALID_USER_ID
curl -i http://localhost:3001/users/99999  # 404 USER_NOT_FOUND
```

5) `/crash` tidak mematikan proses
```
curl -i http://localhost:3001/crash
curl -i http://localhost:3001/health
```
Ekspektasi: Health tetap `ok`; error dicatat server-side tapi tidak bocor.

## Cuplikan Kode: Bagian Rentan vs Perbaikan

### Rentan: Bocor error langsung ke klien
File: `vuln-api/src/index.js`
```
// BAD: leak raw error object
} catch (err) {
  res.status(500).json(err);
}
```

### Perbaikan: Centralized error handler + mapping aman
File: `secure-api/src/index.js`
```
// Map known Postgres errors
if (err && err.code === '23505') {
  return sendError(res, req, 409, 'USER_EMAIL_EXISTS', 'Email already exists');
}

// Centralized error handler
app.use((err, req, res, next) => {
  console.error(`[${req.requestId}]`, err && err.stack ? err.stack : err);
  sendError(res, req, 500, 'INTERNAL_SERVER_ERROR', 'Something went wrong');
});
```

### Rentan: Crash proses dengan unhandled exception
File: `vuln-api/src/index.js`
```
app.get('/crash', (req, res) => {
  res.json({ triggered: true });
  setImmediate(() => { throw new Error('Process crash'); });
});
```

### Perbaikan: Tangani promise rejections di route dan proses-level
File: `secure-api/src/index.js`
```
app.get('/crash', async (req, res, next) => {
  try { await Promise.reject(new Error('Simulated async failure')); }
  catch (err) { next(err); }
});

process.on('unhandledRejection', (reason) => { console.error('[unhandledRejection]', reason); });
process.on('uncaughtException', (error) => { console.error('[uncaughtException]', error.stack || error); });
```

### Rentan: Tidak ada validasi input
File: `vuln-api/src/index.js`
```
const { email, name } = req.body; // not validated
```

### Perbaikan: Validasi dengan express-validator
File: `secure-api/src/index.js`
```
body('email').isEmail().withMessage('email must be valid'),
body('name').isString().isLength({ min: 1, max: 100 })
```

## Prinsip Secure API Design yang Diterapkan
- Konsistensi format error: `error.code`, `error.message`, `requestId`.
- Redaksi pesan: klien tidak menerima stack trace / detail DB.
- Validasi input: mencegah error operasional dan input tidak valid.
- HTTP status yang tepat: 400, 404, 409, 500.
- Observabilitas: `X-Request-Id` dan logging internal.
- Safeguards: handler `unhandledRejection`/`uncaughtException`.

## Pembersihan
Untuk menghentikan semua container:
```
docker-compose down
```

## Catatan
- `vuln-api` berjalan dengan `NODE_ENV=development` untuk memperlihatkan kebocoran error default Express.
- `secure-api` berjalan dengan `NODE_ENV=production` dan middleware tambahan agar respons tetap aman.