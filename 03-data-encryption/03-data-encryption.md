# Writeup: Eksploitasi dan Perbaikan

Tujuan lab: menunjukkan perbedaan desain API yang tidak aman vs aman terkait data encryption (in-rest dan in-transit).

## Skenario
- PII: `full_name`, `email`, `national_id`.
- At-rest (DB):
  - vuln: disimpan plaintext di tabel `users_plain`.
  - fix: disimpan sebagai ciphertext (AES-256-GCM) di tabel `users_secure`. Admin endpoint hanya menampilkan `ciphertext_b64`.
- In-transit (HTTP body):
  - vuln: body request JSON plaintext, terbaca jelas dengan Burp.
  - fix: body request full-body encrypted base64 string. Server mendekripsi dulu baru proses.

## Jalankan Lab
1. `docker compose build && docker compose up -d`
2. Port layanan:
   - vuln-api: `http://localhost:3000`
   - secure-api: `http://localhost:3001`
   - ui-server: `http://localhost:4000`
3. Cek health:
   - vuln: `curl http://localhost:3000/health`
   - secure: `curl http://localhost:3001/health`
4. Catatan konflik Postgres:
   - Jika port `5432` host sudah dipakai, jalankan tanpa mapping host (akses antar-service via `db:5432` internal network) atau matikan Postgres lokal.

## Eksploitasi vuln-api
- Admin dump PII:
  - `curl http://localhost:3001/admin/users` → kembalikan plaintext PII.
- Intercept in-transit:
  - Kirim insert: `curl -X POST http://localhost:3001/users -H 'Content-Type: application/json' -d '{"full_name":"Charlie","email":"charlie@example.com","national_id":"1111222233334444"}'`
  - Di Burp, body terlihat plaintext JSON.
- At-rest:
  - Masuk ke DB dan `SELECT * FROM users_plain;` semua PII terlihat.

## Verifikasi secure-api
- Enkripsi payload (client helper):
  - `curl -X POST http://localhost:3001/tools/encrypt -H 'Content-Type: application/json' -d '{"full_name":"Charlie","email":"charlie@example.com","national_id":"1111222233334444"}'`
  - Ambil `encrypted` base64.
- Kirim ke `/users`:
  - `curl -X POST http://localhost:3001/users -H 'Content-Type: text/plain' --data '<base64 dari langkah sebelumnya>'`
  - Di Burp, body terlihat base64 *tanpa* PII plaintext; sebenarnya ciphertext AES-GCM.
- Admin list:
  - `curl http://localhost:3001/admin/users` → hanya base64 ciphertext.
- At-rest:
  - `SELECT id, encode(ciphertext,'base64') FROM users_secure;` data terenkripsi.

## Kode VULN vs FIX

### VULN (in-transit & at-rest)
File: `vuln-api/src/index.js`
- Parsing JSON plaintext: `app.use(express.json());`
- Insert plaintext: `INSERT INTO users_plain (full_name, email, national_id) ...`
- Admin baca plaintext: `SELECT id, full_name, email, national_id FROM users_plain`

### FIX (in-transit & at-rest)
File: `secure-api/src/index.js`
- Full-body encrypted in-transit:
  - Server menerima `text/plain` base64 dan `decryptObject(req.body)`.
- At-rest encrypted:
  - `encryptObject({ full_name, email, national_id })` → simpan `BYTEA` ciphertext.
- Admin endpoint hanya mengembalikan `ciphertext_b64`.

File: `secure-api/src/crypto.js`
- AES-256-GCM dengan IV 12 byte dan Auth Tag.
- Format packing: `[iv|tag|ciphertext]` → base64 untuk transmit.

## Catatan Keamanan
- Key management: gunakan KMS atau env yang aman. Di lab, key diset via `ENCRYPTION_KEY_BASE64`.
- Jangan expose plaintext PII ke admin endpoint; gunakan access pattern minimal.
- Pertimbangkan field-level encryption jika butuh query spesifik (tidak ditunjukkan di lab ini).

## Cek DB: Plaintext vs Terenkripsi

**Via psql (langsung ke DB di container)**
- Plaintext:
  - `docker compose exec db psql -U labuser -d labdb -c "SELECT id, full_name, email, national_id, role FROM users_plain;"`
- Terenkripsi (BYTEA → base64 agar terbaca):
  - `docker compose exec db psql -U labuser -d labdb -c "SELECT id, encode(ciphertext, 'base64') AS ciphertext_b64, role FROM users_secure;"`

**Via API**
- Ambil daftar terenkripsi (secure-api):
  - `curl -s http://localhost:3001/admin/users | jq`
- Dekripsi satu ciphertext (helper endpoint):
  - `curl -s -X POST http://localhost:3001/tools/decrypt -H 'Content-Type: text/plain' --data '<ciphertext_base64>' | jq`
- Tambah plaintext ke vuln-api:
  - `curl -s -X POST http://localhost:3000/users -H 'Content-Type: application/json' --data '{\"full_name\":\"Charlie\",\"email\":\"charlie@example.com\",\"national_id\":\"9999999999999999\"}' | jq`
- Tambah terenkripsi ke secure-api:
  - Enkripsi payload: `docker compose exec secure-api node scripts/encrypt.js '{\"full_name\":\"Dana\",\"email\":\"dana@example.com\",\"national_id\":\"1111222233334444\"}'`
  - Simpan via API: `curl -s -X POST http://localhost:3001/users -H 'Content-Type: text/plain' --data '<output_base64>' | jq`

**Skema Tabel**
- `users_plain`: `id`, `full_name`, `email`, `national_id`, `role`
- `users_secure`: `id`, `ciphertext` (BYTEA, AES-GCM packed `[iv|tag|ciphertext]`), `role`

## Port & UI
- vuln-api: `3000`
- secure-api: `3001`
- ui-server: `4000`
- Buka UI: `http://localhost:4000/` (CONFIG di UI menunjuk ke port di atas)