# Hands-on Lab: Secure API Design (Rate Limiting & Throttling)

Lab ini menggunakan Node.js (Express) untuk mendemonstrasikan prinsip Secure API Design terkait Rate Limiting & Throttling dengan dua aplikasi:

- Aplikasi vuln (tidak aman): `app-vuln` pada port `3000`
- Aplikasi fix (aman): `app-fixed` pada port `3001`

Database: PostgreSQL dengan tabel `users` dan `items` + dummy data yang otomatis diinisialisasi saat Docker dijalankan. Redis digunakan untuk penyimpanan rate-limit pada aplikasi fix.

## Menjalankan Lab

- Pastikan Docker terinstall.
- Jalankan: `docker compose up --build`
- Tunggu hingga semua service siap (Postgres healthy). 

Endpoint utama:
- `GET http://localhost:3000/api/items` (vuln)
- `POST http://localhost:3000/api/search` (vuln)
- `GET http://localhost:3001/api/items` (fix)
- `POST http://localhost:3001/api/search` (fix) dengan header `X-API-Key`

Dummy API keys:
- Free: `11111111-1111-1111-1111-111111111111`
- Pro: `22222222-2222-2222-2222-222222222222`

## Skenario Eksploitasi (Vuln)

Tujuan: Menunjukkan dua kelemahan umum pada rate limiting & throttling.

1) Bypass rate limit via spoofed header
- Aplikasi vuln menggunakan limiter berbasis IP yang SALAH mempercayai header `X-Forwarded-For` dari klien.
- Penyerang dapat memalsukan `X-Forwarded-For` untuk mengubah identitas IP tanpa batas.

Contoh serangan:
```
# Kirim 120 request dalam 1 menit dengan IP berbeda-beda palsu
for i in $(seq 1 120); do \
  curl -s -H "X-Forwarded-For: 1.2.3.$i" http://localhost:3000/api/items >/dev/null; \
done
```

Hasil: Rate limit tidak efektif karena bucket dihitung berdasarkan header yang bisa dimanipulasi.

2) DoS melalui endpoint berat tanpa throttling efektif
- Endpoint `/api/search` melakukan kerja CPU-bound ~500ms per request.
- Tanpa throttling per-user, banyak request paralel dapat menekan CPU dan menghabiskan resource.

Contoh serangan:
```
# 50 request paralel ke endpoint berat
seq 1 50 | xargs -I{} -P 50 curl -s \
  -X POST http://localhost:3000/api/search \
  -H 'Content-Type: application/json' \
  -d '{"q":"a"}' >/dev/null
```

Hasil: CPU spike, potensi 503 dan latensi ekstrem; limiter global tak efektif.

## Cuplikan Kode Vulnerable

IP-based limiter yang salah mempercayai header (server `vulnerable/server.js`):
```
const buckets = {};
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.ip; // Trusting attacker-controlled header
  const now = Date.now();
  const b = buckets[ip] || { count: 0, reset: now + 60 * 1000 };
  if (b.reset < now) { b.count = 0; b.reset = now + 60 * 1000; }
  b.count++;
  buckets[ip] = b;
  if (b.count > 100) return res.status(429).json({ error: 'Too many requests (vuln limiter)' });
  next();
});
```

Naive throttling global:
```
let pending = 0;
app.use((req, res, next) => {
  pending++;
  if (pending > 1000) return res.status(503).json({ error: 'Server busy (vuln throttle)' });
  res.on('finish', () => { pending = Math.max(0, pending - 1); });
  next();
});
```

Masalah:
- Memakai `X-Forwarded-For` sebagai sumber kebenaran IP.
- Fixed window counter (burst besar saat reset, tidak adil).
- In-memory (tidak terdistribusi, reset saat restart).
- Throttle global tidak melindungi per pengguna/endpoint.

## Perbaikan (Fixed)

Strategi perbaikan di `fixed/server.js`:
- Rate limiting terdistribusi dengan Redis dan kunci berdasarkan `X-API-Key` (fallback ke IP).
- Header standar, tanpa header legacy.
- Throttling per user dengan Bottleneck: kontrol `maxConcurrent` dan `highWater`.
- Memisahkan authentikasi sederhana (mengenali plan `free` vs `pro` untuk diferensiasi kuota).

Cuplikan limiter aman:
```
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => (req.user?.plan === 'pro' ? 300 : 60),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.api_key || req.ip,
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) })
});
```

Cuplikan throttling per-key:
```
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
```

## Uji Coba Perbaikan

1) Rate limiting per user:
```
# 80 request dalam 1 menit dengan API key free
for i in $(seq 1 80); do \
  curl -s -X POST http://localhost:3001/api/search \
    -H 'Content-Type: application/json' \
    -H 'X-API-Key: 11111111-1111-1111-1111-111111111111' \
    -d '{"q":"a"}' >/dev/null; \
done
```
Beberapa request akan menerima `429 Too Many Requests` setelah melewati batas 60/m.

2) Throttling per user:
```
# 10 request paralel user free (dibatasi maxConcurrent=2)
seq 1 10 | xargs -I{} -P 10 curl -s \
  -X POST http://localhost:3001/api/search \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: 11111111-1111-1111-1111-111111111111' \
  -d '{"q":"a"}' >/dev/null
```
Permintaan akan dijadwalkan oleh Bottleneck sehingga beban CPU tetap terkendali.

## Struktur Proyek

- `vulnerable/` — kode tidak aman
- `fixed/` — kode perbaikan aman
- `docker-compose.yml` — orkestrasi services
- `docker/initdb/*.sql` — skema & seed data Postgres

## Catatan Keamanan Tambahan

- Di lingkungan produksi, pertimbangkan pengaturan `app.set('trust proxy', 1)` saat berada di belakang reverse proxy yang terpercaya.
- Gunakan store terdistribusi untuk limiter (Redis) dan monitoring kuota per pengguna.
- Evaluasi kebutuhan kombinasi limiter (rate, burst, sliding window) dan throttle (concurrency, queueing) berdasarkan profil beban.