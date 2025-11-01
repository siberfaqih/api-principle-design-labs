# Secure API Design Principles: Logging & Monitoring Lab (Panduan Gabungan)

## 📋 Overview

Lab hands-on ini mengajarkan prinsip keamanan API dengan fokus pada Logging dan Monitoring. Dokumen ini menggabungkan materi dari README dan Exploitation Guide tanpa duplikasi, menjadi satu panduan komprehensif: arsitektur, setup, eksploitasi, implementasi secure, monitoring, troubleshooting, dan latihan lanjutan.

## 🎯 Learning Objectives

- Memahami pentingnya logging dan monitoring dalam keamanan API
- Mengidentifikasi kerentanan terkait praktik logging yang buruk
- Mengimplementasikan secure logging dengan data sanitization
- Mendeteksi serangan melalui security monitoring
- Membuat audit trail untuk compliance
- Menganalisis pola log untuk incident response
- Mengimplementasikan alerting system untuk real-time threat detection

## 🏗️ Lab Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Vulnerable    │    │   Secure API    │    │     MySQL       │
│      API        │    │   (Port 3001)   │    │   Database      │
│   (Port 3000)   │    │                 │    │   (Port 3306)   │
│                 │    │                 │    │                 │
│ ❌ Poor Logging │    │ ✅ Proper       │    │ • Users Table   │
│ ❌ No Monitoring│    │    Logging      │    │ • Audit Logs    │
│ ❌ SQL Injection│    │ ✅ Security     │    │ • Sessions      │
│ ❌ Weak Auth    │    │    Monitoring   │    │ • Dummy Data    │
│ ❌ Info Leakage │    │ ✅ Input Valid. │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📁 Project Structure

```
secure-api-logging-lab/
├── vulnerable-app/
│   └── server.js              # Vulnerable API (berbagai isu keamanan)
├── secure-app/
│   ├── server.js              # Secure API (proper logging & monitoring)
│   ├── logger.js              # Konfigurasi Winston
│   └── middleware.js          # Security middleware dengan logging
├── database/
│   └── init.sql               # Schema & dummy data
├── logs/                      # Direktori log files
├── docker-compose.yml         # Orkestrasi container
├── Dockerfile                 # Container Node.js
├── package.json               # Dependencies & scripts
├── .env.example               # Template environment variables
└── README.md                  # Panduan gabungan (file ini)
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- curl atau Postman untuk API testing
- Text editor untuk analisis kode

### 1. Setup Environment

```bash
# Clone atau download lab files
git clone <repository-url>
cd secure-api-logging-lab

# Copy environment variables
cp .env.example .env

# Edit .env file jika perlu
nano .env
```

### 2. Start Lab Environment

```bash
# Jalankan vulnerable application beserta database
docker-compose up vulnerable-api db

# Atau jalankan secure application untuk perbandingan
docker-compose up secure-api db

# Atau jalankan keduanya sekaligus
docker-compose up
```

### 3. Verify Setup

```bash
# Test vulnerable API
curl http://localhost:3000/health

# Test secure API
curl http://localhost:3001/health

# Cek koneksi database
docker exec -it secure_api_db mysql -u root -p -e "SHOW DATABASES;"
```

### 4. Endpoints
- Vulnerable API: http://localhost:3000
- Secure API: http://localhost:3001
- Database: localhost:3306

## 🔍 Vulnerability Analysis & Exploitation

### 1) Information Disclosure melalui Logging

- Vulnerability contoh di vulnerable app: logging data sensitif (password, JWT secret, token, kredensial DB).
- Langkah eksploitasi:
```bash
# Akses container logs
docker logs -f vulnerable_api

# Trigger login untuk melihat password di log
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```
- Dampak: Credential stuffing, session hijacking, system compromise.

### 2) SQL Injection dengan Poor Logging

- Vulnerability: Query tanpa parameterized queries.
- Contoh eksploitasi:
```bash
# Bypass authentication
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1 --","password":"anything"}'

# Database enumeration
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' UNION SELECT table_name,2,3,4,5,6,7,8,9 FROM information_schema.tables WHERE table_schema=database() --","password":"anything"}'
```
- Dampak: Full DB access, privilege escalation, data corruption.

### 3) Authentication Bypass & Session Management Issues

- Vulnerability: Tidak ada rate limiting/lockout, JWT secret lemah.
- Brute force contoh:
```bash
passwords=("admin" "password" "123456" "admin123" "password123")
for pass in "${passwords[@]}"; do
  echo "Trying password: $pass"
  curl -X POST http://localhost:3000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$pass\"}"
  echo ""
done
```

### 4) Authorization Bypass

- Vulnerability: Inconsistent checks & no logging untuk failed authorization.
- Eksploitasi: Role manipulation via SQLi, direct object reference.

### 5) Information Disclosure via Error Messages

- Vulnerability: Mengembalikan pesan error internal (DB version, struktur tabel, path).
- Eksploitasi: Trigger error untuk fingerprinting sistem.

## ✅ Secure Implementation Analysis

- Data sanitization untuk log: redaksi fields sensitif (`password`, `token`, `authorization`, dsb).
- Structured security logging: auth success/failure, authorization attempts, suspicious activity.
- Rate limiting dengan logging dan penandaan IP/UA.
- Parameterized queries dan validasi input.
- Environment-based configuration untuk kredensial.

Contoh pola:
```javascript
// Parameterized query
const [users] = await db.execute(
  'SELECT * FROM users WHERE username = ?',
  [username]
);

// Security logging
logAuthentication('password_mismatch', user.id, req.ip, req.get('User-Agent'), false, {
  failedAttempts: newFailedAttempts,
  accountLocked: shouldLock,
});
```

## 🔎 Security Monitoring

- Monitor file log: `logs/security.log`, `logs/audit.log`.
- Query audit DB:
```bash
docker exec -it secure_api_db mysql -u root -p -e "
USE secure_api_lab;
SELECT * FROM security_events 
WHERE severity IN ('HIGH','CRITICAL') 
  AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;
"
```

## Attack Scenarios & Detection

- Credential stuffing: track failed attempts, lockout setelah threshold.
- SQL injection: deteksi pola `union select`, `or 1=1`, log suspicious body/params.
- Privilege escalation: log authorization failures dan audit trail ke DB.

## 📣 Monitoring & Alerting Setup

### Log Analysis Queries
```sql
-- Failed login attempts
SELECT ip_address, COUNT(*) AS attempts, MAX(timestamp) AS last_attempt
FROM audit_logs
WHERE action = 'LOGIN_FAILED' AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY ip_address
HAVING attempts > 5;

-- Suspicious activities
SELECT * FROM security_events
WHERE severity IN ('HIGH','CRITICAL') AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;

-- Unauthorized access attempts
SELECT user_id, ip_address, COUNT(*) AS attempts
FROM audit_logs
WHERE action = 'UNAUTHORIZED_ACCESS' AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY user_id, ip_address;
```

### Alert Conditions

- High: multiple failed logins (IP sama), SQLi detection, unauthorized admin access, account lockout, suspicious UA
- Medium: login times/locations tidak biasa, banyak password change, volume request tinggi, lonjakan error rate

### Response Procedures

- Blok IP mencurigakan, kunci akun terdampak, invalidasi sesi mencurigakan, eskalasi ke tim security
- Investigasi: analisis pola log, cek exfiltrasi, verifikasi integritas, dokumentasi timeline

## 🐛 Troubleshooting

- Database: `docker-compose ps`, `docker-compose restart db`, `docker logs secure_api_db`
- Port conflicts: `lsof -i :3000`, `:3001`, `:3306`
- Log permissions: `chmod 755 logs/`, `chown -R $USER:$USER logs/`

## 🔧 Advanced Exercises

- Custom security rules: login time, geo anomalies, privilege escalation, data exfiltration
- Alerting system: middleware untuk kirim alert saat high risk
- ELK Stack: `docker-compose --profile monitoring up` lalu akses Kibana di `http://localhost:5601`

## ✅ Remediation Checklist

- Logging & Monitoring: structured logging, redaksi data sensitif, agregasi terpusat, rotasi, monitoring real-time, audit trail, alerting otomatis
- AuthN & AuthZ: rate limiting, lockout, JWT kuat, manajemen sesi, log semua event
- Input & SQL Security: parameterized queries, validasi input, deteksi SQLi, sanitasi error, least privilege DB
- Infrastruktur: env vars untuk config sensitif, error handling, security headers & CORS, request ID tracking

## 📊 Assessment Criteria

- Identifikasi 30+ vulnerabilities, eksploitasi, analisis log & monitoring, implementasi secure logging, rules detection, incident response

## 📝 Lab Report Template

- Executive Summary, Technical Findings, Recommendations

## 🔗 Additional Resources

- OWASP API Security Top 10, OWASP Logging Cheat Sheet, Winston Logging, Express Best Practices, Burp, ZAP, SQLMap, JWT.io

## 📄 License & ⚠️ Disclaimer

Lab ini untuk edukasi dan berisi aplikasi yang sengaja dibuat vulnerable. Jangan deploy ke production atau expose ke internet. Gunakan hanya pada environment yang terisolasi dan aman.

Happy Learning! 🚀