Secure API Design Principles Lab (Node.js)

Lab ini menyediakan dua API: vuln-api (tidak aman) dan secure-api (aman) untuk menunjukkan data encryption in-rest dan in-transit.

Cara jalan:
- `docker compose up --build`
- vuln API: `http://localhost:3001`, secure API: `http://localhost:3002`
- Lihat `WRITEUP.md` untuk skenario eksploitasi, langkah uji, dan penjelasan kode vuln vs fix.

Menggunakan Decrypt Tool:
- Postman: di folder Secure API jalankan `Tools: Decrypt Payload (verify)`.
  - Pastikan `encrypted_payload` sudah terisi: jalankan `Tools: Encrypt Payload` atau set variabel koleksi `encrypted_payload` (klik ikon mata di URL → Collection variables).
  - Request akan mengirim `text/plain` berisi base64 ciphertext ke `/tools/decrypt` dan mengembalikan JSON plaintext.
- Curl: `curl -X POST http://localhost:3002/tools/decrypt -H 'Content-Type: text/plain' --data '<base64>'`
- CLI: di folder `secure-api` jalankan `npm run decrypt -- "<base64>"`.