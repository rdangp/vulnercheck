# URL Vulnerability Scanner

Web aplikasi sederhana untuk melakukan passive defensive scan pada URL website.

## Fitur

- Validasi target URL
- Proteksi SSRF: blok target localhost/private IP/internal
- Rate limit API
- Cek HTTP/HTTPS
- Cek informasi SSL/TLS
- Cek security headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options / frame-ancestors
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - CORS wildcard
  - Server / X-Powered-By disclosure
- Cek cookie flags:
  - HttpOnly
  - Secure
  - SameSite
- Export hasil scan ke JSON

## Cara Menjalankan

```bash
npm install
npm start
```

Buka:

```text
http://localhost:3000
```

## Catatan Legal

Gunakan hanya untuk website milik sendiri atau website yang Anda punya izin tertulis untuk diuji.
Aplikasi ini bersifat pasif dan tidak melakukan eksploitasi, brute force, crawling agresif, atau payload injection.
