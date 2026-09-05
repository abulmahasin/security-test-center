# Security Test Center

Laravel 12 dashboard untuk melakukan **authorized security assessment** terhadap aplikasi yang Anda miliki/kelola.

## Fitur

- Multi-session security testing.
- Proof-of-control target verification via `/.well-known/security-test-center.txt`.
- SSRF guard:
  - HTTP/HTTPS only.
  - port allowlist.
  - localhost/link-local/cloud metadata blocked.
  - private IP disabled by default.
- Queue-based progress.
- Security modules:
  - Security Headers
  - TLS Certificate
  - Cookie Security
  - CORS Policy
  - Information Exposure
  - Rate Limit Signals
  - Latency Baseline
  - **DDoS Resilience Simulation** dalam mode controlled-load dengan hard safety caps.
- Findings by severity + evidence + remediation.
- Security score.
- JSON report export.
- Authenticated private workspace.

## Safety model

Aplikasi ini sengaja **tidak** menyediakan arbitrary flood, spoofing, botnet, UDP amplification, raw packet attack, credential attack, exploit payload generator, atau bypass target verification.

Controlled-load hanya dapat berjalan setelah target berhasil membuktikan kontrol dengan file:

```text
https://target.example/.well-known/security-test-center.txt
```

Isi file harus sama persis dengan token yang dihasilkan oleh sesi.

Hard limits berada di server `.env`, bukan hanya di UI:

```env
SECURITY_TEST_LOAD_MAX_VUS=20
SECURITY_TEST_LOAD_MAX_RPS=20
SECURITY_TEST_LOAD_MAX_DURATION=30
SECURITY_TEST_LOAD_MAX_REQUESTS=600
```

## Requirements

- PHP 8.3+
- Composer 2
- SQLite/MySQL
- PHP extensions standar Laravel + OpenSSL
- Queue worker untuk progress async

## Install

```bash
composer install
cp .env.example .env
php artisan key:generate

touch database/database.sqlite
php artisan migrate

php artisan app:create-admin admin@example.com 'gunakan-password-kuat-minimal-12-karakter'

php artisan serve
```

Terminal kedua:

```bash
php artisan queue:work --tries=1 --timeout=180
```

Buka:

```text
http://127.0.0.1:8000
```

## MySQL

Ganti `.env`:

```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=security_test_center
DB_USERNAME=root
DB_PASSWORD=
```

Lalu:

```bash
php artisan migrate
```

## Testing private/internal applications

Private/reserved IP diblokir secara default untuk mengurangi SSRF risk.

Jika Security Test Center memang berada pada jaringan internal yang Anda kontrol:

```env
SECURITY_TEST_ALLOW_PRIVATE_TARGETS=true
```

Tetap gunakan firewall dan deploy aplikasi ini sebagai private/admin-only tool.

## Production deployment

Rekomendasi:

- HTTPS wajib.
- `APP_DEBUG=false`.
- Gunakan MySQL/PostgreSQL.
- Redis untuk queue/cache bila beban meningkat.
- Jalankan queue worker via Supervisor/systemd.
- Batasi akses dashboard dengan VPN/Zero Trust atau allowlist admin.
- Jangan expose dashboard ke internet tanpa proteksi autentikasi tambahan.
- Jalankan controlled-load saat maintenance window.
- Pisahkan mesin Security Test Center dari target production bila pengujian load lebih serius.

## Queue

Default:

```env
QUEUE_CONNECTION=database
```

Worker:

```bash
php artisan queue:work --tries=1 --timeout=180
```

## Struktur

```text
app/
├── Http/Controllers/
├── Jobs/RunSecurityAudit.php
├── Models/
└── Services/SecurityAudit/
    ├── Scanners/
    ├── HttpProbe.php
    ├── TargetGuard.php
    ├── VerificationService.php
    └── ScoreCalculator.php
```

## Catatan

Scanner ini adalah baseline defensive assessment. Untuk audit enterprise lebih lanjut, integrasikan hasil dengan ZAP/Burp Enterprise/Nuclei dalam runner yang diisolasi dan tetap memakai allowlist + proof-of-control.
