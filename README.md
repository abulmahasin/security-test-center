# Security Test Center

Laravel 12 platform untuk **authorized continuous security assessment** terhadap aplikasi yang Anda miliki/kelola.

## Platform capabilities

Security Test Center tidak lagi sekadar menjalankan scan satu kali. Setiap completed assessment menjadi bagian dari **security posture history** sehingga perubahan keamanan dapat dibandingkan dari waktu ke waktu.

### Continuous Security Posture

- Security score + grade `A+` sampai `F`.
- Compliance score berdasarkan modul yang dipilih dan severity hasil audit.
- Baseline otomatis dari assessment sebelumnya untuk target URL yang sama.
- Risk delta terhadap baseline.
- Stable finding fingerprint.
- Finding state `NEW` dan `PERSISTENT`.
- Resolved finding detection.
- Dashboard trend score + compliance.
- Regression counter.
- New/resolved finding metrics.

### Authenticated Security & Privilege Boundaries

Platform dapat masuk ke aplikasi memakai **akun uji yang Anda kontrol** dan memvalidasi authorization setelah login.

Fitur:

- encrypted Test Identity Vault,
- form login dengan configurable login path,
- configurable username field,
- configurable password field,
- Laravel-style CSRF hidden token/meta token support,
- Bearer API token identity,
- configurable success/verification path,
- Role / Permission Matrix,
- read-only privilege boundary checks,
- Broken Access Control detection,
- scheduled authenticated regression testing.

Contoh matrix:

```text
Student Test -> /student/dashboard = ALLOWED
Student Test -> /admin/users       = DENIED
Teacher Test -> /teacher/exams     = ALLOWED
Teacher Test -> /admin/settings    = DENIED
Admin Test   -> /admin/users       = ALLOWED
```

Jika rule `DENIED` menerima HTTP `2xx`, assessment membuat finding **CRITICAL Broken Access Control** karena akun role rendah ternyata dapat membaca resource role tinggi.

Authenticated resource checks hanya menggunakan **GET read-only**. Platform tidak menggunakan brute-force password, credential stuffing, account takeover terhadap akun nyata, atau destructive state-changing actions.

#### Credential protection

Password dan bearer token:

- dienkripsi memakai Laravel `Crypt`,
- tidak disimpan plaintext,
- tidak pernah ditampilkan kembali melalui UI,
- tidak dimasukkan ke log,
- tidak dimasukkan ke JSON report,
- evidence selalu menandai `credentials_redacted=true`,
- response body authenticated endpoint tidak disimpan sebagai evidence.

Gunakan akun khusus testing bila memungkinkan, bukan akun user produksi sehari-hari.

### Flexible Auto Monitoring

Auto monitoring bersifat **opt-in** dan default-nya OFF.

User dapat:

- menjalankan assessment manual saja,
- mengaktifkan monitoring kapan saja,
- menentukan interval sendiri dalam jam, hari, atau minggu,
- mengubah interval tanpa membuat session baru,
- mematikan monitoring kapan saja tanpa menghapus history.

Batas interval minimum 1 jam dan maksimum 1 tahun.

Sebelum setiap auto-run, platform **memverifikasi ulang proof-of-control**. Jika verification file hilang atau berubah, scheduled audit tidak dijalankan.

Scheduled run menyalin encrypted identity vault + authorization matrix sebagai ciphertext sehingga authenticated regression test dapat berjalan tanpa mengekspos secret.

### Security modules

- Security Headers
- TLS Certificate
- Cookie Security
- CORS Policy
- Information Exposure
- Rate Limit Signals
- Latency Baseline
- RFC 9116 `security.txt`
- Passive HTTP Method Exposure
- Passive DNS Posture
- **Sensitive File Exposure**
- **Authenticated Access & Privilege Boundaries**
- **DDoS Resilience Simulation** dalam mode controlled-load dengan hard safety caps

### Sensitive File Exposure Scanner

Scanner mengetahui apakah file yang seharusnya private ternyata dapat dibaca melalui web server.

Fixed paths saat ini:

- `/.env`
- `/.git/config`
- `/storage/logs/laravel.log`
- `/database/database.sqlite`
- `/backup.sql`
- `/backup.zip`
- `/.npmrc`
- `/auth.json`
- `/phpinfo.php`

Scanner membaca sampel kecil maksimal 2048 byte hanya untuk signature detection. Isi secret **tidak disimpan** ke database/report.

Evidence hanya menyimpan path, HTTP status, matched signature, sample limit, dan `content_redacted=true`.

### Safety model

Platform sengaja **tidak** menyediakan:

- arbitrary flood,
- spoofing,
- botnet controls,
- UDP amplification,
- raw packet attacks,
- password brute force / credential stuffing,
- exploit payload generator,
- arbitrary file downloader,
- unauthorized account takeover,
- target-verification bypass.

Controlled-load hanya berjalan pada target yang sudah membuktikan kontrol melalui:

```text
https://target.example/.well-known/security-test-center.txt
```

Hard limits dikunci server-side:

```env
SECURITY_TEST_LOAD_MAX_VUS=20
SECURITY_TEST_LOAD_MAX_RPS=20
SECURITY_TEST_LOAD_MAX_DURATION=30
SECURITY_TEST_LOAD_MAX_REQUESTS=600
```

### SSRF protection

- HTTP/HTTPS only.
- Port allowlist.
- localhost blocked.
- link-local blocked.
- cloud metadata endpoints blocked.
- private IP disabled by default.
- redirects disabled pada probe HTTP agar public target tidak dapat redirect scanner ke internal network.

## Requirements

- PHP 8.3+
- Composer 2
- SQLite/MySQL/PostgreSQL
- PHP OpenSSL
- Queue worker
- Laravel scheduler untuk auto monitoring

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

Queue worker:

```bash
php artisan queue:work --tries=1 --timeout=180
```

## Auto monitoring scheduler

```cron
* * * * * cd /path/to/security-test-center && php artisan schedule:run >> /dev/null 2>&1
```

Untuk local development:

```bash
php artisan schedule:work
```

Dispatcher internal:

```bash
php artisan security:dispatch-scheduled
```

## Testing private/internal applications

Private/reserved IP diblokir secara default. Untuk deployment internal yang memang Anda kontrol:

```env
SECURITY_TEST_ALLOW_PRIVATE_TARGETS=true
```

Tetap deploy platform sebagai private/admin-only tool dan batasi jaringan scanner.

## Production deployment

- HTTPS wajib.
- `APP_DEBUG=false`.
- MySQL/PostgreSQL untuk production.
- Redis direkomendasikan untuk queue/cache.
- Queue worker via Supervisor/systemd.
- Scheduler via cron/systemd.
- Dashboard di belakang VPN, Zero Trust, atau admin allowlist.
- Jalankan controlled-load pada maintenance window.
- Gunakan dedicated test accounts untuk authenticated scans.
- Backup database karena history assessment menjadi baseline posture jangka panjang.

## Architecture

```text
app/
├── Http/Controllers/
│   └── AuthenticatedSecurityController.php
├── Jobs/
│   └── RunSecurityAudit.php
├── Models/
│   ├── SecurityIdentity.php
│   └── SecurityAccessRule.php
└── Services/SecurityAudit/
    ├── AuthenticatedSessionService.php
    ├── Scanners/
    │   ├── AuthenticatedAccessScanner.php
    │   └── SensitiveFilesScanner.php
    ├── HttpProbe.php
    ├── TargetGuard.php
    ├── VerificationService.php
    ├── ScoreCalculator.php
    ├── PostureAnalyzer.php
    └── SecurityAuditManager.php
```

## CI

GitHub Actions menjalankan:

- Composer dependency install,
- database migrations,
- PHP syntax validation,
- automated tests untuk TargetGuard,
- posture baseline/regression engine,
- flexible monitoring controls,
- encrypted identity vault,
- Critical Broken Access Control classification.

## Scope

Platform ini adalah defensive security posture system untuk aset yang Anda kuasai. Tahap enterprise berikutnya dapat menambahkan IDOR/BOLA object-boundary tests, OpenAPI inventory, Laravel security agent, source/runtime correlation, dependency/SAST analysis, policy gates, notifications, dan isolated scanner workers.
