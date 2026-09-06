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

Platform dapat masuk ke aplikasi memakai **akun/session uji yang Anda kontrol** dan memvalidasi authorization setelah login.

Fitur:

- encrypted Test Identity Vault,
- form login dengan configurable login path/field,
- Laravel-style CSRF token support,
- Bearer API token identity,
- **provided dedicated test-session cookie replay**,
- configurable success/verification path,
- Role / Permission Matrix,
- Authorization boundary checks,
- IDOR/BOLA object-boundary checks,
- scheduled authenticated regression testing.

Contoh:

```text
Student Test -> /student/dashboard         = ALLOWED
Student Test -> /admin/users               = DENIED
Student Test -> /api/exam-results/OTHER_ID = DENIED (IDOR/BOLA)
Admin Test   -> /admin/users               = ALLOWED
```

Jika rule `DENIED` menerima HTTP `2xx`, assessment membuat finding **CRITICAL**. Resource checks menggunakan GET read-only.

#### Credential/session protection

Password, bearer token, dan provided test-session cookie:

- dienkripsi memakai Laravel `Crypt`,
- tidak disimpan plaintext,
- tidak pernah ditampilkan kembali melalui UI,
- tidak dimasukkan ke log/report,
- response body authenticated endpoint tidak disimpan.

Session-cookie mode **tidak mencuri cookie**. User harus memasukkan cookie dari dedicated test account yang memang dikontrol sendiri.

### Account Compromise Defense Lab

Module `account_compromise` menguji lapisan yang sering dipakai attacker sebelum account takeover, tetapi dengan bounded safety policy:

- **Login Enumeration Differential**: satu invalid attempt ke akun uji yang diketahui + satu ke username sintetis yang tidak ada.
- **Login Throttling / Lockout Signal**: maksimum tiga invalid attempts pada dedicated test account.
- Tidak ada password dictionary.
- Tidak ada password guessing.
- Tidak ada spraying/credential stuffing.
- Tidak ada brute-force loop.

Finding menjelaskan apakah perbedaan status/redirect/response size membocorkan keberadaan akun dan apakah sinyal 429/Retry-After/rate-limit terlihat pada probe awal.

### Laravel Agent Manifest

Module `laravel_agent` menambahkan **source-assisted security inventory** tanpa mengirim source code atau secret.

Copy:

```text
agent/laravel/SecurityManifestCommand.php
```

ke aplikasi Laravel target sebagai:

```text
app/Console/Commands/SecurityManifestCommand.php
```

lalu jalankan:

```bash
php artisan security:manifest --output=security-manifest.json
```

Import JSON tersebut dari halaman Security Session.

Manifest berisi metadata:

- route method/URI/name/action,
- middleware,
- Laravel/PHP version,
- APP_DEBUG boolean,
- session Secure/HttpOnly/SameSite posture.

Tidak mengekspor `APP_KEY`, password database, token, isi `.env`, source code, atau isi database.

Analyzer menandai antara lain:

- admin/diagnostic route tanpa recognized auth middleware,
- mutating POST/PUT/PATCH/DELETE route tanpa auth,
- admin-like route yang belum menunjukkan role/permission middleware,
- APP_DEBUG aktif,
- session Secure flag mati.

### Flexible Auto Monitoring

Auto monitoring bersifat **opt-in** dan default-nya OFF.

User dapat menjalankan manual saja, mengaktifkan monitoring kapan saja, menentukan interval jam/hari/minggu, mengubah interval, atau mematikannya tanpa menghapus history.

Batas interval minimum 1 jam dan maksimum 1 tahun. Sebelum auto-run, platform memverifikasi ulang proof-of-control.

Scheduled run mewarisi:

- encrypted test identities,
- authorization + IDOR/BOLA rules,
- account-security tests,
- Laravel Agent manifest terbaru.

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
- Sensitive File Exposure
- Authenticated Access & Privilege Boundaries
- Account Compromise Defense
- Laravel Agent Manifest
- DDoS Resilience Simulation dalam mode controlled-load dengan hard safety caps

### Sensitive File Exposure Scanner

Fixed paths saat ini mencakup `/.env`, `/.git/config`, Laravel log, SQLite database, backup SQL/ZIP, `.npmrc`, Composer `auth.json`, dan `phpinfo.php`.

Scanner membaca sampel kecil maksimal 2048 byte hanya untuk signature detection. Isi secret **tidak disimpan** ke database/report.

### Safety model

Platform sengaja **tidak** menyediakan:

- arbitrary flood,
- spoofing/botnet/amplification,
- raw packet attacks,
- password brute force / credential stuffing,
- phishing/credential theft,
- exploit payload generator,
- arbitrary file downloader,
- unauthorized account takeover,
- target-verification bypass.

Controlled/active checks hanya berjalan pada target yang sudah membuktikan kontrol melalui:

```text
https://target.example/.well-known/security-test-center.txt
```

### SSRF protection

- HTTP/HTTPS only.
- Port allowlist.
- localhost/link-local/cloud metadata blocked.
- private IP disabled by default.
- redirects disabled pada probe HTTP yang sensitif terhadap SSRF.

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
- Gunakan dedicated test accounts untuk authenticated/account-security scans.
- Backup database karena history assessment menjadi baseline posture jangka panjang.

## Architecture

```text
app/
├── Http/Controllers/
│   ├── AuthenticatedSecurityController.php
│   ├── AccountSecurityController.php
│   └── LaravelAgentController.php
├── Jobs/RunSecurityAudit.php
├── Models/
│   ├── SecurityIdentity.php
│   ├── SecurityAccessRule.php
│   ├── SecurityAccountTest.php
│   └── SecurityAgentManifest.php
└── Services/SecurityAudit/
    ├── AuthenticatedSessionService.php
    ├── AccountSecurityService.php
    └── Scanners/
        ├── AuthenticatedAccessScanner.php
        ├── AccountCompromiseScanner.php
        ├── LaravelAgentScanner.php
        └── SensitiveFilesScanner.php
```

## CI

GitHub Actions menjalankan dependency install, migrations, PHP syntax validation, dan automated tests untuk TargetGuard, posture regression, flexible monitoring, encrypted identity/session-cookie vault, Broken Access Control, IDOR/BOLA, Account Compromise Defense, serta Laravel Agent analyzer.

## Scope

Platform ini adalah defensive security posture system untuk aset yang Anda kuasai. Pengembangan enterprise berikutnya dapat mencakup OpenAPI inventory, source/runtime correlation yang lebih dalam, dependency/SAST analysis, policy gates, notifications, evidence retention policy, dan isolated scanner workers.
