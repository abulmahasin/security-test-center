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
- Finding state:
  - `NEW`
  - `PERSISTENT`
- Resolved finding detection.
- Dashboard trend score + compliance.
- Regression counter.
- New/resolved finding metrics.

### Continuous monitoring

Session dapat dijadikan template monitoring:

- Manual
- Daily
- Weekly
- Monthly

Sebelum scheduled run, platform **memverifikasi ulang proof-of-control**. Jika verification file sudah hilang atau berubah, scheduled audit tidak dijalankan.

Scheduler membuat session baru untuk setiap run sehingga history, baseline, evidence, dan trend tidak ditimpa.

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
- **DDoS Resilience Simulation** dalam mode controlled-load dengan hard safety caps

### Safety model

Platform sengaja **tidak** menyediakan:

- arbitrary flood
- spoofing
- botnet controls
- UDP amplification
- raw packet attacks
- credential attacks
- exploit payload generator
- target-verification bypass

Controlled-load hanya dapat berjalan pada target yang sudah membuktikan kontrol melalui:

```text
https://target.example/.well-known/security-test-center.txt
```

Isi file harus sama persis dengan token yang dibuat platform.

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
- Laravel scheduler untuk continuous monitoring

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

## Continuous monitoring scheduler

Laravel scheduler harus berjalan setiap menit pada production:

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

Dispatcher hanya memproses due templates dan melakukan proof-of-control re-verification sebelum membuat scheduled assessment baru.

## Testing private/internal applications

Private/reserved IP diblokir secara default untuk mengurangi SSRF risk.

Jika platform memang berada pada jaringan internal yang Anda kontrol:

```env
SECURITY_TEST_ALLOW_PRIVATE_TARGETS=true
```

Gunakan hanya pada deployment private/admin-only dan tetap batasi jaringan scanner.

## Production deployment

- HTTPS wajib.
- `APP_DEBUG=false`.
- MySQL/PostgreSQL untuk production.
- Redis direkomendasikan untuk queue/cache.
- Queue worker via Supervisor/systemd.
- Scheduler via cron/systemd.
- Dashboard di belakang VPN, Zero Trust, atau admin allowlist.
- Jalankan controlled-load pada maintenance window.
- Pisahkan scanner node dari application production untuk capacity testing yang lebih serius.
- Backup database karena history assessment sekarang menjadi baseline posture jangka panjang.

## Architecture

```text
app/
├── Http/Controllers/
├── Jobs/
│   └── RunSecurityAudit.php
├── Models/
└── Services/SecurityAudit/
    ├── Scanners/
    ├── HttpProbe.php
    ├── TargetGuard.php
    ├── VerificationService.php
    ├── ScoreCalculator.php
    ├── PostureAnalyzer.php
    └── SecurityAuditManager.php
```

## CI

GitHub Actions menjalankan:

- Composer dependency install.
- Laravel application preparation.
- Database migrations.
- PHP syntax validation.
- Automated tests including TargetGuard dan posture baseline/regression engine.

## Scope

Platform ini adalah defensive security posture system untuk aset yang Anda kuasai. Integrasi enterprise lanjutan seperti ZAP/Burp Enterprise/Nuclei sebaiknya dijalankan melalui isolated runner dengan allowlist, proof-of-control, dan policy enforcement yang sama.
