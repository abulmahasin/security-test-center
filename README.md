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

### Flexible Auto Monitoring

Auto monitoring bersifat **opt-in** dan default-nya OFF.

User dapat:

- menjalankan assessment manual saja,
- mengaktifkan monitoring kapan saja,
- menentukan interval sendiri dalam jam, hari, atau minggu,
- mengubah interval tanpa membuat session baru,
- mematikan monitoring kapan saja tanpa menghapus history.

Batas interval:

- minimum: 1 jam,
- maksimum: 1 tahun.

Contoh yang valid:

- setiap 6 jam,
- setiap 12 jam,
- setiap 1 hari,
- setiap 3 hari,
- setiap 1 minggu,
- setiap 4 minggu.

Sebelum setiap auto-run, platform **memverifikasi ulang proof-of-control**. Jika verification file sudah hilang atau berubah, scheduled audit tidak dijalankan dan run ditunda sampai ownership dapat diverifikasi lagi.

Setiap auto-run membuat session baru sehingga history, baseline, evidence, dan trend tidak ditimpa.

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
- **DDoS Resilience Simulation** dalam mode controlled-load dengan hard safety caps

### Sensitive File Exposure Scanner

Scanner ini dirancang untuk mengetahui apakah file yang seharusnya private ternyata dapat dibaca melalui web server.

Daftar pemeriksaan saat ini mencakup:

- `/.env`
- `/.git/config`
- `/storage/logs/laravel.log`
- `/database/database.sqlite`
- `/backup.sql`
- `/backup.zip`
- `/.npmrc`
- `/auth.json`
- `/phpinfo.php`

Scanner melakukan request hanya pada **fixed allowlist path** tersebut dan membaca sampel kecil maksimal 2048 byte untuk mencocokkan signature file.

Isi file sensitif **tidak disimpan** ke database maupun report. Evidence hanya menyimpan:

- path,
- HTTP status,
- tipe signature yang cocok,
- ukuran sampel maksimum,
- flag `content_redacted=true`.

Contoh risiko yang dijelaskan report:

- `.env` → kebocoran `APP_KEY`, database credential, API token, mail/storage secret.
- `.git/config` → source-code reconstruction dan kebocoran history/config repository.
- Laravel log → stack trace, path internal, query, token, dan data request.
- SQLite/database backup → kebocoran data aplikasi dalam skala besar.
- `.npmrc` / `auth.json` → token private package/repository.
- `phpinfo.php` → fingerprint runtime, extension, path, dan environment variable.

Setiap finding menampilkan format yang mudah dibaca:

1. **Risiko / Dampak**
2. **Evidence (redacted)**
3. **Solusi / Recommended Remediation**

### Safety model

Platform sengaja **tidak** menyediakan:

- arbitrary flood
- spoofing
- botnet controls
- UDP amplification
- raw packet attacks
- credential attacks
- exploit payload generator
- arbitrary file downloader
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

Laravel scheduler harus berjalan setiap menit pada production agar custom interval dapat dieksekusi mendekati waktu yang ditentukan:

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

Dispatcher hanya memproses session dengan `monitoring_enabled=true`, due time sudah tercapai, target masih verified, dan session template tidak sedang running.

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

- Composer dependency install.
- Laravel application preparation.
- Database migrations.
- PHP syntax validation.
- Automated tests termasuk TargetGuard, posture baseline/regression engine, dan flexible monitoring controls.

## Scope

Platform ini adalah defensive security posture system untuk aset yang Anda kuasai. Integrasi enterprise lanjutan seperti ZAP/Burp Enterprise/Nuclei sebaiknya dijalankan melalui isolated runner dengan allowlist, proof-of-control, dan policy enforcement yang sama.
