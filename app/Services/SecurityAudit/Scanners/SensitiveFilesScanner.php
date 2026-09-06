<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;
use Throwable;

class SensitiveFilesScanner implements Scanner
{
    private const MAX_SAMPLE_BYTES = 2048;

    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $findings = [];

        foreach ($this->checks() as $check) {
            $finding = $this->probe($session, $check);

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings ?: [
            Finding::make(
                'info',
                'Tidak ada sensitive file exposure yang terkonfirmasi',
                'Probe terbatas pada daftar file berisiko tinggi tidak menemukan signature file sensitif yang dapat dibaca publik.',
                'Pertahankan deny-rule web server, simpan secret di luar document root, dan jalankan pemeriksaan ini setelah perubahan deployment.',
                'content_not_stored=true; fixed_path_allowlist=true',
            ),
        ];
    }

    private function probe(SecuritySession $session, array $check): ?array
    {
        $url = rtrim($session->target_url, '/').$check['path'];

        try {
            $response = $this->http->client($url)
                ->withHeaders(['Range' => 'bytes=0-'.(self::MAX_SAMPLE_BYTES - 1)])
                ->withOptions(['stream' => true])
                ->get($url);

            if (! in_array($response->status(), [200, 206], true)) {
                return null;
            }

            $stream = $response->toPsrResponse()->getBody();
            $sample = $stream->read(self::MAX_SAMPLE_BYTES);
            $stream->close();

            if (! $this->matches($sample, $check['signatures'])) {
                return null;
            }

            return Finding::make(
                $check['severity'],
                $check['title'],
                $check['risk'],
                $check['remediation'],
                sprintf(
                    'path=%s; http=%d; signature=%s; sampled_bytes<=%d; content_redacted=true',
                    $check['path'],
                    $response->status(),
                    $check['signature_label'],
                    self::MAX_SAMPLE_BYTES,
                ),
            );
        } catch (Throwable) {
            return null;
        }
    }

    private function matches(string $sample, array $signatures): bool
    {
        foreach ($signatures as $signature) {
            if (str_contains($sample, $signature)) {
                return true;
            }
        }

        return false;
    }

    private function checks(): array
    {
        return [
            [
                'path' => '/.env',
                'severity' => 'critical',
                'title' => 'Environment file (.env) dapat diakses publik',
                'signature_label' => 'application environment secret',
                'signatures' => ['APP_KEY=', 'DB_PASSWORD=', 'APP_ENV='],
                'risk' => 'File .env dapat memuat APP_KEY, kredensial database, mail, cache, storage, dan API token. Jika terbaca publik, attacker dapat memperoleh akses ke layanan internal atau mengambil alih data aplikasi.',
                'remediation' => 'Blokir semua dotfile pada Nginx/Apache, pastikan document root hanya mengarah ke folder public/, rotasi seluruh secret yang mungkin pernah terekspos, lalu hapus .env dari lokasi yang dapat disajikan web server.',
            ],
            [
                'path' => '/.git/config',
                'severity' => 'high',
                'title' => 'Git metadata dapat diakses publik',
                'signature_label' => 'git repository configuration',
                'signatures' => ['[core]', 'repositoryformatversion'],
                'risk' => 'Folder .git yang terekspos dapat membantu rekonstruksi source code, riwayat commit, remote repository, dan konfigurasi aplikasi sehingga memperbesar peluang kebocoran source atau secret lama.',
                'remediation' => 'Jangan deploy folder .git ke document root. Tambahkan deny-rule untuk /.git dan dotfile lain, lalu review history repository untuk memastikan tidak ada secret yang pernah ter-commit.',
            ],
            [
                'path' => '/storage/logs/laravel.log',
                'severity' => 'high',
                'title' => 'Laravel log dapat dibaca publik',
                'signature_label' => 'Laravel application log',
                'signatures' => ['local.ERROR:', 'production.ERROR:', 'Stack trace:'],
                'risk' => 'Log aplikasi dapat mengandung stack trace, query, path server, identifier user, token, atau data request. Informasi ini dapat dipakai untuk memetakan sistem dan mempercepat eksploitasi kelemahan lain.',
                'remediation' => 'Pastikan storage/ berada di luar public web root dan tidak memiliki route/static alias publik. Rotasi log jika berisi data sensitif dan minimalkan logging secret/request credential.',
            ],
            [
                'path' => '/database/database.sqlite',
                'severity' => 'critical',
                'title' => 'Database SQLite dapat diunduh publik',
                'signature_label' => 'SQLite database header',
                'signatures' => ["SQLite format 3\x00"],
                'risk' => 'Database yang dapat diunduh berpotensi memberikan seluruh akun, hash password, data bisnis, token, session, dan informasi pribadi yang tersimpan di aplikasi.',
                'remediation' => 'Pindahkan database di luar document root, blokir ekstensi/database path pada web server, anggap seluruh data di file tersebut telah terekspos, dan lakukan incident review serta rotasi credential terkait.',
            ],
            [
                'path' => '/backup.sql',
                'severity' => 'critical',
                'title' => 'Database backup SQL terindikasi dapat diakses publik',
                'signature_label' => 'SQL database backup',
                'signatures' => ['CREATE TABLE', 'INSERT INTO', '-- MySQL dump'],
                'risk' => 'Backup database sering berisi data produksi lengkap dan kadang lebih mudah diakses dibanding database aktif. Kebocoran dapat menyebabkan kompromi data skala besar.',
                'remediation' => 'Jangan simpan backup pada public directory. Pindahkan ke encrypted private storage dengan access control, hapus backup publik, dan review apakah data/credential di dalam backup perlu dirotasi.',
            ],
            [
                'path' => '/backup.zip',
                'severity' => 'high',
                'title' => 'Archive backup ZIP terindikasi dapat diakses publik',
                'signature_label' => 'ZIP archive header',
                'signatures' => ["PK\x03\x04"],
                'risk' => 'Archive deployment/backup dapat berisi source code, .env, database dump, upload user, configuration, dan file internal lain dalam satu paket yang mudah diunduh.',
                'remediation' => 'Pindahkan archive ke private object storage atau lokasi non-public, terapkan encryption dan retention policy, lalu hapus seluruh archive lama dari document root.',
            ],
            [
                'path' => '/.npmrc',
                'severity' => 'high',
                'title' => 'NPM credential file dapat diakses publik',
                'signature_label' => 'npm authentication configuration',
                'signatures' => ['_authToken=', ':_authToken='],
                'risk' => '.npmrc dapat memuat token registry yang memungkinkan akses ke private package atau publish package atas nama organisasi.',
                'remediation' => 'Blokir dotfile, rotasi token NPM yang mungkin terekspos, gunakan secret manager/CI secret, dan jangan menyalin credential file ke image atau public directory.',
            ],
            [
                'path' => '/auth.json',
                'severity' => 'high',
                'title' => 'Composer auth.json dapat diakses publik',
                'signature_label' => 'Composer repository credentials',
                'signatures' => ['"github-oauth"', '"http-basic"'],
                'risk' => 'Composer auth.json dapat memuat token GitHub atau basic-auth untuk private package repository sehingga pihak lain dapat memperoleh akses repository/package.',
                'remediation' => 'Hapus auth.json dari public/deployment artifact, rotasi token yang terekspos, simpan credential melalui CI secret atau Composer auth pada home user yang tidak dilayani web server.',
            ],
            [
                'path' => '/phpinfo.php',
                'severity' => 'high',
                'title' => 'phpinfo page dapat diakses publik',
                'signature_label' => 'PHP runtime information page',
                'signatures' => ['PHP Version', 'phpinfo()'],
                'risk' => 'phpinfo mengekspos versi runtime, extension, path filesystem, environment variable, header, dan detail konfigurasi yang membantu fingerprinting serta serangan lanjutan.',
                'remediation' => 'Hapus phpinfo.php dari production, batasi diagnostic endpoint ke internal/VPN bila benar-benar diperlukan, dan hindari menampilkan environment variable atau secret pada diagnostic output.',
            ],
        ];
    }
}
