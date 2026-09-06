<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecurityAccountTest;
use App\Models\SecuritySession;
use App\Services\SecurityAudit\AccountSecurityService;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\Scanner;
use Throwable;

class AccountCompromiseScanner implements Scanner
{
    private const MAX_LOCKOUT_ATTEMPTS = 3;

    public function __construct(private readonly AccountSecurityService $accounts)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $tests = SecurityAccountTest::query()
            ->where('security_session_id', $session->id)
            ->where('enabled', true)
            ->with('identity')
            ->get();

        if ($tests->isEmpty()) {
            return [Finding::make(
                'info',
                'Account Compromise Lab belum dikonfigurasi',
                'Belum ada bounded account-security test pada session ini.',
                'Tambahkan dedicated test identity lalu konfigurasi Login Enumeration, Login Throttling, Login Surface, atau Password Recovery Surface. Scanner tidak melakukan password guessing atau credential theft.'
            )];
        }

        $findings = [];

        foreach ($tests as $test) {
            $findings[] = match ($test->kind) {
                'login_enumeration' => $this->loginEnumeration($session, $test),
                'login_throttling' => $this->loginThrottling($session, $test),
                'login_surface' => $this->loginSurface($session, $test),
                'password_reset_surface' => $this->passwordResetSurface($session, $test),
                default => Finding::make(
                    'low',
                    "Account security test tidak dikenal: {$test->label}",
                    'Jenis test tidak didukung oleh engine saat ini.',
                    'Edit atau hapus test case ini.'
                ),
            };
        }

        return $findings;
    }

    private function loginEnumeration(SecuritySession $session, SecurityAccountTest $test): array
    {
        $identity = $test->identity;

        if (! $identity || $identity->auth_type !== 'form' || blank($identity->username)) {
            return Finding::make(
                'medium',
                "Login enumeration test tidak dapat dijalankan: {$test->label}",
                'Test membutuhkan Form Login identity dengan username/email akun uji yang valid.',
                'Gunakan dedicated test account bertipe Form Login. Jangan gunakan akun produksi milik pengguna nyata.',
                $this->evidence($test, 'configuration_error')
            );
        }

        try {
            $known = $this->accounts->invalidLoginAttempt($session, $identity, $identity->username);
            $missingUsername = $this->accounts->syntheticUsername($identity);
            $missing = $this->accounts->invalidLoginAttempt($session, $identity, $missingUsername);
        } catch (Throwable) {
            return Finding::make(
                'medium',
                "Login enumeration test gagal: {$test->label}",
                'Probe login defensif tidak dapat diselesaikan.',
                'Periksa login path, CSRF flow, availability target, dan konfigurasi test identity.',
                $this->evidence($test, 'request_failed')
            );
        }

        $maxLength = max(1, $known['length'], $missing['length']);
        $lengthDelta = abs($known['length'] - $missing['length']);
        $lengthRatio = $lengthDelta / $maxLength;
        $distinguishable = $known['status'] !== $missing['status']
            || $known['location'] !== $missing['location']
            || ($lengthDelta >= 100 && $lengthRatio >= 0.15);

        $evidence = json_encode([
            'test' => 'login_enumeration_differential',
            'known_test_account' => [
                'status' => $known['status'],
                'response_bytes' => $known['length'],
                'location' => $known['location'],
            ],
            'synthetic_missing_account' => [
                'status' => $missing['status'],
                'response_bytes' => $missing['length'],
                'location' => $missing['location'],
            ],
            'response_length_delta' => $lengthDelta,
            'credentials_redacted' => true,
            'password_guessing' => false,
            'response_body_stored' => false,
        ], JSON_UNESCAPED_SLASHES);

        if ($distinguishable) {
            return Finding::make(
                'high',
                "Account Enumeration Signal: {$test->label}",
                'Respons login untuk akun uji yang ada dapat dibedakan dari username sintetis yang tidak ada. Attacker dapat memakai perbedaan status, redirect, atau ukuran respons untuk memvalidasi daftar akun sebelum credential-stuffing/phishing.',
                'Samakan pesan, status, redirect, dan timing login untuk akun valid maupun tidak valid. Terapkan rate limiting, MFA untuk akun sensitif, monitoring failed-login, dan jangan mengungkap apakah email/username terdaftar.',
                $evidence
            );
        }

        return Finding::make(
            'info',
            "Login Enumeration Resistance: {$test->label}",
            'Dua bounded invalid-login probe tidak menemukan perbedaan respons yang jelas antara akun uji terdaftar dan username sintetis.',
            'Pertahankan generic authentication response dan rate limiting. Hasil ini bukan jaminan bahwa seluruh flow bebas enumeration.',
            $evidence
        );
    }

    private function loginThrottling(SecuritySession $session, SecurityAccountTest $test): array
    {
        $identity = $test->identity;

        if (! $identity || $identity->auth_type !== 'form' || blank($identity->username)) {
            return Finding::make(
                'medium',
                "Login throttling test tidak dapat dijalankan: {$test->label}",
                'Test membutuhkan dedicated Form Login test identity.',
                'Tambahkan akun uji khusus agar bounded invalid attempts tidak mengganggu akun pengguna nyata.',
                $this->evidence($test, 'configuration_error')
            );
        }

        $attempts = [];

        try {
            for ($i = 0; $i < self::MAX_LOCKOUT_ATTEMPTS; $i++) {
                $attempts[] = $this->accounts->invalidLoginAttempt($session, $identity, $identity->username);
            }
        } catch (Throwable) {
            return Finding::make(
                'medium',
                "Login throttling test gagal: {$test->label}",
                'Bounded invalid-login probe tidak dapat diselesaikan.',
                'Periksa login path/CSRF target dan ulangi menggunakan dedicated test account.',
                $this->evidence($test, 'request_failed')
            );
        }

        $first = $attempts[0];
        $last = $attempts[array_key_last($attempts)];
        $controlObserved = collect($attempts)->contains(fn (array $attempt) =>
            $attempt['status'] === 429
            || filled($attempt['retry_after'])
            || (string) $attempt['rate_limit_remaining'] === '0'
        ) || $last['status'] !== $first['status'];

        $evidence = json_encode([
            'test' => 'bounded_login_throttling',
            'attempts' => count($attempts),
            'hard_cap' => self::MAX_LOCKOUT_ATTEMPTS,
            'statuses' => array_column($attempts, 'status'),
            'retry_after_observed' => collect($attempts)->contains(fn (array $a) => filled($a['retry_after'])),
            'rate_limit_zero_observed' => collect($attempts)->contains(fn (array $a) => (string) $a['rate_limit_remaining'] === '0'),
            'credentials_redacted' => true,
            'password_guessing' => false,
            'response_body_stored' => false,
        ], JSON_UNESCAPED_SLASHES);

        if ($controlObserved) {
            return Finding::make(
                'info',
                "Login Abuse Control Signal: {$test->label}",
                'Dalam maksimum tiga invalid attempts, target menunjukkan sinyal throttling, rate-limit, atau perubahan denial yang konsisten dengan abuse control.',
                'Pertahankan limiter dan kombinasikan dengan MFA, IP/device anomaly detection, alerting, serta lockout yang tidak mudah dipakai untuk denial-of-service terhadap user.',
                $evidence
            );
        }

        return Finding::make(
            'medium',
            "Tidak ada sinyal login throttling awal: {$test->label}",
            'Tiga invalid attempts terkontrol tidak menunjukkan 429, Retry-After, rate-limit depletion, atau perubahan denial. Ini bukan bukti brute-force pasti dapat dilakukan, tetapi menunjukkan lapisan anti-automation tidak terlihat pada probe awal.',
            'Tambahkan per-account + per-IP rate limiting, exponential backoff, MFA untuk role sensitif, alerting failed-login, dan protection terhadap credential stuffing. Validasi lagi dengan test account.',
            $evidence
        );
    }

    private function loginSurface(SecuritySession $session, SecurityAccountTest $test): array
    {
        $identity = $test->identity;
        $path = $test->path ?: ($identity?->login_path ?: '/login');

        try {
            $surface = $this->accounts->inspectSurface($session, $path);
        } catch (Throwable) {
            return Finding::make(
                'medium',
                "Login surface tidak dapat diperiksa: {$test->label}",
                'GET-only inspection terhadap login page gagal.',
                'Periksa path login dan availability target.',
                $this->evidence($test, 'request_failed')
            );
        }

        $evidence = json_encode(array_merge($surface, [
            'test' => 'login_surface',
            'path' => $path,
            'side_effects' => false,
            'credentials_redacted' => true,
        ]), JSON_UNESCAPED_SLASHES);

        if ($surface['status'] >= 200 && $surface['status'] < 300 && $surface['form_count'] > 0 && ! $surface['csrf_present']) {
            return Finding::make(
                'medium',
                "Login form tanpa CSRF signal: {$test->label}",
                'Login page terdeteksi memiliki form tetapi scanner tidak menemukan CSRF hidden token atau csrf-token meta tag. Pada session-based web login, kondisi ini dapat membuka risiko login CSRF atau menunjukkan proteksi request yang tidak terlihat dari markup.',
                'Pastikan login POST memakai CSRF protection/framework middleware. Jika memakai mekanisme non-CSRF seperti stateless API, dokumentasikan dan validasi origin/cookie policy yang sesuai.',
                $evidence
            );
        }

        return Finding::make(
            'info',
            "Login Surface Baseline: {$test->label}",
            'Login page berhasil diperiksa secara GET-only. Metadata form, CSRF signal, dan autocomplete posture direkam tanpa menyimpan HTML response.',
            'Pertahankan CSRF protection, password-manager-compatible autocomplete, HTTPS, generic login errors, dan MFA untuk role sensitif.',
            $evidence
        );
    }

    private function passwordResetSurface(SecuritySession $session, SecurityAccountTest $test): array
    {
        $path = $test->path ?: '/forgot-password';

        try {
            $surface = $this->accounts->inspectSurface($session, $path);
        } catch (Throwable) {
            return Finding::make(
                'low',
                "Password recovery surface tidak dapat diperiksa: {$test->label}",
                'GET-only inspection terhadap recovery page gagal atau endpoint tidak tersedia.',
                'Pastikan path recovery sesuai konfigurasi aplikasi. Tidak ada reset email atau token yang dikirim oleh test ini.',
                $this->evidence($test, 'request_failed')
            );
        }

        $evidence = json_encode(array_merge($surface, [
            'test' => 'password_reset_surface',
            'path' => $path,
            'reset_request_sent' => false,
            'email_sent' => false,
            'response_body_stored' => false,
        ]), JSON_UNESCAPED_SLASHES);

        if ($surface['status'] >= 200 && $surface['status'] < 300 && $surface['form_count'] > 0 && ! $surface['csrf_present']) {
            return Finding::make(
                'medium',
                "Password recovery form tanpa CSRF signal: {$test->label}",
                'Recovery page memiliki form tetapi tidak menunjukkan CSRF token pada markup yang diperiksa. Recovery workflow adalah jalur account takeover yang sensitif dan harus dilindungi setara dengan login.',
                'Aktifkan CSRF protection pada reset-request form, gunakan generic response untuk email terdaftar/tidak terdaftar, throttle request reset, token sekali pakai berumur pendek, dan invalidasi token lama setelah password berubah.',
                $evidence
            );
        }

        return Finding::make(
            'info',
            "Password Recovery Surface Baseline: {$test->label}",
            'Recovery page diperiksa secara pasif. Scanner tidak mengirim permintaan reset, email, OTP, atau token.',
            'Pastikan recovery response tidak melakukan account enumeration, request di-rate-limit, reset token single-use/short-lived, dan session lama diinvalidasi setelah password berubah.',
            $evidence
        );
    }

    private function evidence(SecurityAccountTest $test, string $result): string
    {
        return json_encode([
            'test_id' => $test->id,
            'kind' => $test->kind,
            'result' => $result,
            'credentials_redacted' => true,
            'response_body_stored' => false,
        ], JSON_UNESCAPED_SLASHES);
    }
}
