<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecurityAccessRule;
use App\Models\SecuritySession;
use App\Services\SecurityAudit\AuthenticatedSessionService;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\Scanner;

class AuthenticatedAccessScanner implements Scanner
{
    public function __construct(private readonly AuthenticatedSessionService $auth)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $session->loadMissing(['identities.accessRules']);
        $identities = $session->identities->where('enabled', true);

        if ($identities->isEmpty()) {
            return [Finding::make(
                'info',
                'Authenticated security belum dikonfigurasi',
                'Belum ada test identity aktif untuk menguji permission setelah login.',
                'Tambahkan dedicated test account dengan role yang mewakili aplikasi Anda, misalnya standard_user, staff, operator, manager, admin, atau API client. Jangan gunakan akun produksi milik user nyata.'
            )];
        }

        $findings = [];

        foreach ($identities as $identity) {
            try {
                $authenticated = $this->auth->authenticate($session, $identity);
            } catch (\Throwable $e) {
                $findings[] = Finding::make(
                    'high',
                    "Authenticated test gagal: {$identity->label}",
                    'Scanner tidak dapat membentuk authenticated session untuk test identity ini. Authorization matrix untuk identity tersebut tidak dapat dipercaya sampai masalah login diselesaikan.',
                    'Periksa login path, username field, success path, credential akun uji, CSRF flow, dan pastikan target masih dapat dijangkau.',
                    $this->evidence($identity->label, $identity->expected_role, null, 'authentication_error')
                );
                continue;
            }

            if (! $authenticated['authenticated']) {
                $findings[] = Finding::make(
                    'high',
                    "Test identity tidak berhasil login: {$identity->label}",
                    'Credential atau alur login akun uji tidak berhasil membentuk session yang dapat divalidasi.',
                    'Periksa credential akun uji, login path, field username, success path, atau gunakan bearer identity untuk API yang memakai token.',
                    $this->evidence($identity->label, $identity->expected_role, $authenticated['status'], 'authentication_failed')
                );
                continue;
            }

            if ($identity->accessRules->isEmpty()) {
                $findings[] = Finding::make(
                    'info',
                    "Authenticated identity aktif: {$identity->label}",
                    'Login berhasil tetapi belum ada authorization boundary rule untuk identity ini.',
                    'Tambahkan rule seperti Standard User → /admin/users = DENIED atau User A → /api/orders/OTHER_ID = DENIED untuk menguji IDOR/BOLA.',
                    $this->evidence($identity->label, $identity->expected_role, $authenticated['status'], 'authenticated_no_rules')
                );
                continue;
            }

            foreach ($identity->accessRules as $rule) {
                $findings[] = $this->evaluateRule($session, $identity->label, $identity->expected_role, $authenticated['client'], $rule);
            }
        }

        return $findings;
    }

    private function evaluateRule(SecuritySession $session, string $identityLabel, ?string $role, $client, SecurityAccessRule $rule): array
    {
        try {
            $response = $this->auth->get($client, $session, $rule->path);
            $status = $response->status();
        } catch (\Throwable) {
            return Finding::make(
                'medium',
                "Authorization check inconclusive: {$rule->label}",
                'Request read-only untuk authorization boundary tidak dapat diselesaikan.',
                'Periksa endpoint, availability target, dan ulangi assessment.',
                $this->evidence($identityLabel, $role, null, 'request_failed', $rule)
            );
        }

        $allowed = $status >= 200 && $status < 300;
        $denied = in_array($status, [401, 403, 404], true) || ($status >= 300 && $status < 400);

        if ($rule->expectation === 'denied' && $allowed) {
            if ($rule->kind === 'idor') {
                return Finding::make(
                    'critical',
                    "Potential IDOR/BOLA: {$identityLabel} dapat membaca {$rule->label}",
                    'Akun terautentikasi menerima response sukses untuk resource yang menurut business rule bukan miliknya atau berada di luar scope/tenant-nya. Ini dapat menyebabkan kebocoran data antar-user, antar-unit, atau antar-tenant tanpa perlu mengambil alih akun admin.'.($rule->business_context ? ' Context: '.$rule->business_context : ''),
                    'Tambahkan ownership/tenant scoping pada query dan policy server-side. Jangan cukup memeriksa bahwa user sudah login; verifikasi bahwa resource benar-benar dimiliki atau berada dalam scope identity tersebut. Gunakan route model binding scoped, policy, query constraint, dan regression test untuk setiap object-level permission.',
                    $this->evidence($identityLabel, $role, $status, 'idor_unexpectedly_allowed', $rule)
                );
            }

            return Finding::make(
                'critical',
                "Broken Access Control: {$identityLabel} dapat mengakses {$rule->label}",
                'Akun dengan role yang seharusnya tidak memiliki akses menerima response sukses pada resource terproteksi. Jika akun role rendah dikompromikan, attacker berpotensi menembus fungsi administratif atau data role lain tanpa perlu mengetahui password admin.'.($rule->business_context ? ' Context: '.$rule->business_context : ''),
                'Terapkan authorization server-side pada route/controller/API menggunakan middleware, policy/gate, permission checks, ownership checks, dan deny-by-default. Jangan mengandalkan menu/tombol yang disembunyikan di UI. Tambahkan automated authorization regression test untuk boundary ini.',
                $this->evidence($identityLabel, $role, $status, 'unexpectedly_allowed', $rule)
            );
        }

        if ($rule->expectation === 'denied' && $denied) {
            return Finding::make(
                'info',
                ($rule->kind === 'idor' ? 'Object boundary enforced: ' : 'Authorization boundary enforced: ').$rule->label,
                'Resource yang dilarang untuk identity ini ditolak sesuai expectation.',
                'Pertahankan policy ini dan jalankan sebagai regression check setiap release.',
                $this->evidence($identityLabel, $role, $status, 'correctly_denied', $rule)
            );
        }

        if ($rule->expectation === 'allowed' && $allowed) {
            return Finding::make(
                'info',
                "Expected access available: {$rule->label}",
                'Identity dapat membuka resource yang memang seharusnya dimiliki role tersebut.',
                'Gunakan hasil ini sebagai baseline permission yang benar.',
                $this->evidence($identityLabel, $role, $status, 'correctly_allowed', $rule)
            );
        }

        if ($rule->expectation === 'allowed' && $denied) {
            return Finding::make(
                'medium',
                "Authorization mismatch: {$identityLabel} ditolak dari {$rule->label}",
                'Role yang seharusnya memiliki akses justru menerima denial/redirect. Ini bukan privilege escalation tetapi menunjukkan permission matrix atau konfigurasi aplikasi tidak sesuai desain.',
                'Periksa middleware, policy, permission assignment, tenant/ownership constraints, dan expected role untuk endpoint tersebut.',
                $this->evidence($identityLabel, $role, $status, 'unexpectedly_denied', $rule)
            );
        }

        return Finding::make(
            'low',
            "Authorization response tidak konklusif: {$rule->label}",
            "Endpoint mengembalikan HTTP {$status}, sehingga tidak dapat diklasifikasikan sebagai allowed atau denied dengan pasti.",
            'Periksa endpoint secara manual dan sesuaikan boundary rule bila endpoint memang mengembalikan status khusus seperti 405/5xx.',
            $this->evidence($identityLabel, $role, $status, 'inconclusive', $rule)
        );
    }

    private function evidence(string $identity, ?string $role, ?int $status, string $result, ?SecurityAccessRule $rule = null): string
    {
        $isAttackPath = in_array($result, ['unexpectedly_allowed', 'idor_unexpectedly_allowed'], true);

        return json_encode([
            'identity' => $identity,
            'expected_role' => $role,
            'kind' => $rule?->kind,
            'path' => $rule?->path,
            'expectation' => $rule?->expectation,
            'http_status' => $status,
            'result' => $result,
            'method' => 'GET',
            'credentials_redacted' => true,
            'response_body_stored' => false,
            'attack_path' => $isAttackPath ? [
                'entry' => $identity.($role ? ' ('.$role.')' : ''),
                'target' => $rule?->path,
                'outcome' => $result === 'idor_unexpectedly_allowed'
                    ? 'Cross-user / Cross-scope Resource Reached'
                    : 'Privileged Resource Reached',
                'severity_hint' => 'critical',
                'steps' => [
                    ['state' => 'start', 'label' => 'Dedicated test identity: '.$identity],
                    ['state' => 'pass', 'label' => 'Authentication completed using encrypted test credential/session'],
                    ['state' => 'pass', 'label' => 'GET '.$rule?->path.' with valid low-privilege identity'],
                    ['state' => 'fail', 'label' => $rule?->kind === 'idor' ? 'Expected ownership/object boundary did not deny request' : 'Expected role/permission boundary did not deny request'],
                    ['state' => 'impact', 'label' => 'HTTP '.($status ?? '?').' — '.$rule?->label],
                ],
            ] : null,
        ], JSON_UNESCAPED_SLASHES);
    }
}
