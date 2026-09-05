<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class CookieScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $response = $this->http->client($session->target_url)->get($session->target_url);
        $cookies = $response->headers()['Set-Cookie'] ?? [];

        if ($cookies === []) {
            return [
                Finding::make('info', 'Tidak ada cookie pada response awal', 'Response halaman target tidak mengirim Set-Cookie.', 'Tidak ada tindakan khusus; pastikan cookie sensitif tetap memiliki flags yang benar saat autentikasi.'),
            ];
        }

        $missingSecure = 0;
        $missingHttpOnly = 0;
        $missingSameSite = 0;

        foreach ($cookies as $cookie) {
            $lower = strtolower($cookie);
            $missingSecure += str_contains($session->target_url, 'https://') && ! str_contains($lower, '; secure') ? 1 : 0;
            $missingHttpOnly += ! str_contains($lower, '; httponly') ? 1 : 0;
            $missingSameSite += ! str_contains($lower, 'samesite=') ? 1 : 0;
        }

        $findings = [];

        if ($missingSecure > 0) {
            $findings[] = Finding::make('high', 'Cookie tanpa Secure flag', "{$missingSecure} cookie tidak memiliki Secure flag.", 'Aktifkan Secure pada seluruh session/auth cookie di HTTPS.');
        }
        if ($missingHttpOnly > 0) {
            $findings[] = Finding::make('medium', 'Cookie tanpa HttpOnly', "{$missingHttpOnly} cookie tidak memiliki HttpOnly.", 'Aktifkan HttpOnly untuk cookie yang tidak perlu dibaca JavaScript.');
        }
        if ($missingSameSite > 0) {
            $findings[] = Finding::make('medium', 'Cookie tanpa SameSite', "{$missingSameSite} cookie tidak memiliki SameSite.", 'Atur SameSite=Lax/Strict, atau None hanya bila memang dibutuhkan dan disertai Secure.');
        }

        return $findings ?: [
            Finding::make('info', 'Cookie baseline baik', 'Cookie pada response awal memiliki flags utama yang diharapkan.', 'Pertahankan kebijakan cookie dan uji juga setelah login.'),
        ];
    }
}
