<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class CorsScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $response = $this->http->client($session->target_url)
            ->withHeaders([
                'Origin' => 'https://security-test.invalid',
                'Access-Control-Request-Method' => 'GET',
            ])
            ->send('OPTIONS', $session->target_url);

        $origin = trim((string) $response->header('Access-Control-Allow-Origin'));
        $credentials = strtolower(trim((string) $response->header('Access-Control-Allow-Credentials')));

        if ($origin === '*' && $credentials === 'true') {
            return [
                Finding::make(
                    'high',
                    'CORS wildcard dengan credentials',
                    'Response mengindikasikan wildcard origin bersamaan dengan credential support.',
                    'Gunakan allowlist origin eksplisit dan jangan kombinasikan wildcard dengan credentialed requests.',
                    "acao={$origin}; credentials={$credentials}",
                ),
            ];
        }

        if ($origin === '*') {
            return [
                Finding::make(
                    'medium',
                    'CORS mengizinkan semua origin',
                    'Access-Control-Allow-Origin bernilai wildcard.',
                    'Batasi origin ke domain yang benar-benar membutuhkan akses cross-origin.',
                    "acao={$origin}",
                ),
            ];
        }

        if ($origin === 'https://security-test.invalid') {
            return [
                Finding::make(
                    'high',
                    'CORS merefleksikan origin arbitrer',
                    'Origin pengujian yang tidak dipercaya direfleksikan kembali sebagai origin yang diizinkan.',
                    'Validasi Origin terhadap allowlist server-side dan jangan merefleksikan nilai Origin tanpa verifikasi.',
                    "acao={$origin}",
                ),
            ];
        }

        return [
            Finding::make('info', 'CORS baseline tidak menunjukkan wildcard arbitrer', 'Probe origin asing tidak mendapatkan akses wildcard/reflection yang jelas.', 'Tetap review CORS pada endpoint API yang menggunakan credentials.'),
        ];
    }
}
