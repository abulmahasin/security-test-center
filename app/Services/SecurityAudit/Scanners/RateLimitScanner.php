<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class RateLimitScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $path = $session->config['rate_limit_path'] ?? '/login';
        $url = rtrim($session->target_url, '/').'/'.ltrim($path, '/');

        $response = $this->http->client($url)->head($url);
        $headers = array_change_key_case($response->headers(), CASE_LOWER);

        $signals = [
            'ratelimit-limit',
            'ratelimit-remaining',
            'x-ratelimit-limit',
            'x-ratelimit-remaining',
            'retry-after',
        ];

        foreach ($signals as $header) {
            if (isset($headers[$header])) {
                return [
                    Finding::make('info', 'Rate-limit signal terdeteksi', "Endpoint {$path} mengirim header throttling.", 'Pertahankan rate limiter pada endpoint autentikasi dan operasi mahal.', "{$header}=".implode(',', $headers[$header])),
                ];
            }
        }

        return [
            Finding::make(
                'low',
                'Rate-limit signal tidak terlihat',
                "Low-volume HEAD probe ke {$path} tidak menemukan header rate-limit. Ini bukan bukti bahwa limiter tidak ada.",
                'Pastikan endpoint login, password reset, OTP, upload dan export memiliki rate limiter server-side dan observability.',
                "status={$response->status()}",
            ),
        ];
    }
}
