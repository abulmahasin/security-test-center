<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class HeadersScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $response = $this->http->client($session->target_url)->get($session->target_url);
        $headers = array_change_key_case($response->headers(), CASE_LOWER);
        $findings = [];

        $recommended = [
            'content-security-policy' => ['medium', 'Content-Security-Policy tidak ditemukan', 'Tambahkan CSP yang membatasi script, frame, object, base-uri dan sumber eksternal sesuai kebutuhan aplikasi.'],
            'strict-transport-security' => ['medium', 'HSTS tidak ditemukan', 'Untuk target HTTPS yang sudah stabil, aktifkan Strict-Transport-Security dengan max-age yang sesuai.'],
            'x-content-type-options' => ['low', 'X-Content-Type-Options tidak ditemukan', 'Tambahkan X-Content-Type-Options: nosniff.'],
            'referrer-policy' => ['low', 'Referrer-Policy tidak ditemukan', 'Gunakan strict-origin-when-cross-origin atau kebijakan yang lebih ketat pada aplikasi sensitif.'],
        ];

        foreach ($recommended as $header => [$severity, $title, $remediation]) {
            if (! isset($headers[$header])) {
                if ($header === 'strict-transport-security' && ! str_starts_with($session->target_url, 'https://')) {
                    continue;
                }

                $findings[] = Finding::make(
                    $severity,
                    $title,
                    "Response tidak menyertakan header {$header}.",
                    $remediation,
                );
            }
        }

        $xFrame = strtolower($headers['x-frame-options'][0] ?? '');
        $csp = strtolower($headers['content-security-policy'][0] ?? '');

        if ($xFrame === '' && ! str_contains($csp, 'frame-ancestors')) {
            $findings[] = Finding::make(
                'medium',
                'Proteksi clickjacking belum terlihat',
                'Tidak ditemukan X-Frame-Options maupun directive CSP frame-ancestors.',
                'Gunakan CSP frame-ancestors sebagai kontrol utama dan X-Frame-Options sebagai kompatibilitas bila diperlukan.',
            );
        }

        return $findings;
    }
}
