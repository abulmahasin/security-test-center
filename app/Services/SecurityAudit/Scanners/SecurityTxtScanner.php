<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class SecurityTxtScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $parts = parse_url($session->target_url);
        $origin = ($parts['scheme'] ?? 'https').'://'.($parts['host'] ?? '');
        if (isset($parts['port'])) {
            $origin .= ':'.$parts['port'];
        }

        $url = rtrim($origin, '/').'/.well-known/security.txt';
        $response = $this->http->client($url)->get($url);

        if ($response->status() === 404) {
            return [Finding::make(
                'low',
                'security.txt belum tersedia',
                'Aplikasi belum mempublikasikan kontak dan kebijakan pelaporan keamanan standar.',
                'Tambahkan /.well-known/security.txt sesuai RFC 9116 dengan Contact, Expires, Canonical dan Policy bila tersedia.',
                'status=404; url='.$url,
            )];
        }

        if (! $response->successful()) {
            return [Finding::make('info', 'security.txt tidak dapat dievaluasi', 'Endpoint security.txt merespons non-2xx.', 'Pastikan endpoint dapat diakses publik bila ingin menerima security disclosure.', 'status='.$response->status())];
        }

        $body = $response->body();
        $missing = [];
        foreach (['Contact:', 'Expires:'] as $required) {
            if (stripos($body, $required) === false) {
                $missing[] = rtrim($required, ':');
            }
        }

        if ($missing) {
            return [Finding::make('low', 'security.txt belum lengkap', 'Dokumen ada tetapi field penting belum lengkap.', 'Tambahkan field yang hilang dan pastikan Expires selalu diperbarui.', 'missing='.implode(',', $missing))];
        }

        return [Finding::make('info', 'security.txt tersedia', 'Security disclosure metadata ditemukan.', 'Pertahankan Contact dan Expires agar selalu valid.', 'status='.$response->status())];
    }
}
