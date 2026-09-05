<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class HttpMethodsScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $response = $this->http->client($session->target_url)->send('OPTIONS', $session->target_url);
        $allow = strtoupper((string) $response->header('Allow', ''));

        if ($allow === '') {
            return [Finding::make('info', 'HTTP method policy tidak diekspos', 'Server tidak mengembalikan header Allow pada OPTIONS.', 'Pastikan reverse proxy dan application router hanya mengaktifkan method yang memang diperlukan.', 'status='.$response->status())];
        }

        $methods = collect(explode(',', $allow))->map(fn ($method) => trim($method))->filter()->values();
        $risky = $methods->intersect(['TRACE', 'TRACK', 'CONNECT'])->values();

        if ($risky->isNotEmpty()) {
            return [Finding::make('high', 'HTTP method berisiko terekspos', 'Header Allow mengiklankan method yang umumnya tidak dibutuhkan aplikasi web.', 'Nonaktifkan TRACE/TRACK/CONNECT pada reverse proxy dan web server kecuali ada kebutuhan yang terdokumentasi.', 'allow='.$methods->implode(','))];
        }

        $writeMethods = $methods->intersect(['PUT', 'DELETE', 'PATCH'])->values();
        if ($writeMethods->isNotEmpty()) {
            return [Finding::make('low', 'HTTP write methods terdeteksi', 'Server mengiklankan write methods. Ini belum berarti vulnerability, tetapi perlu dipastikan seluruh endpoint memiliki authorization yang benar.', 'Validasi authentication, authorization, CSRF/API token policy dan ownership check untuk endpoint write.', 'allow='.$methods->implode(','))];
        }

        return [Finding::make('info', 'HTTP method exposure terkendali', 'Tidak ada method berisiko tinggi pada header Allow.', 'Pertahankan method allowlist pada reverse proxy.', 'allow='.$methods->implode(','))];
    }
}
