<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\Scanner;
use App\Services\SecurityAudit\TargetGuard;

class TlsScanner implements Scanner
{
    public function __construct(private readonly TargetGuard $guard)
    {
    }

    public function scan(SecuritySession $session): array
    {
        if (! str_starts_with($session->target_url, 'https://')) {
            return [
                Finding::make(
                    'high',
                    'Target tidak menggunakan HTTPS',
                    'URL sesi menggunakan HTTP sehingga transport tidak terenkripsi.',
                    'Gunakan HTTPS untuk seluruh aplikasi dan redirect permanen dari HTTP ke HTTPS.',
                ),
            ];
        }

        $this->guard->assertAllowed($session->target_url);

        $parts = parse_url($session->target_url);
        $host = $parts['host'];
        $port = (int) ($parts['port'] ?? 443);

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $host,
                'SNI_enabled' => true,
            ],
        ]);

        $socket = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            8,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if (! $socket) {
            return [
                Finding::make(
                    'high',
                    'TLS handshake gagal',
                    "Koneksi TLS gagal: {$errstr}",
                    'Periksa sertifikat, hostname, chain certificate, cipher policy dan konfigurasi reverse proxy.',
                    "errno={$errno}",
                ),
            ];
        }

        $params = stream_context_get_params($socket);
        fclose($socket);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $parsed = $cert ? openssl_x509_parse($cert) : false;

        if (! is_array($parsed)) {
            return [
                Finding::make('medium', 'Sertifikat tidak dapat dianalisis', 'TLS berhasil terhubung tetapi metadata certificate tidak tersedia.', 'Periksa certificate chain menggunakan tool TLS khusus.'),
            ];
        }

        $findings = [];
        $validTo = (int) ($parsed['validTo_time_t'] ?? 0);
        $days = $validTo > 0 ? (int) floor(($validTo - time()) / 86400) : null;

        if ($days !== null && $days < 0) {
            $findings[] = Finding::make('critical', 'Sertifikat TLS sudah kedaluwarsa', 'Certificate melewati masa berlaku.', 'Renew certificate segera dan aktifkan auto-renew.', "expired_days=".abs($days));
        } elseif ($days !== null && $days < 14) {
            $findings[] = Finding::make('high', 'Sertifikat TLS hampir kedaluwarsa', "Certificate tersisa sekitar {$days} hari.", 'Renew certificate dan validasi mekanisme auto-renew.', "days_remaining={$days}");
        } elseif ($days !== null && $days < 30) {
            $findings[] = Finding::make('medium', 'Sertifikat TLS mendekati masa renewal', "Certificate tersisa sekitar {$days} hari.", 'Pastikan auto-renew dan monitoring certificate berjalan.', "days_remaining={$days}");
        }

        if ($findings === []) {
            $findings[] = Finding::make('info', 'TLS certificate valid', 'Handshake dan validasi certificate berhasil.', 'Pertahankan auto-renew dan monitoring certificate.', $days !== null ? "days_remaining={$days}" : null);
        }

        return $findings;
    }
}
