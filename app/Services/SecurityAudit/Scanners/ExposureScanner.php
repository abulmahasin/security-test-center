<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class ExposureScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $response = $this->http->client($session->target_url)->get($session->target_url);
        $body = strtolower(substr($response->body(), 0, 500000));
        $findings = [];

        $server = $response->header('Server');
        $powered = $response->header('X-Powered-By');

        if ($powered) {
            $findings[] = Finding::make('low', 'X-Powered-By mengekspos teknologi', 'Response membocorkan informasi runtime melalui X-Powered-By.', 'Hapus X-Powered-By pada production.', "X-Powered-By={$powered}");
        }

        if ($server && preg_match('/(apache|nginx|iis|php)\/[\d.]+/i', $server)) {
            $findings[] = Finding::make('low', 'Server banner mengekspos versi', 'Header Server mengandung nama/versi software.', 'Minimalkan detail version banner pada reverse proxy/web server.', "Server={$server}");
        }

        $debugMarkers = ['whoops, looks like something went wrong', 'stack trace', 'sqlstate[', 'ignition', 'exception trace'];
        foreach ($debugMarkers as $marker) {
            if (str_contains($body, $marker)) {
                $findings[] = Finding::make('high', 'Debug/error detail terdeteksi', 'Halaman mengandung marker debug atau exception detail yang berpotensi membocorkan internals.', 'Pastikan APP_DEBUG=false pada production dan tampilkan error generik ke user.', "marker={$marker}");
                break;
            }
        }

        return $findings ?: [
            Finding::make('info', 'Tidak ada exposure mencolok pada halaman awal', 'Probe awal tidak menemukan debug marker atau version banner yang jelas.', 'Tetap lakukan review log, error handler, dan endpoint API secara berkala.'),
        ];
    }
}
