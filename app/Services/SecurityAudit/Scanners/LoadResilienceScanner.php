<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;
use App\Services\SecurityAudit\TargetGuard;
use Illuminate\Http\Client\Pool;
use Illuminate\Support\Facades\Http;

class LoadResilienceScanner implements Scanner
{
    public function __construct(
        private readonly HttpProbe $http,
        private readonly TargetGuard $guard,
    ) {
    }

    public function scan(SecuritySession $session): array
    {
        $this->http->client($session->target_url);

        $config = $session->config['load'] ?? [];
        $vus = min(max((int) ($config['vus'] ?? 5), 1), config('security_test.load.max_vus'));
        $rps = min(max((int) ($config['rps'] ?? 5), 1), config('security_test.load.max_rps'));
        $duration = min(max((int) ($config['duration'] ?? 10), 1), config('security_test.load.max_duration'));
        $maxRequests = config('security_test.load.max_requests');

        $planned = min($rps * $duration, $maxRequests);
        $completed = 0;
        $errors = 0;
        $latencies = [];
        $started = microtime(true);

        while ($completed < $planned && (microtime(true) - $started) < ($duration + 5)) {
            // Re-check DNS/target safety before every batch.
            $this->guard->assertAllowed($session->target_url);
            $secondStart = microtime(true);
            $batchSize = min($rps, $vus, $planned - $completed);

            $requestsStartedAt = hrtime(true);
            $responses = Http::pool(function (Pool $pool) use ($batchSize, $session) {
                $items = [];
                for ($i = 0; $i < $batchSize; $i++) {
                    $items[] = $pool
                        ->timeout(config('security_test.http_timeout'))
                        ->withOptions(['allow_redirects' => false])
                        ->withHeaders(['User-Agent' => 'Security-Test-Center/1.0 Controlled-Load'])
                        ->get($session->target_url);
                }
                return $items;
            });
            $batchMs = (hrtime(true) - $requestsStartedAt) / 1_000_000;

            foreach ($responses as $response) {
                $completed++;
                $latencies[] = $batchMs / max(1, count($responses));

                if ($response instanceof \Throwable || ! method_exists($response, 'successful') || ! $response->successful()) {
                    $errors++;
                }
            }

            $elapsed = microtime(true) - $secondStart;
            if ($elapsed < 1 && $completed < $planned) {
                usleep((int) ((1 - $elapsed) * 1_000_000));
            }
        }

        sort($latencies);
        $p95 = $latencies ? $latencies[(int) ceil(count($latencies) * 0.95) - 1] : 0;
        $errorRate = $completed > 0 ? ($errors / $completed) * 100 : 100;
        $evidence = sprintf('requests=%d/%d; errors=%d; error_rate=%.2f%%; estimated_p95=%.0fms; vus=%d; rps=%d; duration=%ds', $completed, $planned, $errors, $errorRate, $p95, $vus, $rps, $duration);

        if ($errorRate >= 10) {
            return [Finding::make('high', 'Controlled load menghasilkan error rate tinggi', 'Lebih dari 10% request controlled-load gagal/non-2xx.', 'Periksa application worker, reverse proxy, database connections, queue, cache dan autoscaling sebelum menaikkan beban.', $evidence)];
        }

        if ($errorRate >= 2 || $p95 > 1500) {
            return [Finding::make('medium', 'Resilience mulai menurun pada controlled load', 'Error rate atau latency meningkat pada batas load yang dikonfigurasi.', 'Profiling p95, slow query dan saturation metric; optimalkan lalu ulangi pada staging/maintenance window.', $evidence)];
        }

        return [Finding::make('info', 'Controlled load selesai dalam batas aman', 'Tidak terlihat degradasi besar pada profil load yang dibatasi aplikasi.', 'Naikkan kapasitas secara bertahap hanya pada sistem terverifikasi dan maintenance window yang disetujui.', $evidence)];
    }
}
