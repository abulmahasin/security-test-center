<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;

class LatencyScanner implements Scanner
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $samples = [];

        for ($i = 0; $i < 5; $i++) {
            $start = hrtime(true);
            $this->http->client($session->target_url)->head($session->target_url);
            $samples[] = (hrtime(true) - $start) / 1_000_000;
            usleep(150000);
        }

        sort($samples);
        $average = array_sum($samples) / count($samples);
        $p95 = $samples[(int) ceil(count($samples) * 0.95) - 1];
        $evidence = sprintf('avg=%.0fms; p95=%.0fms; samples=%s', $average, $p95, implode(',', array_map(fn ($v) => round($v), $samples)));

        if ($p95 > 2000) {
            return [Finding::make('medium', 'Latency baseline tinggi', 'p95 dari 5 probe ringan melebihi 2 detik.', 'Profiling endpoint, query database, cache, worker saturation dan upstream dependencies.', $evidence)];
        }

        if ($p95 > 1000) {
            return [Finding::make('low', 'Latency baseline perlu diperhatikan', 'p95 dari probe ringan berada di atas 1 detik.', 'Pantau APM/slow query dan targetkan p95 yang lebih rendah untuk endpoint utama.', $evidence)];
        }

        return [Finding::make('info', 'Latency baseline dalam rentang baik', 'Probe ringan tidak menunjukkan latency tinggi.', 'Tetap monitor p95/p99 saat concurrency nyata meningkat.', $evidence)];
    }
}
