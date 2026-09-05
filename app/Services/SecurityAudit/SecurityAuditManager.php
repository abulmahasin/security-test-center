<?php

namespace App\Services\SecurityAudit;

use App\Services\SecurityAudit\Scanners\CookieScanner;
use App\Services\SecurityAudit\Scanners\CorsScanner;
use App\Services\SecurityAudit\Scanners\ExposureScanner;
use App\Services\SecurityAudit\Scanners\HeadersScanner;
use App\Services\SecurityAudit\Scanners\LatencyScanner;
use App\Services\SecurityAudit\Scanners\LoadResilienceScanner;
use App\Services\SecurityAudit\Scanners\RateLimitScanner;
use App\Services\SecurityAudit\Scanners\TlsScanner;
use InvalidArgumentException;

class SecurityAuditManager
{
    public function __construct(
        private readonly HeadersScanner $headers,
        private readonly TlsScanner $tls,
        private readonly CookieScanner $cookies,
        private readonly CorsScanner $cors,
        private readonly ExposureScanner $exposure,
        private readonly RateLimitScanner $rateLimit,
        private readonly LatencyScanner $latency,
        private readonly LoadResilienceScanner $loadResilience,
    ) {
    }

    public function scanner(string $module): Scanner
    {
        return match ($module) {
            'headers' => $this->headers,
            'tls' => $this->tls,
            'cookies' => $this->cookies,
            'cors' => $this->cors,
            'exposure' => $this->exposure,
            'rate_limit' => $this->rateLimit,
            'latency' => $this->latency,
            'load_resilience' => $this->loadResilience,
            default => throw new InvalidArgumentException("Unknown security module: {$module}"),
        };
    }
}
