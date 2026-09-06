<?php

namespace App\Services\SecurityAudit;

use App\Services\SecurityAudit\Scanners\AuthenticatedAccessScanner;
use App\Services\SecurityAudit\Scanners\CookieScanner;
use App\Services\SecurityAudit\Scanners\CorsScanner;
use App\Services\SecurityAudit\Scanners\DnsPostureScanner;
use App\Services\SecurityAudit\Scanners\ExposureScanner;
use App\Services\SecurityAudit\Scanners\HeadersScanner;
use App\Services\SecurityAudit\Scanners\HttpMethodsScanner;
use App\Services\SecurityAudit\Scanners\LatencyScanner;
use App\Services\SecurityAudit\Scanners\LoadResilienceScanner;
use App\Services\SecurityAudit\Scanners\RateLimitScanner;
use App\Services\SecurityAudit\Scanners\SecurityTxtScanner;
use App\Services\SecurityAudit\Scanners\SensitiveFilesScanner;
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
        private readonly SecurityTxtScanner $securityTxt,
        private readonly HttpMethodsScanner $httpMethods,
        private readonly DnsPostureScanner $dnsPosture,
        private readonly SensitiveFilesScanner $sensitiveFiles,
        private readonly AuthenticatedAccessScanner $authenticatedAccess,
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
            'security_txt' => $this->securityTxt,
            'http_methods' => $this->httpMethods,
            'dns_posture' => $this->dnsPosture,
            'sensitive_files' => $this->sensitiveFiles,
            'authenticated_access' => $this->authenticatedAccess,
            default => throw new InvalidArgumentException("Unknown security module: {$module}"),
        };
    }
}
