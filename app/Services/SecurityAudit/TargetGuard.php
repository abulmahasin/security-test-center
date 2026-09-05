<?php

namespace App\Services\SecurityAudit;

use Illuminate\Validation\ValidationException;

class TargetGuard
{
    public function assertAllowed(string $url): void
    {
        $parts = parse_url($url);

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
            $this->reject('URL target tidak valid.');
        }

        if (! in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            $this->reject('Hanya HTTP dan HTTPS yang diizinkan.');
        }

        $host = strtolower(rtrim($parts['host'], '.'));
        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            $this->reject('Localhost diblokir oleh Target Guard.');
        }

        $port = (int) ($parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80));
        if (! in_array($port, config('security_test.allowed_ports'), true)) {
            $this->reject("Port {$port} tidak ada di allowlist SECURITY_TEST_ALLOWED_PORTS.");
        }

        $ips = $this->resolveIps($host);
        if ($ips === []) {
            $this->reject('Hostname target tidak dapat di-resolve.');
        }

        foreach ($ips as $ip) {
            if ($this->isMetadataOrLoopback($ip)) {
                $this->reject("Target mengarah ke alamat terlarang ({$ip}).");
            }

            $isPublic = filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            ) !== false;

            if (! $isPublic && ! config('security_test.allow_private_targets')) {
                $this->reject('Private/reserved IP diblokir. Aktifkan SECURITY_TEST_ALLOW_PRIVATE_TARGETS hanya untuk jaringan yang Anda kelola.');
            }
        }
    }

    private function resolveIps(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }

        $records = @dns_get_record($host, DNS_A | DNS_AAAA) ?: [];
        $ips = [];

        foreach ($records as $record) {
            if (! empty($record['ip'])) {
                $ips[] = $record['ip'];
            }
            if (! empty($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    private function isMetadataOrLoopback(string $ip): bool
    {
        if (in_array($ip, ['169.254.169.254', '0.0.0.0', '::', '::1'], true)) {
            return true;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $long = ip2long($ip);
            $loopbackStart = ip2long('127.0.0.0');
            $loopbackEnd = ip2long('127.255.255.255');
            $linkStart = ip2long('169.254.0.0');
            $linkEnd = ip2long('169.254.255.255');

            return ($long >= $loopbackStart && $long <= $loopbackEnd)
                || ($long >= $linkStart && $long <= $linkEnd);
        }

        return str_starts_with(strtolower($ip), 'fe80:');
    }

    private function reject(string $message): never
    {
        throw ValidationException::withMessages(['target_url' => $message]);
    }
}
