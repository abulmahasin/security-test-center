<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\Scanner;

class DnsPostureScanner implements Scanner
{
    public function scan(SecuritySession $session): array
    {
        $host = (string) parse_url($session->target_url, PHP_URL_HOST);
        if ($host === '') {
            return [Finding::make('medium', 'Hostname target tidak valid', 'Scanner DNS tidak dapat menentukan hostname.', 'Gunakan URL target dengan hostname yang valid.', null)];
        }

        $records = @dns_get_record($host, DNS_A | DNS_AAAA | DNS_CNAME) ?: [];
        if ($records === []) {
            return [Finding::make('medium', 'DNS record tidak ditemukan', 'Tidak ada A, AAAA, atau CNAME yang dapat dibaca untuk target.', 'Periksa DNS zone dan availability target.', 'host='.$host)];
        }

        $types = collect($records)->pluck('type')->filter()->countBy()->map(fn ($count, $type) => $type.':'.$count)->values()->implode(',');
        $cnames = collect($records)->where('type', 'CNAME')->pluck('target')->filter()->values();
        $evidence = 'host='.$host.'; records='.$types;
        if ($cnames->isNotEmpty()) {
            $evidence .= '; cname='.$cnames->implode(',');
        }

        return [Finding::make('info', 'DNS posture tersedia', 'Target memiliki record DNS yang dapat diresolusikan.', 'Pantau perubahan DNS, TTL, dan ownership domain sebagai bagian dari operational security.', $evidence)];
    }
}
