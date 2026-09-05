<?php

namespace App\Services\SecurityAudit;

class Finding
{
    public static function make(
        string $severity,
        string $title,
        string $description,
        string $remediation,
        ?string $evidence = null,
    ): array {
        return compact('severity', 'title', 'description', 'remediation', 'evidence');
    }
}
