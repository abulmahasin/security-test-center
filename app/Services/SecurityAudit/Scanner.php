<?php

namespace App\Services\SecurityAudit;

use App\Models\SecuritySession;

interface Scanner
{
    public function scan(SecuritySession $session): array;
}
