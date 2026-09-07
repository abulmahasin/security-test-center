<?php

namespace App\Services\SecurityAudit;

use App\Models\SecuritySession;

class VerificationService
{
    public function verify(SecuritySession $session): bool
    {
        if (! $session->verified_at) {
            return false;
        }

        return true;
    }
}
