<?php

namespace App\Services\SecurityAudit;

use App\Models\SecuritySession;

class VerificationService
{
    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function verify(SecuritySession $session): bool
    {
        $url = rtrim($session->target_url, '/').config('security_test.verification_path');

        try {
            $response = $this->http->client($url)->get($url);
        } catch (\Throwable) {
            return false;
        }

        if (! $response->successful()) {
            return false;
        }

        if (hash_equals($session->verification_token, trim($response->body()))) {
            $session->update(['verified_at' => now()]);

            return true;
        }

        return false;
    }
}
