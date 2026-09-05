<?php

namespace App\Services\SecurityAudit;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;

class HttpProbe
{
    public function __construct(private readonly TargetGuard $guard)
    {
    }

    public function client(string $url): PendingRequest
    {
        $this->guard->assertAllowed($url);

        return Http::timeout(config('security_test.http_timeout'))
            ->connectTimeout(min(5, config('security_test.http_timeout')))
            ->withOptions([
                // Redirects are intentionally disabled so a public target cannot
                // redirect the scanner into localhost, metadata, or another private host.
                'allow_redirects' => false,
            ])
            ->withHeaders([
                'User-Agent' => 'Security-Test-Center/1.0 Authorized-Audit',
                'Accept' => 'text/html,application/json;q=0.9,*/*;q=0.8',
            ]);
    }
}
