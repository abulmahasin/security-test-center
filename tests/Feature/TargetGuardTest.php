<?php

namespace Tests\Feature;

use App\Services\SecurityAudit\TargetGuard;
use Illuminate\Validation\ValidationException;
use Tests\TestCase;

class TargetGuardTest extends TestCase
{
    public function test_localhost_is_rejected(): void
    {
        $this->expectException(ValidationException::class);

        app(TargetGuard::class)->assertAllowed('http://localhost');
    }

    public function test_cloud_metadata_ip_is_rejected(): void
    {
        $this->expectException(ValidationException::class);

        app(TargetGuard::class)->assertAllowed('http://169.254.169.254');
    }
}
