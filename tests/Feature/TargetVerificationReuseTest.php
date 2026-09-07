<?php

namespace Tests\Feature;

use App\Models\SecuritySession;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class TargetVerificationReuseTest extends TestCase
{
    use RefreshDatabase;

    public function test_new_session_reuses_verified_target_ownership_for_same_user_and_url(): void
    {
        $user = User::create([
            'name' => 'Security Admin',
            'email' => 'security@example.test',
            'password' => Hash::make('strong-test-password'),
        ]);

        $verified = SecuritySession::create([
            'user_id' => $user->id,
            'name' => 'First Assessment',
            'target_url' => 'https://owned.example.test',
            'environment' => 'staging',
            'profile' => 'balanced',
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => ['headers'],
            'config' => [],
            'verification_token' => str_repeat('a', 48),
            'verified_at' => now(),
        ]);

        $next = SecuritySession::create([
            'user_id' => $user->id,
            'name' => 'Second Assessment',
            'target_url' => 'https://owned.example.test',
            'environment' => 'staging',
            'profile' => 'balanced',
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => ['headers'],
            'config' => [],
            'verification_token' => str_repeat('b', 48),
        ]);

        $this->assertNotNull($next->verified_at);
        $this->assertSame($verified->verification_token, $next->verification_token);
        $this->assertTrue($next->isVerified());
    }

    public function test_verification_is_not_reused_across_different_users(): void
    {
        $owner = User::create([
            'name' => 'Owner',
            'email' => 'owner@example.test',
            'password' => Hash::make('strong-test-password'),
        ]);

        $other = User::create([
            'name' => 'Other',
            'email' => 'other@example.test',
            'password' => Hash::make('strong-test-password'),
        ]);

        SecuritySession::create([
            'user_id' => $owner->id,
            'name' => 'Owner Assessment',
            'target_url' => 'https://owned.example.test',
            'environment' => 'staging',
            'profile' => 'balanced',
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => ['headers'],
            'config' => [],
            'verification_token' => str_repeat('a', 48),
            'verified_at' => now(),
        ]);

        $session = SecuritySession::create([
            'user_id' => $other->id,
            'name' => 'Other Assessment',
            'target_url' => 'https://owned.example.test',
            'environment' => 'staging',
            'profile' => 'balanced',
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => ['headers'],
            'config' => [],
            'verification_token' => str_repeat('b', 48),
        ]);

        $this->assertNull($session->verified_at);
        $this->assertSame(str_repeat('b', 48), $session->verification_token);
    }
}
