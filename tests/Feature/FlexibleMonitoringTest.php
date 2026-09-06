<?php

namespace Tests\Feature;

use App\Models\SecuritySession;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class FlexibleMonitoringTest extends TestCase
{
    use RefreshDatabase;

    public function test_verified_user_can_enable_custom_monitoring_interval(): void
    {
        $user = $this->makeUser();
        $session = $this->makeSession($user->id);

        $this->actingAs($user)
            ->patch(route('sessions.monitoring', $session), [
                'monitoring_enabled' => '1',
                'monitoring_interval_value' => 6,
                'monitoring_interval_unit' => 'hours',
            ])
            ->assertRedirect();

        $session->refresh();

        $this->assertTrue($session->monitoring_enabled);
        $this->assertSame(360, $session->schedule_interval_minutes);
        $this->assertNotNull($session->next_run_at);
        $this->assertSame('Every 6 hour(s)', $session->monitoringLabel());
    }

    public function test_user_can_disable_monitoring_without_deleting_session(): void
    {
        $user = $this->makeUser();
        $session = $this->makeSession($user->id);
        $session->update([
            'monitoring_enabled' => true,
            'schedule_frequency' => 'custom',
            'schedule_interval_minutes' => 1440,
            'next_run_at' => now()->addDay(),
        ]);

        $this->actingAs($user)
            ->patch(route('sessions.monitoring', $session), [])
            ->assertRedirect();

        $session->refresh();

        $this->assertFalse($session->monitoring_enabled);
        $this->assertNull($session->schedule_interval_minutes);
        $this->assertNull($session->next_run_at);
        $this->assertDatabaseHas('security_sessions', ['id' => $session->id]);
    }

    private function makeUser(): User
    {
        return User::create([
            'name' => 'Security Admin',
            'email' => uniqid('security-', true).'@example.test',
            'password' => Hash::make('a-very-strong-test-password'),
        ]);
    }

    private function makeSession(int $userId): SecuritySession
    {
        return SecuritySession::create([
            'user_id' => $userId,
            'name' => 'Verified Application',
            'target_url' => 'https://example.com',
            'environment' => 'production',
            'profile' => 'balanced',
            'status' => 'draft',
            'selected_modules' => ['headers', 'sensitive_files'],
            'config' => [],
            'verification_token' => str_repeat('a', 48),
            'verified_at' => now(),
        ]);
    }
}
