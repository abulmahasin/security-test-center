<?php

namespace Tests\Feature;

use App\Models\SecurityAccessRule;
use App\Models\SecurityAccountTest;
use App\Models\SecurityAgentManifest;
use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use App\Models\User;
use App\Services\SecurityAudit\AccountSecurityService;
use App\Services\SecurityAudit\Scanners\AccountCompromiseScanner;
use App\Services\SecurityAudit\Scanners\LaravelAgentScanner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Mockery;
use Tests\TestCase;

class EnterpriseSecurityModulesTest extends TestCase
{
    use RefreshDatabase;

    public function test_account_test_config_is_encrypted_at_rest(): void
    {
        [$session, $identity] = $this->makeSessionAndIdentity();

        $test = new SecurityAccountTest([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => 'Bounded Login Test',
            'kind' => 'login_throttling',
            'enabled' => true,
        ]);
        $test->setConfig(['dedicated_test_account_confirmed' => true, 'marker' => 'secret-config-marker']);
        $test->save();

        $this->assertStringNotContainsString('secret-config-marker', $test->fresh()->config_encrypted);
        $this->assertSame('secret-config-marker', $test->fresh()->config()['marker']);
    }

    public function test_login_enumeration_difference_becomes_high_finding(): void
    {
        [$session, $identity] = $this->makeSessionAndIdentity();

        SecurityAccountTest::create([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => 'Student Enumeration',
            'kind' => 'login_enumeration',
            'enabled' => true,
        ]);

        $service = Mockery::mock(AccountSecurityService::class);
        $service->shouldReceive('invalidLoginAttempt')->once()->withArgs(fn ($s, $i, $username) => $username === $identity->username)->andReturn([
            'status' => 422,
            'length' => 1400,
            'duration_ms' => 80,
            'location' => null,
            'retry_after' => null,
            'rate_limit_remaining' => null,
            'body_stored' => false,
        ]);
        $service->shouldReceive('syntheticUsername')->once()->andReturn('missing@example.test');
        $service->shouldReceive('invalidLoginAttempt')->once()->withArgs(fn ($s, $i, $username) => $username === 'missing@example.test')->andReturn([
            'status' => 404,
            'length' => 500,
            'duration_ms' => 75,
            'location' => null,
            'retry_after' => null,
            'rate_limit_remaining' => null,
            'body_stored' => false,
        ]);

        $findings = (new AccountCompromiseScanner($service))->scan($session);
        $high = collect($findings)->first(fn (array $finding) => $finding['severity'] === 'high');

        $this->assertNotNull($high);
        $this->assertStringContainsString('Enumeration', $high['title']);
        $this->assertStringContainsString('password_guessing', (string) $high['evidence']);
    }

    public function test_password_recovery_surface_without_csrf_becomes_medium_finding(): void
    {
        [$session, $identity] = $this->makeSessionAndIdentity();

        SecurityAccountTest::create([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => 'Recovery Surface',
            'kind' => 'password_reset_surface',
            'path' => '/forgot-password',
            'enabled' => true,
        ]);

        $service = Mockery::mock(AccountSecurityService::class);
        $service->shouldReceive('inspectSurface')->once()->withArgs(fn ($s, $path) => $path === '/forgot-password')->andReturn([
            'status' => 200,
            'length' => 1200,
            'location' => null,
            'csrf_present' => false,
            'password_input_present' => false,
            'email_or_username_input_present' => true,
            'form_count' => 1,
            'autocomplete_values' => ['email'],
            'response_body_stored' => false,
        ]);

        $findings = (new AccountCompromiseScanner($service))->scan($session);
        $medium = collect($findings)->first(fn (array $finding) => $finding['severity'] === 'medium');

        $this->assertNotNull($medium);
        $this->assertStringContainsString('recovery form tanpa csrf', strtolower($medium['title']));
        $this->assertStringContainsString('reset_request_sent', (string) $medium['evidence']);
    }

    public function test_laravel_agent_flags_public_admin_route_as_critical(): void
    {
        [$session] = $this->makeSessionAndIdentity();

        SecurityAgentManifest::create([
            'security_session_id' => $session->id,
            'source_label' => 'LMS Test',
            'framework' => 'laravel',
            'framework_version' => '12.x',
            'routes_count' => 1,
            'manifest' => [
                'security' => [
                    'app_debug' => false,
                    'session_secure' => true,
                ],
                'routes' => [[
                    'methods' => ['GET'],
                    'uri' => 'admin/users',
                    'name' => 'admin.users.index',
                    'action' => 'App\\Http\\Controllers\\AdminUserController@index',
                    'middleware' => ['web'],
                ]],
            ],
            'received_at' => now(),
        ]);

        $findings = (new LaravelAgentScanner())->scan($session);
        $critical = collect($findings)->first(fn (array $finding) => $finding['severity'] === 'critical');

        $this->assertNotNull($critical);
        $this->assertStringContainsString('tanpa auth middleware', $critical['title']);
    }

    public function test_laravel_manifest_can_generate_denied_matrix_for_low_privilege_identity(): void
    {
        [$session, $identity, $user] = $this->makeSessionAndIdentity();

        $manifest = SecurityAgentManifest::create([
            'security_session_id' => $session->id,
            'source_label' => 'LMS Test',
            'framework' => 'laravel',
            'framework_version' => '12.x',
            'routes_count' => 3,
            'manifest' => [
                'security' => ['app_debug' => false, 'session_secure' => true],
                'routes' => [
                    ['methods' => ['GET'], 'uri' => 'admin/users', 'name' => 'admin.users.index', 'middleware' => ['web', 'auth', 'role:admin']],
                    ['methods' => ['GET'], 'uri' => 'settings/security', 'name' => 'settings.security', 'middleware' => ['web', 'auth']],
                    ['methods' => ['GET'], 'uri' => 'students/{student}', 'name' => 'students.show', 'middleware' => ['web', 'auth']],
                ],
            ],
            'received_at' => now(),
        ]);

        $this->actingAs($user)
            ->post(route('sessions.agent-manifests.generate-rules', [$session, $manifest]), [
                'security_identity_id' => $identity->id,
            ])
            ->assertRedirect();

        $this->assertSame(2, SecurityAccessRule::where('security_session_id', $session->id)->count());
        $this->assertDatabaseHas('security_access_rules', [
            'security_identity_id' => $identity->id,
            'path' => '/admin/users',
            'expectation' => 'denied',
            'kind' => 'authorization',
        ]);
        $this->assertDatabaseMissing('security_access_rules', [
            'security_identity_id' => $identity->id,
            'path' => '/students/{student}',
        ]);
    }

    private function makeSessionAndIdentity(): array
    {
        $user = User::create([
            'name' => 'Security Admin',
            'email' => fake()->unique()->safeEmail(),
            'password' => Hash::make('strong-test-password'),
        ]);

        $session = SecuritySession::create([
            'user_id' => $user->id,
            'name' => 'Enterprise Security Test',
            'target_url' => 'https://example.test',
            'environment' => 'staging',
            'profile' => 'balanced',
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => ['account_compromise', 'laravel_agent'],
            'config' => [],
            'verification_token' => str_repeat('a', 48),
            'verified_at' => now(),
        ]);

        $identity = new SecurityIdentity([
            'security_session_id' => $session->id,
            'label' => 'Student Test',
            'expected_role' => 'student',
            'auth_type' => 'form',
            'login_path' => '/login',
            'username_field' => 'email',
            'password_field' => 'password',
            'username' => 'student@example.test',
            'success_path' => '/dashboard',
            'enabled' => true,
        ]);
        $identity->setPassword('test-account-password');
        $identity->save();

        return [$session, $identity, $user];
    }
}
