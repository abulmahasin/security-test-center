<?php

namespace Tests\Feature;

use App\Models\SecurityAccessRule;
use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use App\Models\User;
use App\Services\SecurityAudit\AuthenticatedSessionService;
use App\Services\SecurityAudit\Scanners\AuthenticatedAccessScanner;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Hash;
use Mockery;
use Tests\TestCase;

class AuthenticatedSecurityTest extends TestCase
{
    use RefreshDatabase;

    public function test_test_identity_secret_is_encrypted_at_rest(): void
    {
        $session = $this->makeSession();
        $password = 'Very-Secret-Test-Password-123!';

        $identity = new SecurityIdentity([
            'security_session_id' => $session->id,
            'label' => 'Student Test',
            'expected_role' => 'student',
            'auth_type' => 'form',
            'login_path' => '/login',
            'username_field' => 'email',
            'username' => 'student@example.test',
            'success_path' => '/dashboard',
            'enabled' => true,
        ]);
        $identity->setPassword($password);
        $identity->save();

        $this->assertNotSame($password, $identity->fresh()->password_encrypted);
        $this->assertStringNotContainsString($password, $identity->fresh()->password_encrypted);
        $this->assertSame($password, $identity->fresh()->password());
    }

    public function test_denied_boundary_returning_200_becomes_critical_broken_access_control(): void
    {
        $session = $this->makeSession();

        $identity = new SecurityIdentity([
            'security_session_id' => $session->id,
            'label' => 'Student Test',
            'expected_role' => 'student',
            'auth_type' => 'form',
            'login_path' => '/login',
            'username_field' => 'email',
            'username' => 'student@example.test',
            'success_path' => '/dashboard',
            'enabled' => true,
        ]);
        $identity->setPassword('test-password-only');
        $identity->save();

        SecurityAccessRule::create([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => 'Admin User Management',
            'path' => '/admin/users',
            'expectation' => 'denied',
        ]);

        $auth = Mockery::mock(AuthenticatedSessionService::class);
        $client = new \stdClass();
        $auth->shouldReceive('authenticate')->once()->andReturn([
            'client' => $client,
            'authenticated' => true,
            'status' => 200,
            'reason' => 'ok',
        ]);
        $auth->shouldReceive('get')->once()->andReturn(new Response(new Psr7Response(200)));

        $findings = (new AuthenticatedAccessScanner($auth))->scan($session);
        $critical = collect($findings)->first(fn (array $finding) => $finding['severity'] === 'critical');

        $this->assertNotNull($critical);
        $this->assertStringContainsString('Broken Access Control', $critical['title']);
        $this->assertStringContainsString('credentials_redacted', (string) $critical['evidence']);
    }

    private function makeSession(): SecuritySession
    {
        $user = User::create([
            'name' => 'Security Admin',
            'email' => fake()->unique()->safeEmail(),
            'password' => Hash::make('strong-test-password'),
        ]);

        return SecuritySession::create([
            'user_id' => $user->id,
            'name' => 'Authenticated Security Test',
            'target_url' => 'https://example.test',
            'environment' => 'staging',
            'profile' => 'balanced',
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => ['authenticated_access'],
            'config' => [],
            'verification_token' => str_repeat('a', 48),
            'verified_at' => now(),
        ]);
    }
}
