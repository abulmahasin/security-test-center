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
use Illuminate\Support\Facades\Http;
use Mockery;
use Tests\TestCase;

class AuthenticatedSecurityTest extends TestCase
{
    use RefreshDatabase;

    public function test_test_identity_secret_is_encrypted_at_rest(): void
    {
        $session = $this->makeSession();
        $password = 'Very-Secret-Test-Password-123!';

        $identity = $this->makeIdentity($session, $password);

        $this->assertNotSame($password, $identity->fresh()->password_encrypted);
        $this->assertStringNotContainsString($password, $identity->fresh()->password_encrypted);
        $this->assertSame($password, $identity->fresh()->password());
    }

    public function test_test_session_cookie_is_encrypted_at_rest(): void
    {
        $session = $this->makeSession();
        $cookie = 'laravel_session=test-session-cookie-value; XSRF-TOKEN=test-xsrf';

        $identity = new SecurityIdentity([
            'security_session_id' => $session->id,
            'label' => 'Student Session Replay Test',
            'expected_role' => 'student',
            'auth_type' => 'cookie',
            'username' => '',
            'success_path' => '/dashboard',
            'enabled' => true,
        ]);
        $identity->setSessionCookie($cookie);
        $identity->save();

        $this->assertStringNotContainsString($cookie, $identity->fresh()->session_cookie_encrypted);
        $this->assertSame($cookie, $identity->fresh()->sessionCookie());
    }

    public function test_denied_boundary_returning_200_becomes_critical_broken_access_control(): void
    {
        $session = $this->makeSession();
        $identity = $this->makeIdentity($session);

        SecurityAccessRule::create([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => 'Admin User Management',
            'kind' => 'authorization',
            'path' => '/admin/users',
            'expectation' => 'denied',
            'business_context' => 'Student must never access administrative user management.',
        ]);

        $critical = $this->criticalFindingFor($session, 200);

        $this->assertNotNull($critical);
        $this->assertStringContainsString('Broken Access Control', $critical['title']);
        $this->assertStringContainsString('credentials_redacted', (string) $critical['evidence']);
    }

    public function test_idor_boundary_returning_200_is_classified_as_critical_bola(): void
    {
        $session = $this->makeSession();
        $identity = $this->makeIdentity($session);

        SecurityAccessRule::create([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => 'Another Student Exam Result',
            'kind' => 'idor',
            'path' => '/api/exam-results/9999',
            'expectation' => 'denied',
            'business_context' => 'Result 9999 belongs to another student.',
        ]);

        $critical = $this->criticalFindingFor($session, 200);

        $this->assertNotNull($critical);
        $this->assertStringContainsString('IDOR/BOLA', $critical['title']);
        $this->assertStringContainsString('idor_unexpectedly_allowed', (string) $critical['evidence']);
        $this->assertStringContainsString('another student', strtolower($critical['description']));
    }

    private function criticalFindingFor(SecuritySession $session, int $status): ?array
    {
        $auth = Mockery::mock(AuthenticatedSessionService::class);
        $client = Http::withOptions(['allow_redirects' => false]);
        $auth->shouldReceive('authenticate')->once()->andReturn([
            'client' => $client,
            'authenticated' => true,
            'status' => 200,
            'reason' => 'ok',
        ]);
        $auth->shouldReceive('get')->once()->andReturn(new Response(new Psr7Response($status)));

        $findings = (new AuthenticatedAccessScanner($auth))->scan($session->fresh());

        return collect($findings)->first(fn (array $finding) => $finding['severity'] === 'critical');
    }

    private function makeIdentity(SecuritySession $session, string $password = 'test-password-only'): SecurityIdentity
    {
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
        $identity->setPassword($password);
        $identity->save();

        return $identity;
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
