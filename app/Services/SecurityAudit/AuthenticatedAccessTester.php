<?php

namespace App\Services\SecurityAudit;

use App\Models\SecurityAccessCase;
use App\Models\SecurityAccessResult;
use App\Models\SecurityTestIdentity;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

class AuthenticatedAccessTester
{
    public function __construct(private readonly TargetGuard $guard)
    {
    }

    public function runCase(SecurityAccessCase $case): SecurityAccessResult
    {
        $case->loadMissing(['session', 'identity']);
        $session = $case->session;
        $identity = $case->identity;

        if (! $session->isVerified()) {
            throw new RuntimeException('Target harus terverifikasi sebelum authenticated testing.');
        }

        if (! $identity->enabled || ! $case->enabled) {
            throw new RuntimeException('Identity atau test case sedang dinonaktifkan.');
        }

        $targetUrl = $this->absoluteUrl($session->target_url, $case->path);
        $this->guard->assertAllowed($targetUrl);

        $started = microtime(true);
        $response = $this->authenticatedRequest($identity, $session->target_url, $case->method, $targetUrl);
        $durationMs = (int) round((microtime(true) - $started) * 1000);
        $status = $response->status();
        $expectedForbidden = $case->expected_policy === 'forbidden';

        if ($expectedForbidden) {
            $passed = in_array($status, [401, 403, 404], true);
        } else {
            $passed = $status >= 200 && $status < 300;
        }

        $outcome = $passed ? 'pass' : 'fail';
        $severity = null;
        $summary = '';
        $remediation = null;

        if ($passed) {
            $summary = $expectedForbidden
                ? "Access boundary bekerja: {$identity->role_label} ditolak pada resource yang seharusnya terlarang."
                : "Expected access berhasil untuk identity {$identity->role_label}.";
        } elseif ($expectedForbidden && $status >= 200 && $status < 300) {
            $severity = $case->kind === 'idor' ? 'critical' : 'high';
            $summary = $case->kind === 'idor'
                ? "Potential IDOR/BOLA: identity {$identity->role_label} dapat membaca resource yang seharusnya bukan miliknya."
                : "Broken access control: identity {$identity->role_label} berhasil membuka resource yang seharusnya dilarang.";
            $remediation = 'Terapkan authorization server-side pada setiap request menggunakan middleware, policy/gate, ownership check, atau scoped query. Jangan mengandalkan menu/tombol yang disembunyikan di frontend.';
        } else {
            $severity = 'medium';
            $summary = "Expected access gagal atau menghasilkan status tak terduga ({$status}).";
            $remediation = 'Periksa autentikasi akun uji, route middleware, policy, dan expected policy pada test case.';
        }

        $identity->update([
            'last_verified_at' => now(),
            'last_auth_status' => $status >= 200 && $status < 500 ? 'tested' : 'error',
        ]);

        return SecurityAccessResult::create([
            'security_access_case_id' => $case->id,
            'security_session_id' => $session->id,
            'security_test_identity_id' => $identity->id,
            'outcome' => $outcome,
            'status_code' => $status,
            'severity' => $severity,
            'summary' => $summary,
            'evidence' => json_encode([
                'method' => $case->method,
                'path' => $case->path,
                'status' => $status,
                'identity' => $identity->name,
                'role' => $identity->role_label,
                'response_body_stored' => false,
                'location' => $this->redactLocation($response->header('Location')),
            ], JSON_UNESCAPED_SLASHES),
            'remediation' => $remediation,
            'response_bytes' => strlen($response->body()),
            'duration_ms' => $durationMs,
            'executed_at' => now(),
        ]);
    }

    private function authenticatedRequest(SecurityTestIdentity $identity, string $baseUrl, string $method, string $targetUrl)
    {
        $credentials = $identity->credentials ?? [];
        $request = $this->baseClient();

        return match ($identity->auth_type) {
            'bearer' => $this->send($request->withToken((string) ($credentials['token'] ?? '')), $method, $targetUrl),
            'basic' => $this->send($request->withBasicAuth((string) ($credentials['username'] ?? ''), (string) ($credentials['password'] ?? '')), $method, $targetUrl),
            'cookie' => $this->send($request->withHeaders(['Cookie' => (string) ($credentials['cookie'] ?? '')]), $method, $targetUrl),
            'form' => $this->formLoginAndSend($credentials, $baseUrl, $method, $targetUrl),
            default => throw new RuntimeException('Auth type tidak didukung.'),
        };
    }

    private function formLoginAndSend(array $credentials, string $baseUrl, string $method, string $targetUrl)
    {
        $loginUrl = $this->absoluteUrl($baseUrl, (string) ($credentials['login_path'] ?? '/login'));
        $this->guard->assertAllowed($loginUrl);

        $jar = new CookieJar();
        $client = $this->baseClient()->withOptions(['cookies' => $jar]);
        $loginPage = $client->get($loginUrl);

        $token = null;
        if (preg_match('/name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']/i', $loginPage->body(), $match)) {
            $token = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        }

        $payload = [
            (string) ($credentials['username_field'] ?? 'email') => (string) ($credentials['username'] ?? ''),
            (string) ($credentials['password_field'] ?? 'password') => (string) ($credentials['password'] ?? ''),
        ];

        if ($token) {
            $payload['_token'] = $token;
        }

        $client->asForm()->post($loginUrl, $payload);

        return $this->send($client, $method, $targetUrl);
    }

    private function baseClient(): PendingRequest
    {
        return Http::timeout(config('security_test.http_timeout'))
            ->connectTimeout(min(5, config('security_test.http_timeout')))
            ->withOptions(['allow_redirects' => false])
            ->withHeaders([
                'User-Agent' => 'Security-Test-Center/2.0 Authenticated-Authorization-Validation',
                'Accept' => 'text/html,application/json;q=0.9,*/*;q=0.8',
            ]);
    }

    private function send(PendingRequest $request, string $method, string $url)
    {
        try {
            return match (strtoupper($method)) {
                'HEAD' => $request->head($url),
                default => $request->get($url),
            };
        } catch (Throwable $e) {
            throw new RuntimeException('Authenticated request gagal: '.$e->getMessage(), previous: $e);
        }
    }

    private function absoluteUrl(string $baseUrl, string $path): string
    {
        if (filter_var($path, FILTER_VALIDATE_URL)) {
            $baseHost = strtolower((string) parse_url($baseUrl, PHP_URL_HOST));
            $pathHost = strtolower((string) parse_url($path, PHP_URL_HOST));
            if ($baseHost !== $pathHost) {
                throw new RuntimeException('Access case harus tetap pada host target yang terverifikasi.');
            }

            return $path;
        }

        return rtrim($baseUrl, '/').'/'.ltrim($path, '/');
    }

    private function redactLocation(?string $location): ?string
    {
        if (! $location) {
            return null;
        }

        $parts = parse_url($location);
        if (! is_array($parts)) {
            return '[redacted]';
        }

        return $parts['path'] ?? '/';
    }
}
