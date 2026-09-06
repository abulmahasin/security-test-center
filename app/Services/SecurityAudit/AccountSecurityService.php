<?php

namespace App\Services\SecurityAudit;

use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class AccountSecurityService
{
    public function __construct(private readonly TargetGuard $guard)
    {
    }

    public function invalidLoginAttempt(SecuritySession $session, SecurityIdentity $identity, string $username): array
    {
        $loginUrl = $this->url($session, $identity->login_path ?: '/login');
        $jar = new CookieJar();
        $client = $this->client($loginUrl, $jar);
        $loginPage = $client->get($loginUrl);

        $payload = [
            $identity->username_field ?: 'email' => $username,
            $identity->password_field ?: 'password' => 'STC-invalid-'.Str::random(24),
        ];

        if ($token = $this->extractCsrfToken($loginPage->body())) {
            $payload['_token'] = $token;
        }

        $started = microtime(true);
        $response = $client->asForm()->post($loginUrl, $payload);
        $duration = (int) round((microtime(true) - $started) * 1000);

        return [
            'status' => $response->status(),
            'length' => strlen($response->body()),
            'duration_ms' => $duration,
            'location' => $this->redactLocation($response->header('Location')),
            'retry_after' => $response->header('Retry-After'),
            'rate_limit_remaining' => $response->header('X-RateLimit-Remaining') ?: $response->header('RateLimit-Remaining'),
            'body_stored' => false,
        ];
    }

    public function inspectSurface(SecuritySession $session, string $path): array
    {
        $url = $this->url($session, $path);
        $jar = new CookieJar();
        $response = $this->client($url, $jar)->get($url);
        $sample = substr($response->body(), 0, 500000);
        $lower = strtolower($sample);

        preg_match_all('/<form\b/i', $sample, $forms);
        preg_match_all('/autocomplete=["\']([^"\']+)["\']/i', $sample, $autocompleteMatches);

        return [
            'status' => $response->status(),
            'length' => strlen($response->body()),
            'location' => $this->redactLocation($response->header('Location')),
            'csrf_present' => $this->extractCsrfToken($sample) !== null,
            'password_input_present' => preg_match('/<input[^>]*type=["\']password["\']/i', $sample) === 1,
            'email_or_username_input_present' => str_contains($lower, 'type="email"')
                || str_contains($lower, "type='email'")
                || preg_match('/<input[^>]*name=["\'](?:email|username|login)["\']/i', $sample) === 1,
            'form_count' => count($forms[0] ?? []),
            'autocomplete_values' => array_values(array_unique(array_map(
                fn ($value) => mb_substr(strtolower((string) $value), 0, 40),
                $autocompleteMatches[1] ?? []
            ))),
            'response_body_stored' => false,
        ];
    }

    public function syntheticUsername(SecurityIdentity $identity): string
    {
        $username = (string) $identity->username;

        if (str_contains($username, '@')) {
            [$local, $domain] = array_pad(explode('@', $username, 2), 2, 'example.invalid');
            return $local.'+stc-missing-'.Str::lower(Str::random(12)).'@'.$domain;
        }

        return 'stc_missing_'.Str::lower(Str::random(20));
    }

    private function client(string $url, CookieJar $jar): PendingRequest
    {
        $this->guard->assertAllowed($url);

        return Http::timeout(config('security_test.http_timeout'))
            ->connectTimeout(min(5, config('security_test.http_timeout')))
            ->withOptions([
                'allow_redirects' => false,
                'cookies' => $jar,
            ])
            ->withHeaders([
                'User-Agent' => 'Security-Test-Center/2.0 Account-Defense-Validation',
                'Accept' => 'text/html,application/json;q=0.9,*/*;q=0.8',
            ]);
    }

    private function url(SecuritySession $session, string $path): string
    {
        $url = rtrim($session->target_url, '/').'/'.ltrim($path, '/');
        $this->guard->assertAllowed($url);

        return $url;
    }

    private function extractCsrfToken(string $html): ?string
    {
        $sample = substr($html, 0, 500000);

        if (preg_match('/<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\'][^>]*>/i', $sample, $match)) {
            return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        }

        if (preg_match('/<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\'][^>]*>/i', $sample, $match)) {
            return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        }

        return null;
    }

    private function redactLocation(?string $location): ?string
    {
        if (! $location) {
            return null;
        }

        $parts = parse_url($location);
        return is_array($parts) ? ($parts['path'] ?? '/') : '[redacted]';
    }
}
