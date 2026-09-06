<?php

namespace App\Services\SecurityAudit;

use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

class AuthenticatedSessionService
{
    public function __construct(private readonly TargetGuard $guard)
    {
    }

    /**
     * @return array{client: PendingRequest, authenticated: bool, status: int|null, reason: string}
     */
    public function authenticate(SecuritySession $session, SecurityIdentity $identity): array
    {
        if ($identity->auth_type === 'bearer') {
            $token = $identity->bearerToken();

            if (blank($token)) {
                return ['client' => $this->client($session->target_url), 'authenticated' => false, 'status' => null, 'reason' => 'Bearer token tidak tersedia.'];
            }

            $client = $this->client($session->target_url)->withToken($token);
            $probe = $this->safeGet($client, $this->url($session, $identity->success_path));

            return [
                'client' => $client,
                'authenticated' => $this->isAllowedResponse($probe),
                'status' => $probe->status(),
                'reason' => $this->isAllowedResponse($probe) ? 'Bearer identity verified.' : 'Bearer identity tidak dapat mengakses verification path.',
            ];
        }

        $jar = new CookieJar();
        $loginUrl = $this->url($session, $identity->login_path);
        $successUrl = $this->url($session, $identity->success_path);
        $client = $this->client($loginUrl, $jar);

        $loginPage = $this->safeGet($client, $loginUrl);
        $payload = [
            $identity->username_field => $identity->username,
            $identity->password_field ?: 'password' => $identity->password(),
        ];

        if ($token = $this->extractCsrfToken($loginPage->body())) {
            $payload['_token'] = $token;
        }

        $loginResponse = $client->asForm()->post($loginUrl, $payload);

        if (in_array($loginResponse->status(), [401, 403, 419, 422], true)) {
            return [
                'client' => $client,
                'authenticated' => false,
                'status' => $loginResponse->status(),
                'reason' => 'Login ditolak oleh target.',
            ];
        }

        $probe = $this->safeGet($client, $successUrl);

        return [
            'client' => $client,
            'authenticated' => $this->isAllowedResponse($probe),
            'status' => $probe->status(),
            'reason' => $this->isAllowedResponse($probe) ? 'Session login verified.' : 'Login response diterima tetapi verification path tetap tidak dapat diakses.',
        ];
    }

    public function get(PendingRequest $client, SecuritySession $session, string $path): Response
    {
        return $this->safeGet($client, $this->url($session, $path));
    }

    private function client(string $url, ?CookieJar $jar = null): PendingRequest
    {
        $this->guard->assertAllowed($url);

        $options = ['allow_redirects' => false];
        if ($jar) {
            $options['cookies'] = $jar;
        }

        return Http::timeout(config('security_test.http_timeout'))
            ->connectTimeout(min(5, config('security_test.http_timeout')))
            ->withOptions($options)
            ->withHeaders([
                'User-Agent' => 'Security-Test-Center/1.0 Authenticated-Authorized-Audit',
                'Accept' => 'text/html,application/json;q=0.9,*/*;q=0.8',
            ]);
    }

    private function safeGet(PendingRequest $client, string $url): Response
    {
        $this->guard->assertAllowed($url);

        return $client->get($url);
    }

    private function url(SecuritySession $session, string $path): string
    {
        $path = '/'.ltrim($path, '/');
        $url = rtrim($session->target_url, '/').$path;
        $this->guard->assertAllowed($url);

        return $url;
    }

    private function isAllowedResponse(Response $response): bool
    {
        return $response->status() >= 200 && $response->status() < 300;
    }

    private function extractCsrfToken(string $html): ?string
    {
        $sample = substr($html, 0, 500000);

        if (preg_match('/<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\'][^>]*>/i', $sample, $match)) {
            return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        }

        if (preg_match('/<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']_token["\'][^>]*>/i', $sample, $match)) {
            return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        }

        if (preg_match('/<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\'][^>]*>/i', $sample, $match)) {
            return html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5);
        }

        return null;
    }
}
