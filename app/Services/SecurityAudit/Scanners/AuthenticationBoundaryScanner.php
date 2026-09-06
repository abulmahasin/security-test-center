<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecurityAgentManifest;
use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\HttpProbe;
use App\Services\SecurityAudit\Scanner;
use Illuminate\Support\Str;
use Throwable;

class AuthenticationBoundaryScanner implements Scanner
{
    private const MAX_ROUTES = 40;

    public function __construct(private readonly HttpProbe $http)
    {
    }

    public function scan(SecuritySession $session): array
    {
        $candidates = $this->candidates($session);

        if ($candidates->isEmpty()) {
            return [Finding::make(
                'info',
                'Authentication Boundary belum memiliki protected-route inventory',
                'Scanner tidak menemukan route statis GET/HEAD yang dapat dibuktikan sebagai protected resource dari Laravel Agent manifest atau authorization matrix.',
                'Import Laravel Agent manifest atau tambahkan access-control rules. Setelah itu scanner dapat menguji route tersebut sebagai Guest tanpa credential/token dan merekam attack-path replay jika boundary gagal.'
            )];
        }

        $findings = [];
        $protected = 0;
        $failed = 0;
        $loginShells = 0;

        foreach ($candidates->take(self::MAX_ROUTES) as $candidate) {
            try {
                $guest = $this->probe($session, $candidate['path']);
            } catch (Throwable) {
                $findings[] = Finding::make(
                    'low',
                    'Guest boundary probe inconclusive: '.$candidate['path'],
                    'Unauthenticated GET tidak dapat diselesaikan untuk route ini.',
                    'Periksa availability target dan jalankan assessment ulang.',
                    $this->evidence($candidate, null, 'guest_request_failed', 'guest')
                );
                continue;
            }

            if ($this->isDenied($guest['status'])) {
                $protected++;

                if ($candidate['token_protected']) {
                    try {
                        $invalidToken = $this->probe($session, $candidate['path'], true);
                    } catch (Throwable) {
                        continue;
                    }

                    if ($this->isSuccessfulResource($invalidToken)) {
                        $failed++;
                        $findings[] = $this->failureFinding(
                            $candidate,
                            $invalidToken,
                            'invalid_token_accepted',
                            'Synthetic Invalid Token',
                            'Request memakai bearer token sintetis yang sengaja tidak valid, namun protected resource tetap mengembalikan response sukses.'
                        );
                    }
                }

                continue;
            }

            if ($guest['status'] >= 200 && $guest['status'] < 300 && $guest['looks_like_login']) {
                $loginShells++;
                $findings[] = Finding::make(
                    'low',
                    'Protected route returns HTTP 200 login shell: '.$candidate['path'],
                    'Route yang diharapkan protected mengembalikan HTTP 2xx tetapi kontennya terlihat seperti login form/shell. Ini tidak diklasifikasikan sebagai authentication bypass, namun dapat mengaburkan monitoring berbasis status code.',
                    'Bila memungkinkan gunakan 302 ke login untuk web atau 401/403 untuk API. Pastikan resource sensitif tidak ikut dirender di HTML/JSON sebelum autentikasi.',
                    $this->evidence($candidate, $guest, 'login_shell_200', 'guest')
                );
                continue;
            }

            if ($this->isSuccessfulResource($guest)) {
                $failed++;
                $findings[] = $this->failureFinding(
                    $candidate,
                    $guest,
                    'guest_unexpectedly_allowed',
                    'Guest / No Account',
                    'Request dikirim tanpa session, credential, cookie autentikasi, atau Authorization header, tetapi protected resource mengembalikan response sukses.'
                );
                continue;
            }

            $findings[] = Finding::make(
                'low',
                'Authentication response inconclusive: '.$candidate['path'],
                'Guest request menghasilkan HTTP '.$guest['status'].', sehingga route tidak dapat diklasifikasikan dengan pasti sebagai protected atau exposed.',
                'Periksa behavior endpoint dan sesuaikan route/middleware bila status khusus ini memang disengaja.',
                $this->evidence($candidate, $guest, 'inconclusive', 'guest')
            );
        }

        array_unshift($findings, Finding::make(
            $failed > 0 ? 'high' : 'info',
            $failed > 0 ? 'Authentication Boundary attack paths detected' : 'Authentication Boundary baseline completed',
            $failed > 0
                ? "Ditemukan {$failed} protected-route boundary failure dari unauthenticated/invalid-token replay. Setiap failure memiliki Attack Path Replay terpisah."
                : "Tidak ditemukan protected resource yang jelas dapat dibaca Guest pada bounded scan ini. {$protected} route menunjukkan denial/redirect yang sesuai; {$loginShells} route menggunakan HTTP 200 login shell.",
            'Pertahankan server-side authentication middleware, token validation, dan regression test. Gunakan Attack Path Replay untuk memperbaiki boundary failure satu per satu.',
            json_encode([
                'tested_routes' => min($candidates->count(), self::MAX_ROUTES),
                'correctly_protected' => $protected,
                'boundary_failures' => $failed,
                'login_shells' => $loginShells,
                'request_mode' => 'GET-only',
                'credential_used' => false,
                'token_guessing' => false,
                'response_body_stored' => false,
            ], JSON_UNESCAPED_SLASHES)
        ));

        return $findings;
    }

    private function candidates(SecuritySession $session)
    {
        $routes = collect();
        $manifest = SecurityAgentManifest::query()
            ->where('security_session_id', $session->id)
            ->latest('received_at')
            ->latest('id')
            ->first();

        foreach (($manifest?->manifest['routes'] ?? []) as $route) {
            if (! is_array($route)) {
                continue;
            }

            $path = '/'.ltrim((string) ($route['uri'] ?? ''), '/');
            $methods = collect($route['methods'] ?? [])->map(fn ($method) => strtoupper((string) $method));
            $middleware = collect($route['middleware'] ?? [])->map(fn ($item) => strtolower((string) $item));
            $hasAuth = $middleware->contains(fn (string $item) =>
                $item === 'auth'
                || str_starts_with($item, 'auth:')
                || str_contains($item, 'sanctum')
                || str_contains($item, 'passport')
                || str_contains($item, 'jwt')
            );
            $readOnly = $methods->isEmpty() || $methods->contains(fn (string $method) => in_array($method, ['GET', 'HEAD'], true));
            $static = ! str_contains($path, '{') && ! str_contains($path, '}');

            if (! $hasAuth || ! $readOnly || ! $static) {
                continue;
            }

            $routes->push([
                'path' => $path,
                'source' => 'laravel_agent_manifest',
                'name' => (string) ($route['name'] ?? ''),
                'middleware' => $route['middleware'] ?? [],
                'token_protected' => $middleware->contains(fn (string $item) =>
                    str_contains($item, 'sanctum')
                    || str_contains($item, 'passport')
                    || str_contains($item, 'jwt')
                    || $item === 'auth:api'
                ),
            ]);
        }

        $session->loadMissing('accessRules');
        foreach ($session->accessRules->where('expectation', 'denied') as $rule) {
            $path = '/'.ltrim((string) $rule->path, '/');
            if (str_contains($path, '{') || str_contains($path, '}')) {
                continue;
            }

            $routes->push([
                'path' => $path,
                'source' => 'authorization_matrix',
                'name' => $rule->label,
                'middleware' => [],
                'token_protected' => str_starts_with($path, '/api/'),
            ]);
        }

        return $routes
            ->filter(fn (array $route) => $route['path'] !== '/')
            ->unique('path')
            ->values();
    }

    private function probe(SecuritySession $session, string $path, bool $invalidToken = false): array
    {
        $url = rtrim($session->target_url, '/').'/'.ltrim($path, '/');
        $client = $this->http->client($url);

        if ($invalidToken) {
            $client = $client->withToken('stc-invalid-'.Str::lower(Str::random(32)));
        }

        $response = $client->get($url);
        $sample = substr($response->body(), 0, 65536);

        return [
            'status' => $response->status(),
            'content_type' => mb_substr((string) $response->header('Content-Type'), 0, 120),
            'location' => $this->redactLocation($response->header('Location')),
            'looks_like_login' => $this->looksLikeLogin($sample),
            'sampled_bytes' => strlen($sample),
        ];
    }

    private function failureFinding(array $candidate, array $response, string $result, string $entry, string $description): array
    {
        $sensitive = preg_match('#^/(admin|administrator|management|settings|users|roles|permissions|telescope|horizon|pulse)(/|$)#i', $candidate['path']) === 1;
        $severity = $sensitive ? 'critical' : 'high';
        $title = $result === 'invalid_token_accepted'
            ? 'Invalid token accepted by protected resource: '.$candidate['path']
            : 'Unauthenticated access to protected resource: '.$candidate['path'];

        return Finding::make(
            $severity,
            $title,
            $description.' Dari sisi attacker, ini berarti resource dapat dicapai tanpa boundary autentikasi yang diharapkan.',
            'Terapkan authentication middleware server-side pada route/API, validasi token secara ketat, gunakan 401/403 untuk API, dan pastikan authorization tetap diperiksa setelah autentikasi. Tambahkan regression test untuk route ini.',
            $this->evidence($candidate, $response, $result, $entry)
        );
    }

    private function evidence(array $candidate, ?array $response, string $result, string $entry): string
    {
        return json_encode([
            'result' => $result,
            'path' => $candidate['path'],
            'route_name' => $candidate['name'],
            'source' => $candidate['source'],
            'middleware' => $candidate['middleware'],
            'http_status' => $response['status'] ?? null,
            'content_type' => $response['content_type'] ?? null,
            'location' => $response['location'] ?? null,
            'method' => 'GET',
            'credential_used' => false,
            'credential_theft' => false,
            'token_guessing' => false,
            'response_body_stored' => false,
            'attack_path' => in_array($result, ['guest_unexpectedly_allowed', 'invalid_token_accepted'], true) ? [
                'entry' => $entry,
                'target' => $candidate['path'],
                'outcome' => 'Protected Resource Reached',
                'severity_hint' => preg_match('#^/(admin|administrator|management|settings|users|roles|permissions)(/|$)#i', $candidate['path']) === 1 ? 'critical' : 'high',
                'steps' => [
                    ['state' => 'start', 'label' => $entry],
                    ['state' => 'pass', 'label' => 'Target ownership already verified'],
                    ['state' => 'pass', 'label' => 'GET request prepared without valid authentication'],
                    ['state' => 'fail', 'label' => 'Expected authentication boundary did not deny request'],
                    ['state' => 'impact', 'label' => 'HTTP '.($response['status'] ?? '?').' from '.$candidate['path']],
                ],
            ] : null,
        ], JSON_UNESCAPED_SLASHES);
    }

    private function isDenied(int $status): bool
    {
        return in_array($status, [401, 403, 404], true) || ($status >= 300 && $status < 400);
    }

    private function isSuccessfulResource(array $response): bool
    {
        return $response['status'] >= 200 && $response['status'] < 300 && ! $response['looks_like_login'];
    }

    private function looksLikeLogin(string $body): bool
    {
        $lower = strtolower($body);

        return preg_match('/<input[^>]+type=["\']password["\']/i', $body) === 1
            || (str_contains($lower, 'login') && str_contains($lower, 'password'))
            || (str_contains($lower, 'sign in') && str_contains($lower, 'password'));
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
