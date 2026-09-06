<?php

namespace App\Http\Controllers;

use App\Models\SecurityAccessRule;
use App\Models\SecurityAgentManifest;
use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class LaravelAgentController extends Controller
{
    public function store(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus diverifikasi sebelum source-assisted manifest diimport.');

        $data = $request->validate([
            'source_label' => ['nullable', 'string', 'max:120'],
            'manifest_json' => ['required', 'string', 'max:1000000'],
        ]);

        try {
            $manifest = json_decode($data['manifest_json'], true, flags: JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw ValidationException::withMessages([
                'manifest_json' => 'Manifest JSON tidak valid.',
            ]);
        }

        if (! is_array($manifest)) {
            throw ValidationException::withMessages([
                'manifest_json' => 'Manifest harus berupa JSON object.',
            ]);
        }

        $routes = $manifest['routes'] ?? null;
        if (! is_array($routes)) {
            throw ValidationException::withMessages([
                'manifest_json' => 'Manifest harus memiliki array routes.',
            ]);
        }

        if (count($routes) > 5000) {
            throw ValidationException::withMessages([
                'manifest_json' => 'Manifest dibatasi maksimal 5.000 routes.',
            ]);
        }

        $sanitizedRoutes = collect($routes)->map(function ($route): array {
            $route = is_array($route) ? $route : [];

            return [
                'methods' => array_values(array_slice(array_map('strval', (array) ($route['methods'] ?? [])), 0, 12)),
                'uri' => mb_substr((string) ($route['uri'] ?? ''), 0, 500),
                'name' => mb_substr((string) ($route['name'] ?? ''), 0, 255),
                'action' => mb_substr((string) ($route['action'] ?? ''), 0, 500),
                'middleware' => array_values(array_slice(array_map('strval', (array) ($route['middleware'] ?? [])), 0, 50)),
            ];
        })->values()->all();

        $sanitized = [
            'app' => mb_substr((string) ($manifest['app'] ?? ''), 0, 120),
            'environment' => mb_substr((string) ($manifest['environment'] ?? ''), 0, 60),
            'framework' => 'laravel',
            'framework_version' => mb_substr((string) ($manifest['framework_version'] ?? ''), 0, 40),
            'php_version' => mb_substr((string) ($manifest['php_version'] ?? ''), 0, 40),
            'security' => [
                'app_debug' => (bool) data_get($manifest, 'security.app_debug', false),
                'session_secure' => data_get($manifest, 'security.session_secure'),
                'session_http_only' => data_get($manifest, 'security.session_http_only'),
                'session_same_site' => mb_substr((string) data_get($manifest, 'security.session_same_site', ''), 0, 30),
            ],
            'routes' => $sanitizedRoutes,
        ];

        SecurityAgentManifest::create([
            'security_session_id' => $session->id,
            'source_label' => $data['source_label'] ?: ($sanitized['app'] ?: 'Laravel Application'),
            'framework' => 'laravel',
            'framework_version' => $sanitized['framework_version'] ?: null,
            'routes_count' => count($sanitizedRoutes),
            'manifest' => $sanitized,
            'received_at' => now(),
        ]);

        return back()->with('success', 'Laravel Agent manifest berhasil diimport dan siap dianalisis pada audit berikutnya.');
    }

    public function generateRules(Request $request, int $session, int $manifest): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus diverifikasi sebelum matrix dibuat.');

        $data = $request->validate([
            'security_identity_id' => ['required', 'integer'],
        ]);

        $manifestRecord = SecurityAgentManifest::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($manifest);

        $identity = SecurityIdentity::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($data['security_identity_id']);

        $role = strtolower((string) $identity->expected_role);
        if ($role !== '' && preg_match('/(^|[_\-\s])(super[ _-]?admin|admin|administrator)($|[_\-\s])/i', $role)) {
            return back()->withErrors([
                'matrix' => 'Auto DENIED matrix ditujukan untuk test identity role rendah/non-admin. Untuk akun admin, buat ALLOWED rule secara eksplisit.',
            ]);
        }

        $routes = collect(($manifestRecord->manifest ?? [])['routes'] ?? [])
            ->filter(fn ($route) => is_array($route))
            ->filter(function (array $route): bool {
                $uri = '/'.ltrim((string) ($route['uri'] ?? ''), '/');
                $methods = collect($route['methods'] ?? [])->map(fn ($m) => strtoupper((string) $m));
                $static = ! str_contains($uri, '{') && ! str_contains($uri, '}');
                $readOnly = $methods->isEmpty() || $methods->contains(fn ($method) => in_array($method, ['GET', 'HEAD'], true));
                $sensitive = preg_match('#^/(admin|administrator|management|settings|users|roles|permissions|telescope|horizon|pulse)(/|$)#i', $uri) === 1;

                return $static && $readOnly && $sensitive;
            })
            ->take(100);

        $created = 0;
        foreach ($routes as $route) {
            $path = '/'.ltrim((string) ($route['uri'] ?? ''), '/');
            $routeName = trim((string) ($route['name'] ?? ''));
            $label = $routeName !== '' ? $routeName : $path;

            $rule = SecurityAccessRule::firstOrCreate(
                [
                    'security_session_id' => $session->id,
                    'security_identity_id' => $identity->id,
                    'path' => $path,
                    'expectation' => 'denied',
                ],
                [
                    'label' => mb_substr('Auto: '.$label, 0, 160),
                    'kind' => 'authorization',
                    'business_context' => 'Auto-generated from Laravel Agent manifest as an administrative/sensitive read-only route. Low-privilege identity should not receive successful access.',
                ],
            );

            if ($rule->wasRecentlyCreated) {
                $created++;
            }
        }

        return back()->with('success', "Authorization matrix generated: {$created} new DENIED rule(s) for {$identity->label}. Existing duplicates were preserved.");
    }

    public function destroy(int $manifest): RedirectResponse
    {
        $manifest = SecurityAgentManifest::query()
            ->whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
            ->findOrFail($manifest);

        $manifest->delete();

        return back()->with('success', 'Laravel Agent manifest dihapus.');
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }
}
