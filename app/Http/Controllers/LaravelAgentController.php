<?php

namespace App\Http\Controllers;

use App\Models\SecurityAgentManifest;
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
