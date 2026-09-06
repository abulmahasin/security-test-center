<?php

namespace App\Services\SecurityAudit\Scanners;

use App\Models\SecurityAgentManifest;
use App\Models\SecuritySession;
use App\Services\SecurityAudit\Finding;
use App\Services\SecurityAudit\Scanner;

class LaravelAgentScanner implements Scanner
{
    public function scan(SecuritySession $session): array
    {
        $manifestRecord = SecurityAgentManifest::query()
            ->where('security_session_id', $session->id)
            ->latest('received_at')
            ->latest('id')
            ->first();

        if (! $manifestRecord) {
            return [Finding::make(
                'info',
                'Laravel Agent manifest belum tersedia',
                'Belum ada source-assisted route/config manifest untuk target ini.',
                'Generate manifest dari aplikasi Laravel yang Anda kontrol lalu import ke session. Agent hanya mengekspor metadata route/config keamanan, bukan source code, credential, atau isi database.'
            )];
        }

        $manifest = $manifestRecord->manifest ?? [];
        $routes = collect($manifest['routes'] ?? [])->filter(fn ($route) => is_array($route));
        $security = is_array($manifest['security'] ?? null) ? $manifest['security'] : [];
        $findings = [];

        foreach ($routes as $route) {
            $uri = '/'.ltrim((string) ($route['uri'] ?? ''), '/');
            $methods = collect($route['methods'] ?? [$route['method'] ?? 'GET'])
                ->map(fn ($method) => strtoupper((string) $method))
                ->filter()
                ->values();
            $middleware = collect($route['middleware'] ?? [])
                ->map(fn ($item) => strtolower((string) $item));

            $hasAuth = $middleware->contains(fn (string $item) =>
                $item === 'auth'
                || str_starts_with($item, 'auth:')
                || str_contains($item, 'sanctum')
                || str_contains($item, 'passport')
                || str_contains($item, 'jwt')
            );
            $hasAuthorization = $middleware->contains(fn (string $item) =>
                str_starts_with($item, 'can:')
                || str_contains($item, 'permission:')
                || str_contains($item, 'role:')
            );
            $mutating = $methods->contains(fn (string $method) => in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true));
            $adminLike = preg_match('#^/(admin|administrator|management|settings|users|roles|permissions)(/|$)#i', $uri) === 1;
            $sensitiveTool = preg_match('#^/(telescope|horizon|pulse|phpinfo)(/|$)#i', $uri) === 1;

            if (($adminLike || $sensitiveTool) && ! $hasAuth) {
                $findings[] = Finding::make(
                    'critical',
                    "Laravel route sensitif tanpa auth middleware: {$uri}",
                    'Source-assisted route inventory menunjukkan endpoint administratif/diagnostik yang tidak memiliki middleware autentikasi yang dapat dikenali. Jika route benar-benar reachable, guest dapat mencapai attack surface sensitif tanpa akun.',
                    'Tambahkan auth middleware yang sesuai, batasi diagnostic tools di production, dan terapkan authorization per role/permission. Setelah diperbaiki, import manifest baru dan jadikan check ini CI security gate.',
                    $this->routeEvidence($route, $hasAuth, $hasAuthorization)
                );
                continue;
            }

            if ($mutating && ! $hasAuth) {
                $findings[] = Finding::make(
                    'high',
                    "Mutating Laravel route tanpa auth middleware: {$uri}",
                    'Route POST/PUT/PATCH/DELETE terlihat tidak memiliki auth middleware. Endpoint mutating publik meningkatkan risiko perubahan data tanpa autentikasi, walau validasi/controller internal masih perlu diperiksa.',
                    'Pastikan mutating endpoint yang bukan sengaja publik dilindungi auth middleware dan authorization server-side. Untuk endpoint publik seperti login/webhook, gunakan signature, CSRF/rate-limit, atau secret validation yang sesuai.',
                    $this->routeEvidence($route, $hasAuth, $hasAuthorization)
                );
            } elseif ($adminLike && $hasAuth && ! $hasAuthorization) {
                $findings[] = Finding::make(
                    'medium',
                    "Admin-like route belum menunjukkan role/permission middleware: {$uri}",
                    'Route memiliki authentication tetapi manifest tidak menunjukkan can/role/permission middleware. Authorization mungkin berada di controller/policy, sehingga hasil ini adalah review signal, bukan bukti vulnerability.',
                    'Pastikan controller memakai Policy/Gate/permission check dan tambahkan Access Control Lab rule untuk role rendah terhadap route ini.',
                    $this->routeEvidence($route, $hasAuth, $hasAuthorization)
                );
            }
        }

        if (($security['app_debug'] ?? false) === true) {
            $findings[] = Finding::make(
                'critical',
                'Laravel APP_DEBUG aktif menurut agent manifest',
                'Debug mode pada environment yang dapat diakses dapat membocorkan stack trace, filesystem path, query, environment detail, dan application internals.',
                'Set APP_DEBUG=false pada production dan clear configuration cache. Pastikan error detail hanya masuk log internal.',
                json_encode(['app_debug' => true, 'source' => 'laravel_agent_manifest'], JSON_UNESCAPED_SLASHES)
            );
        }

        if (($security['session_secure'] ?? null) === false) {
            $findings[] = Finding::make(
                'high',
                'Laravel session cookie Secure flag dinonaktifkan',
                'Agent manifest menunjukkan session cookie tidak dipaksa HTTPS-only. Pada deployment HTTPS, cookie dapat lebih mudah terekspos jika transport downgrade/misconfiguration terjadi.',
                'Aktifkan SESSION_SECURE_COOKIE=true pada production HTTPS dan verifikasi reverse proxy/trusted proxy configuration.',
                json_encode(['session_secure' => false, 'source' => 'laravel_agent_manifest'], JSON_UNESCAPED_SLASHES)
            );
        }

        if ($findings === []) {
            $findings[] = Finding::make(
                'info',
                'Laravel Agent route inventory tidak menemukan exposure mencolok',
                "Manifest berisi {$routes->count()} route. Heuristic review tidak menemukan admin/public atau mutating/public route yang jelas pada metadata middleware.",
                'Tetap kombinasikan source-assisted inventory dengan authenticated Access Control Lab karena Policy/Gate di controller tidak selalu terlihat dari route middleware.',
                json_encode([
                    'routes' => $routes->count(),
                    'framework_version' => $manifestRecord->framework_version,
                    'source' => 'laravel_agent_manifest',
                ], JSON_UNESCAPED_SLASHES)
            );
        }

        return $findings;
    }

    private function routeEvidence(array $route, bool $hasAuth, bool $hasAuthorization): string
    {
        return json_encode([
            'uri' => $route['uri'] ?? null,
            'methods' => $route['methods'] ?? [$route['method'] ?? null],
            'name' => $route['name'] ?? null,
            'action' => $route['action'] ?? null,
            'middleware' => $route['middleware'] ?? [],
            'recognized_auth' => $hasAuth,
            'recognized_route_authorization' => $hasAuthorization,
            'source_code_stored' => false,
            'credentials_stored' => false,
        ], JSON_UNESCAPED_SLASHES);
    }
}
