<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Route;

class SecurityManifestCommand extends Command
{
    protected $signature = 'security:manifest {--output= : Optional output JSON path}';
    protected $description = 'Export a redacted route/config security manifest for Security Test Center';

    public function handle(): int
    {
        $routes = collect(Route::getRoutes()->getRoutes())->map(function ($route): array {
            return [
                'methods' => array_values(array_diff($route->methods(), ['HEAD'])),
                'uri' => $route->uri(),
                'name' => $route->getName(),
                'action' => $route->getActionName(),
                'middleware' => array_values($route->gatherMiddleware()),
            ];
        })->values()->all();

        $manifest = [
            'app' => (string) config('app.name'),
            'environment' => (string) app()->environment(),
            'framework' => 'laravel',
            'framework_version' => app()->version(),
            'php_version' => PHP_VERSION,
            'security' => [
                'app_debug' => (bool) config('app.debug'),
                'session_secure' => config('session.secure'),
                'session_http_only' => config('session.http_only'),
                'session_same_site' => config('session.same_site'),
            ],
            'routes' => $routes,
        ];

        $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $output = $this->option('output');

        if ($output) {
            file_put_contents($output, $json.PHP_EOL);
            $this->info("Security manifest written to {$output}");
            return self::SUCCESS;
        }

        $this->line($json);

        return self::SUCCESS;
    }
}
