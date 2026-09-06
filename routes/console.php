<?php

use App\Jobs\RunSecurityAudit;
use App\Models\SecuritySession;
use App\Models\User;
use App\Services\SecurityAudit\VerificationService;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schedule;

Artisan::command('app:create-admin {email} {password} {--name=Administrator}', function (): void {
    $email = strtolower(trim((string) $this->argument('email')));
    $password = (string) $this->argument('password');

    if (! filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->error('Email tidak valid.');
        return;
    }

    if (strlen($password) < 12) {
        $this->error('Password minimal 12 karakter.');
        return;
    }

    $user = User::updateOrCreate(
        ['email' => $email],
        [
            'name' => (string) $this->option('name'),
            'password' => Hash::make($password),
            'email_verified_at' => now(),
        ],
    );

    $this->info("Admin siap: {$user->email}");
})->purpose('Create or update the local Security Test Center admin account.');

Artisan::command('security:dispatch-scheduled', function (): void {
    $verification = app(VerificationService::class);

    $templates = SecuritySession::query()
        ->where('monitoring_enabled', true)
        ->whereNotNull('schedule_interval_minutes')
        ->whereNotNull('next_run_at')
        ->where('next_run_at', '<=', now())
        ->whereNotNull('verified_at')
        ->whereNotIn('status', ['queued', 'running'])
        ->orderBy('next_run_at')
        ->limit(50)
        ->get();

    foreach ($templates as $template) {
        $interval = max(60, min((int) $template->schedule_interval_minutes, 525600));

        if (! $verification->verify($template)) {
            $template->update([
                'next_run_at' => now()->addMinutes(min($interval, 360)),
                'metadata' => array_merge($template->metadata ?? [], [
                    'last_schedule_error' => 'Proof-of-control re-verification failed. Monitoring tetap aktif, tetapi run ditunda sampai ownership dapat diverifikasi lagi.',
                    'last_schedule_error_at' => now()->toIso8601String(),
                ]),
            ]);
            $this->warn("Skipped {$template->name}: verification failed.");
            continue;
        }

        $scheduledLabel = ' · Auto '.now()->format('Y-m-d H:i');
        $safeBaseName = mb_substr($template->name, 0, max(1, 120 - mb_strlen($scheduledLabel)));

        $run = SecuritySession::create([
            'user_id' => $template->user_id,
            'name' => $safeBaseName.$scheduledLabel,
            'target_url' => $template->target_url,
            'environment' => $template->environment,
            'profile' => $template->profile,
            'status' => 'queued',
            'progress' => 1,
            'current_stage' => 'Queued by auto monitoring',
            'selected_modules' => $template->selected_modules,
            'config' => $template->config,
            'verification_token' => $template->verification_token,
            'verified_at' => now(),
            'monitoring_enabled' => false,
            'schedule_frequency' => null,
            'schedule_interval_minutes' => null,
            'metadata' => [
                'scheduled_from_session_id' => $template->id,
                'scheduled_at' => now()->toIso8601String(),
                'monitoring_interval_minutes' => $interval,
            ],
        ]);

        $template->loadMissing(['identities.accessRules', 'accountTests', 'agentManifests']);
        $identityMap = [];

        foreach ($template->identities as $identity) {
            $runIdentity = $run->identities()->create([
                'label' => $identity->label,
                'expected_role' => $identity->expected_role,
                'auth_type' => $identity->auth_type,
                'login_path' => $identity->login_path,
                'username_field' => $identity->username_field,
                'password_field' => $identity->password_field,
                'username' => $identity->username,
                'password_encrypted' => $identity->password_encrypted,
                'bearer_token_encrypted' => $identity->bearer_token_encrypted,
                'session_cookie_encrypted' => $identity->session_cookie_encrypted,
                'success_path' => $identity->success_path,
                'enabled' => $identity->enabled,
            ]);
            $identityMap[$identity->id] = $runIdentity->id;

            foreach ($identity->accessRules as $rule) {
                $runIdentity->accessRules()->create([
                    'security_session_id' => $run->id,
                    'label' => $rule->label,
                    'kind' => $rule->kind,
                    'path' => $rule->path,
                    'expectation' => $rule->expectation,
                    'business_context' => $rule->business_context,
                ]);
            }
        }

        foreach ($template->accountTests as $test) {
            $run->accountTests()->create([
                'security_identity_id' => $test->security_identity_id ? ($identityMap[$test->security_identity_id] ?? null) : null,
                'label' => $test->label,
                'kind' => $test->kind,
                'path' => $test->path,
                'config_encrypted' => $test->config_encrypted,
                'enabled' => $test->enabled,
            ]);
        }

        if ($latestManifest = $template->agentManifests->sortByDesc('received_at')->first()) {
            $run->agentManifests()->create([
                'source_label' => $latestManifest->source_label,
                'framework' => $latestManifest->framework,
                'framework_version' => $latestManifest->framework_version,
                'routes_count' => $latestManifest->routes_count,
                'manifest' => $latestManifest->manifest,
                'received_at' => $latestManifest->received_at,
            ]);
        }

        $template->update([
            'last_scheduled_at' => now(),
            'next_run_at' => now()->addMinutes($interval),
            'metadata' => array_merge($template->metadata ?? [], [
                'last_schedule_error' => null,
                'last_scheduled_session_id' => $run->id,
                'last_scheduled_at' => now()->toIso8601String(),
            ]),
        ]);

        RunSecurityAudit::dispatch($run->id);
        $this->info("Queued session #{$run->id} for {$template->target_url}");
    }

    $this->info('Flexible monitoring dispatch complete.');
})->purpose('Re-verify ownership and queue due opt-in security monitoring runs.');

Schedule::command('security:dispatch-scheduled')->everyMinute()->withoutOverlapping();
