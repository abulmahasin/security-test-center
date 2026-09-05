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
        ->whereNotNull('schedule_frequency')
        ->whereNotNull('next_run_at')
        ->where('next_run_at', '<=', now())
        ->whereNotNull('verified_at')
        ->whereNotIn('status', ['queued', 'running'])
        ->orderBy('next_run_at')
        ->limit(50)
        ->get();

    foreach ($templates as $template) {
        if (! $verification->verify($template)) {
            $template->update([
                'next_run_at' => now()->addHours(6),
                'metadata' => array_merge($template->metadata ?? [], [
                    'last_schedule_error' => 'Proof-of-control re-verification failed.',
                    'last_schedule_error_at' => now()->toIso8601String(),
                ]),
            ]);
            $this->warn("Skipped {$template->name}: verification failed.");
            continue;
        }

        $run = SecuritySession::create([
            'user_id' => $template->user_id,
            'name' => $template->name.' · Scheduled '.now()->format('Y-m-d H:i'),
            'target_url' => $template->target_url,
            'environment' => $template->environment,
            'profile' => $template->profile,
            'status' => 'queued',
            'progress' => 1,
            'current_stage' => 'Queued by scheduler',
            'selected_modules' => $template->selected_modules,
            'config' => $template->config,
            'verification_token' => $template->verification_token,
            'verified_at' => now(),
            'metadata' => [
                'scheduled_from_session_id' => $template->id,
                'scheduled_at' => now()->toIso8601String(),
            ],
        ]);

        $nextRun = match ($template->schedule_frequency) {
            'daily' => now()->addDay(),
            'weekly' => now()->addWeek(),
            'monthly' => now()->addMonth(),
            default => null,
        };

        $template->update([
            'last_scheduled_at' => now(),
            'next_run_at' => $nextRun,
        ]);

        RunSecurityAudit::dispatch($run->id);
        $this->info("Queued session #{$run->id} for {$template->target_url}");
    }

    $this->info('Scheduled security dispatch complete.');
})->purpose('Re-verify ownership and queue due continuous security audits.');

Schedule::command('security:dispatch-scheduled')->hourly()->withoutOverlapping();
