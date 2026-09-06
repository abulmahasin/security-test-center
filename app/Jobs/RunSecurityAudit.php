<?php

namespace App\Jobs;

use App\Models\SecurityFinding;
use App\Models\SecurityLog;
use App\Models\SecuritySession;
use App\Services\SecurityAudit\PostureAnalyzer;
use App\Services\SecurityAudit\ScoreCalculator;
use App\Services\SecurityAudit\SecurityAuditManager;
use App\Services\SecurityAudit\TargetGuard;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Throwable;

class RunSecurityAudit implements ShouldQueue
{
    use Queueable;

    public int $timeout = 180;

    public function __construct(public readonly int $securitySessionId)
    {
    }

    public function handle(
        SecurityAuditManager $manager,
        ScoreCalculator $score,
        PostureAnalyzer $posture,
        TargetGuard $guard,
    ): void {
        $session = SecuritySession::findOrFail($this->securitySessionId);

        if (! $session->isVerified()) {
            $session->update(['status' => 'failed', 'error_message' => 'Target verification is required.']);
            return;
        }

        try {
            $guard->assertAllowed($session->target_url);

            $modules = array_values($session->selected_modules ?? []);
            $total = max(1, count($modules));

            $session->update([
                'status' => 'running',
                'started_at' => now(),
                'progress' => 3,
                'current_stage' => 'Initializing security engine',
            ]);

            $this->log($session, 'info', 'Audit started', ['modules' => $modules]);

            foreach ($modules as $index => $module) {
                $progress = min(88, 5 + (int) floor(($index / $total) * 82));

                $session->update([
                    'progress' => $progress,
                    'current_stage' => "Running {$module}",
                ]);

                $this->runModule($manager, $session, $module);
            }

            if (in_array('laravel_agent', $modules, true) || in_array('authenticated_access', $modules, true)) {
                $session->update([
                    'progress' => 90,
                    'current_stage' => 'Replaying Guest / No Account authentication boundaries',
                ]);

                $this->runModule($manager, $session, 'authentication_boundary');
            }

            $session->update(['progress' => 93, 'current_stage' => 'Calculating risk score']);
            $finalScore = $score->calculate($session->findings()->get());

            $session->update(['progress' => 96, 'current_stage' => 'Comparing security posture']);
            $postureData = $posture->finalize($session->fresh(), $finalScore);

            $session->update(array_merge($postureData, [
                'status' => 'completed',
                'progress' => 100,
                'current_stage' => 'Completed',
                'score' => $finalScore,
                'completed_at' => now(),
            ]));

            $this->log($session, 'info', 'Audit completed', [
                'score' => $finalScore,
                'grade' => $postureData['grade'],
                'compliance' => $postureData['compliance_score'],
                'new_findings' => $postureData['new_findings_count'],
                'resolved_findings' => $postureData['resolved_findings_count'],
                'risk_delta' => $postureData['risk_delta'],
            ]);
        } catch (Throwable $e) {
            report($e);

            $session->update([
                'status' => 'failed',
                'current_stage' => 'Failed',
                'error_message' => mb_substr($e->getMessage(), 0, 1000),
                'completed_at' => now(),
            ]);

            $this->log($session, 'error', 'Audit failed', ['message' => $e->getMessage()]);
        }
    }

    private function runModule(SecurityAuditManager $manager, SecuritySession $session, string $module): void
    {
        $this->log($session, 'info', "Running module: {$module}");
        $results = $manager->scanner($module)->scan($session);

        foreach ($results as $result) {
            SecurityFinding::create([
                'security_session_id' => $session->id,
                'module' => $module,
                'severity' => $result['severity'],
                'title' => $result['title'],
                'description' => $result['description'],
                'evidence' => $result['evidence'] ?? null,
                'remediation' => $result['remediation'],
                'status' => 'open',
            ]);
        }

        $this->log($session, 'info', "Module completed: {$module}", ['findings' => count($results)]);
    }

    private function log(SecuritySession $session, string $level, string $message, array $meta = []): void
    {
        SecurityLog::create([
            'security_session_id' => $session->id,
            'level' => $level,
            'message' => $message,
            'meta' => $meta ?: null,
            'created_at' => now(),
        ]);
    }
}
