<?php

namespace App\Services\SecurityAudit;

use App\Models\SecuritySession;
use Illuminate\Support\Collection;

class PostureAnalyzer
{
    public function finalize(SecuritySession $session, int $score): array
    {
        $findings = $session->findings()->get();

        foreach ($findings as $finding) {
            $finding->update([
                'fingerprint' => $this->fingerprint($finding->module, $finding->title),
            ]);
        }

        $findings = $session->findings()->get();

        $baseline = SecuritySession::query()
            ->where('user_id', $session->user_id)
            ->where('target_url', $session->target_url)
            ->where('status', 'completed')
            ->whereKeyNot($session->id)
            ->whereNotNull('completed_at')
            ->latest('completed_at')
            ->first();

        $previous = $baseline?->findings()->whereNotNull('fingerprint')->get() ?? collect();
        $previousFingerprints = $previous->pluck('fingerprint')->filter()->unique();
        $currentFingerprints = $findings->pluck('fingerprint')->filter()->unique();

        $newCount = 0;
        foreach ($findings as $finding) {
            $changeType = $previousFingerprints->contains($finding->fingerprint) ? 'persistent' : 'new';
            $finding->update(['change_type' => $changeType]);
            if ($changeType === 'new' && $finding->severity !== 'info') {
                $newCount++;
            }
        }

        $resolved = $previousFingerprints->diff($currentFingerprints)->values();
        $compliance = $this->complianceScore($findings, $session->selected_modules ?? []);

        return [
            'baseline_session_id' => $baseline?->id,
            'grade' => $this->grade($score),
            'compliance_score' => $compliance,
            'risk_delta' => $baseline?->score !== null ? $score - $baseline->score : null,
            'new_findings_count' => $newCount,
            'resolved_findings_count' => $resolved->count(),
            'metadata' => array_merge($session->metadata ?? [], [
                'resolved_fingerprints' => $resolved->all(),
                'baseline_score' => $baseline?->score,
                'posture_generated_at' => now()->toIso8601String(),
            ]),
        ];
    }

    public function fingerprint(string $module, string $title): string
    {
        return hash('sha256', strtolower(trim($module).'|'.trim($title)));
    }

    private function complianceScore(Collection $findings, array $selectedModules): int
    {
        $modules = collect($selectedModules)->unique()->values();
        if ($modules->isEmpty()) {
            return 0;
        }

        $passed = $modules->filter(function (string $module) use ($findings): bool {
            return ! $findings
                ->where('module', $module)
                ->whereIn('severity', ['critical', 'high'])
                ->isNotEmpty();
        })->count();

        $base = (int) round(($passed / $modules->count()) * 100);
        $mediumPenalty = min(20, $findings->where('severity', 'medium')->count() * 3);

        return max(0, min(100, $base - $mediumPenalty));
    }

    private function grade(int $score): string
    {
        return match (true) {
            $score >= 95 => 'A+',
            $score >= 90 => 'A',
            $score >= 85 => 'B+',
            $score >= 80 => 'B',
            $score >= 70 => 'C',
            $score >= 60 => 'D',
            default => 'F',
        };
    }
}
