<?php

namespace App\Http\Controllers;

use App\Models\SecurityFinding;
use App\Models\SecuritySession;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class DashboardController extends Controller
{
    public function __invoke(): View
    {
        $userId = Auth::id();

        $sessions = SecuritySession::query()
            ->where('user_id', $userId)
            ->latest()
            ->withCount('findings')
            ->limit(14)
            ->get();

        $completed = SecuritySession::query()
            ->where('user_id', $userId)
            ->where('status', 'completed')
            ->whereNotNull('score')
            ->latest('completed_at')
            ->limit(24)
            ->get();

        $latest = $completed->first();

        $stats = [
            'sessions' => SecuritySession::where('user_id', $userId)->count(),
            'targets' => SecuritySession::where('user_id', $userId)->distinct()->count('target_url'),
            'scheduled' => SecuritySession::where('user_id', $userId)->whereNotNull('schedule_frequency')->count(),
            'open_high' => SecurityFinding::whereHas('session', fn ($query) => $query->where('user_id', $userId))
                ->whereIn('severity', ['critical', 'high'])
                ->where('status', 'open')
                ->count(),
            'latest_score' => $latest?->score,
            'latest_grade' => $latest?->grade,
            'latest_compliance' => $latest?->compliance_score,
            'average_score' => $completed->isNotEmpty() ? (int) round($completed->avg('score')) : null,
            'regressions' => $completed->where('risk_delta', '<', 0)->count(),
            'new_findings' => (int) $completed->sum('new_findings_count'),
            'resolved_findings' => (int) $completed->sum('resolved_findings_count'),
        ];

        $trend = $completed
            ->sortBy('completed_at')
            ->values()
            ->map(fn (SecuritySession $session) => [
                'name' => $session->name,
                'score' => $session->score,
                'compliance' => $session->compliance_score,
                'completed_at' => optional($session->completed_at)->format('d M H:i'),
            ]);

        $upcoming = SecuritySession::query()
            ->where('user_id', $userId)
            ->whereNotNull('next_run_at')
            ->orderBy('next_run_at')
            ->limit(6)
            ->get(['id', 'name', 'target_url', 'schedule_frequency', 'next_run_at']);

        return view('dashboard', compact('sessions', 'stats', 'trend', 'upcoming'));
    }
}
