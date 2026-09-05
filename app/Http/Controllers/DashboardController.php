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
        $sessions = SecuritySession::query()
            ->where('user_id', Auth::id())
            ->latest()
            ->withCount('findings')
            ->limit(12)
            ->get();

        $latest = $sessions->firstWhere('status', 'completed');

        $stats = [
            'sessions' => SecuritySession::where('user_id', Auth::id())->count(),
            'verified' => SecuritySession::where('user_id', Auth::id())->whereNotNull('verified_at')->count(),
            'open_high' => SecurityFinding::whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
                ->whereIn('severity', ['critical', 'high'])
                ->where('status', 'open')
                ->count(),
            'latest_score' => $latest?->score,
        ];

        return view('dashboard', compact('sessions', 'stats'));
    }
}
