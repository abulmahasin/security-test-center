<?php

namespace App\Http\Controllers;

use App\Models\SecurityFinding;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class SecurityFindingController extends Controller
{
    public function updateStatus(Request $request, int $finding): RedirectResponse
    {
        $data = $request->validate([
            'status' => ['required', Rule::in(['open', 'acknowledged', 'accepted_risk', 'resolved', 'false_positive'])],
        ]);

        $finding = SecurityFinding::query()
            ->whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
            ->findOrFail($finding);

        $finding->update(['status' => $data['status']]);

        return back()->with('success', 'Finding lifecycle diperbarui.');
    }
}
