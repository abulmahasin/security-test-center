<?php

namespace App\Http\Controllers;

use App\Models\SecurityGuestBoundary;
use App\Models\SecuritySession;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class GuestBoundaryController extends Controller
{
    public function store(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus diverifikasi sebelum Guest / No Account boundary dikonfigurasi.');

        $data = $request->validate([
            'label' => ['required', 'string', 'max:160'],
            'path' => ['required', 'string', 'max:500', 'regex:/^\/.+/'],
            'auth_mode' => ['required', Rule::in(['session', 'bearer'])],
            'business_context' => ['nullable', 'string', 'max:3000'],
        ]);

        SecurityGuestBoundary::updateOrCreate(
            [
                'security_session_id' => $session->id,
                'path' => $data['path'],
                'auth_mode' => $data['auth_mode'],
            ],
            [
                'label' => $data['label'],
                'business_context' => $data['business_context'] ?? null,
                'enabled' => true,
            ]
        );

        return back()->with('success', 'Guest / No Account protected-route boundary disimpan.');
    }

    public function destroy(int $boundary): RedirectResponse
    {
        $boundary = SecurityGuestBoundary::query()
            ->whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
            ->findOrFail($boundary);

        $boundary->delete();

        return back()->with('success', 'Guest boundary dihapus.');
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }
}
