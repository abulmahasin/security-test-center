<?php

namespace App\Http\Controllers;

use App\Models\SecurityAccountTest;
use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class AccountSecurityController extends Controller
{
    public function store(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus diverifikasi sebelum account-security testing dikonfigurasi.');

        $data = $request->validate([
            'security_identity_id' => ['required', 'integer'],
            'label' => ['required', 'string', 'max:160'],
            'kind' => ['required', Rule::in([
                'login_enumeration',
                'login_throttling',
                'login_surface',
                'password_reset_surface',
            ])],
            'path' => ['nullable', 'string', 'max:255', 'starts_with:/'],
            'dedicated_test_account_confirmed' => ['accepted'],
        ]);

        $identity = SecurityIdentity::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($data['security_identity_id']);

        if ($identity->auth_type !== 'form') {
            return back()->withErrors([
                'account_test' => 'Account Compromise Lab saat ini membutuhkan identity bertipe Form Login.',
            ]);
        }

        $test = new SecurityAccountTest([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => $data['label'],
            'kind' => $data['kind'],
            'path' => $data['kind'] === 'password_reset_surface'
                ? ($data['path'] ?: '/forgot-password')
                : ($data['kind'] === 'login_surface' ? ($identity->login_path ?: '/login') : null),
            'enabled' => true,
        ]);

        $test->setConfig(match ($data['kind']) {
            'login_throttling' => [
                'dedicated_test_account_confirmed' => true,
                'request_policy' => ['max_invalid_attempts' => 3, 'password_guessing' => false],
            ],
            'login_enumeration' => [
                'dedicated_test_account_confirmed' => true,
                'request_policy' => [
                    'known_account_attempts' => 1,
                    'synthetic_account_attempts' => 1,
                    'password_guessing' => false,
                ],
            ],
            default => [
                'dedicated_test_account_confirmed' => true,
                'request_policy' => ['method' => 'GET', 'side_effects' => false],
            ],
        });
        $test->save();

        return back()->with('success', 'Account-security test ditambahkan dengan bounded safety policy.');
    }

    public function destroy(int $test): RedirectResponse
    {
        $test = SecurityAccountTest::query()
            ->whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
            ->findOrFail($test);

        $test->delete();

        return back()->with('success', 'Account-security test dihapus.');
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }
}
