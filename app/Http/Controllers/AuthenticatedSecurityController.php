<?php

namespace App\Http\Controllers;

use App\Models\SecurityAccessRule;
use App\Models\SecurityIdentity;
use App\Models\SecuritySession;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class AuthenticatedSecurityController extends Controller
{
    public function storeIdentity(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);

        $data = $request->validate([
            'label' => ['required', 'string', 'max:120'],
            'expected_role' => ['nullable', 'string', 'max:80'],
            'auth_type' => ['required', Rule::in(['form', 'bearer'])],
            'login_path' => ['nullable', 'string', 'max:255', 'starts_with:/'],
            'username_field' => ['nullable', 'string', 'max:80'],
            'password_field' => ['nullable', 'string', 'max:80'],
            'username' => ['nullable', 'string', 'max:255'],
            'password' => ['nullable', 'string', 'max:4096'],
            'bearer_token' => ['nullable', 'string', 'max:8192'],
            'success_path' => ['nullable', 'string', 'max:255', 'starts_with:/'],
        ]);

        if ($data['auth_type'] === 'form' && (blank($data['username']) || blank($data['password']))) {
            return back()->withErrors(['identity' => 'Form login membutuhkan username/email dan password akun uji.']);
        }

        if ($data['auth_type'] === 'bearer' && blank($data['bearer_token'])) {
            return back()->withErrors(['identity' => 'Bearer authentication membutuhkan test token.']);
        }

        $identity = new SecurityIdentity([
            'security_session_id' => $session->id,
            'label' => $data['label'],
            'expected_role' => $data['expected_role'] ?? null,
            'auth_type' => $data['auth_type'],
            'login_path' => $data['login_path'] ?? '/login',
            'username_field' => $data['username_field'] ?? 'email',
            'password_field' => $data['password_field'] ?? 'password',
            'username' => $data['username'] ?? '',
            'success_path' => $data['success_path'] ?? '/',
            'enabled' => true,
        ]);
        $identity->setPassword($data['password'] ?? null);
        $identity->setBearerToken($data['bearer_token'] ?? null);
        $identity->save();

        return back()->with('success', 'Test identity ditambahkan. Secret disimpan terenkripsi dan tidak pernah ditampilkan kembali.');
    }

    public function destroyIdentity(int $identity): RedirectResponse
    {
        $identity = SecurityIdentity::query()
            ->whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
            ->findOrFail($identity);

        $identity->delete();

        return back()->with('success', 'Test identity dan access rules terkait dihapus.');
    }

    public function storeRule(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);

        $data = $request->validate([
            'security_identity_id' => ['required', 'integer'],
            'label' => ['required', 'string', 'max:160'],
            'path' => ['required', 'string', 'max:255', 'starts_with:/'],
            'expectation' => ['required', Rule::in(['allowed', 'denied'])],
        ]);

        $identity = $session->identities()->findOrFail($data['security_identity_id']);

        SecurityAccessRule::create([
            'security_session_id' => $session->id,
            'security_identity_id' => $identity->id,
            'label' => $data['label'],
            'path' => $data['path'],
            'expectation' => $data['expectation'],
        ]);

        return back()->with('success', 'Authorization boundary rule ditambahkan. Scanner hanya melakukan read-only GET pada path ini.');
    }

    public function destroyRule(int $rule): RedirectResponse
    {
        $rule = SecurityAccessRule::query()
            ->whereHas('session', fn ($query) => $query->where('user_id', Auth::id()))
            ->findOrFail($rule);

        $rule->delete();

        return back()->with('success', 'Authorization boundary rule dihapus.');
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }
}
