<?php

namespace App\Http\Controllers;

use App\Models\SecurityAccessCase;
use App\Models\SecuritySession;
use App\Models\SecurityTestIdentity;
use App\Services\SecurityAudit\AuthenticatedAccessTester;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

class SecurityAccessLabController extends Controller
{
    public function index(int $session): View
    {
        $session = $this->ownedSession($session)->load([
            'testIdentities' => fn ($query) => $query->latest(),
            'accessCases' => fn ($query) => $query->with(['identity', 'results' => fn ($results) => $results->limit(5)])->latest(),
        ]);

        return view('sessions.access-lab', compact('session'));
    }

    public function storeIdentity(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus terverifikasi terlebih dahulu.');

        $data = $request->validate([
            'name' => ['required', 'string', 'max:100'],
            'role_label' => ['nullable', 'string', 'max:80'],
            'auth_type' => ['required', Rule::in(['form', 'bearer', 'basic', 'cookie'])],
            'username' => ['nullable', 'string', 'max:255'],
            'password' => ['nullable', 'string', 'max:1000'],
            'token' => ['nullable', 'string', 'max:5000'],
            'cookie' => ['nullable', 'string', 'max:5000'],
            'login_path' => ['nullable', 'string', 'max:1000'],
            'username_field' => ['nullable', 'string', 'max:80'],
            'password_field' => ['nullable', 'string', 'max:80'],
        ]);

        $credentials = match ($data['auth_type']) {
            'bearer' => ['token' => $data['token'] ?? ''],
            'cookie' => ['cookie' => $data['cookie'] ?? ''],
            'basic' => [
                'username' => $data['username'] ?? '',
                'password' => $data['password'] ?? '',
            ],
            default => [
                'username' => $data['username'] ?? '',
                'password' => $data['password'] ?? '',
                'login_path' => '/'.ltrim((string) ($data['login_path'] ?? '/login'), '/'),
                'username_field' => $data['username_field'] ?: 'email',
                'password_field' => $data['password_field'] ?: 'password',
            ],
        };

        SecurityTestIdentity::create([
            'security_session_id' => $session->id,
            'name' => $data['name'],
            'role_label' => $data['role_label'] ?: $data['name'],
            'auth_type' => $data['auth_type'],
            'credentials' => $credentials,
            'enabled' => true,
        ]);

        return back()->with('success', 'Test identity disimpan terenkripsi. Credential tidak pernah ditampilkan kembali.');
    }

    public function destroyIdentity(int $session, int $identity): RedirectResponse
    {
        $session = $this->ownedSession($session);
        $identity = SecurityTestIdentity::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($identity);
        $identity->delete();

        return back()->with('success', 'Test identity dan test case terkait dihapus.');
    }

    public function storeCase(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus terverifikasi terlebih dahulu.');

        $data = $request->validate([
            'security_test_identity_id' => ['required', 'integer'],
            'name' => ['required', 'string', 'max:140'],
            'kind' => ['required', Rule::in(['authorization', 'idor'])],
            'method' => ['required', Rule::in(['GET', 'HEAD'])],
            'path' => ['required', 'string', 'max:1000'],
            'expected_policy' => ['required', Rule::in(['forbidden', 'allowed'])],
            'business_context' => ['nullable', 'string', 'max:3000'],
        ]);

        $identity = SecurityTestIdentity::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($data['security_test_identity_id']);

        SecurityAccessCase::create([
            'security_session_id' => $session->id,
            'security_test_identity_id' => $identity->id,
            'name' => $data['name'],
            'kind' => $data['kind'],
            'method' => $data['method'],
            'path' => $data['path'],
            'expected_policy' => $data['expected_policy'],
            'business_context' => $data['business_context'],
            'enabled' => true,
        ]);

        return back()->with('success', 'Authorization test case berhasil dibuat.');
    }

    public function runCase(int $session, int $case, AuthenticatedAccessTester $tester): RedirectResponse
    {
        $session = $this->ownedSession($session);
        $case = SecurityAccessCase::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($case);

        $result = $tester->runCase($case);

        return back()->with(
            $result->outcome === 'pass' ? 'success' : 'warning',
            $result->outcome === 'pass'
                ? 'Access-control test PASS: boundary sesuai policy.'
                : 'Access-control test FAIL: ditemukan indikasi kelemahan authorization.'
        );
    }

    public function runAll(int $session, AuthenticatedAccessTester $tester): RedirectResponse
    {
        $session = $this->ownedSession($session);
        abort_unless($session->isVerified(), 422, 'Target harus terverifikasi terlebih dahulu.');

        $cases = SecurityAccessCase::query()
            ->where('security_session_id', $session->id)
            ->where('enabled', true)
            ->with('identity')
            ->get();

        $failed = 0;
        foreach ($cases as $case) {
            $result = $tester->runCase($case);
            if ($result->outcome === 'fail') {
                $failed++;
            }
        }

        return back()->with(
            $failed > 0 ? 'warning' : 'success',
            $failed > 0
                ? "Access Control Lab selesai: {$failed} case gagal dan perlu ditinjau."
                : 'Access Control Lab selesai: seluruh case sesuai expected policy.'
        );
    }

    public function destroyCase(int $session, int $case): RedirectResponse
    {
        $session = $this->ownedSession($session);
        SecurityAccessCase::query()
            ->where('security_session_id', $session->id)
            ->findOrFail($case)
            ->delete();

        return back()->with('success', 'Test case dihapus.');
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }
}
