<?php

namespace App\Http\Controllers;

use App\Jobs\RunSecurityAudit;
use App\Models\SecuritySession;
use App\Services\SecurityAudit\TargetGuard;
use App\Services\SecurityAudit\VerificationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

class SecuritySessionController extends Controller
{
    private const MODULES = [
        'headers', 'tls', 'cookies', 'cors', 'exposure', 'rate_limit', 'latency', 'security_txt',
        'http_methods', 'dns_posture', 'sensitive_files', 'authenticated_access', 'account_compromise',
        'laravel_agent', 'load_resilience',
    ];

    public function create(): View
    {
        return view('sessions.create', [
            'moduleOptions' => [
                'headers' => ['Security Headers', 'CSP, HSTS, framing, MIME sniffing, referrer policy.'],
                'tls' => ['TLS Certificate', 'Certificate expiry, hostname, HTTPS posture.'],
                'cookies' => ['Cookie Security', 'Secure, HttpOnly dan SameSite pada cookie.'],
                'cors' => ['CORS Policy', 'Mendeteksi wildcard/credential policy berisiko.'],
                'exposure' => ['Information Exposure', 'Server banner, debug markers dan informasi sensitif.'],
                'rate_limit' => ['Rate Limit Signals', 'Memeriksa header throttle pada endpoint sensitif secara low-volume.'],
                'latency' => ['Latency Baseline', 'Baseline respons ringan untuk mendeteksi bottleneck awal.'],
                'security_txt' => ['Security.txt', 'RFC 9116 disclosure policy dan security contact.'],
                'http_methods' => ['HTTP Methods', 'Passive OPTIONS review tanpa mengeksekusi method berbahaya.'],
                'dns_posture' => ['DNS Posture', 'A/AAAA/CNAME resolution baseline secara pasif.'],
                'sensitive_files' => ['Sensitive File Exposure', 'Memeriksa .env, .git, log, database, backup, credential file, dan phpinfo tanpa menyimpan isi secret.'],
                'authenticated_access' => ['Authenticated Access & Privilege Boundaries', 'Login memakai akun uji terenkripsi lalu validasi apakah role rendah dapat membaca resource admin/role lain. Read-only GET only.'],
                'account_compromise' => ['Account Compromise Defense', 'Bounded account-enumeration dan login-throttling checks dengan dedicated test account. Tanpa brute force/password guessing.'],
                'laravel_agent' => ['Laravel Agent Manifest', 'Source-assisted route/middleware/config inventory untuk menemukan admin/public, mutating/public, dan posture Laravel yang berisiko.'],
                'load_resilience' => ['DDoS Resilience Simulation', 'Controlled GET load dengan hard safety caps dan ownership verification.'],
            ],
        ]);
    }

    public function store(Request $request, TargetGuard $guard): RedirectResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'target_url' => ['required', 'url:http,https', 'max:2048'],
            'environment' => ['required', Rule::in(['production', 'staging', 'development', 'local'])],
            'profile' => ['required', Rule::in(['quick', 'balanced', 'deep', 'custom'])],
            'modules' => ['required', 'array', 'min:1'],
            'modules.*' => ['required', Rule::in(self::MODULES)],
            'load.vus' => ['nullable', 'integer', 'min:1'],
            'load.rps' => ['nullable', 'integer', 'min:1'],
            'load.duration' => ['nullable', 'integer', 'min:1'],
            'rate_limit_path' => ['nullable', 'string', 'max:255'],
            'monitoring_enabled' => ['nullable', 'boolean'],
            'monitoring_interval_value' => ['nullable', 'integer', 'min:1', 'max:8760'],
            'monitoring_interval_unit' => ['nullable', Rule::in(['hours', 'days', 'weeks'])],
        ]);

        $targetUrl = rtrim($data['target_url'], '/');
        $guard->assertAllowed($targetUrl);

        $monitoringEnabled = $request->boolean('monitoring_enabled');
        $intervalMinutes = $monitoringEnabled ? $this->monitoringIntervalMinutes($data) : null;

        $session = SecuritySession::create([
            'user_id' => Auth::id(),
            'name' => $data['name'],
            'target_url' => $targetUrl,
            'environment' => $data['environment'],
            'profile' => $data['profile'],
            'status' => 'draft',
            'progress' => 0,
            'selected_modules' => array_values(array_unique($data['modules'])),
            'config' => [
                'load' => [
                    'vus' => min(max((int) ($data['load']['vus'] ?? 5), 1), config('security_test.load.max_vus')),
                    'rps' => min(max((int) ($data['load']['rps'] ?? 5), 1), config('security_test.load.max_rps')),
                    'duration' => min(max((int) ($data['load']['duration'] ?? 10), 1), config('security_test.load.max_duration')),
                ],
                'rate_limit_path' => '/'.ltrim((string) ($data['rate_limit_path'] ?? '/login'), '/'),
            ],
            'schedule_frequency' => $monitoringEnabled ? 'custom' : null,
            'monitoring_enabled' => $monitoringEnabled,
            'schedule_interval_minutes' => $intervalMinutes,
            'verification_token' => Str::random(48),
        ]);

        return redirect()->route('sessions.show', $session)->with('success', 'Security session dibuat. Verifikasi target sebelum audit atau monitoring dijalankan.');
    }

    public function show(int $session): View
    {
        $session = $this->ownedSession($session)->load([
            'baseline',
            'findings',
            'identities.accessRules',
            'accountTests.identity',
            'agentManifests' => fn ($query) => $query->latest('received_at')->limit(5),
            'logs' => fn ($query) => $query->limit(80),
        ]);

        return view('sessions.show', compact('session'));
    }

    public function verify(int $session, VerificationService $verification): RedirectResponse
    {
        $session = $this->ownedSession($session);

        if ($verification->verify($session)) {
            if ($session->monitoring_enabled && $session->schedule_interval_minutes && ! $session->next_run_at) {
                $session->update(['next_run_at' => now()->addMinutes($session->schedule_interval_minutes)]);
            }

            return back()->with('success', 'Target berhasil diverifikasi. Audit dapat dijalankan dan monitoring aktif hanya jika Anda mengaktifkannya.');
        }

        return back()->withErrors([
            'verification' => 'Token verifikasi tidak ditemukan atau tidak sama dengan token sesi.',
        ]);
    }

    public function updateMonitoring(Request $request, int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);

        $data = $request->validate([
            'monitoring_enabled' => ['nullable', 'boolean'],
            'monitoring_interval_value' => ['nullable', 'integer', 'min:1', 'max:8760'],
            'monitoring_interval_unit' => ['nullable', Rule::in(['hours', 'days', 'weeks'])],
        ]);

        $enabled = $request->boolean('monitoring_enabled');

        if (! $enabled) {
            $session->update([
                'monitoring_enabled' => false,
                'schedule_frequency' => null,
                'schedule_interval_minutes' => null,
                'next_run_at' => null,
            ]);

            return back()->with('success', 'Auto monitoring dimatikan. Session tetap dapat dijalankan manual kapan saja.');
        }

        abort_unless($session->isVerified(), 422, 'Target harus diverifikasi sebelum auto monitoring diaktifkan.');

        $intervalMinutes = $this->monitoringIntervalMinutes($data);

        $session->update([
            'monitoring_enabled' => true,
            'schedule_frequency' => 'custom',
            'schedule_interval_minutes' => $intervalMinutes,
            'next_run_at' => now()->addMinutes($intervalMinutes),
        ]);

        return back()->with('success', 'Auto monitoring aktif: '.$session->fresh()->monitoringLabel().'.');
    }

    public function run(int $session): RedirectResponse
    {
        $session = $this->ownedSession($session);

        abort_unless($session->isVerified(), 422, 'Target belum diverifikasi.');
        abort_if(in_array($session->status, ['queued', 'running'], true), 409, 'Audit sedang berjalan.');

        $session->findings()->delete();
        $session->logs()->delete();
        $session->update([
            'status' => 'queued',
            'progress' => 1,
            'current_stage' => 'Queued',
            'score' => null,
            'grade' => null,
            'compliance_score' => null,
            'risk_delta' => null,
            'new_findings_count' => 0,
            'resolved_findings_count' => 0,
            'baseline_session_id' => null,
            'started_at' => null,
            'completed_at' => null,
            'error_message' => null,
            'metadata' => null,
        ]);

        RunSecurityAudit::dispatch($session->id);

        return back()->with('success', 'Audit masuk antrean. Halaman ini akan memperbarui progress otomatis.');
    }

    public function status(int $session): JsonResponse
    {
        $session = $this->ownedSession($session);

        return response()->json([
            'status' => $session->status,
            'progress' => $session->progress,
            'stage' => $session->current_stage,
            'score' => $session->score,
            'grade' => $session->grade,
            'compliance_score' => $session->compliance_score,
            'risk_delta' => $session->risk_delta,
            'new_findings' => $session->new_findings_count,
            'resolved_findings' => $session->resolved_findings_count,
            'error' => $session->error_message,
            'findings' => $session->findings()->count(),
            'logs' => $session->logs()->limit(25)->get(['level', 'message', 'created_at'])->reverse()->values(),
        ]);
    }

    public function report(int $session): JsonResponse
    {
        $session = $this->ownedSession($session)->load([
            'findings',
            'baseline',
            'identities.accessRules',
            'accountTests.identity',
            'agentManifests' => fn ($query) => $query->latest('received_at')->limit(1),
        ]);

        return response()->json([
            'session' => [
                'id' => $session->id,
                'name' => $session->name,
                'target_url' => $session->target_url,
                'environment' => $session->environment,
                'status' => $session->status,
                'score' => $session->score,
                'grade' => $session->grade,
                'compliance_score' => $session->compliance_score,
                'risk_delta' => $session->risk_delta,
                'new_findings' => $session->new_findings_count,
                'resolved_findings' => $session->resolved_findings_count,
                'baseline_session_id' => $session->baseline_session_id,
                'baseline_score' => $session->baseline?->score,
                'monitoring_enabled' => $session->monitoring_enabled,
                'monitoring_interval_minutes' => $session->schedule_interval_minutes,
                'monitoring_label' => $session->monitoringLabel(),
                'next_run_at' => $session->next_run_at,
                'modules' => $session->selected_modules,
                'started_at' => $session->started_at,
                'completed_at' => $session->completed_at,
            ],
            'authenticated_security' => [
                'identity_count' => $session->identities->count(),
                'rule_count' => $session->identities->sum(fn ($identity) => $identity->accessRules->count()),
                'account_test_count' => $session->accountTests->count(),
                'identities' => $session->identities->map(fn ($identity) => [
                    'label' => $identity->label,
                    'expected_role' => $identity->expected_role,
                    'auth_type' => $identity->auth_type,
                    'enabled' => $identity->enabled,
                    'credentials_redacted' => true,
                    'rules' => $identity->accessRules->map(fn ($rule) => [
                        'label' => $rule->label,
                        'path' => $rule->path,
                        'expectation' => $rule->expectation,
                        'kind' => $rule->kind,
                        'business_context' => $rule->business_context,
                        'method' => 'GET',
                    ])->values(),
                ])->values(),
                'account_tests' => $session->accountTests->map(fn ($test) => [
                    'label' => $test->label,
                    'kind' => $test->kind,
                    'identity' => $test->identity?->label,
                    'hard_bounded' => true,
                    'password_guessing' => false,
                ])->values(),
            ],
            'laravel_agent' => [
                'manifest_available' => $session->agentManifests->isNotEmpty(),
                'latest' => $session->agentManifests->first() ? [
                    'source_label' => $session->agentManifests->first()->source_label,
                    'framework_version' => $session->agentManifests->first()->framework_version,
                    'routes_count' => $session->agentManifests->first()->routes_count,
                    'received_at' => $session->agentManifests->first()->received_at,
                ] : null,
            ],
            'summary' => [
                'critical' => $session->findings->where('severity', 'critical')->count(),
                'high' => $session->findings->where('severity', 'high')->count(),
                'medium' => $session->findings->where('severity', 'medium')->count(),
                'low' => $session->findings->where('severity', 'low')->count(),
                'info' => $session->findings->where('severity', 'info')->count(),
            ],
            'findings' => $session->findings->map(fn ($finding) => [
                'module' => $finding->module,
                'fingerprint' => $finding->fingerprint,
                'change_type' => $finding->change_type,
                'severity' => $finding->severity,
                'title' => $finding->title,
                'risk' => $finding->description,
                'evidence' => $finding->evidence,
                'solution' => $finding->remediation,
                'status' => $finding->status,
            ])->values(),
        ]);
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }

    private function monitoringIntervalMinutes(array $data): int
    {
        if (empty($data['monitoring_interval_value']) || empty($data['monitoring_interval_unit'])) {
            throw ValidationException::withMessages([
                'monitoring_interval_value' => 'Tentukan interval auto monitoring terlebih dahulu.',
            ]);
        }

        $value = (int) $data['monitoring_interval_value'];
        $minutes = match ($data['monitoring_interval_unit']) {
            'hours' => $value * 60,
            'days' => $value * 1440,
            'weeks' => $value * 10080,
            default => 0,
        };

        if ($minutes < 60 || $minutes > 525600) {
            throw ValidationException::withMessages([
                'monitoring_interval_value' => 'Interval monitoring minimal 1 jam dan maksimal 1 tahun.',
            ]);
        }

        return $minutes;
    }
}
