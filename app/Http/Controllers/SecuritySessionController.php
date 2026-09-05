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
use Illuminate\View\View;

class SecuritySessionController extends Controller
{
    private const MODULES = [
        'headers', 'tls', 'cookies', 'cors', 'exposure', 'rate_limit', 'latency', 'security_txt',
        'http_methods', 'dns_posture', 'load_resilience',
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
            'schedule_frequency' => ['nullable', Rule::in(['none', 'daily', 'weekly', 'monthly'])],
        ]);

        $targetUrl = rtrim($data['target_url'], '/');
        $guard->assertAllowed($targetUrl);

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
            'schedule_frequency' => ($data['schedule_frequency'] ?? 'none') === 'none' ? null : $data['schedule_frequency'],
            'verification_token' => Str::random(48),
        ]);

        return redirect()->route('sessions.show', $session)->with('success', 'Security session dibuat. Verifikasi target sebelum menjalankan audit.');
    }

    public function show(int $session): View
    {
        $session = $this->ownedSession($session)->load([
            'baseline',
            'findings',
            'logs' => fn ($query) => $query->limit(80),
        ]);

        return view('sessions.show', compact('session'));
    }

    public function verify(int $session, VerificationService $verification): RedirectResponse
    {
        $session = $this->ownedSession($session);

        if ($verification->verify($session)) {
            if ($session->schedule_frequency && ! $session->next_run_at) {
                $session->update(['next_run_at' => $this->nextSchedule($session->schedule_frequency)]);
            }

            return back()->with('success', 'Target berhasil diverifikasi. Audit dan continuous monitoring sudah dapat dijalankan.');
        }

        return back()->withErrors([
            'verification' => 'Token verifikasi tidak ditemukan atau tidak sama dengan token sesi.',
        ]);
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
        $session = $this->ownedSession($session)->load(['findings', 'baseline']);

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
                'schedule_frequency' => $session->schedule_frequency,
                'next_run_at' => $session->next_run_at,
                'modules' => $session->selected_modules,
                'started_at' => $session->started_at,
                'completed_at' => $session->completed_at,
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
                'description' => $finding->description,
                'evidence' => $finding->evidence,
                'remediation' => $finding->remediation,
                'status' => $finding->status,
            ])->values(),
        ]);
    }

    private function ownedSession(int $id): SecuritySession
    {
        return SecuritySession::query()->where('user_id', Auth::id())->findOrFail($id);
    }

    private function nextSchedule(string $frequency)
    {
        return match ($frequency) {
            'daily' => now()->addDay(),
            'weekly' => now()->addWeek(),
            'monthly' => now()->addMonth(),
            default => null,
        };
    }
}
