<?php

namespace Tests\Feature;

use App\Models\SecurityFinding;
use App\Models\SecuritySession;
use App\Models\User;
use App\Services\SecurityAudit\PostureAnalyzer;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class PostureAnalyzerTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_detects_persistent_new_and_resolved_findings_against_baseline(): void
    {
        $user = User::create([
            'name' => 'Security Admin',
            'email' => 'security@example.test',
            'password' => Hash::make('a-very-strong-test-password'),
        ]);

        $baseline = $this->session($user->id, 'completed', 78);
        SecurityFinding::create($this->finding($baseline->id, 'headers', 'Missing HSTS', 'high'));
        SecurityFinding::create($this->finding($baseline->id, 'cookies', 'Cookie policy weak', 'medium'));

        $analyzer = app(PostureAnalyzer::class);
        $baselineData = $analyzer->finalize($baseline, 78);
        $baseline->update(array_merge($baselineData, ['score' => 78, 'completed_at' => now()->subMinute()]));

        $current = $this->session($user->id, 'running', null);
        SecurityFinding::create($this->finding($current->id, 'headers', 'Missing HSTS', 'high'));
        SecurityFinding::create($this->finding($current->id, 'tls', 'Certificate expires soon', 'medium'));

        $result = $analyzer->finalize($current, 84);
        $current->update($result);

        $this->assertSame($baseline->id, $current->fresh()->baseline_session_id);
        $this->assertSame(6, $current->fresh()->risk_delta);
        $this->assertSame(1, $current->fresh()->new_findings_count);
        $this->assertSame(1, $current->fresh()->resolved_findings_count);
        $this->assertSame('persistent', $current->findings()->where('title', 'Missing HSTS')->first()->change_type);
        $this->assertSame('new', $current->findings()->where('title', 'Certificate expires soon')->first()->change_type);
    }

    private function session(int $userId, string $status, ?int $score): SecuritySession
    {
        return SecuritySession::create([
            'user_id' => $userId,
            'name' => 'Production Security Baseline',
            'target_url' => 'https://example.test',
            'environment' => 'production',
            'profile' => 'balanced',
            'status' => $status,
            'score' => $score,
            'selected_modules' => ['headers', 'cookies', 'tls'],
            'config' => [],
            'verification_token' => str_repeat('a', 48),
            'verified_at' => now(),
            'completed_at' => $status === 'completed' ? now()->subMinutes(2) : null,
        ]);
    }

    private function finding(int $sessionId, string $module, string $title, string $severity): array
    {
        return [
            'security_session_id' => $sessionId,
            'module' => $module,
            'severity' => $severity,
            'title' => $title,
            'description' => 'Test finding',
            'remediation' => 'Fix the control',
            'status' => 'open',
        ];
    }
}
